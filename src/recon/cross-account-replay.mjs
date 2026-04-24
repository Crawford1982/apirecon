import { mkdirSync, writeFileSync } from 'node:fs';

import { IdorDetector } from './idor-detector.mjs';
import { analyzeBody, diffAnalyses } from './response-analyzer.mjs';
import { resolveAuthHeaders } from './auth-bundle.mjs';
import { shellSingleQuote } from './idor-replay.mjs';
import { substituteVariable } from './graphql-parser.mjs';
import { RateGovernor } from './rate-governor.mjs';
import { buildEvidenceChain, deriveSeverity } from './evidence-chain.mjs';

/**
 * @typedef {object} AccountSpec
 * @property {string} label         human label, e.g. "A" / "B"
 * @property {import('./auth-bundle.mjs').AuthBundle} bundle
 * @property {string[]} scopeIds    this account's *own* scope IDs (profile IDs)
 */

/**
 * Cross-account IDOR verifier.
 *
 * Takes two {@link AccountSpec}s and a set of IDOR candidate findings and
 * runs a matrix of replay probes. For each `path-scope` (or `query`) finding
 * it issues:
 *
 *   1. `own`      — ownAuth + ownScopeId        (baseline; should be 200)
 *   2. `swap`     — ownAuth + otherScopeId      (**the actual IDOR probe**)
 *   3. `reverse`  — otherAuth + ownScopeId      (symmetrical probe, optional)
 *
 * It then feeds both bodies into {@link analyzeBody} and {@link diffAnalyses}
 * and assigns a verdict:
 *
 *   - `confirmed`    swap returned 200 with the same shape as baseline AND
 *                    the body contained the *other* account's identity hint
 *                    or distinct PII/signal volume.
 *   - `likely`       swap returned 200 with the same shape as baseline and
 *                    non-trivial body, but no identity hints detected.
 *   - `blocked`      swap returned 401/403/404.
 *   - `public`       swap returned identical body to baseline (public data).
 *   - `inconclusive` anything else (server errors, rate limits, redirects).
 *
 * Only candidates whose verdict is `confirmed` or `likely` warrant manual
 * report-writing. Everything else is silenced by default.
 */
export class CrossAccountReplay {
  /**
   * @param {object} opts
   * @param {AccountSpec} opts.accountA
   * @param {AccountSpec} [opts.accountB]          optional; when absent, `swap` uses `extraScopeIds` only
   * @param {string[]} [opts.extraScopeIds]        additional known target scope IDs (e.g. OSINT / shared DNA relative list)
   * @param {{ isAllowed: (url: string) => boolean } | null} [opts.scope]
   * @param {number} [opts.maxRps]
   * @param {number} [opts.timeoutMs]
   * @param {boolean} [opts.verbose]
   */
  constructor({ accountA, accountB, extraScopeIds = [], scope, maxRps = 3, timeoutMs = 8000, verbose = true, onResult = null }) {
    if (!accountA || !accountA.bundle) throw new Error('accountA bundle required');
    this.accountA = accountA;
    this.accountB = accountB || null;
    this.extraScopeIds = extraScopeIds.filter(Boolean);
    this.scope = scope || null;
    this.maxRps = maxRps;
    this.timeoutMs = timeoutMs;
    this.verbose = verbose;
    /** @type {((result: any, i: number, total: number) => void) | null} */
    this.onResult = onResult;
    this.governor = new RateGovernor({ maxRps });

    /** @type {any[]} */
    this.results = [];
  }

  /**
   * Build the full probe queue for a set of IDOR findings.
   *
   * @param {any[]} findings
   */
  buildQueue(findings) {
    /** @type {any[]} */
    const queue = [];
    const aIds = new Set(this.accountA.scopeIds);
    const bIds = new Set(
      (this.accountB?.scopeIds || []).concat(this.extraScopeIds),
    );

    for (const finding of findings) {
      if (!['path', 'query', 'nested-url', 'graphql-variable'].includes(finding.idorSource)) continue;

      const ownId = finding.idValue;
      if (!ownId) continue;

      const isGql = finding.idorSource === 'graphql-variable';
      const baselineUrl = isGql ? finding.operation?.endpointUrl : finding.sampleUrls?.[0];
      if (!baselineUrl) continue;

      /** @type {string[]} */
      const swapIds = [...bIds].filter((id) => id && id !== ownId);
      if (swapIds.length === 0) continue;

      for (const swapId of swapIds) {
        let swapUrl = baselineUrl;
        let ownBody = null;
        let swapBody = null;

        if (isGql) {
          ownBody = {
            query: finding.operation.query,
            operationName: finding.operation.operationName || undefined,
            variables: finding.operation.variables,
          };
          swapBody = substituteVariable(finding.operation, finding.operation.variablePath, swapId);
          if (!swapBody) continue;
        } else {
          const mutated = IdorDetector.substituteId(finding, swapId);
          if (!mutated) continue;
          swapUrl = mutated;
        }

        if (this.scope && !this.scope.isAllowed(swapUrl)) continue;

        queue.push({
          finding,
          ownId,
          swapId,
          probes: {
            own: {
              auth: 'A',
              url: baselineUrl,
              body: ownBody,
              label: `A/own(${ownId.slice(0, 8)}…)`,
            },
            swap: {
              auth: 'A',
              url: swapUrl,
              body: swapBody,
              label: `A/swap(${swapId.slice(0, 8)}…)`,
            },
            ...(this.accountB ?
              {
                reverseOwn: {
                  auth: 'B',
                  url: swapUrl,
                  body: swapBody,
                  label: `B/own(${swapId.slice(0, 8)}…)`,
                },
                reverseSwap: {
                  auth: 'B',
                  url: baselineUrl,
                  body: ownBody,
                  label: `B/swap(${ownId.slice(0, 8)}…)`,
                },
              }
            : {}),
          },
        });
      }
    }

    return queue;
  }

  /** @param {{ auth: 'A' | 'B', url: string, label: string }} probe @param {string} method */
  async fetchProbe(probe, method) {
    const bundle = probe.auth === 'A' ? this.accountA.bundle : this.accountB?.bundle;
    if (!bundle) {
      return {
        url: probe.url,
        auth: probe.auth,
        label: probe.label,
        error: 'no-auth-bundle',
      };
    }

    const extraHeaders = {
      Accept: 'application/json',
      'User-Agent': 'apirecon-cross-account/0.2 (+authorized testing only)',
    };
    if (probe.body != null) extraHeaders['Content-Type'] = 'application/json';
    const headers = resolveAuthHeaders(bundle, probe.url, extraHeaders);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    const start = Date.now();

    await this.governor.acquire(probe.url);

    try {
      const response = await fetch(probe.url, {
        method: String(method || 'GET'),
        headers,
        signal: controller.signal,
        redirect: 'manual',
        body: probe.body != null ? JSON.stringify(probe.body) : undefined,
      });
      clearTimeout(timeout);

      this.governor.report(probe.url, {
        status: response.status,
        retryAfter: response.headers.get('retry-after'),
      });
      if (response.status === 429 && this.verbose) {
        process.stdout.write(
          `\n[rate] 429 on ${probe.url} — backing off\n`,
        );
      }

      const ct = response.headers.get('content-type') || '';
      /** @type {unknown} */
      let body = null;
      let bodyText = null;
      if (ct.includes('application/json')) {
        try {
          body = await response.json();
        } catch {
          bodyText = (await response.text()).slice(0, 4000);
        }
      } else {
        bodyText = (await response.text()).slice(0, 4000);
      }

      return {
        url: probe.url,
        auth: probe.auth,
        label: probe.label,
        status: response.status,
        statusText: response.statusText,
        contentType: ct,
        body,
        bodyText,
        durationMs: Date.now() - start,
      };
    } catch (err) {
      clearTimeout(timeout);
      return {
        url: probe.url,
        auth: probe.auth,
        label: probe.label,
        error: /** @type {Error} */ (err).message,
        durationMs: Date.now() - start,
      };
    }
  }

  /**
   * Run the full matrix for one queue entry and verdict.
   * @param {any} entry
   */
  async runEntry(entry) {
    const method = entry.finding.method || 'GET';

    /** @type {Record<string, any>} */
    const results = {};
    for (const [key, probe] of Object.entries(entry.probes)) {
      results[key] = await this.fetchProbe(/** @type {any} */ (probe), method);
    }

    const aHints = this.accountA.scopeIds.concat([entry.ownId]);
    const bHints = (this.accountB?.scopeIds || []).concat([entry.swapId]);

    const ownAnalysis = results.own?.body ? analyzeBody(results.own.body, { identityHints: aHints }) : null;
    const swapAnalysis = results.swap?.body ? analyzeBody(results.swap.body, { identityHints: bHints }) : null;

    const diff = ownAnalysis && swapAnalysis ? diffAnalyses(ownAnalysis, swapAnalysis) : null;
    const verdict = this.verdict(results.own, results.swap, ownAnalysis, swapAnalysis, diff, entry.swapId);

    const evidenceChain = buildEvidenceChain(
      results.own ?? {},
      results.swap ?? {},
      { ownHints: aHints, swapHints: bHints },
    );
    const severity = deriveSeverity(verdict.kind, evidenceChain, entry.finding.idorRisk ?? 5);

    return {
      finding: pickFindingFields(entry.finding),
      ownId: entry.ownId,
      swapId: entry.swapId,
      probes: results,
      analyses: { own: ownAnalysis, swap: swapAnalysis },
      diff,
      verdict,
      evidenceChain,
      severity,
      curl: {
        own: buildCurl(entry.finding.method, results.own?.url, this.accountA.bundle, entry.probes.own?.body),
        swap: buildCurl(entry.finding.method, results.swap?.url, this.accountA.bundle, entry.probes.swap?.body),
      },
    };
  }

  /**
   * @param {any} own  baseline probe result
   * @param {any} swap cross-account probe result
   * @param {ReturnType<typeof analyzeBody> | null} ownAnal
   * @param {ReturnType<typeof analyzeBody> | null} swapAnal
   * @param {ReturnType<typeof diffAnalyses> | null} diff
   * @param {string} swapId  the *target* id — if this appears in the swap body it's a strong hit
   */
  verdict(own, swap, ownAnal, swapAnal, diff, swapId) {
    if (!swap || swap.error) return { kind: 'inconclusive', reason: swap?.error || 'no-response' };
    if (swap.status === 401 || swap.status === 403) return { kind: 'blocked', reason: `HTTP ${swap.status}` };
    if (swap.status === 404) return { kind: 'blocked', reason: 'HTTP 404 (not-found)' };
    if (swap.status === 429) return { kind: 'inconclusive', reason: 'rate-limited' };
    if (swap.status >= 500) return { kind: 'inconclusive', reason: `HTTP ${swap.status}` };
    if (swap.status >= 300 && swap.status < 400) return { kind: 'inconclusive', reason: `HTTP ${swap.status} redirect` };

    const reasons = [];
    const hintHits = swapAnal?.identityHintHits?.includes(swapId);
    const sameShape = diff?.similarShape && diff.bothHaveData;
    const identicalBody = diff && diff.jaccard > 0.95 && diff.sizeDelta === 0;

    if (identicalBody) {
      return { kind: 'public', reason: 'identical response body — likely public/non-personalised data', reasons };
    }

    if (hintHits) {
      reasons.push(`swap body contains target id ${swapId}`);
      reasons.push(`same-shape=${sameShape} jaccard=${diff?.jaccard ?? 'n/a'}`);
      return { kind: 'confirmed', reason: 'target id present in swap response body', reasons };
    }

    if (sameShape && (swapAnal?.leakScore || 0) >= 10) {
      reasons.push(`same-shape response with leakScore=${swapAnal.leakScore}`);
      reasons.push(`jaccard=${diff.jaccard}`);
      return { kind: 'likely', reason: 'same-shape response with PII signals for swapped id', reasons };
    }

    if (sameShape) {
      reasons.push(`same-shape response, low leak signals`);
      return { kind: 'likely', reason: 'same-shape response', reasons };
    }

    return { kind: 'inconclusive', reason: diff ? diff.verdict : 'no-diff', reasons };
  }

  /**
   * @param {any[]} findings
   */
  async run(findings) {
    const queue = this.buildQueue(findings);
    if (this.verbose) {
      console.log(
        `CrossAccountReplay: ${queue.length} probe(s) across ${findings.length} candidate(s) · maxRps=${this.maxRps}`,
      );
    }

    for (let i = 0; i < queue.length; i++) {
      if (this.verbose && !this.onResult) process.stdout.write(`\rProgress: ${i + 1}/${queue.length}`);
      const res = await this.runEntry(queue[i]);
      this.results.push(res);
      if (this.onResult) this.onResult(res, i, queue.length);
    }
    if (this.verbose && !this.onResult) process.stdout.write('\n');

    return this.summarize();
  }

  summarize() {
    const by = { confirmed: 0, likely: 0, blocked: 0, public: 0, inconclusive: 0 };
    for (const r of this.results) {
      by[r.verdict.kind] = (by[r.verdict.kind] || 0) + 1;
    }
    // Sort reportable findings by CVSS score descending.
    const bySeverity = (a, b) => (b.severity?.cvss ?? 0) - (a.severity?.cvss ?? 0);
    return {
      meta: { tool: 'apirecon-cross-account', version: '2.0', timestamp: Date.now() },
      stats: by,
      confirmed: this.results.filter((r) => r.verdict.kind === 'confirmed').sort(bySeverity),
      likely: this.results.filter((r) => r.verdict.kind === 'likely').sort(bySeverity),
      all: this.results,
    };
  }

  exportReport(outputDir = './output') {
    mkdirSync(outputDir, { recursive: true });
    const ts = Date.now();
    const file = `${outputDir}/cross-account-replay-${ts}.json`;
    writeFileSync(file, JSON.stringify(this.summarize(), null, 2));
    return file;
  }
}

function pickFindingFields(f) {
  return {
    method: f.method,
    path: f.path,
    pathTemplate: f.pathTemplate,
    host: f.host,
    idorSource: f.idorSource,
    idType: f.idType,
    idValue: f.idValue,
    queryParam: f.queryParam,
    scopeWord: f.scopeWord,
    idorRisk: f.idorRisk,
    riskReasons: f.riskReasons,
  };
}

function buildCurl(method, url, bundle, body) {
  if (!url) return null;
  const m = String(method || 'GET').toUpperCase();
  const parts = ['curl', '-sS'];
  if (m !== 'GET') parts.push('-X', m);
  parts.push(shellSingleQuote(url));
  const extra = {
    Accept: 'application/json',
    'User-Agent': 'apirecon-cross-account/0.2 (+authorized testing only)',
  };
  if (body != null) extra['Content-Type'] = 'application/json';
  const headers = resolveAuthHeaders(bundle, url, extra);
  for (const [k, v] of Object.entries(headers)) {
    parts.push('-H', shellSingleQuote(`${k}: ${v}`));
  }
  if (body != null) parts.push('--data-raw', shellSingleQuote(JSON.stringify(body)));
  return parts.join(' ');
}
