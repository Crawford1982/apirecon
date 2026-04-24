/**
 * orchestrator.mjs
 *
 * Full end-to-end pipeline for cross-account IDOR discovery.
 * Chains: load → filter → detect → diff-replay → evidence → report (MD + HTML).
 *
 *   npm run recon:full -- \
 *     --traffic-file-a ./output/traffic-raw-<tsA>.json \
 *     --auth-bundle-a  ./output/auth-bundle-<tsA>.json \
 *     --auth-bundle-b  ./output/auth-bundle-<tsB>.json \
 *     --scope-file     ./examples/scope.23andme.yaml
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

import { TrafficFilter } from './traffic-filter.mjs';
import { EndpointInventory } from './endpoint-inventory.mjs';
import { IdorDetector } from './idor-detector.mjs';
import { extractGraphqlOperations, operationsToFindings } from './graphql-parser.mjs';
import { CrossAccountReplay } from './cross-account-replay.mjs';
import { renderBountyReport, renderHtmlReport } from './report-generator.mjs';
import { version } from '../version.mjs';

// ─── console styling ─────────────────────────────────────────────────────────

const FG = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
};

const VERDICT_ICONS = {
  confirmed: `${FG.red}${FG.bold}[CONFIRMED]${FG.reset}`,
  likely: `${FG.yellow}[LIKELY]   ${FG.reset}`,
  blocked: `${FG.green}[BLOCKED]  ${FG.reset}`,
  public: `${FG.gray}[PUBLIC]   ${FG.reset}`,
  inconclusive: `${FG.gray}[?]        ${FG.reset}`,
};

const BAR = `${FG.dim}${'═'.repeat(68)}${FG.reset}`;

function banner(text) {
  console.log('');
  console.log(BAR);
  console.log(` ${FG.bold}${FG.cyan}${text}${FG.reset}`);
  console.log(BAR);
}

function step(n, total, text) {
  console.log(`\n${FG.bold}[${n}/${total}]${FG.reset} ${text}`);
}

function info(text) {
  console.log(`      ${FG.dim}${text}${FG.reset}`);
}

function highlight(text) {
  console.log(`      ${text}`);
}

// ─── file helpers ─────────────────────────────────────────────────────────────

/** @param {string} path @returns {any[]} */
function loadTraffic(path) {
  const raw = JSON.parse(readFileSync(path, 'utf8'));
  return Array.isArray(raw) ? raw : raw?.requests || [];
}

/** @param {string} path @returns {import('./auth-bundle.mjs').AuthBundle} */
function loadBundle(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

/** @param {import('./auth-bundle.mjs').AuthBundle} b @returns {string[]} */
function scopeIdsFrom(b) {
  return [...new Set((b?.identities || []).map((i) => i.value))];
}

// ─── orchestrator ─────────────────────────────────────────────────────────────

/**
 * @typedef {object} OrchestratorOptions
 * @property {string}   trafficFileA       Account A traffic capture
 * @property {string}   authBundleA        Account A auth bundle
 * @property {string}   [trafficFileB]     Optional account B traffic
 * @property {string}   [authBundleB]      Optional account B auth bundle
 * @property {string[]} [extraScopeIds]    Additional target IDs (OSINT / manual)
 * @property {{ isAllowed: (u: string) => boolean } | null} [scope]
 * @property {number}   [maxRps]
 * @property {number}   [timeoutMs]
 * @property {string}   [outputDir]
 * @property {string}   [target]           Human label for the report
 */

export class Orchestrator {
  /** @param {OrchestratorOptions} opts */
  constructor(opts) {
    this.trafficFileA = opts.trafficFileA;
    this.authBundleA = opts.authBundleA;
    this.trafficFileB = opts.trafficFileB || null;
    this.authBundleB = opts.authBundleB || null;
    this.extraScopeIds = opts.extraScopeIds || [];
    this.scope = opts.scope || null;
    this.maxRps = opts.maxRps || 3;
    this.timeoutMs = opts.timeoutMs || 10000;
    this.outputDir = opts.outputDir || './output';
    this.target = opts.target || 'target';
  }

  async run() {
    const ts = Date.now();
    mkdirSync(this.outputDir, { recursive: true });

    banner(`apirecon  ·  Cross-Account IDOR Pipeline  ·  ${new Date().toISOString().slice(0, 10)}`);

    // ── Step 1: Load ───────────────────────────────────────────────────────────
    step(1, 5, 'Loading traffic & auth bundles…');

    const bundleA = loadBundle(this.authBundleA);
    const bundleB = this.authBundleB ? loadBundle(this.authBundleB) : null;

    const rawA = loadTraffic(this.trafficFileA);
    const rawB = this.trafficFileB && existsSync(this.trafficFileB) ? loadTraffic(this.trafficFileB) : [];
    const allTraffic = [...rawA, ...rawB];

    const aIds = scopeIdsFrom(bundleA);
    const bIds = bundleB
      ? scopeIdsFrom(bundleB)
      : this.extraScopeIds.length
        ? this.extraScopeIds
        : [];

    info(`Account A: ${aIds.slice(0, 3).join(', ') || '(no ids extracted)'}`);
    if (bundleB) {
      info(`Account B: ${bIds.slice(0, 3).join(', ') || '(no ids extracted)'}`);
    } else if (this.extraScopeIds.length) {
      info(`Target IDs: ${this.extraScopeIds.slice(0, 3).join(', ')}`);
    }
    info(`Traffic:   ${rawA.length} request(s) from A${rawB.length ? ` + ${rawB.length} from B` : ''}`);

    if (bIds.length === 0) {
      console.log(`\n${FG.red}No target scope IDs available.${FG.reset}`);
      console.log('  Provide --auth-bundle-b or --extra-scope-ids <csv>');
      process.exit(1);
    }

    // ── Step 2: Detect ─────────────────────────────────────────────────────────
    step(2, 5, 'Detecting IDOR candidates…');

    const apiTraffic = TrafficFilter.jsonApis(allTraffic);
    const scopedTraffic = this.scope
      ? apiTraffic.filter((r) => this.scope.isAllowed(String(r.url)))
      : apiTraffic;
    const inventory = EndpointInventory.build(scopedTraffic);

    const restCandidates = IdorDetector.find(inventory);
    const { operations } = extractGraphqlOperations(scopedTraffic);
    const gqlCandidates = operationsToFindings(operations);

    const allCandidates = [...restCandidates, ...gqlCandidates];

    if (allCandidates.length === 0) {
      console.log(`\n${FG.yellow}No IDOR candidates detected.${FG.reset}`);
      console.log('  Capture more traffic: log in and navigate deeper into the app.');
      process.exit(0);
    }

    const groups = IdorDetector.groupByScope(restCandidates);
    info(`Scope groups: ${groups.length}`);
    info(`Candidates:   ${allCandidates.length} (rest=${restCandidates.length} gql=${gqlCandidates.length})`);
    if (allCandidates.length > 0) {
      const top = allCandidates.reduce((a, b) => ((a.idorRisk || 0) >= (b.idorRisk || 0) ? a : b));
      info(`Top finding:  ${top.method} ${top.pathTemplate || top.path}  [risk=${top.idorRisk}]`);
    }

    // ── Step 3: Diff replay ────────────────────────────────────────────────────
    step(3, 5, `Running cross-account diff replay (${allCandidates.length} probes, ${this.maxRps} RPS)…`);

    const runner = new CrossAccountReplay({
      accountA: { label: 'A', bundle: bundleA, scopeIds: aIds },
      accountB: bundleB ? { label: 'B', bundle: bundleB, scopeIds: bIds } : undefined,
      extraScopeIds: bundleB ? this.extraScopeIds : [...bIds, ...this.extraScopeIds],
      scope: this.scope,
      maxRps: this.maxRps,
      timeoutMs: this.timeoutMs,
      verbose: false,
      onResult: (result, i, total) => {
        const v = result.verdict.kind;
        const icon = VERDICT_ICONS[v] || VERDICT_ICONS.inconclusive;
        const url = result.probes?.swap?.url || result.finding?.path || '?';
        const evidence = result.evidenceChain?.evidenceScore ?? result.analyses?.swap?.leakScore ?? 0;
        const jaccard = result.diff?.jaccard ?? 0;

        if (v === 'confirmed' || v === 'likely') {
          console.log(`      ${icon} ${FG.bold}${url}${FG.reset}`);
          console.log(`               ${FG.dim}evidence=${evidence}  shape=${jaccard}  ${result.verdict.reason}${FG.reset}`);
        } else if (v === 'blocked') {
          console.log(`      ${icon} ${url}  ${FG.dim}(${result.verdict.reason})${FG.reset}`);
        } else {
          process.stdout.write(`\r      ${FG.dim}Progress: ${i + 1}/${total} (${v})${FG.reset}      `);
        }
      },
    });

    const summary = await runner.run(allCandidates);
    process.stdout.write('\n');

    const inconclusiveCount = summary.stats.inconclusive || 0;
    if (inconclusiveCount > 0) {
      info(`+ ${inconclusiveCount} inconclusive (rate-limited, server errors, redirects)`);
    }

    // ── Step 4: Evidence chains ────────────────────────────────────────────────
    step(4, 5, 'Building evidence chains…');

    const reportable = [...(summary.confirmed || []), ...(summary.likely || [])];
    if (reportable.length === 0) {
      info('No confirmed or likely cross-tenant reads — no reportable findings.');
    } else {
      const allLeaks = reportable
        .flatMap((r) => r.evidenceChain?.keyLeaks || [])
        .filter((v, i, a) => a.indexOf(v) === i)
        .slice(0, 6);
      if (allLeaks.length) {
        highlight(`${FG.red}Leaking fields: ${allLeaks.join('  ·  ')}${FG.reset}`);
      }
    }

    // ── Step 5: Generate reports ───────────────────────────────────────────────
    step(5, 5, 'Generating reports…');

    const reportOpts = {
      target: this.target,
      toolVersion: `apirecon v${version}`,
    };

    const jsonFile = `${this.outputDir}/cross-account-replay-${ts}.json`;
    writeFileSync(jsonFile, JSON.stringify(summary, null, 2));
    info(`Raw data:  ${jsonFile}`);

    const mdContent = renderBountyReport(summary, reportOpts);
    const mdFile = `${this.outputDir}/bounty-report-${ts}.md`;
    writeFileSync(mdFile, mdContent);
    info(`Markdown:  ${mdFile}`);

    const htmlContent = renderHtmlReport(summary, reportOpts);
    const htmlFile = `${this.outputDir}/bounty-report-${ts}.html`;
    writeFileSync(htmlFile, htmlContent);
    info(`HTML:      ${htmlFile}`);

    // ── Summary ────────────────────────────────────────────────────────────────
    const s = summary.stats;
    const topSeverity = reportable.length > 0
      ? reportable[0].severity?.label || 'Medium'
      : 'None';
    const topCvss = reportable.length > 0 ? reportable[0].severity?.cvss || 0 : 0;

    console.log('');
    console.log(BAR);
    const confirmedStr = s.confirmed > 0 ? `${FG.red}${FG.bold}CONFIRMED: ${s.confirmed}${FG.reset}` : `CONFIRMED: 0`;
    const likelyStr = s.likely > 0 ? `${FG.yellow}LIKELY: ${s.likely}${FG.reset}` : `LIKELY: 0`;
    console.log(` ${confirmedStr}  ${likelyStr}  BLOCKED: ${s.blocked || 0}  INCONCLUSIVE: ${s.inconclusive || 0}`);
    if (reportable.length > 0) {
      console.log(` ${FG.bold}Severity: ${topSeverity}  CVSS: ${topCvss.toFixed(1)}${FG.reset}`);
    }
    console.log(BAR);
    console.log('');

    return { summary, files: { json: jsonFile, md: mdFile, html: htmlFile } };
  }
}
