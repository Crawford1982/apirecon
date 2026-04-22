import { mkdirSync, writeFileSync } from 'node:fs';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

/** Bash-safe single-quoted string for copy-paste curl one-liners. */
export function shellSingleQuote(str) {
  return `'${String(str).replace(/'/g, `'\\''`)}'`;
}

export class IdorReplay {
  /**
   * @param {object} opts
   * @param {{ isAllowed: (url: string) => boolean } | null} [opts.scope]
   * @param {number} [opts.maxRps]
   * @param {number} [opts.timeoutMs]
   * @param {string | null} [opts.auth]
   */
  constructor({ scope, maxRps = 5, timeoutMs = 8000, auth = null }) {
    this.scope = scope;
    this.maxRps = maxRps;
    this.timeoutMs = timeoutMs;
    /** @type {string | null} */
    this.auth = auth;
    /** @type {unknown[]} */
    this.results = [];
  }

  /**
   * @param {import('./idor-detector.mjs').IdorDetector extends { find: infer X } ? never : any[]} candidates
   */
  buildTestQueue(candidates) {
    /** @type {object[]} */
    const queue = [];

    for (const candidate of candidates) {
      const tests = candidate.testSuggestion?.testUrls || [];
      const baseUrl = candidate.sampleUrls?.[0];
      if (!baseUrl) continue;
      let origin;
      try {
        origin = new URL(baseUrl).origin;
      } catch {
        continue;
      }

      for (const testPath of tests) {
        const testUrl =
          /^https?:\/\//i.test(testPath) ?
            testPath
          : `${origin}${testPath.startsWith('/') ? testPath : `/${testPath}`}`;
        if (this.scope && !this.scope.isAllowed(testUrl)) continue;

        queue.push({
          originalUrl: baseUrl,
          method: candidate.method,
          path: candidate.path,
          idValue: candidate.idValue,
          idorRisk: candidate.idorRisk,
          idType: candidate.idType,
          testUrl,
        });
      }
    }

    return queue;
  }

  /**
   * Copy-paste bash `curl` for bounty write-ups (same method, URL, and headers as replay).
   *
   * @param {{ method?: string, testUrl: string, auth?: string | null }} opts
   */
  static buildReplayCurl({ method, testUrl, auth = null }) {
    const m = String(method || 'GET').toUpperCase();
    const parts = ['curl', '-sS'];
    if (m !== 'GET') {
      parts.push('-X', m);
    }
    parts.push(shellSingleQuote(testUrl));
    parts.push('-H', shellSingleQuote('Accept: application/json'));
    parts.push(
      '-H',
      shellSingleQuote('User-Agent: apirecon-idor-replay/0.1 (+authorized testing only)'),
    );
    if (auth) {
      const a = auth.startsWith('Bearer ') ? auth : `Bearer ${auth}`;
      parts.push('-H', shellSingleQuote(`Authorization: ${a}`));
    }
    return parts.join(' ');
  }

  /**
   * @param {object[]} queue
   */
  async runSequential(queue) {
    const minInterval = 1000 / Math.max(1, this.maxRps);
    let last = 0;

    for (let i = 0; i < queue.length; i++) {
      const testCase = queue[i];
      const now = Date.now();
      const wait = Math.max(0, minInterval - (now - last));
      if (wait) await sleep(wait);
      last = Date.now();

      process.stdout.write(`\rProgress: ${i + 1}/${queue.length}`);
      const result = await this.executeTest(testCase);
      this.results.push(result);
    }
    process.stdout.write('\n');
  }

  async executeTest(testCase) {
    const start = Date.now();
    try {
      const headers = {
        Accept: 'application/json',
        'User-Agent': 'apirecon-idor-replay/0.1 (+authorized testing only)',
      };
      if (this.auth) {
        headers.Authorization = this.auth.startsWith('Bearer ')
          ? this.auth
          : `Bearer ${this.auth}`;
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.timeoutMs);

      const response = await fetch(testCase.testUrl, {
        method: String(testCase.method || 'GET'),
        headers,
        signal: controller.signal,
      });

      clearTimeout(timeout);

      const ct = response.headers.get('content-type') || '';
      /** @type {unknown} */
      let body = null;
      let bodyText = null;
      if (ct.includes('application/json')) {
        try {
          body = await response.json();
        } catch {
          bodyText = (await response.text()).slice(0, 2000);
        }
      } else {
        bodyText = (await response.text()).slice(0, 2000);
      }

      const duration = Date.now() - start;
      const finding = this.classifyFinding(response.status, body);

      return {
        status: 'completed',
        originalUrl: testCase.originalUrl,
        testUrl: testCase.testUrl,
        method: testCase.method,
        responseStatus: response.status,
        responseStatusText: response.statusText,
        contentType: ct,
        body,
        bodyText,
        duration,
        idorRisk: testCase.idorRisk,
        idType: testCase.idType,
        finding,
        replayCurl: IdorReplay.buildReplayCurl({
          method: testCase.method,
          testUrl: testCase.testUrl,
          auth: this.auth,
        }),
      };
    } catch (error) {
      return {
        status: 'error',
        originalUrl: testCase.originalUrl,
        testUrl: testCase.testUrl,
        method: testCase.method,
        error: /** @type {Error} */ (error).message,
        idorRisk: testCase.idorRisk,
        idType: testCase.idType,
        finding: null,
        replayCurl: IdorReplay.buildReplayCurl({
          method: testCase.method,
          testUrl: testCase.testUrl,
          auth: this.auth,
        }),
      };
    }
  }

  /**
   * @param {number} status
   * @param {unknown} body
   */
  classifyFinding(status, body) {
    if (status === 200 && body && typeof body === 'object' && !Array.isArray(body)) {
      const keys = Object.keys(body);
      if (keys.length > 0) {
        return {
          severity: 'high',
          type: 'idor-success',
          description:
            'HTTP 200 with JSON body for modified ID — verify manually; may be IDOR or public resource.',
          evidence: { bodyKeys: keys.slice(0, 30) },
        };
      }
    }
    if (status === 403 || status === 401) {
      return {
        severity: 'info',
        type: 'idor-blocked',
        description: 'Unauthorized/forbidden for modified ID.',
      };
    }
    if (status === 404) {
      return {
        severity: 'info',
        type: 'idor-not-found',
        description: 'Not found for modified ID.',
      };
    }
    if (status >= 500) {
      return {
        severity: 'medium',
        type: 'idor-server-error',
        description: 'Server error on modified ID — review response body for leaks.',
      };
    }
    return {
      severity: 'low',
      type: 'idor-unknown',
      description: `HTTP ${status} for modified ID.`,
      evidence: { status },
    };
  }

  summarize() {
    const findings = this.results.filter(
      (r) =>
        r &&
        typeof r === 'object' &&
        /** @type {{ finding?: { severity?: string }}} */ (r).finding &&
        ['high', 'medium'].includes(String(/** @type {{ finding: { severity: string }}} */ (r).finding.severity)),
    );
    const blocked = this.results.filter(
      (r) =>
        r &&
        typeof r === 'object' &&
        /** @type {{ finding?: { type?: string }}} */ (r).finding?.type === 'idor-blocked',
    );

    return {
      meta: {
        tool: 'apirecon-idor-replay',
        timestamp: Date.now(),
        totalTests: this.results.length,
        successfulTests: this.results.filter((r) => /** @type {{status?:string}} */ (r).status === 'completed')
          .length,
        errorTests: this.results.filter((r) => /** @type {{status?:string}} */ (r).status === 'error').length,
      },
      stats: {
        highSeverityFindings: this.results.filter(
          (r) => /** @type {{finding?:{severity?:string}}} */ (r).finding?.severity === 'high',
        ).length,
        mediumSeverityFindings: this.results.filter(
          (r) => /** @type {{finding?:{severity?:string}}} */ (r).finding?.severity === 'medium',
        ).length,
        blockedRequests: blocked.length,
        notFoundResponses: this.results.filter(
          (r) => /** @type {{finding?:{type?:string}}} */ (r).finding?.type === 'idor-not-found',
        ).length,
      },
      notableFindings: findings,
      allResults: this.results,
    };
  }

  /**
   * @param {object[]} candidates
   */
  async run(candidates) {
    const queue = this.buildTestQueue(candidates);
    console.log(`IDOR replay: ${queue.length} derived requests (sequential, ${this.maxRps} req/s max)`);
    await this.runSequential(queue);
    const summary = this.summarize();
    console.log(`Done. high=${summary.stats.highSeverityFindings} medium=${summary.stats.mediumSeverityFindings}`);
    return summary;
  }

  exportReport(outputDir = './output') {
    mkdirSync(outputDir, { recursive: true });
    const ts = Date.now();
    const reportFile = `${outputDir}/idor-replay-${ts}.json`;
    const summary = this.summarize();
    writeFileSync(
      reportFile,
      JSON.stringify(
        {
          meta: { tool: 'apirecon-idor-replay', version: '0.1.0', timestamp: ts },
          summary,
        },
        null,
        2,
      ),
    );
    console.log(`Report: ${reportFile}`);
    return reportFile;
  }
}
