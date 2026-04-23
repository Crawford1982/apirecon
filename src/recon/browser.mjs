import { chromium } from 'playwright';

import { AutoNavigator } from './auto-navigator.mjs';
import { sleep } from './utils.mjs';

/**
 * @typedef {object} CapturedRequest
 * @property {'request'} type
 * @property {number} timestamp
 * @property {string} url
 * @property {string} method
 * @property {Record<string, string>} headers
 * @property {string|undefined} postData
 * @property {string} resourceType
 * @property {number} [status]
 * @property {string} [statusText]
 * @property {Record<string, string>} [responseHeaders]
 * @property {unknown} [responseBody]
 * @property {number} [responseTime]
 * @property {string} [error]
 */

/**
 * @param {object} opts
 * @param {string} opts.target
 * @param {boolean} [opts.headless]
 * @param {{ isAllowed: (url: string) => boolean } | null} [opts.scope]
 * @param {number} [opts.timeoutMs]
 * @param {() => Promise<void>} [opts.onReady]
 * @param {boolean} [opts.autoNavigate]
 * @param {object} [opts.autoNavigateOptions]
 * @param {number} [opts.autoNavigateLoginGraceMs]
 * @returns {Promise<CapturedRequest[]>}
 */
export async function launchBrowser({
  target,
  headless = false,
  scope,
  timeoutMs = 60000,
  onReady,
  autoNavigate = false,
  autoNavigateOptions = {},
  autoNavigateLoginGraceMs = 5000,
}) {
  const browser = await chromium.launch({
    headless,
    args: ['--disable-blink-features=AutomationControlled'],
  });

  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    userAgent:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  });

  const page = await context.newPage();
  /** @type {CapturedRequest[]} */
  const traffic = [];

  // Running counters for heartbeat
  let totalRequests = 0;
  let inScopeRequests = 0;
  let jsonApiRequests = 0;

  page.on('requestfinished', async (request) => {
    const url = request.url();
    totalRequests++;
    if (scope && !scope.isAllowed(url)) return;
    inScopeRequests++;

    const response = await request.response();
    const t0 = Date.now();

    /** @type {CapturedRequest} */
    const row = {
      type: 'request',
      timestamp: t0,
      url,
      method: request.method(),
      headers: request.headers(),
      postData: request.postData() ?? undefined,
      resourceType: request.resourceType(),
    };

    if (!response) {
      row.error = 'no_response';
      traffic.push(row);
      return;
    }

    row.status = response.status();
    row.statusText = response.statusText();
    row.responseHeaders = response.headers();
    row.responseTime = Math.max(0, Date.now() - t0);

    const ct = (response.headers()['content-type'] || '').toLowerCase();
    const rt = String(request.resourceType() || '').toLowerCase();
    if (ct.includes('application/json') || (['xhr', 'fetch'].includes(rt) && ct.includes('json'))) {
      jsonApiRequests++;
      try {
        row.responseBody = await response.json();
      } catch {
        try {
          const t = await response.text();
          row.responseBody = t;
        } catch (e) {
          row.error = /** @type {Error} */ (e).message;
        }
      }
    }

    traffic.push(row);
  });

  page.on('console', (msg) => {
    if (msg.type() === 'error') {
      traffic.push({
        type: 'console-error',
        timestamp: Date.now(),
        text: msg.text(),
        location: msg.location(),
      });
    }
  });

  /** @type {AbortController} */
  const abortController = new AbortController();

  const onSigint = () => {
    console.log('\n[apirecon] SIGINT received — stopping capture and saving…');
    abortController.abort();
  };
  process.once('SIGINT', onSigint);

  try {
    console.log(`Navigating to ${target}...`);
    await page.goto(target, { waitUntil: 'domcontentloaded', timeout: timeoutMs });

    if (onReady) await onReady();

    /** @type {() => { total: number, inScope: number, jsonApi: number }} */
    const getTrafficStats = () => ({
      total: totalRequests,
      inScope: inScopeRequests,
      jsonApi: jsonApiRequests,
    });

    const runNavigator = async () => {
      const nav = new AutoNavigator(page, {
        verbose: true,
        getTrafficStats,
        signal: abortController.signal,
        ...autoNavigateOptions,
      });
      await nav.run();
    };

    if (autoNavigate) {
      console.log(
        `Auto-navigate: waiting ${autoNavigateLoginGraceMs}ms — log in now if needed, then crawl starts.`,
      );
      await sleep(autoNavigateLoginGraceMs);
      await runNavigator();
    } else {
      console.log('Browser is open. Log in manually, then:');
      console.log('  [ENTER] or "a" + ENTER → automated SPA crawl (safe — skips destructive actions)');
      console.log('  any other input + ENTER → finish capture now');
      console.log('');

      const userInput = await new Promise((resolve) => {
        process.stdin.once('data', (data) => resolve(data.toString().trim()));
      });

      if (userInput === '' || userInput.toLowerCase() === 'a') {
        await runNavigator();
      }
    }

    await sleep(3000);
  } finally {
    process.off('SIGINT', onSigint);
    await browser.close().catch(() => {});
  }

  return traffic.filter((t) => t.type === 'request' && typeof t.status === 'number');
}
