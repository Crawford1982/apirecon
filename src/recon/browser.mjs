import { chromium } from 'playwright';

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
 * @returns {Promise<CapturedRequest[]>}
 */
export async function launchBrowser({ target, headless = false, scope, timeoutMs = 60000, onReady }) {
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

  page.on('requestfinished', async (request) => {
    const url = request.url();
    if (scope && !scope.isAllowed(url)) return;

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
    if (ct.includes('application/json')) {
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

  console.log(`Navigating to ${target}...`);
  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: timeoutMs });

  if (onReady) await onReady();

  console.log('Browser is open. Navigate manually, then press ENTER in this terminal to finish…');

  await new Promise((resolve) => {
    process.stdin.once('data', () => resolve(undefined));
  });

  await new Promise((r) => setTimeout(r, 2000));
  await browser.close();

  return traffic.filter((t) => t.type === 'request' && typeof t.status === 'number');
}
