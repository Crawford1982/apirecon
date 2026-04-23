import { chromium } from 'playwright';

import { AutoNavigator } from './auto-navigator.mjs';
import { defaultChromeUserDataDir } from './chrome-profile.mjs';
import {
  findPageOnHost,
  tryAssistGoogleOAuth,
  waitUntilHostname,
} from './wait-for-auth.mjs';
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
 * @param {boolean} [opts.useChromeProfile] launchPersistentContext with real Chrome user data (Google OAuth session reuse)
 * @param {string} [opts.chromeUserDataDir] defaults to OS Chrome “User Data” path + env APIRECON_CHROME_USER_DATA
 * @param {string} [opts.chromeProfileDirectory] “Default”, “Profile 1”, …
 * @param {number} [opts.loginTimeoutMs] wait for you.23andme.com during OAuth (default 180000)
 * @param {boolean} [opts.waitForYouApp] after navigation, poll until hostname is you.23andme.com (23andMe targets)
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
  useChromeProfile = false,
  chromeUserDataDir = '',
  chromeProfileDirectory = 'Default',
  loginTimeoutMs = 180000,
  waitForYouApp = false,
}) {
  /** @type {import('playwright').Browser | null} */
  let browser = null;
  /** @type {import('playwright').BrowserContext} */
  let context;
  /** @type {import('playwright').Page} */
  let page;

  /** @type {CapturedRequest[]} */
  const traffic = [];

  let totalRequests = 0;
  let inScopeRequests = 0;
  let jsonApiRequests = 0;

  /** @type {WeakSet<import('playwright').Page>} */
  const attachedPages = new WeakSet();

  /**
   * @param {import('playwright').Page} p
   */
  function attachTrafficToPage(p) {
    if (attachedPages.has(p)) return;
    attachedPages.add(p);

    p.on('requestfinished', async (request) => {
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

    p.on('console', (msg) => {
      if (msg.type() === 'error') {
        traffic.push({
          type: 'console-error',
          timestamp: Date.now(),
          text: msg.text(),
          location: msg.location(),
        });
      }
    });
  }

  const effectiveHeadless = useChromeProfile ? false : headless;
  if (useChromeProfile && headless) {
    console.warn('[apirecon] --use-chrome-profile needs a visible browser — ignoring --headless.');
  }
  if (useChromeProfile) {
    console.warn(
      '[apirecon] Close all regular Chrome windows before using --use-chrome-profile or the profile may be locked.',
    );
  }

  const userDataDir = useChromeProfile ?
      chromeUserDataDir.trim() || process.env.APIRECON_CHROME_USER_DATA?.trim() || defaultChromeUserDataDir()
    : '';

  if (useChromeProfile) {
    console.log(`[apirecon] Chrome profile: ${userDataDir} (directory: ${chromeProfileDirectory})`);

    /** @type {import('playwright').LaunchPersistentContextOptions} */
    const persistOpts = {
      channel: 'chrome',
      headless: false,
      viewport: { width: 1280, height: 720 },
      args: [
        '--disable-blink-features=AutomationControlled',
        `--profile-directory=${chromeProfileDirectory}`,
        '--no-first-run',
        '--no-default-browser-check',
      ],
    };

    try {
      context = await chromium.launchPersistentContext(userDataDir, persistOpts);
    } catch (e) {
      const msg = /** @type {Error} */ (e).message;
      console.warn(`[apirecon] launchPersistentContext(channel:chrome) failed (${msg}). Retrying without channel…`);
      context = await chromium.launchPersistentContext(userDataDir, {
        ...persistOpts,
        channel: undefined,
      });
    }

    context.on('page', (newPage) => attachTrafficToPage(newPage));

    const existing = context.pages()[0];
    page = existing ?? (await context.newPage());
    attachTrafficToPage(page);
  } else {
    browser = await chromium.launch({
      headless: effectiveHeadless,
      args: ['--disable-blink-features=AutomationControlled'],
    });

    context = await browser.newContext({
      viewport: { width: 1280, height: 720 },
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    });

    context.on('page', (newPage) => attachTrafficToPage(newPage));

    page = await context.newPage();
    attachTrafficToPage(page);
  }

  /** @type {AbortController} */
  const abortController = new AbortController();

  const onSigint = () => {
    console.log('\n[apirecon] SIGINT received — stopping capture and saving…');
    abortController.abort();
  };
  process.once('SIGINT', onSigint);

  try {
    console.log(`Navigating to ${target}…`);
    console.log(
      '  If the window shows about:blank, that is normal until the response arrives (can take 30–60s on slow networks).',
    );
    console.log(`  Timeout for this step: ${Math.round(timeoutMs / 1000)}s (--timeout-ms to increase).`);

    try {
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: timeoutMs });
    } catch (e) {
      const err = /** @type {Error} */ (e);
      console.error(`[apirecon] Navigation failed: ${err.message}`);
      console.error(
        '  Fixes: quit all Chrome windows and retry --use-chrome-profile; try without --use-chrome-profile; check VPN/firewall/DNS; increase --timeout-ms.',
      );
      throw e;
    }

    console.log(`[apirecon] Loaded: ${page.url()}`);

    if (onReady) await onReady();

    if (String(target).includes('23andme.com')) {
      await tryAssistGoogleOAuth(page);
    }

    if (waitForYouApp) {
      console.log(
        `[apirecon] Waiting up to ${Math.round(loginTimeoutMs / 1000)}s for you.23andme.com (complete OAuth in the browser)…`,
      );

      const landed = await waitUntilHostname(page, 'you.23andme.com', loginTimeoutMs, (msg) =>
        console.log('[apirecon]', msg),
      );
      if (!landed) {
        console.warn(
          '[apirecon] Timed out waiting for you.23andme.com — finish login in the browser, then press ENTER / continue.',
        );
      }

      const onYou = await findPageOnHost(context, 'you.23andme.com');
      if (onYou) {
        await onYou.bringToFront();
        page = onYou;
        console.log(`[apirecon] Using tab: ${page.url()}`);
      } else {
        console.warn(`[apirecon] Could not find a tab on you.23andme.com yet (current: ${page.url()}).`);
      }
    }

    /** @type {() => { total: number, inScope: number, jsonApi: number }} */
    const getTrafficStats = () => ({
      total: totalRequests,
      inScope: inScopeRequests,
      jsonApi: jsonApiRequests,
    });

    const runNavigator = async () => {
      let crawlPage = (await findPageOnHost(context, 'you.23andme.com')) ?? page;
      await crawlPage.bringToFront().catch(() => {});

      const nav = new AutoNavigator(crawlPage, {
        verbose: true,
        getTrafficStats,
        signal: abortController.signal,
        ...autoNavigateOptions,
      });
      await nav.run();
    };

    if (autoNavigate) {
      console.log(
        `Auto-navigate: waiting ${autoNavigateLoginGraceMs}ms, then crawl (you should already be on you.23andme.com if --wait ran).`,
      );
      await sleep(autoNavigateLoginGraceMs);
      await runNavigator();
    } else {
      console.log('Browser is open. When the app is ready:');
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
    await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }

  return traffic.filter((t) => t.type === 'request' && typeof t.status === 'number');
}
