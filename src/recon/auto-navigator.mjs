import { sleep } from './utils.mjs';

/**
 * Destructive or session-ending action detector.
 *
 * These patterns are deliberately aggressive: during bounty recon, preserving
 * the test account matters far more than an extra endpoint hit.  Anything
 * matching the deny-list is skipped regardless of visibility / position.
 */
const DESTRUCTIVE_TEXT = [
  /\blog\s*out\b/i,
  /\bsign\s*out\b/i,
  /\bsign\s*in\b/i,
  /\bdelete\b/i,
  /\bremove\b/i,
  /\bdeactivate\b/i,
  /\bdisable\b/i,
  /\bunsubscribe\b/i,
  /\bunlink\b/i,
  /\brevoke\b/i,
  /\bterminate\b/i,
  /\bpurge\b/i,
  /\berase\b/i,
  /\bdestroy\b/i,
  /\bwipe\b/i,
  /\bclose\s*account\b/i,
  /\breset\s*password\b/i,
  /\bchange\s*password\b/i,
  /\bchange\s*email\b/i,
  /\btransfer\s*ownership\b/i,
  /\bcancel\s*(subscription|membership|plan|account)\b/i,
  /\bblock\s*user\b/i,
  /\breport\b/i,
  /\bpay\b/i,
  /\bcheckout\b/i,
  /\bsubmit\s*order\b/i,
  /\bplace\s*order\b/i,
  /\bpurchase\b/i,
  /\bbuy\b/i,
  /\bconfirm\s*(purchase|payment|order)\b/i,
];

const DESTRUCTIVE_HREF = [
  /\/logout/i,
  /\/signout/i,
  /\/sign-out/i,
  /\/delete/i,
  /\/remove/i,
  /\/deactivate/i,
  /\/close-account/i,
  /\/reset-password/i,
  /\/change-password/i,
  /\/cancel-(subscription|plan|membership)/i,
  /\/unsubscribe/i,
];

/**
 * Pure, side-effect-free destructive-action check.  Exported for tests.
 *
 * @param {{ text?: string | null, aria?: string | null, title?: string | null, href?: string | null }} info
 * @param {{ text?: RegExp[], href?: RegExp[] }} [extra]
 * @returns {{ destructive: boolean, reason: string }}
 */
export function isDestructiveAction(info, extra = {}) {
  const denyText = [...DESTRUCTIVE_TEXT, ...(extra.text ?? [])];
  const denyHref = [...DESTRUCTIVE_HREF, ...(extra.href ?? [])];
  const haystack = [info.text, info.aria, info.title].filter(Boolean).join(' ');
  for (const r of denyText) {
    if (r.test(haystack)) return { destructive: true, reason: `text:${r.source}` };
  }
  if (info.href) {
    for (const r of denyHref) {
      if (r.test(info.href)) return { destructive: true, reason: `href:${r.source}` };
    }
  }
  return { destructive: false, reason: '' };
}

const SAFE_INPUT_VALUES = {
  text: 'apirecon-test',
  search: 'apirecon-test',
  email: 'apirecon-test@example.com',
  url: 'https://example.com',
  tel: '5555550123',
  number: '1',
};

export class AutoNavigator {
  /**
   * @param {import('playwright').Page} page
   * @param {object} [options]
   * @param {number} [options.clickDelay=700]       Small delay between actions
   * @param {number} [options.actionTimeoutMs=8000] Per-click / per-fill timeout
   * @param {number} [options.networkIdleMs=1200]   How long to wait for quiet network
   * @param {number} [options.maxTotalClicks=400]   Global click ceiling
   * @param {number} [options.maxClicksPerRoute=40] Clicks before we move on
   * @param {number} [options.maxRoutes=40]         Unique pathnames to visit
   * @param {number} [options.maxDurationMs=600000] Hard wall clock budget (10min)
   * @param {number} [options.maxPaginationSteps=5] "Load more" / "Next" per route
   * @param {boolean} [options.verbose=true]
   * @param {boolean} [options.fillForms=true]
   * @param {(() => { total: number, inScope: number, jsonApi: number })} [options.getTrafficStats]
   * @param {AbortSignal} [options.signal]
   * @param {string[]} [options.extraDestructiveText] additional deny-list patterns (strings)
   */
  constructor(page, options = {}) {
    this.page = page;
    this.options = {
      clickDelay: options.clickDelay ?? 700,
      actionTimeoutMs: options.actionTimeoutMs ?? 8000,
      networkIdleMs: options.networkIdleMs ?? 1200,
      maxTotalClicks: options.maxTotalClicks ?? 400,
      maxClicksPerRoute: options.maxClicksPerRoute ?? 40,
      maxRoutes: options.maxRoutes ?? 40,
      maxDurationMs: options.maxDurationMs ?? 10 * 60 * 1000,
      maxPaginationSteps: options.maxPaginationSteps ?? 5,
      verbose: options.verbose !== false,
      fillForms: options.fillForms !== false,
      getTrafficStats: options.getTrafficStats ?? null,
      signal: options.signal ?? null,
      extraDestructiveText: options.extraDestructiveText ?? [],
    };

    /** @type {RegExp[]} */
    this.denyText = [
      ...DESTRUCTIVE_TEXT,
      ...this.options.extraDestructiveText.map((p) => new RegExp(p, 'i')),
    ];
    this.denyHref = DESTRUCTIVE_HREF;

    this.startOrigin = null;
    /** @type {Set<string>} */
    this.visitedRoutes = new Set();
    /** @type {string[]} */
    this.routeQueue = [];
    /** @type {number} */
    this.startTime = 0;

    this.stats = {
      clicks: 0,
      fills: 0,
      selects: 0,
      scrolls: 0,
      paginations: 0,
      navigations: 0,
      routesVisited: 0,
      errors: 0,
      skippedDestructive: 0,
    };
    /** @type {ReturnType<typeof setInterval> | null} */
    this.heartbeat = null;
  }

  // ─── public entry ────────────────────────────────────────────────────────

  async run() {
    this.startTime = Date.now();
    this.startOrigin = safeOrigin(this.page.url());

    this.log('');
    this.log('Auto-navigator starting');
    this.log(`  origin:  ${this.startOrigin}`);
    this.log(`  limits:  ${this.options.maxRoutes} routes · ${this.options.maxTotalClicks} clicks · ${Math.round(this.options.maxDurationMs / 1000)}s`);
    this.log('');

    await this.hookPushState();
    this.startHeartbeat();

    this.routeQueue.push(this.page.url());

    try {
      while (
        this.routeQueue.length > 0 &&
        this.visitedRoutes.size < this.options.maxRoutes &&
        !this.isBudgetExceeded()
      ) {
        const url = this.routeQueue.shift();
        if (!url) break;
        await this.visitRoute(url);
      }

      await this.finalPass();
    } finally {
      this.stopHeartbeat();
    }

    this.log('');
    this.log(
      `Auto-navigator done — routes=${this.stats.routesVisited} clicks=${this.stats.clicks} fills=${this.stats.fills} selects=${this.stats.selects} pages=${this.stats.paginations} nav=${this.stats.navigations} skippedDestructive=${this.stats.skippedDestructive} errors=${this.stats.errors}`,
    );
    const traffic = this.fetchTrafficStats();
    if (traffic) {
      this.log(
        `   traffic captured: total=${traffic.total} inScope=${traffic.inScope} jsonApi=${traffic.jsonApi}`,
      );
    }
  }

  // ─── per-route work ──────────────────────────────────────────────────────

  /** @param {string} targetUrl */
  async visitRoute(targetUrl) {
    const key = this.routeKey(targetUrl);
    if (this.visitedRoutes.has(key)) return;
    this.visitedRoutes.add(key);

    const currentKey = this.routeKey(this.page.url());
    if (currentKey !== key) {
      try {
        await this.page.goto(targetUrl, {
          waitUntil: 'domcontentloaded',
          timeout: 25000,
        });
        this.stats.navigations++;
      } catch {
        this.stats.errors++;
        return;
      }
    }

    this.stats.routesVisited++;
    this.log(`[route ${this.stats.routesVisited}/${this.options.maxRoutes}] ${this.page.url()}`);

    await this.waitForStableState();
    await this.dismissConsentAndCookieBanners();

    const routeClicksBefore = this.stats.clicks;
    const routeClickBudget = () =>
      this.stats.clicks - routeClicksBefore < this.options.maxClicksPerRoute;

    await this.discoverLinks();

    await this.interactOnCurrentPage(routeClickBudget);

    await this.exhaustPagination();

    await this.scrollAndRescan(routeClickBudget);

    await this.handleAnyOpenModal();
  }

  // ─── interaction primitives ──────────────────────────────────────────────

  /** @param {() => boolean} stillBudgeted */
  async interactOnCurrentPage(stillBudgeted) {
    await this.clickTabs(stillBudgeted);
    await this.clickButtons(stillBudgeted);
    if (this.options.fillForms) {
      await this.exerciseInputs(stillBudgeted);
      await this.exerciseSelects(stillBudgeted);
    }
  }

  /** @param {() => boolean} stillBudgeted */
  async clickTabs(stillBudgeted) {
    const tabLoc = this.page.locator('[role="tab"], [role="tablist"] [role="tab"]');
    await this.clickEachByIndex(tabLoc, 'tab', stillBudgeted);
  }

  /** @param {() => boolean} stillBudgeted */
  async clickButtons(stillBudgeted) {
    const buttonLoc = this.page.locator(
      'button:not([disabled]), [role="button"]:not([disabled]), input[type="submit"]:not([disabled]), details > summary',
    );
    await this.clickEachByIndex(buttonLoc, 'button', stillBudgeted);
  }

  /**
   * Generic "snapshot indices, click each" loop that tolerates DOM re-renders.
   * Stops if a click caused navigation (caller decides whether to continue).
   *
   * @param {import('playwright').Locator} locator
   * @param {string} kind
   * @param {() => boolean} stillBudgeted
   */
  async clickEachByIndex(locator, kind, stillBudgeted) {
    let count = 0;
    try {
      count = await locator.count();
    } catch {
      return;
    }
    if (count === 0) return;

    /** @type {Set<string>} */
    const clickedFingerprints = new Set();
    const cap = Math.min(count, this.options.maxClicksPerRoute * 2);
    const urlAtStart = this.page.url();

    for (let i = 0; i < cap; i++) {
      if (this.isBudgetExceeded() || !stillBudgeted()) return;
      if (this.stats.clicks >= this.options.maxTotalClicks) return;

      const item = locator.nth(i);
      let fingerprint = '';
      try {
        fingerprint = await this.fingerprintElement(item);
      } catch {
        continue;
      }
      if (!fingerprint) continue;
      if (clickedFingerprints.has(fingerprint)) continue;
      clickedFingerprints.add(fingerprint);

      const safety = await this.safetyCheck(item);
      if (safety.skip) {
        this.stats.skippedDestructive++;
        if (safety.reason && this.options.verbose) {
          this.log(`     skip [${kind}]: ${safety.reason}`);
        }
        continue;
      }

      const ok = await this.safeClick(item, kind, safety.label);
      if (!ok) continue;

      // Navigated? Enqueue, then return so caller re-queues current page if needed.
      if (this.page.url() !== urlAtStart) {
        this.enqueueCurrentUrl();
        return;
      }
    }
  }

  /** @param {() => boolean} stillBudgeted */
  async exerciseInputs(stillBudgeted) {
    const inputLoc = this.page.locator(
      'input[type="text"]:not([disabled]), input[type="search"]:not([disabled]), input:not([type]):not([disabled]), input[type="email"]:not([disabled]), input[type="number"]:not([disabled]), input[type="url"]:not([disabled]), input[type="tel"]:not([disabled])',
    );

    let count = 0;
    try {
      count = await inputLoc.count();
    } catch {
      return;
    }

    for (let i = 0; i < Math.min(count, 8); i++) {
      if (!stillBudgeted() || this.isBudgetExceeded()) return;

      const field = inputLoc.nth(i);
      try {
        if (!(await field.isVisible())) continue;
        if (!(await field.isEditable())) continue;
        const type = (await field.getAttribute('type')) || 'text';
        const value = SAFE_INPUT_VALUES[type] ?? SAFE_INPUT_VALUES.text;

        await field.fill(value, { timeout: this.options.actionTimeoutMs });
        await field.press('Enter', { timeout: this.options.actionTimeoutMs }).catch(() => {});
        this.stats.fills++;
        if (this.options.verbose) this.log(`     fill [${type}]: ${value}`);
        await this.settle();
      } catch {
        this.stats.errors++;
      }
    }
  }

  /** @param {() => boolean} stillBudgeted */
  async exerciseSelects(stillBudgeted) {
    const selectLoc = this.page.locator('select:not([disabled])');
    let count = 0;
    try {
      count = await selectLoc.count();
    } catch {
      return;
    }

    for (let i = 0; i < Math.min(count, 5); i++) {
      if (!stillBudgeted() || this.isBudgetExceeded()) return;
      try {
        const sel = selectLoc.nth(i);
        if (!(await sel.isVisible())) continue;

        const options = await sel.locator('option').all();
        if (options.length <= 1) continue;
        const optIdx = Math.min(1, options.length - 1);
        const optValue = await options[optIdx].getAttribute('value');
        if (!optValue) continue;
        await sel.selectOption(optValue, { timeout: this.options.actionTimeoutMs });
        this.stats.selects++;
        if (this.options.verbose) this.log(`     select: ${optValue}`);
        await this.settle();
      } catch {
        this.stats.errors++;
      }
    }
  }

  async exhaustPagination() {
    const patterns = [
      'button:has-text("Load more")',
      'button:has-text("Show more")',
      'button:has-text("More")',
      'button:has-text("Next")',
      'a:has-text("Next")',
      '[aria-label*="next" i]',
      '[class*="pagination" i] [class*="next" i]',
    ];

    for (let step = 0; step < this.options.maxPaginationSteps; step++) {
      if (this.isBudgetExceeded()) return;

      let clickedOne = false;
      for (const sel of patterns) {
        const loc = this.page.locator(sel).first();
        try {
          if (!(await loc.count())) continue;
          if (!(await loc.isVisible())) continue;
          const safety = await this.safetyCheck(loc);
          if (safety.skip) continue;

          const before = this.page.url();
          const clicked = await this.safeClick(loc, 'pagination', safety.label);
          if (clicked) {
            this.stats.paginations++;
            clickedOne = true;
            if (this.page.url() !== before) {
              this.enqueueCurrentUrl();
              return;
            }
          }
        } catch {
          /* try next pattern */
        }
      }
      if (!clickedOne) return;
    }
  }

  /** @param {() => boolean} stillBudgeted */
  async scrollAndRescan(stillBudgeted) {
    let previousHeight = 0;
    const maxScrolls = 12;

    for (let i = 0; i < maxScrolls; i++) {
      if (this.isBudgetExceeded() || !stillBudgeted()) return;
      const currentHeight = await this.page.evaluate(() => document.body.scrollHeight).catch(() => 0);
      if (currentHeight === previousHeight && i > 2) break;
      previousHeight = currentHeight;

      await this.page
        .evaluate(() => window.scrollBy(0, window.innerHeight * 0.9))
        .catch(() => {});
      this.stats.scrolls++;
      await sleep(this.options.networkIdleMs);
    }

    await this.page.evaluate(() => window.scrollTo(0, 0)).catch(() => {});
  }

  async handleAnyOpenModal() {
    const modalLoc = this.page.locator(
      '[role="dialog"], [role="modal"], [class*="modal" i], [class*="dialog" i]',
    );
    let visible = false;
    try {
      visible = (await modalLoc.count()) > 0 && (await modalLoc.first().isVisible());
    } catch {
      return;
    }
    if (!visible) return;

    const modal = modalLoc.first();
    const buttons = modal.locator('button, a, [role="button"]');
    const cnt = await buttons.count().catch(() => 0);
    for (let i = 0; i < Math.min(cnt, 6); i++) {
      const btn = buttons.nth(i);
      const safety = await this.safetyCheck(btn);
      if (safety.skip) {
        this.stats.skippedDestructive++;
        continue;
      }
      await this.safeClick(btn, 'modal', safety.label);
    }

    await this.page.keyboard.press('Escape').catch(() => {});
    await sleep(500);
  }

  async dismissConsentAndCookieBanners() {
    const accepts = [
      'button:has-text("Accept")',
      'button:has-text("I agree")',
      'button:has-text("Got it")',
      'button:has-text("OK")',
      'button:has-text("Continue")',
      '[aria-label*="accept cookies" i]',
    ];
    for (const sel of accepts) {
      const loc = this.page.locator(sel).first();
      try {
        if ((await loc.count()) && (await loc.isVisible())) {
          await loc.click({ timeout: 3000 });
          this.stats.clicks++;
          await sleep(500);
          return;
        }
      } catch {
        /* ignore */
      }
    }
  }

  async finalPass() {
    if (this.isBudgetExceeded()) return;
    try {
      if (await this.page.evaluate(() => window.history.length > 1)) {
        await this.page
          .goBack({ waitUntil: 'domcontentloaded', timeout: 15000 })
          .catch(() => {});
        await sleep(800);
        await this.page
          .goForward({ waitUntil: 'domcontentloaded', timeout: 15000 })
          .catch(() => {});
        await sleep(800);
        this.stats.navigations += 2;
      }
    } catch {
      /* ignore */
    }
  }

  // ─── helpers ─────────────────────────────────────────────────────────────

  /**
   * @param {import('playwright').Locator} loc
   * @param {string} kind
   * @param {string} label
   */
  async safeClick(loc, kind, label = '') {
    try {
      if (!(await loc.isVisible().catch(() => false))) return false;
      await loc.scrollIntoViewIfNeeded({ timeout: 3000 }).catch(() => {});
      await loc.click({ timeout: this.options.actionTimeoutMs, trial: false });
      this.stats.clicks++;
      if (this.options.verbose && label) {
        this.log(`     click [${kind}]: ${label.slice(0, 60)}`);
      }
      await this.settle();
      return true;
    } catch {
      this.stats.errors++;
      return false;
    }
  }

  /** Wait for quiet-ish network, bounded. */
  async settle() {
    await this.page
      .waitForLoadState('networkidle', { timeout: this.options.networkIdleMs + 4000 })
      .catch(() => {});
    await sleep(this.options.clickDelay);
  }

  async waitForStableState() {
    await this.page.waitForLoadState('domcontentloaded').catch(() => {});
    await sleep(800);
    await this.page.waitForLoadState('networkidle', { timeout: 8000 }).catch(() => {});
    try {
      await this.page.waitForFunction(
        () => {
          const spinners = document.querySelectorAll(
            '[class*="loading"], [class*="spinner"], [class*="skeleton"]',
          );
          return spinners.length === 0;
        },
        { timeout: 6000 },
      );
    } catch {
      /* ignore */
    }
  }

  async discoverLinks() {
    /** @type {string[]} */
    let hrefs = [];
    try {
      hrefs = await this.page.$$eval('a[href]', (anchors) =>
        anchors
          .map((a) => /** @type {HTMLAnchorElement} */ (a).href)
          .filter((h) => !!h),
      );
    } catch {
      return;
    }

    const currentOrigin = safeOrigin(this.page.url());
    for (const href of hrefs) {
      if (this.visitedRoutes.size + this.routeQueue.length >= this.options.maxRoutes * 2) break;
      if (!/^https?:/i.test(href)) continue;
      const origin = safeOrigin(href);
      if (!origin || origin !== this.startOrigin) {
        // Also allow same-origin as current page (handles OAuth bounces that
        // leave us on e.g. auth.* and back onto you.* later)
        if (origin !== currentOrigin) continue;
      }
      const key = this.routeKey(href);
      if (this.visitedRoutes.has(key)) continue;
      if (this.routeQueue.some((u) => this.routeKey(u) === key)) continue;
      if (this.denyHref.some((r) => r.test(href))) continue;
      this.routeQueue.push(href);
    }
  }

  /** @param {import('playwright').Locator} loc */
  async safetyCheck(loc) {
    /** @type {{ text: string, aria: string | null, title: string | null, href: string | null }} */
    let info = { text: '', aria: null, title: null, href: null };
    try {
      info = await loc.evaluate((el) => ({
        text: (/** @type {HTMLElement} */ (el).innerText || el.textContent || '').slice(0, 200),
        aria: el.getAttribute('aria-label'),
        title: el.getAttribute('title'),
        href: el.getAttribute('href'),
      }));
    } catch {
      return { skip: true, reason: 'element-detached', label: '' };
    }

    const label = (info.text || info.aria || info.title || '').trim();
    const extra = {
      text: this.options.extraDestructiveText.map((p) => new RegExp(p, 'i')),
      href: [],
    };
    const verdict = isDestructiveAction(info, extra);
    if (verdict.destructive) {
      return { skip: true, reason: `destructive:${verdict.reason} "${label.slice(0, 40)}"`, label };
    }
    if (info.href) {
      if (info.href.startsWith('mailto:') || info.href.startsWith('javascript:')) {
        return { skip: true, reason: 'non-http-href', label };
      }
      try {
        const abs = new URL(info.href, this.page.url());
        const cur = new URL(this.page.url());
        if (abs.origin !== cur.origin && abs.origin !== this.startOrigin) {
          return { skip: true, reason: 'cross-origin', label };
        }
      } catch {
        return { skip: true, reason: 'bad-href', label };
      }
    }
    return { skip: false, reason: '', label };
  }

  /** Stable-ish per-page fingerprint for a locator. */
  /** @param {import('playwright').Locator} loc */
  async fingerprintElement(loc) {
    try {
      return await loc.evaluate((el) => {
        const text = (/** @type {HTMLElement} */ (el).innerText || el.textContent || '').trim().slice(0, 80);
        const aria = el.getAttribute('aria-label') || '';
        const href = el.getAttribute('href') || '';
        const dtid = el.getAttribute('data-testid') || '';
        return `${text}|${aria}|${href}|${dtid}`;
      });
    } catch {
      return '';
    }
  }

  /** Pathname-only key so `?ts=…` cache-busting doesn't inflate the queue. */
  /** @param {string} url */
  routeKey(url) {
    try {
      const u = new URL(url);
      return `${u.origin}${u.pathname}`;
    } catch {
      return url;
    }
  }

  enqueueCurrentUrl() {
    const key = this.routeKey(this.page.url());
    if (this.visitedRoutes.has(key)) return;
    if (this.routeQueue.some((u) => this.routeKey(u) === key)) return;
    this.routeQueue.unshift(this.page.url());
  }

  async hookPushState() {
    try {
      await this.page.addInitScript(() => {
        const push = history.pushState;
        const replace = history.replaceState;
        /** @param {string} u */
        const dispatch = (u) => {
          try {
            window.dispatchEvent(new CustomEvent('__apirecon_route', { detail: u }));
          } catch {
            /* ignore */
          }
        };
        history.pushState = function (...args) {
          const r = push.apply(this, args);
          dispatch(String(args[2] ?? location.href));
          return r;
        };
        history.replaceState = function (...args) {
          const r = replace.apply(this, args);
          dispatch(String(args[2] ?? location.href));
          return r;
        };
        window.addEventListener('popstate', () => dispatch(location.href));
      });
      await this.page.exposeFunction('__apireconRouteSeen', (u) => {
        if (!u || typeof u !== 'string') return;
        try {
          const abs = new URL(u, this.page.url()).toString();
          const key = this.routeKey(abs);
          if (this.visitedRoutes.has(key)) return;
          if (this.routeQueue.some((x) => this.routeKey(x) === key)) return;
          if (safeOrigin(abs) !== this.startOrigin) return;
          this.routeQueue.push(abs);
        } catch {
          /* ignore */
        }
      });
      await this.page.evaluate(() => {
        window.addEventListener('__apirecon_route', (/** @type {Event} */ ev) => {
          // @ts-ignore custom event detail
          const u = ev.detail;
          // @ts-ignore exposed binding
          window.__apireconRouteSeen(u).catch(() => {});
        });
      });
    } catch {
      /* setup hooks best-effort */
    }
  }

  startHeartbeat() {
    if (!this.options.getTrafficStats && !this.options.verbose) return;
    this.heartbeat = setInterval(() => {
      const t = this.fetchTrafficStats();
      const elapsed = Math.round((Date.now() - this.startTime) / 1000);
      const core = `routes=${this.stats.routesVisited}/${this.options.maxRoutes} clicks=${this.stats.clicks}/${this.options.maxTotalClicks} queued=${this.routeQueue.length}`;
      const traf = t ? ` · traffic total=${t.total} inScope=${t.inScope} jsonApi=${t.jsonApi}` : '';
      this.log(`   heartbeat t=${elapsed}s ${core}${traf}`);
    }, 5000).unref?.();
  }

  stopHeartbeat() {
    if (this.heartbeat) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  fetchTrafficStats() {
    if (!this.options.getTrafficStats) return null;
    try {
      return this.options.getTrafficStats();
    } catch {
      return null;
    }
  }

  isBudgetExceeded() {
    if (this.options.signal?.aborted) return true;
    if (Date.now() - this.startTime > this.options.maxDurationMs) return true;
    if (this.stats.clicks >= this.options.maxTotalClicks) return true;
    return false;
  }

  /** @param {string} msg */
  log(msg) {
    if (this.options.verbose) console.log(msg);
  }
}

/** @param {string} u */
function safeOrigin(u) {
  try {
    return new URL(u).origin;
  } catch {
    return null;
  }
}
