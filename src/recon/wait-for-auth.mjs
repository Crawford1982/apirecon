import { sleep } from './utils.mjs';

/**
 * Best-effort: if we're on 23andMe auth, click "Sign in with Google" so an existing
 * Google session in the Chrome profile can continue without typing passwords into this tool.
 *
 * @param {import('playwright').Page} page
 */
export async function tryAssistGoogleOAuth(page) {
  try {
    const u = new URL(page.url());
    if (!u.hostname.includes('auth.23andme.com')) return;

    const btn = page.getByRole('button', { name: /google/i }).first();
    if (await btn.isVisible({ timeout: 2500 }).catch(() => false)) {
      console.log('[apirecon] Found “Sign in with Google” — clicking (uses your Chrome profile session if available).');
      await btn.click({ timeout: 12000 });
      await sleep(1500);
    }
  } catch {
    /* ignore */
  }
}

/**
 * Poll until URL hostname matches, or timeout. Use for OAuth redirect completion.
 *
 * @param {import('playwright').Page} page
 * @param {string} hostname e.g. you.23andme.com
 * @param {number} timeoutMs
 * @param {(msg: string) => void} [onTick]
 */
export async function waitUntilHostname(page, hostname, timeoutMs, onTick) {
  const deadline = Date.now() + timeoutMs;
  let lastLog = 0;

  while (Date.now() < deadline) {
    try {
      const h = new URL(page.url()).hostname;
      if (h === hostname) return true;
    } catch {
      /* ignore */
    }
    const now = Date.now();
    if (onTick && now - lastLog > 15000) {
      lastLog = now;
      try {
        onTick(`still waiting for https://${hostname}/ … (current: ${page.url()})`);
      } catch {
        /* ignore */
      }
    }
    await sleep(400);
  }
  return false;
}

/**
 * Prefer a tab/window that is already on the given host (OAuth popups / redirects).
 *
 * @param {import('playwright').BrowserContext} context
 * @param {string} hostname
 * @returns {Promise<import('playwright').Page | null>}
 */
export async function findPageOnHost(context, hostname) {
  for (const p of context.pages()) {
    try {
      if (new URL(p.url()).hostname === hostname) return p;
    } catch {
      /* ignore */
    }
  }
  return null;
}
