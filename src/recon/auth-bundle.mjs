import { isScopeWord, classifyValue } from './id-shape.mjs';

/**
 * @typedef {object} AuthBundle
 * @property {{ version: number, target: string, capturedAt: number, source: string }} meta
 * @property {Array<Record<string, any>>} cookies       raw Playwright cookies
 * @property {Record<string, Record<string, string>>} hostHeaders  host -> last-seen auth-ish headers
 * @property {Array<{ host: string, scopeWord: string, kind: string, value: string, hits: number }>} identities  observed IDs
 */

/**
 * Auth-ish request headers we harvest from captured traffic. Names match
 * what real SPAs send — some apps use custom names, so the list is
 * intentionally generous. Cookies come from `context.cookies()` directly.
 */
const AUTH_HEADER_KEYS = new Set([
  'authorization',
  'cookie',
  'x-csrftoken',
  'x-csrf-token',
  'x-xsrf-token',
  'x-requested-with',
  'x-auth-token',
  'x-api-key',
  'x-api-token',
  'x-session-token',
  'x-session-id',
  'x-account-token',
  'x-tenant-id',
  'x-customer-id',
  'x-user-id',
  'x-app-version',
  'x-platform',
  'x-client-id',
  'x-client-version',
  'x-device-id',
  'x-request-id',
  'x-correlation-id',
  // 23andMe-specific / likely
  'x-23andme-client',
  'x-23andme-session',
]);

/**
 * Pull cookies + auth headers + observed scope identities from a Playwright
 * context plus the captured traffic array. Designed to run once at the end
 * of a capture, before the context closes.
 *
 * @param {object} args
 * @param {import('playwright').BrowserContext} args.context
 * @param {string} args.target
 * @param {any[]} args.traffic
 * @returns {Promise<AuthBundle>}
 */
export async function extractAuthBundle({ context, target, traffic }) {
  const cookies = await context.cookies().catch(() => []);

  /** @type {Record<string, Record<string, string>>} */
  const hostHeaders = {};
  /** @type {Map<string, number>} */
  const identityCandidates = new Map();

  for (const req of traffic) {
    if (!req || req.type !== 'request') continue;
    if (!req.url) continue;

    let u;
    try {
      u = new URL(String(req.url));
    } catch {
      continue;
    }
    const host = u.hostname;

    const headers = (req.headers && typeof req.headers === 'object') ? req.headers : {};
    if (!hostHeaders[host]) hostHeaders[host] = {};
    for (const [rawKey, rawVal] of Object.entries(headers)) {
      const kl = String(rawKey || '').toLowerCase();
      if (!AUTH_HEADER_KEYS.has(kl)) continue;
      if (kl === 'cookie') continue; // cookies come from context.cookies() instead
      if (!rawVal) continue;
      hostHeaders[host][rawKey] = String(rawVal);
    }

    const segs = u.pathname.split('/').filter(Boolean);
    for (let i = 1; i < segs.length; i++) {
      if (!isScopeWord(segs[i - 1])) continue;
      const cand = segs[i];
      const cls = classifyValue(cand);
      if (!cls) continue;
      const key = `${host}|${segs[i - 1]}|${cand}`;
      identityCandidates.set(key, (identityCandidates.get(key) || 0) + 1);
      break;
    }
  }

  const identities = [...identityCandidates.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 30)
    .map(([key, hits]) => {
      const [host, scopeWord, value] = key.split('|');
      return {
        host,
        scopeWord,
        kind: scopeWord === 'p' ? 'profile_id' : `${scopeWord}_id`,
        value,
        hits,
      };
    });

  return {
    meta: {
      version: 1,
      target,
      capturedAt: Date.now(),
      source: 'playwright-capture',
    },
    cookies,
    hostHeaders,
    identities,
  };
}

/**
 * Format a bundle into a one-line `curl`-friendly `Cookie:` header for a
 * specific target host/path (used by replay and bounty-report builders).
 *
 * @param {AuthBundle} bundle
 * @param {string} targetUrl
 */
export function cookieHeaderFor(bundle, targetUrl) {
  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    return '';
  }
  const parts = [];
  for (const c of bundle.cookies || []) {
    if (!c || !c.name) continue;
    const dom = String(c.domain || '').replace(/^\./, '');
    if (!dom) continue;
    if (!(u.hostname === dom || u.hostname.endsWith('.' + dom))) continue;
    if (c.path && !u.pathname.startsWith(c.path)) continue;
    if (c.secure && u.protocol !== 'https:') continue;
    parts.push(`${c.name}=${c.value}`);
  }
  return parts.join('; ');
}

/**
 * Resolve the auth headers to send when replaying `targetUrl`. Picks the
 * host entry, merges global cookies, drops nothing the user explicitly set.
 *
 * @param {AuthBundle | null | undefined} bundle
 * @param {string} targetUrl
 * @param {Record<string, string>} [extraHeaders]
 */
export function resolveAuthHeaders(bundle, targetUrl, extraHeaders = {}) {
  /** @type {Record<string, string>} */
  const out = { ...extraHeaders };
  if (!bundle) return out;

  let u;
  try {
    u = new URL(targetUrl);
  } catch {
    return out;
  }

  const hostEntry = bundle.hostHeaders?.[u.hostname];
  if (hostEntry) {
    for (const [k, v] of Object.entries(hostEntry)) {
      if (out[k] == null) out[k] = v;
    }
  }

  const cookieHeader = cookieHeaderFor(bundle, targetUrl);
  if (cookieHeader && out.Cookie == null && out.cookie == null) {
    out.Cookie = cookieHeader;
  }

  return out;
}
