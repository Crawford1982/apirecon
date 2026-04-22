/**
 * YAML scope compatible with graphqlai (`allowHosts`, `pathPrefixes`).
 */
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';

/**
 * @param {string} filePath
 * @param {string} [fallbackTargetUrl] derive default host when allowHosts omitted
 */
export function loadScope(filePath, fallbackTargetUrl = '') {
  const raw = readFileSync(filePath, 'utf8');
  const doc = /** @type {Record<string, unknown>} */ (yaml.load(raw));

  /** @type {string[]} */
  let allowHosts = [];
  const ah = doc.allowHosts;
  if (Array.isArray(ah)) allowHosts = ah.map(String);
  else if (typeof ah === 'string') allowHosts = [ah];

  if (allowHosts.length === 0 && fallbackTargetUrl) {
    try {
      allowHosts = [new URL(fallbackTargetUrl).hostname];
    } catch {
      /* ignore */
    }
  }

  /** @type {string[]} */
  let pathPrefixes = ['/'];
  const pp = doc.pathPrefixes;
  if (Array.isArray(pp) && pp.length) {
    pathPrefixes = pp.map((p) => (String(p).startsWith('/') ? String(p) : `/${String(p)}`));
  }

  const hostsLower = new Set(allowHosts.map((h) => h.toLowerCase()));

  return {
    allowHosts: hostsLower,
    pathPrefixes,
    maxRps: typeof doc.maxRps === 'number' ? doc.maxRps : 5,
    maxConcurrency: typeof doc.maxConcurrency === 'number' ? doc.maxConcurrency : 5,

    /** @param {string} urlStr */
    isAllowed(urlStr) {
      try {
        const u = new URL(urlStr);
        const host = u.hostname.toLowerCase();
        if (hostsLower.size > 0 && !hostsLower.has(host)) return false;

        const pathname = u.pathname || '/';
        const prefixes = pathPrefixes.length ? pathPrefixes : ['/'];
        const okPath = prefixes.some((p) => {
          if (p === '/') return true;
          return pathname === p || pathname.startsWith(`${p}/`) || pathname.startsWith(p);
        });
        return okPath;
      } catch {
        return false;
      }
    },
  };
}
