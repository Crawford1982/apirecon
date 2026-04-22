export class IdorDetector {
  static ID_PATTERNS = [
    { regex: /\d{4,}\/?$/, type: 'numeric-long', risk: 2 },
    { regex: /\/\d{1,3}\/?$/, type: 'numeric-short', risk: 3 },
    {
      regex: /\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\/?$/i,
      type: 'uuid',
      risk: 2,
    },
    { regex: /\/[A-Za-z0-9_-]{20,}\/?$/, type: 'opaque-token', risk: 3 },
    { regex: /\/users?\/[^/]+\/?$/i, type: 'user-path', risk: 5 },
    { regex: /\/profiles?\/[^/]+\/?$/i, type: 'profile-path', risk: 5 },
    { regex: /\/accounts?\/[^/]+\/?$/i, type: 'account-path', risk: 5 },
    { regex: /\/relatives?\/[^/]+\/?$/i, type: 'relative-path', risk: 4 },
    { regex: /\/dna\/[^/]+\/?$/i, type: 'dna-path', risk: 4 },
    { regex: /\/downloads?\/[^/]+\/?$/i, type: 'download-path', risk: 4 },
    { regex: /\/reports?\/[^/]+\/?$/i, type: 'report-path', risk: 3 },
    { regex: /\/orders?\/[^/]+\/?$/i, type: 'order-path', risk: 3 },
  ];

  /** Query keys that rarely identify a single resource for IDOR testing */
  static QUERY_PARAM_DENYLIST = new Set([
    'page',
    'per_page',
    'perpage',
    'limit',
    'offset',
    'size',
    'cursor',
    'sort',
    'order',
    'direction',
    'q',
    'query',
    'search',
    'filter',
    'fields',
    'expand',
    'include',
    'callback',
    'format',
    'locale',
    'lang',
    'token',
    'csrf',
    'state',
    'nonce',
    'timestamp',
    't',
    'v',
    'version',
    'cb',
    'ref',
    'utm_source',
    'utm_medium',
    'utm_campaign',
  ]);

  /** Query keys that usually carry resource identifiers */
  static QUERY_PARAM_ID_NAMES = new Set([
    'id',
    'ids',
    'uid',
    'userid',
    'user_id',
    'profile_id',
    'profileid',
    'profileId',
    'account_id',
    'accountid',
    'accountId',
    'customer_id',
    'customerid',
    'member_id',
    'memberid',
    'relative_id',
    'relativeid',
    'order_id',
    'orderid',
    'report_id',
    'reportid',
    'participant_id',
    'sample_id',
  ]);

  /**
   * @param {ReturnType<import('./endpoint-inventory.mjs').EndpointInventory['build']>} inventory
   */
  static find(inventory) {
    const candidates = [];
    const seen = new Set();

    for (const endpoint of inventory.endpoints) {
      for (const pattern of this.ID_PATTERNS) {
        if (pattern.regex.test(endpoint.path)) {
          const idValue = this.extractPathId(endpoint.path);
          const riskScore = this.scorePathRisk(endpoint, pattern);
          const sig = `p:${endpoint.method}:${endpoint.path}:${idValue}`;
          if (!seen.has(sig)) {
            seen.add(sig);
            candidates.push({
              ...endpoint,
              idType: pattern.type,
              idValue,
              idorRisk: riskScore,
              idorSource: 'path',
              testSuggestion: this.suggestPathTests(endpoint, idValue),
            });
          }
          break;
        }
      }

      for (const q of this.findQueryParamCandidates(endpoint)) {
        const sig = `q:${q.method}:${q.path}:${q.queryParam}:${q.idValue}`;
        if (seen.has(sig)) continue;
        seen.add(sig);
        candidates.push(q);
      }
    }

    return candidates.sort((a, b) => b.idorRisk - a.idorRisk);
  }

  /** @param {string} path */
  static extractPathId(path) {
    const parts = path.split('/').filter(Boolean);
    return parts[parts.length - 1] || '';
  }

  /** @param {object} endpoint */
  static findQueryParamCandidates(endpoint) {
    /** @type {object[]} */
    const out = [];
    const usedKeys = new Set();
    const urls = endpoint.sampleUrls || [];
    const maxUrls = Math.min(urls.length, 15);

    for (let i = 0; i < maxUrls; i++) {
      let u;
      try {
        u = new URL(String(urls[i]));
      } catch {
        continue;
      }

      for (const [rawKey, rawVal] of u.searchParams.entries()) {
        const keyLower = rawKey.toLowerCase();
        if (usedKeys.has(keyLower)) continue;
        if (this.QUERY_PARAM_DENYLIST.has(keyLower)) continue;

        const classified = this.classifyQueryParam(rawKey, rawVal);
        if (!classified) continue;

        usedKeys.add(keyLower);
        const riskScore = this.scoreQueryRisk(endpoint, classified, rawKey);

        out.push({
          ...endpoint,
          idType: classified.type,
          idValue: rawVal,
          idorRisk: riskScore,
          idorSource: 'query',
          queryParam: rawKey,
          testSuggestion: this.suggestQueryTests(urls[i], rawKey, rawVal),
        });
      }
    }

    return out;
  }

  /** @param {string} key @param {string} value */
  static classifyQueryParam(key, value) {
    if (!value || value.length > 200) return null;
    const kl = key.toLowerCase();
    const named = this.QUERY_PARAM_ID_NAMES.has(kl);

    if (/^\d{1,16}$/.test(value)) {
      const digits = value.length;
      const type = digits >= 4 ? 'query-numeric-long' : 'query-numeric-short';
      let risk = digits >= 4 ? 3 : 2;
      if (named) risk += 2;
      return { type, risk };
    }

    if (
      /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value)
    ) {
      return { type: 'query-uuid', risk: named ? 5 : 3 };
    }

    if (/^[A-Za-z0-9_-]{22,}$/.test(value)) {
      return { type: 'query-opaque', risk: named ? 5 : 4 };
    }

    if (named && /^[A-Za-z0-9_-]{6,}$/.test(value)) {
      return { type: 'query-named-opaque', risk: 4 };
    }

    return null;
  }

  static scorePathRisk(endpoint, pattern) {
    let score = pattern.risk;
    if (endpoint.method === 'GET') score += 1;
    if (['PUT', 'PATCH', 'DELETE'].includes(endpoint.method)) score += 2;
    const pathLower = endpoint.path.toLowerCase();
    if (pathLower.includes('profile')) score += 2;
    if (pathLower.includes('user')) score += 2;
    if (pathLower.includes('dna')) score += 1;
    if (pathLower.includes('relative')) score += 1;
    if (pathLower.includes('download')) score += 1;
    if (pathLower.includes('payment')) score += 1;
    if (endpoint.hits > 1) score += 1;
    return Math.min(score, 10);
  }

  /** @param {{ risk: number, type: string }} classified */
  static scoreQueryRisk(endpoint, classified, paramKey) {
    let score = classified.risk;
    if (endpoint.method === 'GET') score += 1;
    if (['PUT', 'PATCH', 'DELETE'].includes(endpoint.method)) score += 2;
    const pk = paramKey.toLowerCase();
    if (pk.includes('profile')) score += 2;
    if (pk.includes('user') || pk.includes('account')) score += 2;
    if (pk.includes('relative')) score += 1;
    if (pk.includes('dna')) score += 1;
    if (endpoint.hits > 1) score += 1;
    if (this.QUERY_PARAM_ID_NAMES.has(pk)) score += 1;
    return Math.min(score, 10);
  }

  /** @param {object} endpoint @param {string} idValue */
  static suggestPathTests(endpoint, idValue) {
    const basePath = endpoint.path.replace(/\/[^/]+$/, '');
    /** @type {string[]} */
    const urls = [];
    const inc = this.incrementId(idValue);
    const dec = this.decrementId(idValue);
    if (basePath && inc) urls.push(`${basePath}/${inc}`);
    if (basePath && dec) urls.push(`${basePath}/${dec}`);
    if (basePath) urls.push(`${basePath}/0`, `${basePath}/1`);
    if (!basePath && endpoint.path.match(/^\/\d+$/)) {
      if (inc) urls.push(`/${inc}`);
      if (dec) urls.push(`/${dec}`);
      urls.push('/0', '/1');
    }

    return {
      type: 'idor-sequence',
      description: 'Try neighboring IDs only on systems you are authorized to test.',
      testUrls: urls,
    };
  }

  /** @param {string} sampleUrl @param {string} paramKey @param {string} paramValue */
  static suggestQueryTests(sampleUrl, paramKey, paramValue) {
    /** @type {string[]} */
    const urls = [];
    try {
      const inc = this.incrementId(paramValue);
      const dec = this.decrementId(paramValue);

      if (inc) {
        const u = new URL(String(sampleUrl));
        u.searchParams.set(paramKey, inc);
        urls.push(u.toString());
      }
      if (dec) {
        const u = new URL(String(sampleUrl));
        u.searchParams.set(paramKey, dec);
        urls.push(u.toString());
      }
      {
        const u = new URL(String(sampleUrl));
        u.searchParams.set(paramKey, '0');
        urls.push(u.toString());
      }
      {
        const u = new URL(String(sampleUrl));
        u.searchParams.set(paramKey, '1');
        urls.push(u.toString());
      }
    } catch {
      /* skip malformed sample URLs */
    }

    return {
      type: 'idor-sequence',
      description:
        'Try neighboring / boundary query values only on systems you are authorized to test.',
      testUrls: urls,
    };
  }

  static incrementId(id) {
    const num = parseInt(id, 10);
    return Number.isNaN(num) ? null : String(num + 1);
  }

  static decrementId(id) {
    const num = parseInt(id, 10);
    return Number.isNaN(num) || num <= 0 ? null : String(num - 1);
  }
}
