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

  /**
   * @param {ReturnType<import('./endpoint-inventory.mjs').EndpointInventory['build']>} inventory
   */
  static find(inventory) {
    const candidates = [];

    for (const endpoint of inventory.endpoints) {
      for (const pattern of this.ID_PATTERNS) {
        if (pattern.regex.test(endpoint.path)) {
          const idValue = this.extractId(endpoint.path);
          const riskScore = this.scoreRisk(endpoint, pattern);

          candidates.push({
            ...endpoint,
            idType: pattern.type,
            idValue,
            idorRisk: riskScore,
            testSuggestion: this.suggestTest(endpoint, idValue),
          });
          break;
        }
      }
    }

    return candidates.sort((a, b) => b.idorRisk - a.idorRisk);
  }

  /** @param {string} path */
  static extractId(path) {
    const parts = path.split('/').filter(Boolean);
    return parts[parts.length - 1] || '';
  }

  static scoreRisk(endpoint, pattern) {
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

  static suggestTest(endpoint, idValue) {
    const basePath = endpoint.path.replace(/\/[^/]+$/, '');
    /** @type {string[]} */
    const urls = [];
    const inc = this.incrementId(idValue);
    const dec = this.decrementId(idValue);
    if (basePath && inc) urls.push(`${basePath}/${inc}`);
    if (basePath && dec) urls.push(`${basePath}/${dec}`);
    if (basePath) urls.push(`${basePath}/0`, `${basePath}/1`);
    // Root-ish paths like `/12345` → try siblings at same depth
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

  static incrementId(id) {
    const num = parseInt(id, 10);
    return Number.isNaN(num) ? null : String(num + 1);
  }

  static decrementId(id) {
    const num = parseInt(id, 10);
    return Number.isNaN(num) || num <= 0 ? null : String(num - 1);
  }
}
