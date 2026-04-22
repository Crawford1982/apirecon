export class EndpointInventory {
  /**
   * @param {unknown[]} traffic
   */
  static build(traffic) {
    const endpoints = new Map();
    const hosts = new Set();
    const origins = new Set();

    for (const req of traffic) {
      if (!req || typeof req !== 'object') continue;
      const r = /** @type {Record<string, unknown>} */ (req);
      if (r.type !== 'request') continue;
      try {
        const url = new URL(String(r.url));
        hosts.add(url.hostname);
        origins.add(`${url.protocol}//${url.hostname}`);

        const method = String(r.method || 'GET').toUpperCase();
        const key = `${method} ${url.pathname}`;
        const existing = endpoints.get(key);

        const rh = /** @type {Record<string, string>} */ (r.responseHeaders || {});
        const ct = rh['content-type'] || rh['Content-Type'] || '';

        if (existing) {
          existing.hits += 1;
          existing.sampleUrls.push(String(r.url));
          for (const [k] of url.searchParams) {
            if (!existing.queryParams.includes(k)) existing.queryParams.push(k);
          }
          const body = r.responseBody;
          if (body && typeof body === 'object' && !Array.isArray(body)) {
            existing.responseShapes.push(Object.keys(body));
          }
          if (!existing.statusCodes.includes(Number(r.status))) existing.statusCodes.push(Number(r.status));
          if (ct && !existing.contentTypes.includes(ct)) existing.contentTypes.push(ct);
        } else {
          const body = r.responseBody;
          endpoints.set(key, {
            method,
            path: url.pathname,
            host: url.hostname,
            hits: 1,
            sampleUrls: [String(r.url)],
            queryParams: [...url.searchParams.keys()],
            responseShapes:
              body && typeof body === 'object' && !Array.isArray(body) ? [Object.keys(body)] : [],
            statusCodes: [Number(r.status)],
            contentTypes: ct ? [ct] : [],
          });
        }
      } catch {
        /* skip */
      }
    }

    return {
      origins: [...origins],
      hosts: [...hosts],
      endpoints: [...endpoints.values()].sort((a, b) => b.hits - a.hits),
    };
  }
}
