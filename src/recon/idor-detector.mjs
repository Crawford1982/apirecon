import {
  classifyValue,
  isIdName,
  isPaginationKey,
  isResourceWord,
  isScopeWord,
  normKey,
  looksLikeWord,
} from './id-shape.mjs';

/**
 * @typedef {object} Finding
 * @property {string} method
 * @property {string} path                original path from the capture
 * @property {string} pathTemplate        path with IDs replaced by `{id}`
 * @property {string} host
 * @property {number} hits
 * @property {string[]} sampleUrls
 * @property {string[]} [queryParams]
 * @property {string[][]} [responseShapes]
 * @property {number[]} [statusCodes]
 * @property {string[]} [contentTypes]
 * @property {string} idorSource          path | query | nested-url
 * @property {string} idType              shape-derived label
 * @property {string} idValue             the actual token we'd mutate
 * @property {string} [queryParam]        query key, when idorSource === 'query'
 * @property {string} [scopeWord]         parent scope segment (e.g. "p", "users")
 * @property {string} [scopeKey]          stable key for grouping (scopeWord:idValue)
 * @property {number} idorRisk            final 1..10 score
 * @property {string[]} riskReasons       human-readable "why this scored X"
 * @property {{ type: string, description: string, testUrls: string[] }} testSuggestion
 */

/**
 * IDOR candidate detector v2.
 *
 * Differences vs v1:
 *  - Structural path model: recognises `/{scopeWord}/{scopeId}/…` and
 *    treats `scopeId` as the primary IDOR target (not the terminal segment).
 *  - Shape classifier filters out resource-name tokens (e.g. `notifications`,
 *    `all_questions_data_for_dashboard`) that the v1 opaque-token regex
 *    misclassified as IDs.
 *  - Pagination / sort / filter query keys are centrally denylisted with
 *    separator-agnostic matching (`page-size` == `page_size` == `pageSize`).
 *  - Detects IDs embedded inside URL-encoded `?url=…` query values — the
 *    "API proxy" pattern that 23andMe's `content-resource-ajax` uses.
 *  - Exposes {@link IdorDetector.groupByScope} so reports can collapse many
 *    child endpoints into one actionable IDOR surface.
 */
export class IdorDetector {
  /**
   * @param {ReturnType<import('./endpoint-inventory.mjs').EndpointInventory['build']>} inventory
   * @returns {Finding[]}
   */
  static find(inventory) {
    /** @type {Finding[]} */
    const findings = [];
    const seen = new Set();

    const push = (f) => {
      const sig = `${f.idorSource}:${f.method}:${f.pathTemplate}:${f.queryParam || ''}:${f.idValue}`;
      if (seen.has(sig)) return;
      seen.add(sig);
      findings.push(f);
    };

    for (const endpoint of inventory.endpoints) {
      for (const f of this.findPathFindings(endpoint)) push(f);
      for (const f of this.findQueryFindings(endpoint)) push(f);
      for (const f of this.findNestedUrlFindings(endpoint)) push(f);
    }

    return findings.sort((a, b) => b.idorRisk - a.idorRisk);
  }

  /**
   * Collapse findings into one entry per `scopeKey` (e.g. all endpoints under
   * `/p/<id>/…` become one "profile-scope IDOR" group).
   *
   * Findings without a scope are returned under a synthetic `__orphan__` key.
   *
   * @param {Finding[]} findings
   */
  static groupByScope(findings) {
    /** @type {Record<string, { scopeKey: string, scopeWord: string | null, scopeId: string | null, maxRisk: number, findings: Finding[] }>} */
    const groups = {};
    for (const f of findings) {
      const key = f.scopeKey || '__orphan__';
      if (!groups[key]) {
        groups[key] = {
          scopeKey: key,
          scopeWord: f.scopeWord || null,
          scopeId: key === '__orphan__' ? null : f.idValue,
          maxRisk: 0,
          findings: [],
        };
      }
      groups[key].findings.push(f);
      if (f.idorRisk > groups[key].maxRisk) groups[key].maxRisk = f.idorRisk;
    }
    return Object.values(groups).sort((a, b) => b.maxRisk - a.maxRisk);
  }

  /**
   * Split a path into non-empty segments without losing info about trailing `/`.
   * @param {string} path
   */
  static segments(path) {
    return String(path || '')
      .split('/')
      .filter((s) => s.length > 0);
  }

  /**
   * Build a path template by replacing ID-shaped segments with `{id}` and
   * scope IDs with `{scope_id}` markers.
   *
   * @param {string} path
   */
  static pathTemplate(path) {
    const segs = this.segments(path);
    const out = [];
    for (let i = 0; i < segs.length; i++) {
      const prev = i > 0 ? segs[i - 1] : '';
      const cls = classifyValue(segs[i]);
      if (cls && isScopeWord(prev)) {
        out.push('{scope_id}');
      } else if (cls) {
        out.push('{id}');
      } else {
        out.push(segs[i]);
      }
    }
    return '/' + out.join('/') + (path.endsWith('/') ? '/' : '');
  }

  /**
   * Detect path-based IDOR surfaces.
   *
   * Two kinds of finding emitted:
   *  1. `path-scope`: `/<scopeWord>/<id>/…` — the scope ID is the target.
   *     Emitted *once* per (method, pathTemplate, scopeId). Every child
   *     endpoint contributes to the same `scopeKey`.
   *  2. `path-terminal`: path ends in an ID segment with no scope parent.
   *
   * @param {any} endpoint
   * @returns {Finding[]}
   */
  static findPathFindings(endpoint) {
    const segs = this.segments(endpoint.path);
    if (segs.length === 0) return [];

    /** @type {Finding[]} */
    const out = [];

    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      const prev = i > 0 ? segs[i - 1] : '';
      const cls = classifyValue(seg);
      if (!cls) continue;

      const isScopeChild = isScopeWord(prev);
      const isTerminal = i === segs.length - 1;

      if (!isScopeChild && !isTerminal) continue;

      const pathTemplate = this.pathTemplate(endpoint.path);
      const sourceKind = isScopeChild ? 'path-scope' : 'path-terminal';

      const { risk, reasons } = this.scoreRisk({
        endpoint,
        baseRisk: cls.risk,
        shape: cls.shape,
        source: sourceKind,
        segmentIndex: i,
        totalSegments: segs.length,
        scopeWord: isScopeChild ? prev : null,
        pathTemplate,
      });

      const scopeKey = isScopeChild ? `${normKey(prev)}:${seg}` : null;

      out.push({
        method: endpoint.method,
        path: endpoint.path,
        pathTemplate,
        host: endpoint.host,
        hits: endpoint.hits,
        sampleUrls: endpoint.sampleUrls,
        queryParams: endpoint.queryParams,
        responseShapes: endpoint.responseShapes,
        statusCodes: endpoint.statusCodes,
        contentTypes: endpoint.contentTypes,
        idorSource: 'path',
        idType: isScopeChild ? `scope:${cls.shape}` : `terminal:${cls.shape}`,
        idValue: seg,
        scopeWord: isScopeChild ? prev : undefined,
        scopeKey: scopeKey || undefined,
        idorRisk: risk,
        riskReasons: reasons,
        testSuggestion: this.suggestPathTests(endpoint, segs, i),
      });

      if (isScopeChild) {
        // Stop at first scope we find — deeper segments are assumed to be
        // "child resources" under the scope, not additional IDOR surfaces.
        break;
      }
    }

    return out;
  }

  /**
   * @param {any} endpoint
   * @returns {Finding[]}
   */
  static findQueryFindings(endpoint) {
    /** @type {Finding[]} */
    const out = [];
    const usedKeys = new Set();
    const urls = endpoint.sampleUrls || [];
    const maxUrls = Math.min(urls.length, 15);

    for (let i = 0; i < maxUrls; i++) {
      /** @type {URL} */
      let u;
      try {
        u = new URL(String(urls[i]));
      } catch {
        continue;
      }

      for (const [rawKey, rawVal] of u.searchParams.entries()) {
        const nkey = normKey(rawKey);
        if (usedKeys.has(nkey)) continue;
        if (isPaginationKey(rawKey)) continue;

        const named = isIdName(rawKey);
        const cls = classifyValue(rawVal);
        if (!cls && !named) continue;
        if (!cls) continue;
        // Extra guard: named ID keys can carry opaque short tokens that we
        // wouldn't otherwise classify; rerun with more permissive rules.

        usedKeys.add(nkey);

        const { risk, reasons } = this.scoreRisk({
          endpoint,
          baseRisk: cls.risk + (named ? 2 : 0),
          shape: cls.shape,
          source: 'query',
          queryKey: rawKey,
          pathTemplate: this.pathTemplate(endpoint.path),
        });

        out.push({
          method: endpoint.method,
          path: endpoint.path,
          pathTemplate: this.pathTemplate(endpoint.path),
          host: endpoint.host,
          hits: endpoint.hits,
          sampleUrls: endpoint.sampleUrls,
          queryParams: endpoint.queryParams,
          responseShapes: endpoint.responseShapes,
          statusCodes: endpoint.statusCodes,
          contentTypes: endpoint.contentTypes,
          idorSource: 'query',
          idType: `query-${cls.shape}`,
          idValue: rawVal,
          queryParam: rawKey,
          idorRisk: risk,
          riskReasons: reasons,
          testSuggestion: this.suggestQueryTests(urls[i], rawKey, rawVal),
        });
      }
    }

    return out;
  }

  /**
   * Detect IDs embedded inside URL-encoded query values.
   * Example: `?url=%2F3%2Fcontent%2Frecommended%2F%3Fprofile_id%3DXXXX…`.
   *
   * @param {any} endpoint
   * @returns {Finding[]}
   */
  static findNestedUrlFindings(endpoint) {
    /** @type {Finding[]} */
    const out = [];
    const seen = new Set();
    const urls = endpoint.sampleUrls || [];
    const maxUrls = Math.min(urls.length, 10);

    for (let i = 0; i < maxUrls; i++) {
      /** @type {URL} */
      let u;
      try {
        u = new URL(String(urls[i]));
      } catch {
        continue;
      }

      for (const [rawKey, rawVal] of u.searchParams.entries()) {
        if (!rawVal || rawVal.length < 5) continue;
        const looksLikeUrlish =
          rawVal.startsWith('/') ||
          rawVal.startsWith('http') ||
          rawVal.includes('%2F') ||
          rawVal.includes('?');
        if (!looksLikeUrlish) continue;

        /** @type {URL | null} */
        let nested = null;
        try {
          const candidate =
            rawVal.startsWith('http') ? rawVal : `https://nested.local${rawVal.startsWith('/') ? rawVal : '/' + rawVal}`;
          nested = new URL(candidate);
        } catch {
          continue;
        }

        for (const [nkRaw, nvRaw] of nested.searchParams.entries()) {
          if (isPaginationKey(nkRaw)) continue;
          const named = isIdName(nkRaw);
          const cls = classifyValue(nvRaw);
          if (!cls) continue;
          if (!named && cls.risk < 4) continue;

          const sig = `${normKey(nkRaw)}:${nvRaw}`;
          if (seen.has(sig)) continue;
          seen.add(sig);

          const { risk, reasons } = this.scoreRisk({
            endpoint,
            baseRisk: cls.risk + (named ? 2 : 0) + 1, // nested is more suspicious
            shape: cls.shape,
            source: 'nested-url',
            queryKey: nkRaw,
            pathTemplate: this.pathTemplate(endpoint.path),
          });

          out.push({
            method: endpoint.method,
            path: endpoint.path,
            pathTemplate: this.pathTemplate(endpoint.path),
            host: endpoint.host,
            hits: endpoint.hits,
            sampleUrls: [urls[i]],
            queryParams: endpoint.queryParams,
            responseShapes: endpoint.responseShapes,
            statusCodes: endpoint.statusCodes,
            contentTypes: endpoint.contentTypes,
            idorSource: 'nested-url',
            idType: `nested-${cls.shape}`,
            idValue: nvRaw,
            queryParam: `${rawKey}[${nkRaw}]`,
            idorRisk: risk,
            riskReasons: reasons,
            testSuggestion: this.suggestNestedUrlTests(urls[i], rawKey, nested, nkRaw, nvRaw),
          });
        }
      }
    }

    return out;
  }

  /**
   * Compose the final 1..10 risk score from shape + context signals.
   *
   * @param {object} ctx
   * @param {any} ctx.endpoint
   * @param {number} ctx.baseRisk
   * @param {string} ctx.shape
   * @param {string} ctx.source
   * @param {number} [ctx.segmentIndex]
   * @param {number} [ctx.totalSegments]
   * @param {string | null} [ctx.scopeWord]
   * @param {string} [ctx.queryKey]
   * @param {string} [ctx.pathTemplate]
   */
  static scoreRisk(ctx) {
    let score = ctx.baseRisk;
    /** @type {string[]} */
    const reasons = [`shape=${ctx.shape}(+${ctx.baseRisk})`];

    const method = String(ctx.endpoint?.method || 'GET').toUpperCase();
    if (method === 'GET') {
      score += 1;
      reasons.push('GET read (+1)');
    } else if (['PUT', 'PATCH', 'DELETE'].includes(method)) {
      score += 3;
      reasons.push(`${method} write (+3)`);
    } else if (method === 'POST') {
      score += 1;
      reasons.push('POST (+1)');
    }

    const pathLower = String(ctx.endpoint?.path || '').toLowerCase();
    const bump = (re, amt, label) => {
      if (re.test(pathLower)) {
        score += amt;
        reasons.push(`${label}(+${amt})`);
      }
    };

    bump(/(^|\/)(profile|user|account|member|customer)s?(\/|$)/, 2, 'user/profile path');
    bump(/(^|\/)(relative|relatives|family|share)s?(\/|$)/, 1, 'relative/share path');
    bump(/(^|\/)(dna|ancestry|health|genetic|trait|wellness|raw)s?(\/|$)/, 2, 'dna/health path');
    bump(/(download|export|raw[-_]?data)/, 2, 'download/export path');
    bump(/(payment|billing|invoice|order|subscription|card)/, 1, 'billing path');
    bump(/(address|phone|email|ssn|dob)/, 1, 'pii path');
    bump(/(admin|internal|sudo|impersonate)/, 2, 'admin path');

    if (ctx.scopeWord) {
      score += 2;
      reasons.push(`scope parent "${ctx.scopeWord}" (+2)`);
    }
    if (ctx.source === 'nested-url') {
      score += 1;
      reasons.push('nested-url (+1)');
    }
    if (ctx.queryKey && isIdName(ctx.queryKey)) {
      score += 1;
      reasons.push(`id-name query "${ctx.queryKey}" (+1)`);
    }
    if ((ctx.endpoint?.hits || 0) >= 5) {
      score += 1;
      reasons.push('hot endpoint hits>=5 (+1)');
    }

    // Cap
    return { risk: Math.max(1, Math.min(10, score)), reasons };
  }

  /**
   * Mutate a path's ID at a given segment index and produce neighbour
   * suggestions (±1, 0, 1, zero-hex, same-length-zero). We leave the rest
   * of the path untouched so a scope-parent mutation still hits children.
   *
   * @param {any} endpoint
   * @param {string[]} segs
   * @param {number} idIndex
   */
  static suggestPathTests(endpoint, segs, idIndex) {
    const idValue = segs[idIndex];
    /** @type {string[]} */
    const urls = [];

    const build = (newVal) => {
      const copy = segs.slice();
      copy[idIndex] = newVal;
      const path = '/' + copy.join('/') + (endpoint.path.endsWith('/') ? '/' : '');
      return path;
    };

    const numericInc = this.incrementId(idValue);
    const numericDec = this.decrementId(idValue);
    if (numericInc) urls.push(build(numericInc));
    if (numericDec) urls.push(build(numericDec));

    if (/^\d+$/.test(idValue)) {
      urls.push(build('0'), build('1'));
    } else if (/^[a-f0-9]+$/i.test(idValue) && idValue.length >= 8) {
      urls.push(build('0'.repeat(idValue.length)));
      urls.push(build(idValue.slice(0, -1) + '0'));
      urls.push(build(idValue.slice(0, -1) + '1'));
    } else if (/^[A-Za-z0-9_-]+$/.test(idValue)) {
      urls.push(build(idValue.slice(0, -1) + '0'));
      urls.push(build(idValue.slice(0, -1) + '1'));
    }

    return {
      type: 'idor-sequence',
      description:
        'Try neighbouring / boundary values. IDOR is confirmed only with a second account’s real ID plus your own auth — see --account-b mode.',
      testUrls: [...new Set(urls)],
    };
  }

  /** @param {string} sampleUrl @param {string} paramKey @param {string} paramValue */
  static suggestQueryTests(sampleUrl, paramKey, paramValue) {
    /** @type {string[]} */
    const urls = [];
    try {
      const mutate = (newVal) => {
        const u = new URL(String(sampleUrl));
        u.searchParams.set(paramKey, newVal);
        urls.push(u.toString());
      };
      const inc = this.incrementId(paramValue);
      const dec = this.decrementId(paramValue);
      if (inc) mutate(inc);
      if (dec) mutate(dec);
      mutate('0');
      mutate('1');
      if (/^[a-f0-9]+$/i.test(paramValue) && paramValue.length >= 8) {
        mutate('0'.repeat(paramValue.length));
      }
    } catch {
      /* skip */
    }
    return {
      type: 'idor-sequence',
      description: 'Mutate the query id and compare response to baseline.',
      testUrls: [...new Set(urls)],
    };
  }

  /**
   * @param {string} outerSampleUrl
   * @param {string} outerKey
   * @param {URL} nested
   * @param {string} nestedKey
   * @param {string} nestedValue
   */
  static suggestNestedUrlTests(outerSampleUrl, outerKey, nested, nestedKey, nestedValue) {
    /** @type {string[]} */
    const urls = [];
    const rebuild = (newVal) => {
      try {
        const nestedCopy = new URL(nested.toString());
        nestedCopy.searchParams.set(nestedKey, newVal);
        const inner =
          nestedCopy.host === 'nested.local' ?
            `${nestedCopy.pathname}${nestedCopy.search}`
          : nestedCopy.toString();
        const outer = new URL(String(outerSampleUrl));
        outer.searchParams.set(outerKey, inner);
        urls.push(outer.toString());
      } catch {
        /* skip */
      }
    };

    const inc = this.incrementId(nestedValue);
    const dec = this.decrementId(nestedValue);
    if (inc) rebuild(inc);
    if (dec) rebuild(dec);
    rebuild('0');
    rebuild('1');
    if (/^[a-f0-9]+$/i.test(nestedValue) && nestedValue.length >= 8) {
      rebuild('0'.repeat(nestedValue.length));
    }

    return {
      type: 'idor-sequence',
      description:
        'Mutate the ID embedded inside the proxied `url` query value, then replay through the outer endpoint.',
      testUrls: [...new Set(urls)],
    };
  }

  /**
   * Replace a finding's {scope_id} / {id} with a specific target value.
   * Used by cross-account replay to construct the *exact* URL that probes
   * a known foreign tenant ID, rather than random neighbours.
   *
   * @param {Finding} finding
   * @param {string} newId
   */
  static substituteId(finding, newId) {
    const sample = finding.sampleUrls?.[0];
    if (!sample) return null;
    let u;
    try {
      u = new URL(String(sample));
    } catch {
      return null;
    }

    if (finding.idorSource === 'path') {
      const segs = u.pathname.split('/').filter(Boolean);
      const idx = segs.findIndex((s) => s === finding.idValue);
      if (idx < 0) return null;
      segs[idx] = newId;
      u.pathname = '/' + segs.join('/') + (u.pathname.endsWith('/') ? '/' : '');
      return u.toString();
    }

    if (finding.idorSource === 'query' && finding.queryParam) {
      u.searchParams.set(finding.queryParam, newId);
      return u.toString();
    }

    if (finding.idorSource === 'nested-url' && finding.queryParam) {
      // queryParam is like "outer[inner]" — we need to edit the inner key inside the outer value.
      const m = /^(.+)\[(.+)\]$/.exec(finding.queryParam);
      if (!m) return null;
      const [, outerKey, innerKey] = m;
      const rawInner = u.searchParams.get(outerKey);
      if (!rawInner) return null;
      try {
        const nested = new URL(
          rawInner.startsWith('http') ?
            rawInner
          : `https://nested.local${rawInner.startsWith('/') ? rawInner : '/' + rawInner}`,
        );
        nested.searchParams.set(innerKey, newId);
        const inner =
          nested.host === 'nested.local' ?
            `${nested.pathname}${nested.search}`
          : nested.toString();
        u.searchParams.set(outerKey, inner);
        return u.toString();
      } catch {
        return null;
      }
    }

    return null;
  }

  static incrementId(id) {
    if (!id) return null;
    if (/^\d+$/.test(id)) return String(parseInt(id, 10) + 1);
    if (/^[a-f0-9]+$/i.test(id) && id.length >= 8) {
      const last = id.charAt(id.length - 1);
      const bumped = ((parseInt(last, 16) + 1) % 16).toString(16);
      return id.slice(0, -1) + bumped;
    }
    return null;
  }

  static decrementId(id) {
    if (!id) return null;
    if (/^\d+$/.test(id)) {
      const n = parseInt(id, 10);
      return n > 0 ? String(n - 1) : null;
    }
    if (/^[a-f0-9]+$/i.test(id) && id.length >= 8) {
      const last = id.charAt(id.length - 1);
      const lowered = ((parseInt(last, 16) + 15) % 16).toString(16);
      return id.slice(0, -1) + lowered;
    }
    return null;
  }
}

// Re-exports so downstream code (tests, report) can use the same shape helpers
export { classifyValue, isIdName, isPaginationKey, isResourceWord, isScopeWord, normKey, looksLikeWord };
