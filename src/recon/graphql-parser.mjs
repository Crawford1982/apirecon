import { classifyValue, isIdName, isPaginationKey } from './id-shape.mjs';

/**
 * @typedef {object} GraphqlOperation
 * @property {string} endpointUrl
 * @property {string} method
 * @property {string|null} operationName
 * @property {'query'|'mutation'|'subscription'|'unknown'} operationType
 * @property {string|null} query
 * @property {Record<string, unknown>} variables
 * @property {Array<{ path: string, name: string, value: string, idType: string, risk: number }>} idVariables
 * @property {number} hits
 * @property {number} [sampleStatus]
 */

const GRAPHQL_PATH_HINTS = ['/graphql', '/gql', '/api/graphql'];

/**
 * @param {string} url
 */
function looksLikeGraphqlUrl(url) {
  const lower = String(url || '').toLowerCase();
  return GRAPHQL_PATH_HINTS.some((h) => lower.includes(h));
}

/** @param {unknown} body */
function parseMaybeJson(body) {
  if (body == null) return null;
  if (typeof body === 'object') return body;
  try {
    return JSON.parse(String(body));
  } catch {
    return null;
  }
}

/** @param {string} q */
function detectOperationType(q) {
  const s = String(q || '').trim();
  if (!s) return 'unknown';
  const m = /^\s*(query|mutation|subscription)\b/.exec(s);
  return /** @type {any} */ (m ? m[1] : 'unknown');
}

/**
 * Walk a `variables` object and emit leaves whose value *looks* like an ID
 * or whose key is an ID-name.
 *
 * @param {unknown} vars
 * @param {string[]} path
 * @param {Array<{ path: string, name: string, value: string, idType: string, risk: number }>} out
 */
function walkVariables(vars, path, out) {
  if (vars == null) return;
  if (Array.isArray(vars)) {
    vars.forEach((v, i) => walkVariables(v, path.concat(`[${i}]`), out));
    return;
  }
  if (typeof vars === 'object') {
    for (const [k, v] of Object.entries(vars)) {
      walkVariables(v, path.concat(k), out);
    }
    return;
  }
  const value = String(vars);
  const leafKey = path[path.length - 1] || '';
  if (isPaginationKey(String(leafKey))) return;
  const nameMatch = isIdName(String(leafKey));
  const shape = classifyValue(value);
  if (!shape && !nameMatch) return;

  // Risk: base from shape + 2 if the variable is named like an ID.
  const risk = (shape?.risk ?? 0) + (nameMatch ? 2 : 0);
  if (risk === 0) return;

  out.push({
    path: path.join('.'),
    name: String(leafKey),
    value,
    idType: shape?.shape || 'id-name-hint',
    risk,
  });
}

/**
 * Extract GraphQL operations from raw captured traffic.
 *
 * @param {any[]} traffic
 * @returns {{ operations: GraphqlOperation[], endpoints: string[] }}
 */
export function extractGraphqlOperations(traffic) {
  /** @type {Map<string, GraphqlOperation>} */
  const byKey = new Map();
  /** @type {Set<string>} */
  const endpoints = new Set();

  for (const req of traffic) {
    if (!req || req.type !== 'request') continue;
    const url = String(req.url || '');
    if (!looksLikeGraphqlUrl(url)) continue;
    endpoints.add(url.split('?')[0]);

    const method = String(req.method || 'GET').toUpperCase();
    if (method !== 'POST' && method !== 'GET') continue;

    /** @type {Array<{ query?: string, operationName?: string, variables?: any }>} */
    let payloads = [];

    if (method === 'POST') {
      const body = parseMaybeJson(req.postData);
      if (!body) continue;
      payloads = Array.isArray(body) ? body : [body];
    } else {
      try {
        const u = new URL(url);
        const q = u.searchParams.get('query');
        const variables = u.searchParams.get('variables');
        const operationName = u.searchParams.get('operationName');
        if (!q) continue;
        payloads = [
          {
            query: q,
            operationName: operationName || undefined,
            variables: variables ? parseMaybeJson(variables) || {} : {},
          },
        ];
      } catch {
        continue;
      }
    }

    for (const p of payloads) {
      if (!p || typeof p !== 'object') continue;
      const query = typeof p.query === 'string' ? p.query : null;
      const opName = typeof p.operationName === 'string' && p.operationName ? p.operationName : inferOperationName(query);

      /** @type {Array<{ path: string, name: string, value: string, idType: string, risk: number }>} */
      const idVars = [];
      if (p.variables && typeof p.variables === 'object') walkVariables(p.variables, [], idVars);

      const endpointUrl = url.split('?')[0];
      const key = `${endpointUrl}::${opName || '(anonymous)'}`;
      const existing = byKey.get(key);
      if (existing) {
        existing.hits += 1;
        if (idVars.length > existing.idVariables.length) existing.idVariables = idVars;
        continue;
      }
      byKey.set(key, {
        endpointUrl,
        method,
        operationName: opName,
        operationType: detectOperationType(query || ''),
        query,
        variables: /** @type {Record<string, unknown>} */ (p.variables || {}),
        idVariables: idVars,
        hits: 1,
        sampleStatus: typeof req.status === 'number' ? req.status : undefined,
      });
    }
  }

  return {
    operations: [...byKey.values()].sort((a, b) => b.hits - a.hits),
    endpoints: [...endpoints],
  };
}

/** @param {string | null} query */
function inferOperationName(query) {
  if (!query) return null;
  const m = /\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)/.exec(query);
  return m ? m[2] : null;
}

/**
 * Turn parsed operations into IDOR-candidate-shaped findings so they flow
 * through the same replay / reporting machinery as REST findings.
 *
 * @param {GraphqlOperation[]} operations
 */
export function operationsToFindings(operations) {
  /** @type {any[]} */
  const out = [];
  for (const op of operations) {
    for (const v of op.idVariables) {
      const risk = Math.min(10, v.risk + (op.operationType === 'mutation' ? 2 : 0) + Math.min(2, Math.log10(op.hits + 1)));
      out.push({
        idorSource: 'graphql-variable',
        host: (() => {
          try {
            return new URL(op.endpointUrl).hostname;
          } catch {
            return '';
          }
        })(),
        method: op.method,
        path: new URL(op.endpointUrl).pathname,
        pathTemplate: `${op.method} ${new URL(op.endpointUrl).pathname} · ${op.operationType} ${op.operationName || '(anonymous)'}  ${v.path}=<{id}>`,
        sampleUrls: [op.endpointUrl],
        idType: `gql-var:${v.idType}`,
        idValue: v.value,
        idorRisk: Math.round(risk),
        riskReasons: [
          `graphql=${op.operationType}:${op.operationName || 'anonymous'}`,
          `variable=${v.path}`,
          `shape=${v.idType}`,
          ...(op.operationType === 'mutation' ? ['method=mutation(+2)'] : []),
        ],
        operation: {
          endpointUrl: op.endpointUrl,
          operationName: op.operationName,
          operationType: op.operationType,
          query: op.query,
          variables: op.variables,
          variablePath: v.path,
          variableName: v.name,
        },
      });
    }
  }
  return out;
}

/**
 * Rebuild a GraphQL request body with a mutated variable value — used by
 * replay to swap in a foreign id.
 *
 * @param {GraphqlOperation | { query: string, operationName?: string | null, variables: Record<string, unknown> }} op
 * @param {string} variablePath   dot/bracket path used by {@link walkVariables}
 * @param {string} newValue
 */
export function substituteVariable(op, variablePath, newValue) {
  const variables = JSON.parse(JSON.stringify(op.variables || {}));
  const tokens = variablePath.split('.').flatMap((s) => {
    const parts = s.split(/[\[\]]/).filter(Boolean);
    return parts;
  });
  let cursor = variables;
  for (let i = 0; i < tokens.length - 1; i++) {
    const t = tokens[i];
    if (/^\d+$/.test(t)) cursor = cursor[Number(t)];
    else cursor = cursor?.[t];
    if (cursor == null) return null;
  }
  const leaf = tokens[tokens.length - 1];
  if (/^\d+$/.test(leaf)) cursor[Number(leaf)] = newValue;
  else cursor[leaf] = newValue;
  return {
    query: op.query,
    operationName: op.operationName || undefined,
    variables,
  };
}
