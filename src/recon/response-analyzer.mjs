/**
 * Response-body analyzer: walks any JSON/text body and extracts:
 *   - PII markers (emails, phones, DOB-ish dates, street addresses, SSN-ish)
 *   - identity tokens (uuid, long hex, long base64url)
 *   - domain-specific tokens (genetic variants `rsID`, haplogroup codes)
 *   - a structural fingerprint (set of JSON paths) for diffing responses
 *     across accounts without caring about value changes.
 *
 * The scorer returns:
 *   - `leakScore`   0..100  "how bad does this response look from a data-
 *                   exposure standpoint"
 *   - `signals`     array of `{ kind, count, sample }`
 *   - `fingerprint` sorted array of JSON paths present in the body
 *
 * Intentionally conservative on redaction: we return samples of the first
 * occurrence so the user can verify it's real PII, but we never return
 * full values for SSN or payment-card-like patterns.
 */

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const PHONE_NA = /\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b/g;
const PHONE_INTL = /\b\+?\d{1,3}[-. ]?\d{2,4}[-. ]?\d{3,4}[-. ]?\d{3,4}\b/g;
const DOB = /\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b\d{2}\/\d{2}\/(?:19|20)\d{2}\b/g;
const SSN = /\b\d{3}-\d{2}-\d{4}\b/g;
const ZIP_US = /\b\d{5}(?:-\d{4})?\b/g;
const CC_LIKE = /\b(?:\d[ -]?){13,19}\b/g;
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const UUID = /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi;
const HEX_16 = /\b[a-f0-9]{16}\b/gi;
const HEX_32 = /\b[a-f0-9]{32}\b/gi;
const HEX_40 = /\b[a-f0-9]{40}\b/gi;
const B64_LONG = /\b[A-Za-z0-9_-]{24,}\b/g;

// 23andMe / genetics specific
const RSID = /\brs\d{2,9}\b/g;
const HAPLO_Y = /\b[A-Z]\d{1,4}(?:[a-z]\d?)*\b/g; // e.g. R1b1a1a2, I2a2b — weak, filtered
const HAPLO_MT = /\b(?:H|J|K|L\d?|M\d?|N|T|U|V|X|Y|Z)\d*[a-z]?\d?[a-z]?\b/g;
const STREET = /\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,4}(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Ln|Lane|Dr|Drive|Ct|Court|Way|Pl|Place|Pkwy|Parkway|Hwy|Highway)\b/g;

const NAME_KEYS = new Set([
  'name',
  'first_name',
  'firstname',
  'last_name',
  'lastname',
  'full_name',
  'fullname',
  'display_name',
  'displayname',
  'given_name',
  'family_name',
]);

const EMAIL_KEYS = new Set(['email', 'email_address', 'emailaddress', 'mail']);
const PHONE_KEYS = new Set(['phone', 'phone_number', 'phonenumber', 'mobile', 'tel']);
const DOB_KEYS = new Set(['dob', 'date_of_birth', 'dateofbirth', 'birthday', 'birthdate']);
const ADDRESS_KEYS = new Set([
  'address',
  'street',
  'street1',
  'address_line_1',
  'address1',
  'city',
  'zip',
  'zipcode',
  'zip_code',
  'postal_code',
  'postalcode',
]);

/**
 * Redact the middle of a string while preserving length cues.
 * @param {string} s
 */
function redact(s) {
  if (s == null) return '';
  const v = String(s);
  if (v.length <= 4) return '*'.repeat(v.length);
  return `${v.slice(0, 2)}…${v.slice(-2)} (len=${v.length})`;
}

/** @param {number} x @param {number} cap */
function clamp(x, cap = 100) {
  return Math.max(0, Math.min(cap, x));
}

/**
 * Walk an arbitrary JSON value and collect all string values plus the JSON
 * paths where they live. Limits depth and count to stay cheap.
 *
 * @param {unknown} root
 */
export function walkStrings(root, { maxNodes = 5000, maxDepth = 12 } = {}) {
  /** @type {Array<{ path: string, key: string | null, value: string }>} */
  const out = [];
  /** @type {Set<string>} */
  const paths = new Set();
  let count = 0;

  /**
   * @param {unknown} node
   * @param {string} path
   * @param {string | null} key
   * @param {number} depth
   */
  function walk(node, path, key, depth) {
    if (count >= maxNodes || depth > maxDepth) return;
    count++;
    paths.add(path);

    if (node == null) return;
    if (typeof node === 'string') {
      out.push({ path, key, value: node });
      return;
    }
    if (typeof node === 'number' || typeof node === 'boolean') {
      out.push({ path, key, value: String(node) });
      return;
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length && count < maxNodes; i++) {
        walk(node[i], `${path}[]`, null, depth + 1);
      }
      return;
    }
    if (typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        if (count >= maxNodes) break;
        walk(v, path ? `${path}.${k}` : k, k, depth + 1);
      }
    }
  }

  walk(root, '', null, 0);
  return { strings: out, paths: [...paths].sort() };
}

/**
 * Score a response body for data-exposure signals.
 *
 * @param {unknown} body   parsed JSON (object / array / string / primitive)
 * @param {object} [opts]
 * @param {string[]} [opts.identityHints]   "your" known values — if any of
 *                                          these appear in the body it's a
 *                                          strong signal the response really
 *                                          is tied to that identity.
 */
export function analyzeBody(body, opts = {}) {
  const hints = new Set((opts.identityHints || []).filter(Boolean).map((x) => String(x)));

  const { strings, paths } = walkStrings(body);

  /** @type {Record<string, { count: number, samples: string[] }>} */
  const signals = {};
  const bump = (kind, sample) => {
    if (!signals[kind]) signals[kind] = { count: 0, samples: [] };
    signals[kind].count += 1;
    if (signals[kind].samples.length < 3) signals[kind].samples.push(sample);
  };

  /** @type {Set<string>} */
  const hintHits = new Set();

  const scanValue = (raw, keyLower, pathLower) => {
    if (!raw) return;
    const v = String(raw);

    for (const h of hints) {
      if (v.includes(h)) hintHits.add(h);
    }

    // Key-driven hints are strong — an "email" key's value is an email even
    // if it doesn't pattern-match (e.g. trimmed / encoded). Value patterns
    // are the fallback.
    if (keyLower) {
      if (EMAIL_KEYS.has(keyLower)) bump('email', v);
      else if (NAME_KEYS.has(keyLower) && /^[A-Za-z][A-Za-z\-' ]{1,60}$/.test(v)) bump('name', v);
      else if (PHONE_KEYS.has(keyLower)) bump('phone', v);
      else if (DOB_KEYS.has(keyLower)) bump('dob', v);
      else if (ADDRESS_KEYS.has(keyLower)) bump('address', v);
    }

    for (const m of v.match(EMAIL) || []) bump('email', m);
    for (const m of v.match(SSN) || []) bump('ssn', redact(m));
    for (const m of v.match(CC_LIKE) || []) {
      // avoid noisy matches on long numeric IDs without separators
      if (/[- ]/.test(m)) bump('cc-like', redact(m));
    }
    for (const m of v.match(JWT) || []) bump('jwt', redact(m));
    for (const m of v.match(DOB) || []) bump('dob-pattern', m);
    for (const m of v.match(STREET) || []) bump('street', m);
    for (const m of v.match(PHONE_NA) || []) bump('phone', m);
    for (const m of v.match(PHONE_INTL) || []) {
      if (!/^\d{5,8}$/.test(m)) bump('phone-intl', m);
    }
    for (const m of v.match(RSID) || []) bump('rsid', m);
    for (const m of v.match(UUID) || []) bump('uuid', m);
    for (const m of v.match(HEX_40) || []) bump('hex-40', m);
    for (const m of v.match(HEX_32) || []) bump('hex-32', m);
    for (const m of v.match(HEX_16) || []) bump('hex-16', m);

    const zipMatches = v.match(ZIP_US) || [];
    if (keyLower && (ADDRESS_KEYS.has(keyLower) || keyLower.includes('zip') || keyLower.includes('postal'))) {
      for (const m of zipMatches) bump('zip', m);
    }

    if ((keyLower || '').includes('haplo') || (pathLower || '').includes('haplo')) {
      for (const m of v.match(HAPLO_Y) || []) bump('haplogroup-y', m);
      for (const m of v.match(HAPLO_MT) || []) bump('haplogroup-mt', m);
    }
  };

  for (const { path, key, value } of strings) {
    const keyLower = key ? key.toLowerCase() : '';
    const pathLower = path ? path.toLowerCase() : '';
    scanValue(value, keyLower, pathLower);
  }

  // Compute leakScore: weighted sum of PII signals, capped at 100.
  const weights = {
    ssn: 40,
    email: 10,
    name: 8,
    dob: 12,
    'dob-pattern': 6,
    phone: 8,
    'phone-intl': 6,
    address: 8,
    street: 10,
    zip: 2,
    'cc-like': 40,
    jwt: 25,
    rsid: 3,
    'haplogroup-y': 4,
    'haplogroup-mt': 4,
    uuid: 1,
    'hex-16': 1,
    'hex-32': 1,
    'hex-40': 1,
  };

  let score = 0;
  for (const [kind, { count }] of Object.entries(signals)) {
    const w = weights[kind] ?? 1;
    score += w * Math.min(count, 5);
  }
  if (hintHits.size > 0) score += 30; // identity hint present: very likely real tenant data

  const sizeBytes = approxByteSize(body);

  return {
    leakScore: clamp(Math.round(score)),
    byteSize: sizeBytes,
    stringCount: strings.length,
    uniquePaths: paths.length,
    fingerprint: paths,
    signals,
    identityHintHits: [...hintHits],
  };
}

/** @param {unknown} body */
function approxByteSize(body) {
  if (body == null) return 0;
  if (typeof body === 'string') return body.length;
  try {
    return JSON.stringify(body).length;
  } catch {
    return 0;
  }
}

/**
 * Compare two analyses of baseline (A) and replayed-with-other-id (B) bodies.
 * Returns whether the response "changed meaningfully" — i.e. B is not just
 * a rate-limit / auth-block / identical-cached response.
 *
 * @param {ReturnType<typeof analyzeBody>} a
 * @param {ReturnType<typeof analyzeBody>} b
 */
export function diffAnalyses(a, b) {
  const fpA = new Set(a.fingerprint);
  const fpB = new Set(b.fingerprint);
  const shared = [...fpA].filter((x) => fpB.has(x)).length;
  const union = new Set([...fpA, ...fpB]).size || 1;
  const jaccard = shared / union;

  const bothHaveData = a.stringCount >= 3 && b.stringCount >= 3;
  const similarShape = jaccard > 0.6;
  const sizeDelta = Math.abs(a.byteSize - b.byteSize);
  const sizeRatio = a.byteSize > 0 ? b.byteSize / a.byteSize : 0;

  return {
    jaccard: Number(jaccard.toFixed(3)),
    sharedPaths: shared,
    totalPaths: union,
    bothHaveData,
    similarShape,
    sizeDelta,
    sizeRatio: Number(sizeRatio.toFixed(3)),
    leakScoreDelta: b.leakScore - a.leakScore,
    verdict: similarShape && bothHaveData ?
        'same-shape-data-returned'
      : b.stringCount <= 2 ? 'empty-or-error'
      : 'shape-changed',
  };
}
