/**
 * evidence-chain.mjs
 *
 * Field-level evidence extraction and cross-account diff.
 *
 * The gap between "the response was similar" and "this field leaked Bob's email
 * to Alice's session" is what makes a finding reportable. This module bridges it.
 *
 * Core output per probe pair:
 *   - changedFields  : fields whose *value* differs → the data that leaked
 *   - sensitiveLeaks : subset flagged as PII / genetic / financial
 *   - missingInSwap  : fields present in baseline but absent in swap
 *   - addedInSwap    : fields only in swap (could be extra data returned)
 *   - evidenceScore  : 0..100, how strong the field-level evidence is
 */

import { walkStrings } from './response-analyzer.mjs';

// ─── field sensitivity ────────────────────────────────────────────────────────

/** Normalize a key for case-insensitive, separator-agnostic matching. */
function normKey(k) {
  return String(k || '').toLowerCase().replace(/[_\-. ]/g, '');
}

const CRITICAL_KEYS = new Set([
  'ssn', 'sin', 'taxid', 'nationalid', 'passport',
  'creditcard', 'cardnumber', 'cvv', 'routingnumber', 'accountnumber',
  'rawgenotype', 'rawdna', 'vcf', 'genotype',
]);

const HIGH_KEYS = new Set([
  'email', 'emailaddress', 'firstname', 'lastname', 'fullname',
  'displayname', 'givenname', 'familyname', 'dob', 'dateofbirth',
  'birthday', 'birthdate', 'phone', 'phonenumber', 'mobile', 'address',
  'street', 'zip', 'postalcode', 'haplogroup', 'haplogroupy', 'haplogroupmt',
  'maternalhaplogroup', 'paternalhaplogroup',
  'ancestrycomposition', 'ancestrybreakdown',
]);

const MEDIUM_KEYS = new Set([
  'id', 'uid', 'uuid', 'userid', 'profileid', 'accountid', 'memberid',
  'username', 'handle', 'location', 'city', 'region', 'country',
  'createdat', 'updatedat', 'joinedat', 'kitid', 'sampleid',
  'subscription', 'plan', 'tier',
]);

/** Score 0..4 for a single field based on key name + value shape. */
export function sensitivityScore(key, value) {
  const kl = normKey(key);
  if (CRITICAL_KEYS.has(kl)) return 4;
  if (HIGH_KEYS.has(kl)) return 3;
  if (MEDIUM_KEYS.has(kl)) return 2;

  // Value-shape heuristics even if key name is opaque.
  const v = String(value || '');
  if (/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/.test(v)) return 3;
  if (/\b(?:19|20)\d{2}-\d{2}-\d{2}\b/.test(v)) return 2;
  if (/\b[A-Z]\d{1,4}[a-z]\d?[a-z]?\b/.test(v) && kl.includes('haplo')) return 3;
  if (/\brs\d{2,9}\b/.test(v)) return 2;

  return 0;
}

const SENSITIVITY_LABELS = ['', 'low', 'medium', 'high', 'critical'];

// ─── field extraction ─────────────────────────────────────────────────────────

/**
 * Flatten a JSON body into a map of dotted-path → value.
 * @param {unknown} body
 * @returns {Map<string, string>}
 */
function flattenBody(body) {
  const { strings } = walkStrings(body, { maxNodes: 8000, maxDepth: 15 });
  const out = new Map();
  for (const { path, value } of strings) {
    if (!path) continue;
    // Keep last value for duplicate paths (e.g. arrays).
    out.set(path, String(value ?? ''));
  }
  return out;
}

// ─── field-level diff ─────────────────────────────────────────────────────────

/**
 * @typedef {object} FieldDiff
 * @property {string}   path
 * @property {string}   key
 * @property {string}   ownValue
 * @property {string}   swapValue
 * @property {number}   sensitivity   0..4
 * @property {string}   sensitivityLabel
 * @property {boolean}  isId          value looks like an opaque ID
 */

/**
 * @typedef {object} EvidenceChain
 * @property {FieldDiff[]} changedFields
 * @property {FieldDiff[]} sensitiveLeaks
 * @property {string[]}    missingInSwap
 * @property {string[]}    addedInSwap
 * @property {number}      evidenceScore   0..100
 * @property {string}      summary
 * @property {string[]}    keyLeaks        short labels for the report headline
 */

/** @param {string} v */
function looksLikeId(v) {
  if (!v) return false;
  if (/^[a-f0-9]{8,64}$/i.test(v)) return true;
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(v)) return true;
  if (/^\d{3,19}$/.test(v)) return true;
  return false;
}

/**
 * Produce a structured evidence chain from two raw probe results.
 *
 * @param {{ body?: unknown, status?: number }} ownResult    baseline (own id)
 * @param {{ body?: unknown, status?: number }} swapResult   cross-account (foreign id)
 * @param {{ ownHints?: string[], swapHints?: string[] }} [hints]
 * @returns {EvidenceChain}
 */
export function buildEvidenceChain(ownResult, swapResult, hints = {}) {
  const ownFields = flattenBody(ownResult?.body ?? null);
  const swapFields = flattenBody(swapResult?.body ?? null);

  /** @type {FieldDiff[]} */
  const changedFields = [];
  /** @type {string[]} */
  const missingInSwap = [];
  /** @type {string[]} */
  const addedInSwap = [];

  // Paths in own but not swap.
  for (const [path] of ownFields) {
    if (!swapFields.has(path)) missingInSwap.push(path);
  }

  // Paths in swap but not own.
  for (const [path] of swapFields) {
    if (!ownFields.has(path)) addedInSwap.push(path);
  }

  // Shared paths where value differs.
  for (const [path, ownValue] of ownFields) {
    const swapValue = swapFields.get(path);
    if (swapValue == null || swapValue === ownValue) continue;

    const leafKeyRaw = path.split('.').pop()?.replace(/\[\d+\]$/, '') ?? '';
    const sens = Math.max(sensitivityScore(leafKeyRaw, ownValue), sensitivityScore(leafKeyRaw, swapValue));

    changedFields.push({
      path,
      key: leafKeyRaw,
      ownValue: ownValue.slice(0, 120),
      swapValue: swapValue.slice(0, 120),
      sensitivity: sens,
      sensitivityLabel: SENSITIVITY_LABELS[sens] || 'none',
      isId: looksLikeId(ownValue) || looksLikeId(swapValue),
    });
  }

  // Sort by sensitivity desc.
  changedFields.sort((a, b) => b.sensitivity - a.sensitivity);

  const sensitiveLeaks = changedFields.filter((f) => f.sensitivity >= 2);

  // Evidence score: weighted sum of sensitivity, capped at 100.
  let score = 0;
  for (const f of changedFields) {
    score += f.sensitivity * (f.sensitivity === 4 ? 20 : f.sensitivity === 3 ? 12 : f.sensitivity === 2 ? 5 : 1);
  }
  // Bonus: cross-account identity hints actually appear in swap body.
  const swapBodyStr = JSON.stringify(swapResult?.body ?? '');
  for (const h of hints.swapHints ?? []) {
    if (h && swapBodyStr.includes(h)) score += 25;
  }
  const evidenceScore = Math.min(100, Math.round(score));

  const keyLeaks = sensitiveLeaks
    .slice(0, 4)
    .map((f) => `${f.key} [${f.sensitivityLabel}]`);

  const summary =
    sensitiveLeaks.length > 0
      ? `${sensitiveLeaks.length} sensitive field(s) changed between accounts: ${keyLeaks.join(', ')}`
      : changedFields.length > 0
        ? `${changedFields.length} field(s) differ but no high-sensitivity leaks detected`
        : `Responses appear identical or swap body is empty`;

  return { changedFields, sensitiveLeaks, missingInSwap, addedInSwap, evidenceScore, summary, keyLeaks };
}

/**
 * Score severity from a combination of verdict and evidence chain.
 *
 * @param {'confirmed'|'likely'|'blocked'|'public'|'inconclusive'} verdict
 * @param {EvidenceChain | null} chain
 * @param {number} idorRisk  0..10 from detector
 */
export function deriveSeverity(verdict, chain, idorRisk = 5) {
  if (verdict !== 'confirmed' && verdict !== 'likely') {
    return { label: 'Informational', cvss: 0.0, color: '#6b7280' };
  }

  const sensMax = chain ? Math.max(0, ...chain.sensitiveLeaks.map((f) => f.sensitivity)) : 0;
  const evidence = chain?.evidenceScore ?? 0;

  // Critical: genetic data, SSN, CC, confirmed + high evidence
  if (sensMax >= 4 || (sensMax >= 3 && evidence >= 50 && verdict === 'confirmed')) {
    return { label: 'Critical', cvss: 9.1, color: '#dc2626' };
  }
  if (sensMax >= 3 || (evidence >= 35 && verdict === 'confirmed')) {
    return { label: 'High', cvss: 7.6, color: '#ea580c' };
  }
  if (sensMax >= 2 || (evidence >= 15 && idorRisk >= 8)) {
    return { label: 'Medium', cvss: 5.5, color: '#ca8a04' };
  }
  return { label: 'Low', cvss: 3.5, color: '#2563eb' };
}
