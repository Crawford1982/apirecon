#!/usr/bin/env node
/**
 * recon:full
 *
 * End-to-end cross-account IDOR pipeline:
 *   detect → diff-replay → evidence chains → HTML + Markdown bounty report
 *
 * Usage:
 *   npm run recon:full -- \
 *     --traffic-file-a  ./output/traffic-raw-<tsA>.json  \
 *     --auth-bundle-a   ./output/auth-bundle-<tsA>.json  \
 *     --auth-bundle-b   ./output/auth-bundle-<tsB>.json  \
 *     [--traffic-file-b ./output/traffic-raw-<tsB>.json] \
 *     [--extra-scope-ids <id1,id2,…>]                   \
 *     [--scope-file      ./examples/scope.23andme.yaml]  \
 *     [--max-rps         3]                              \
 *     [--target          you.23andme.com]
 */

import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { loadScope } from '../src/safety/scope.mjs';
import { Orchestrator } from '../src/recon/orchestrator.mjs';

const { values } = parseArgs({
  args: process.argv.slice(2),
  options: {
    'traffic-file-a':  { type: 'string' },
    'auth-bundle-a':   { type: 'string' },
    'traffic-file-b':  { type: 'string' },
    'auth-bundle-b':   { type: 'string' },
    'extra-scope-ids': { type: 'string' },
    'scope-file':      { type: 'string' },
    'max-rps':         { type: 'string', default: '3' },
    'timeout-ms':      { type: 'string' },
    'output-dir':      { type: 'string' },
    target:            { type: 'string', short: 't' },
    help:              { type: 'boolean', short: 'h', default: false },
  },
  strict: false,
});

if (values.help) {
  console.log(`
apirecon recon:full — end-to-end cross-account IDOR pipeline

REQUIRED
  --traffic-file-a <path>    Account A traffic capture  (traffic-raw-*.json)
  --auth-bundle-a  <path>    Account A auth bundle       (auth-bundle-*.json)

ACCOUNT B  (one of these must be provided)
  --auth-bundle-b  <path>    Account B auth bundle
  --extra-scope-ids <csv>    Known foreign profile/user IDs (comma-separated)

OPTIONAL
  --traffic-file-b <path>    Account B traffic capture (enhances B's scope IDs)
  --scope-file <path>        Scope YAML (allowHosts, pathPrefixes)
  --max-rps <n>              Requests per second (default 3)
  --timeout-ms <n>           Per-request timeout (default 10000)
  --output-dir <path>        Output directory (default ./output)
  --target <label>           Target label for report (default: from traffic)
`.trim());
  process.exit(0);
}

// ── Validate ──────────────────────────────────────────────────────────────────

const trafficFileA = values['traffic-file-a']?.trim();
const authBundleA  = values['auth-bundle-a']?.trim();
const authBundleB  = values['auth-bundle-b']?.trim();
const trafficFileB = values['traffic-file-b']?.trim();
const extraScopeIds = String(values['extra-scope-ids'] || '').split(',').map((s) => s.trim()).filter(Boolean);

if (!trafficFileA || !existsSync(trafficFileA)) {
  console.error('Error: --traffic-file-a is required and must exist');
  process.exit(1);
}
if (!authBundleA || !existsSync(authBundleA)) {
  console.error('Error: --auth-bundle-a is required and must exist');
  process.exit(1);
}
if (!authBundleB && extraScopeIds.length === 0) {
  console.error('Error: provide --auth-bundle-b (account B) or --extra-scope-ids <csv>');
  process.exit(1);
}
if (authBundleB && !existsSync(authBundleB)) {
  console.error(`Error: auth-bundle-b not found: ${authBundleB}`);
  process.exit(1);
}

// ── Scope ─────────────────────────────────────────────────────────────────────

let scope = null;
if (values['scope-file']?.trim()) {
  const sf = values['scope-file'].trim();
  if (!existsSync(sf)) {
    console.error(`Error: scope file not found: ${sf}`);
    process.exit(1);
  }
  scope = loadScope(sf, values.target || 'https://you.23andme.com');
}

// ── Run ───────────────────────────────────────────────────────────────────────

const orchestrator = new Orchestrator({
  trafficFileA,
  authBundleA,
  trafficFileB:  trafficFileB || null,
  authBundleB:   authBundleB  || null,
  extraScopeIds,
  scope,
  maxRps:    Math.max(1, parseInt(String(values['max-rps']), 10) || 3),
  timeoutMs: parseInt(String(values['timeout-ms'] || ''), 10) || 10000,
  outputDir: values['output-dir']?.trim() || './output',
  target:    values.target?.trim() || 'you.23andme.com',
});

orchestrator.run().catch((err) => {
  console.error('\nFatal error:', err.message);
  process.exit(1);
});
