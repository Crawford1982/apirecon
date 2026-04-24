#!/usr/bin/env node

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

import { version } from '../src/version.mjs';
import { loadScope } from '../src/safety/scope.mjs';
import { launchBrowser } from '../src/recon/browser.mjs';
import { TrafficFilter } from '../src/recon/traffic-filter.mjs';
import { EndpointInventory } from '../src/recon/endpoint-inventory.mjs';
import { IdorDetector } from '../src/recon/idor-detector.mjs';
import { OpenApiExporter } from '../src/recon/exporters/openapi.mjs';
import { GraphqlExporter } from '../src/recon/exporters/graphql.mjs';
import { IdorReplay } from '../src/recon/idor-replay.mjs';
import { CrossAccountReplay } from '../src/recon/cross-account-replay.mjs';
import { extractGraphqlOperations, operationsToFindings } from '../src/recon/graphql-parser.mjs';
import { renderBountyReport, renderHtmlReport } from '../src/recon/report-generator.mjs';
import { Orchestrator } from '../src/recon/orchestrator.mjs';

const HELP = `
apirecon v${version}
Browser-driven traffic capture → JSON API inventory → OpenAPI hints → GraphQL bridge notes → optional IDOR replay.

USAGE:
  apirecon --mode browser     --target <url> [--scope-file <path>]
  apirecon --mode analyze     --traffic-file <path> [--scope-file <path>]
  apirecon --mode replay      --traffic-file <path> [--scope-file <path>] [--auth <token>]
  apirecon --mode diff-replay --traffic-file <path> --auth-bundle <path>
                              [--auth-bundle-b <path>] [--target-scope-ids <csv>]
  apirecon --mode report      --cross-account-file <path> [--target <label>]

Only test systems you are explicitly authorized to test.

OPTIONS:
  --mode <browser|analyze|replay|diff-replay|report>
  --target <url>               Origin to open first (browser mode)
  --traffic-file <path>        Raw capture JSON array (analyze / replay)
  --scope-file <path>          YAML (allowHosts, pathPrefixes) — matches graphqlai style
  --output-dir <path>          Default ./output
  --headless                   Headless Chromium (browser mode)
  --max-rps <n>                Replay throttle (default 5)
  --timeout-ms <n>             Navigation / fetch timeout (browser default 60000)
  --no-export-openapi          Skip OpenAPI artifact
  --no-export-graphql          Skip GraphQL hints artifact
  --idor-only                  Analyze: print IDOR summary only (still writes report)
  --auth <token>               Bearer token for replay (or RECON_AUTH_TOKEN env)
  --ci                         Replay/analyze: exit 2 when high-severity replay hits
  --auto-navigate, -a          After load: wait 5s then auto-click crawl (browser mode; skip ENTER)
  --use-chrome-profile        Use your real Chrome user-data dir (Google OAuth reuse; closes clean browser)
  --chrome-user-data <dir>    Chrome “User Data” folder (Windows: …\\Chrome\\User Data); env APIRECON_CHROME_USER_DATA
  --chrome-profile-dir <name>  Profile folder name inside User Data (Default, Profile 1, …); env APIRECON_CHROME_PROFILE_DIR
  --login-timeout-ms <n>       Max wait for https://you.23andme.com after OAuth (default 180000)
  --no-wait-for-you-app       Skip polling for you.23andme.com before crawl (not recommended for 23andMe)
  --auth-bundle <path>         diff-replay: account A auth-bundle-*.json
  --auth-bundle-a <path>       full mode: account A auth-bundle-*.json
  --auth-bundle-b <path>       Account B auth bundle (diff-replay / full)
  --traffic-file-a <path>      full mode: account A traffic file
  --traffic-file-b <path>      full mode: account B traffic file
  --target-scope-ids <csv>     Foreign scope IDs to probe (diff-replay / full)
  --extra-scope-ids <csv>      Alias for --target-scope-ids
  --help, -h
  --version, -V
`;

function showHelp() {
  console.log(HELP.trim());
}

const argvList = process.argv.slice(2);
const { values } = parseArgs({
  args: argvList,
  options: {
    target: { type: 'string', short: 't' },
    mode: { type: 'string' },
    'traffic-file': { type: 'string' },
    'scope-file': { type: 'string' },
    'output-dir': { type: 'string' },
    headless: { type: 'boolean', default: false },
    'max-rps': { type: 'string', default: '5' },
    'timeout-ms': { type: 'string' },
    'idor-only': { type: 'boolean', default: false },
    auth: { type: 'string' },
    ci: { type: 'boolean', default: false },
    'auto-navigate': { type: 'boolean', short: 'a', default: false },
    'use-chrome-profile': { type: 'boolean', default: false },
    'chrome-user-data': { type: 'string' },
    'chrome-profile-dir': { type: 'string' },
    'login-timeout-ms': { type: 'string' },
    'no-wait-for-you-app': { type: 'boolean', default: false },
    'auth-bundle': { type: 'string' },
    'auth-bundle-a': { type: 'string' },
    'auth-bundle-b': { type: 'string' },
    'traffic-file-a': { type: 'string' },
    'traffic-file-b': { type: 'string' },
    'target-scope-ids': { type: 'string' },
    'extra-scope-ids': { type: 'string' },
    'cross-account-file': { type: 'string' },
    help: { type: 'boolean', short: 'h', default: false },
    version: { type: 'boolean', short: 'V', default: false },
  },
  strict: false,
});

if (values.help) {
  showHelp();
  process.exit(0);
}

if (values.version) {
  console.log(version);
  process.exit(0);
}

const MODE = values.mode;
const TARGET = values.target;
const TRAFFIC_FILE = values['traffic-file'];
const SCOPE_FILE = values['scope-file'];
const OUTPUT_DIR = values['output-dir'] || './output';
const HEADLESS = values.headless;
const MAX_RPS = Math.max(1, parseInt(String(values['max-rps']), 10) || 5);
const TIMEOUT_MS =
  parseInt(String(values['timeout-ms'] ?? ''), 10) ||
  (MODE === 'browser' ? 60000 : 8000);
const EXPORT_OPENAPI = !argvList.includes('--no-export-openapi');
const EXPORT_GRAPHQL = !argvList.includes('--no-export-graphql');
const IDOR_ONLY = values['idor-only'] === true;
const CI = values.ci === true;
const AUTO_NAVIGATE = values['auto-navigate'] === true;
const USE_CHROME_PROFILE = values['use-chrome-profile'] === true;
const CHROME_USER_DATA =
  values['chrome-user-data']?.trim() || process.env.APIRECON_CHROME_USER_DATA?.trim() || '';
const CHROME_PROFILE_DIR =
  values['chrome-profile-dir']?.trim() || process.env.APIRECON_CHROME_PROFILE_DIR?.trim() || 'Default';
const LOGIN_TIMEOUT_MS =
  parseInt(String(values['login-timeout-ms'] ?? process.env.APIRECON_LOGIN_TIMEOUT_MS ?? ''), 10) ||
  180000;
const WAIT_FOR_YOU_APP =
  values['no-wait-for-you-app'] !== true && String(TARGET || '').includes('23andme.com');
const AUTH =
  values.auth?.trim() ||
  process.env.RECON_AUTH_TOKEN?.trim() ||
  process.env.GRAPHQLAI_TOKEN?.trim() ||
  null;

if (!MODE || !['browser', 'analyze', 'replay', 'diff-replay', 'full', 'report'].includes(MODE)) {
  console.error('Error: --mode must be browser, analyze, replay, diff-replay, full, or report');
  process.exit(1);
}

const AUTH_BUNDLE_FILE = (values['auth-bundle'] || values['auth-bundle-a'])?.trim() || '';
const AUTH_BUNDLE_B_FILE = values['auth-bundle-b']?.trim() || '';
const TRAFFIC_FILE_A = (values['traffic-file-a'] || values['traffic-file'])?.trim() || '';
const TRAFFIC_FILE_B = values['traffic-file-b']?.trim() || '';
const TARGET_SCOPE_IDS = String(values['target-scope-ids'] || values['extra-scope-ids'] || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

/** @param {string} path @returns {import('../src/recon/auth-bundle.mjs').AuthBundle} */
function readAuthBundle(path) {
  if (!existsSync(path)) {
    console.error(`Auth bundle not found: ${path}`);
    process.exit(1);
  }
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    console.error(`Auth bundle is not valid JSON: ${path} (${/** @type {Error} */ (e).message})`);
    process.exit(1);
  }
}

mkdirSync(OUTPUT_DIR, { recursive: true });

/** @param {any[]} candidates */
function countBySourceObject(candidates) {
  const by = { path: 0, query: 0, 'nested-url': 0, 'graphql-variable': 0 };
  for (const c of candidates) {
    const k = c.idorSource || 'path';
    if (k in by) by[k] += 1;
  }
  return by;
}

/** @param {any[]} candidates */
function countBySource(candidates) {
  const b = countBySourceObject(candidates);
  return `path=${b.path} query=${b.query} nested=${b['nested-url']} gql=${b['graphql-variable']}`;
}

let scope = null;
if (SCOPE_FILE) {
  if (!existsSync(SCOPE_FILE)) {
    console.error(`Scope file not found: ${SCOPE_FILE}`);
    process.exit(1);
  }
  scope = loadScope(SCOPE_FILE, TARGET || 'http://localhost');
}

const TS = Date.now();

async function analyzeFlow(trafficFilePath, ts) {
  const tFile = trafficFilePath || TRAFFIC_FILE;
  if (!tFile || !existsSync(tFile)) {
    console.error(`Traffic file not found: ${tFile}`);
    process.exit(1);
  }

  console.log(`apirecon analyze — ${tFile}`);
  const rawText = readFileSync(tFile, 'utf8');
  /** @type {unknown} */
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    console.error('Traffic file must be JSON');
    process.exit(1);
  }

  const raw = Array.isArray(parsed) ? parsed : parsed?.requests || [];
  if (!Array.isArray(raw)) {
    console.error('Expected JSON array of captured requests');
    process.exit(1);
  }

  const apiTraffic = TrafficFilter.jsonApis(raw);
  const scopedTraffic = scope ? apiTraffic.filter((req) => scope.isAllowed(String(req.url))) : apiTraffic;

  console.log(`Total captured: ${raw.length} · JSON APIs: ${apiTraffic.length} · In scope: ${scopedTraffic.length}`);

  const inventory = EndpointInventory.build(scopedTraffic);
  console.log(`Unique endpoints: ${inventory.endpoints.length}`);

  const restFindings = IdorDetector.find(inventory);

  const gqlExtract = extractGraphqlOperations(scopedTraffic);
  const gqlFindings = operationsToFindings(gqlExtract.operations);

  const idorCandidates = restFindings.concat(gqlFindings);
  const idorScopeGroups = IdorDetector.groupByScope(idorCandidates);
  const scopeGroupsReal = idorScopeGroups.filter((g) => g.scopeKey !== '__orphan__');

  console.log(
    `IDOR candidates: ${idorCandidates.length}  |  scope groups: ${scopeGroupsReal.length}  |  sources: ${countBySource(idorCandidates)}`,
  );
  if (gqlExtract.operations.length) {
    console.log(
      `GraphQL: ${gqlExtract.operations.length} operation(s) across ${gqlExtract.endpoints.length} endpoint(s), ${gqlFindings.length} ID-shaped variables`,
    );
    const top = gqlExtract.operations
      .filter((o) => o.idVariables.length > 0)
      .slice(0, 5);
    top.forEach((o, i) => {
      const vars = o.idVariables.map((v) => `${v.name}=${v.value} (${v.idType})`).join(', ');
      console.log(`  ${i + 1}. ${o.operationType} ${o.operationName || '(anonymous)'} · ${o.hits}x · ${vars}`);
    });
  }

  if (scopeGroupsReal.length) {
    console.log('\nScope-parent IDORs (each group shares a single <scope_id> — swap it to probe cross-tenant reads):');
    scopeGroupsReal.slice(0, 10).forEach((g, i) => {
      console.log(
        `  ${i + 1}. [risk ${g.maxRisk}] /${g.scopeWord}/${g.scopeId}/…  (${g.findings.length} child endpoint${g.findings.length === 1 ? '' : 's'})`,
      );
      g.findings
        .slice()
        .sort((a, b) => b.idorRisk - a.idorRisk)
        .slice(0, 5)
        .forEach((f) => {
          console.log(`       [${f.idorRisk}] ${f.method} ${f.pathTemplate}   (${f.idType})`);
        });
    });
  }

  const nonScope = idorCandidates.filter((c) => !c.scopeKey);
  if (nonScope.length && (IDOR_ONLY || scopeGroupsReal.length === 0)) {
    console.log('\nOther IDOR candidates:');
    nonScope.slice(0, 20).forEach((c, i) => {
      const q = c.queryParam ? ` ?${c.queryParam}` : '';
      console.log(
        `  ${i + 1}. [${c.idorRisk}] ${c.method} ${c.path} (${c.idType}: ${c.idValue})${q}`,
      );
    });
  }

  /** @type {string[]} */
  const outputs = [];

  if (EXPORT_OPENAPI && !IDOR_ONLY) {
    const openApiSpec = OpenApiExporter.convert(inventory);
    const oaFile = `${OUTPUT_DIR}/recon-openapi-${ts}.json`;
    writeFileSync(oaFile, JSON.stringify(openApiSpec, null, 2));
    console.log(`OpenAPI: ${oaFile}`);
    outputs.push(oaFile);
  }

  if (EXPORT_GRAPHQL && !IDOR_ONLY) {
    const gqlHints = GraphqlExporter.convert(inventory);
    const gqlFile = `${OUTPUT_DIR}/recon-graphql-${ts}.json`;
    writeFileSync(gqlFile, JSON.stringify(gqlHints, null, 2));
    console.log(`GraphQL hints: ${gqlFile}`);
    outputs.push(gqlFile);
  }

  const report = {
    meta: {
      tool: 'apirecon',
      version,
      timestamp: ts,
      scopeFile: SCOPE_FILE || null,
    },
    stats: {
      totalRequests: raw.length,
      apiRequests: apiTraffic.length,
      scopedRequests: scopedTraffic.length,
      uniqueEndpoints: inventory.endpoints.length,
      idorCandidates: idorCandidates.length,
      idorScopeGroups: scopeGroupsReal.length,
      idorSources: countBySourceObject(idorCandidates),
    },
    inventory,
    idorCandidates,
    idorScopeGroups,
    outputs,
  };

  const reportFile = `${OUTPUT_DIR}/recon-report-${ts}.json`;
  writeFileSync(reportFile, JSON.stringify(report, null, 2));
  console.log(`Report: ${reportFile}`);

}

async function main() {
  if (MODE === 'browser') {
    if (!TARGET) {
      console.error('browser mode requires --target');
      process.exit(1);
    }

    const trafficFile = TRAFFIC_FILE || `${OUTPUT_DIR}/traffic-raw-${TS}.json`;

    console.log(`Browser mode → ${trafficFile}`);
    if (USE_CHROME_PROFILE) {
      console.log(
        'Chrome profile mode: uses your Google session from disk (close Chrome first to avoid profile lock).\n',
      );
    }
    if (AUTO_NAVIGATE) {
      console.log(
        'Auto-navigate on: after navigation, 5s grace for login, then automated SPA crawl (no ENTER).\n',
      );
    } else {
      console.log(
        'When ready: ENTER or "a" + ENTER to auto-crawl; other input + ENTER finishes capture.\n',
      );
    }
    if (WAIT_FOR_YOU_APP) {
      console.log(
        'Will wait for https://you.23andme.com/ (OAuth). Use --no-wait-for-you-app to skip.\n',
      );
    }

    const { traffic, authBundle } = await launchBrowser({
      target: TARGET,
      headless: HEADLESS,
      scope,
      timeoutMs: TIMEOUT_MS,
      autoNavigate: AUTO_NAVIGATE,
      autoNavigateOptions: {
        clickDelay: 2000,
        scrollDelay: 1200,
      },
      useChromeProfile: USE_CHROME_PROFILE,
      chromeUserDataDir: CHROME_USER_DATA,
      chromeProfileDirectory: CHROME_PROFILE_DIR,
      loginTimeoutMs: LOGIN_TIMEOUT_MS,
      waitForYouApp: WAIT_FOR_YOU_APP,
    });

    writeFileSync(trafficFile, JSON.stringify(traffic, null, 2));
    console.log(`Wrote ${traffic.length} requests → ${trafficFile}`);

    if (authBundle) {
      const authFile = `${OUTPUT_DIR}/auth-bundle-${TS}.json`;
      writeFileSync(authFile, JSON.stringify(authBundle, null, 2));
      const hostsWithHeaders = Object.entries(authBundle.hostHeaders || {})
        .filter(([, h]) => Object.keys(h).length > 0)
        .map(([h]) => h);
      console.log(
        `Auth bundle: ${authFile}  (cookies=${authBundle.cookies?.length || 0} · hosts-with-auth=${hostsWithHeaders.length} · identities=${authBundle.identities?.length || 0})`,
      );
      if (authBundle.identities?.length) {
        const top = authBundle.identities.slice(0, 5);
        console.log(
          `  Your observed identities: ${top.map((id) => `${id.kind}=${id.value}`).join(', ')}`,
        );
      }
    }

    await analyzeFlow(trafficFile, TS);
    return;
  }

  if (MODE === 'analyze') {
    await analyzeFlow(TRAFFIC_FILE, TS);
    return;
  }

  if (MODE === 'replay') {
    const tFile = TRAFFIC_FILE;
    if (!tFile || !existsSync(tFile)) {
      console.error('replay mode requires --traffic-file');
      process.exit(1);
    }

    const rawText = readFileSync(tFile, 'utf8');
    const parsed = JSON.parse(rawText);
    const raw = Array.isArray(parsed) ? parsed : parsed?.requests || [];
    if (!Array.isArray(raw)) {
      console.error('Expected JSON array');
      process.exit(1);
    }

    const apiTraffic = TrafficFilter.jsonApis(raw);
    const scopedTraffic = scope ? apiTraffic.filter((req) => scope.isAllowed(String(req.url))) : apiTraffic;
    const inventory = EndpointInventory.build(scopedTraffic);
    const idorCandidates = IdorDetector.find(inventory);

    if (idorCandidates.length === 0) {
      console.log('No IDOR candidates found; nothing to replay.');
      process.exit(0);
    }

    console.log(`Replaying ${idorCandidates.length} candidate endpoint pattern(s)…`);

    const replay = new IdorReplay({
      scope,
      maxRps: typeof scope?.maxRps === 'number' ? scope.maxRps : MAX_RPS,
      timeoutMs: TIMEOUT_MS,
      auth: AUTH,
    });

    const summary = await replay.run(idorCandidates);
    replay.exportReport(OUTPUT_DIR);

    if (CI && summary.stats.highSeverityFindings > 0) {
      console.error(`CI: ${summary.stats.highSeverityFindings} high-severity replay classification(s)`);
      process.exit(2);
    }
  }

  if (MODE === 'diff-replay') {
    const tFile = TRAFFIC_FILE;
    if (!tFile || !existsSync(tFile)) {
      console.error('diff-replay requires --traffic-file');
      process.exit(1);
    }
    if (!AUTH_BUNDLE_FILE) {
      console.error('diff-replay requires --auth-bundle (your account A bundle from browser mode)');
      process.exit(1);
    }

    const bundleA = readAuthBundle(AUTH_BUNDLE_FILE);
    const bundleB = AUTH_BUNDLE_B_FILE ? readAuthBundle(AUTH_BUNDLE_B_FILE) : null;

    const rawText = readFileSync(tFile, 'utf8');
    const parsed = JSON.parse(rawText);
    const raw = Array.isArray(parsed) ? parsed : parsed?.requests || [];
    const apiTraffic = TrafficFilter.jsonApis(raw);
    const scopedTraffic = scope ? apiTraffic.filter((req) => scope.isAllowed(String(req.url))) : apiTraffic;
    const inventory = EndpointInventory.build(scopedTraffic);
    const idorCandidates = IdorDetector.find(inventory);

    console.log(
      `[diff-replay] ${tFile} → ${raw.length} raw row(s) · ${apiTraffic.length} JSON API · ${scopedTraffic.length} in-scope · ${idorCandidates.length} IDOR candidate(s)`,
    );
    if (idorCandidates.length === 0) {
      console.log('No IDOR candidates to diff-replay (capture deeper traffic or widen scope).');
      process.exit(0);
    }

    /** @param {import('../src/recon/auth-bundle.mjs').AuthBundle} b */
    const scopeIdsFrom = (b) => [...new Set((b.identities || []).map((i) => i.value))];

    const runner = new CrossAccountReplay({
      accountA: { label: 'A', bundle: bundleA, scopeIds: scopeIdsFrom(bundleA) },
      accountB: bundleB ? { label: 'B', bundle: bundleB, scopeIds: scopeIdsFrom(bundleB) } : undefined,
      extraScopeIds: TARGET_SCOPE_IDS.concat(bundleB ? scopeIdsFrom(bundleB) : []),
      scope,
      maxRps: typeof scope?.maxRps === 'number' ? scope.maxRps : MAX_RPS,
      timeoutMs: TIMEOUT_MS,
      verbose: true,
    });

    const aIds = scopeIdsFrom(bundleA);
    const bIds = (bundleB ? scopeIdsFrom(bundleB) : []).concat(TARGET_SCOPE_IDS);
    console.log(
      `Cross-account diff-replay: A ids=[${aIds.join(',') || '(none)'}] · B ids=[${bIds.join(',') || '(none)'}] · candidates=${idorCandidates.length}`,
    );
    if (bIds.length === 0) {
      console.error(
        'No target scope IDs to swap to. Pass --target-scope-ids <csv> or provide --auth-bundle-b.',
      );
      process.exit(1);
    }

    const summary = await runner.run(idorCandidates);
    const reportFile = runner.exportReport(OUTPUT_DIR);

    const s = summary.stats;
    console.log(
      `Verdicts: confirmed=${s.confirmed || 0} · likely=${s.likely || 0} · blocked=${s.blocked || 0} · public=${s.public || 0} · inconclusive=${s.inconclusive || 0}`,
    );

    /** @param {any[]} rows */
    const replayDiagnostics = (rows) => {
      let ownOk = 0;
      let swapBy = {};
      for (const r of rows || []) {
        const os = r.probes?.own?.status;
        if (typeof os === 'number' && os >= 200 && os < 300) ownOk += 1;
        const ss = r.probes?.swap?.status;
        if (typeof ss === 'number') swapBy[ss] = (swapBy[ss] || 0) + 1;
      }
      const total = (rows || []).length;
      console.log(
        `[diff-replay] Baseline probes (your id): ${ownOk}/${total} returned HTTP 2xx · Swap status mix: ${Object.entries(swapBy)
          .sort((a, b) => Number(a[0]) - Number(b[0]))
          .map(([k, v]) => `${k}×${v}`)
          .join(', ') || 'n/a'}`,
      );
      if (total > 0 && ownOk === 0) {
        console.log(
          '[diff-replay] Warning: no baseline 2xx — cookies/session from --auth-bundle are likely expired or replay headers differ from the browser. Run recon:browser again (same session), then recon:diff immediately, or paste fresh Cookie / Authorization into the bundle.',
        );
      }
    };
    replayDiagnostics(summary.all);

    if ((summary.confirmed || []).length) {
      console.log('\nConfirmed cross-tenant reads:');
      summary.confirmed.forEach((r, i) => {
        console.log(`  ${i + 1}. ${r.finding.method} ${r.probes.swap.url}`);
        console.log(`       reason: ${r.verdict.reason}`);
        if (r.evidenceChain?.summary) console.log(`       fields: ${r.evidenceChain.summary}`);
        console.log(`       curl:   ${r.curl.swap}`);
      });
    }
    if ((summary.likely || []).length) {
      console.log('\nLikely cross-tenant reads (needs manual review):');
      summary.likely.forEach((r, i) => {
        console.log(`  ${i + 1}. ${r.finding.method} ${r.probes.swap.url}`);
        console.log(`       reason: ${r.verdict.reason}`);
        if (r.evidenceChain?.summary) console.log(`       fields: ${r.evidenceChain.summary}`);
        console.log(`       curl:   ${r.curl.swap}`);
      });
    }
    console.log(`\nJSON:  ${reportFile}`);

    const mdPath = `${OUTPUT_DIR}/bounty-report-${TS}.md`;
    writeFileSync(mdPath, renderBountyReport(summary, { target: TARGET || 'target', toolVersion: `apirecon v${version}` }));
    console.log(`Bounty report (markdown): ${mdPath}`);

    const htmlPath = `${OUTPUT_DIR}/bounty-report-${TS}.html`;
    writeFileSync(htmlPath, renderHtmlReport(summary, { target: TARGET || 'target', toolVersion: `apirecon v${version}` }));
    console.log(`Bounty report (HTML):     ${htmlPath}`);

    if (CI && (s.confirmed || 0) > 0) process.exit(2);
  }

  if (MODE === 'full') {
    const tFileA = TRAFFIC_FILE_A;
    if (!tFileA || !existsSync(tFileA)) {
      console.error('full mode requires --traffic-file-a (or --traffic-file) pointing to account A capture');
      process.exit(1);
    }
    if (!AUTH_BUNDLE_FILE) {
      console.error('full mode requires --auth-bundle-a (or --auth-bundle)');
      process.exit(1);
    }
    if (!AUTH_BUNDLE_B_FILE && TARGET_SCOPE_IDS.length === 0) {
      console.error('full mode requires --auth-bundle-b or --extra-scope-ids with at least one target ID');
      process.exit(1);
    }

    const orch = new Orchestrator({
      trafficFileA: tFileA,
      authBundleA: AUTH_BUNDLE_FILE,
      trafficFileB: TRAFFIC_FILE_B || null,
      authBundleB: AUTH_BUNDLE_B_FILE || null,
      extraScopeIds: TARGET_SCOPE_IDS,
      scope,
      maxRps: typeof scope?.maxRps === 'number' ? scope.maxRps : MAX_RPS,
      timeoutMs: TIMEOUT_MS,
      outputDir: OUTPUT_DIR,
      target: TARGET || 'you.23andme.com',
    });

    const { files } = await orch.run();

    if (CI) {
      const raw = JSON.parse(readFileSync(files.json, 'utf8'));
      if ((raw.stats?.confirmed || 0) > 0) process.exit(2);
    }
  }

  if (MODE === 'report') {
    const file = values['cross-account-file']?.trim();
    if (!file || !existsSync(file)) {
      console.error('report mode requires --cross-account-file ./output/cross-account-replay-<ts>.json');
      process.exit(1);
    }
    const summary = JSON.parse(readFileSync(file, 'utf8'));
    const reportOpts = { target: TARGET || 'target', toolVersion: `apirecon v${version}` };
    const md = renderBountyReport(summary, reportOpts);
    const mdPath = `${OUTPUT_DIR}/bounty-report-${TS}.md`;
    writeFileSync(mdPath, md);
    console.log(`Bounty report (markdown): ${mdPath}`);
    const htmlPath = `${OUTPUT_DIR}/bounty-report-${TS}.html`;
    writeFileSync(htmlPath, renderHtmlReport(summary, reportOpts));
    console.log(`Bounty report (HTML):     ${htmlPath}`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
