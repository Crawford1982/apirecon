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

const HELP = `
apirecon v${version}
Browser-driven traffic capture → JSON API inventory → OpenAPI hints → GraphQL bridge notes → optional IDOR replay.

USAGE:
  apirecon --mode browser --target <url> [--scope-file <path>]
  apirecon --mode analyze --traffic-file <path> [--scope-file <path>]
  apirecon --mode replay --traffic-file <path> [--scope-file <path>] [--auth <token>]

Only test systems you are explicitly authorized to test.

OPTIONS:
  --mode <browser|analyze|replay>
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

if (!MODE || !['browser', 'analyze', 'replay'].includes(MODE)) {
  console.error('Error: --mode must be browser, analyze, or replay');
  process.exit(1);
}

mkdirSync(OUTPUT_DIR, { recursive: true });

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

  const idorCandidates = IdorDetector.find(inventory);
  console.log(`IDOR candidates (heuristic): ${idorCandidates.length}`);
  if (idorCandidates.length && IDOR_ONLY) {
    idorCandidates.slice(0, 40).forEach((c, i) => {
      const q = /** @type {{ queryParam?: string }} */ (c).queryParam;
      console.log(
        `  ${i + 1}. [${c.idorRisk}] ${c.method} ${c.path} (${c.idType}: ${c.idValue})${q ? ` ?${q}` : ''}`,
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
    },
    inventory,
    idorCandidates,
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

    const traffic = await launchBrowser({
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
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
