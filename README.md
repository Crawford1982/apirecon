# apirecon

Browser-driven **REST/JSON API recon** companion to [**graphqlai**](https://github.com/Crawford1982/graphqlai): capture traffic from Chromium, summarize endpoints, emit rough **OpenAPI** hints and **GraphQL placement** notes, then run **IDOR** heuristics, optional **neighbor-ID replay**, and a **two-account / hex-swap** pipeline with **verdicts**, **field-level evidence**, and **HTML + Markdown bounty reports**.

Forked from the workflow and YAML scope conventions used in `graphqlai`, but intentionally **broader than GraphQL-only** tooling.

## Quick start

```bash
npm install
npx playwright install chromium
```

| Script | What it does |
|--------|----------------|
| `npm run recon:browser`   | Capture + optional auto-navigate; writes `traffic-raw-*.json`, `auth-bundle-*.json` |
| `npm run recon:analyze`  | IDOR + GraphQL variable hints from a capture |
| `npm run recon:replay`   | Sequential ID probes (`RECON_AUTH_TOKEN` or `--auth`) |
| `npm run recon:diff`     | Cross-account / swap-id matrix replay, verdicts, **MD + HTML** reports |
| `npm run recon:full`     | One command: **detect → diff-replay → evidence → reports** (needs two bundles or `--target-scope-ids`) |
| `npm run recon:report`  | Regenerate **MD + HTML** from an existing `cross-account-replay-*.json` |

CLI entry: `node bin/apirecon.mjs` (or `npx apirecon` if linked). Modes: `browser`, `analyze`, `replay`, `diff-replay`, `full`, `report` — use `--help`.

### Example: capture and analyze (JSONPlaceholder)

```bash
# Use a JSON resource URL so the page actually issues JSON API traffic (the home page is HTML-only).
npm run recon:browser -- --target https://jsonplaceholder.typicode.com/posts/1 --scope-file ./examples/scope.jsonplaceholder.yaml --headless
# In the browser session, wait a few seconds, then press ENTER (or use --auto-navigate / -a for a safe SPA crawl)

npm run recon:analyze -- --traffic-file ./output/traffic-raw-<timestamp>.json --scope-file ./examples/scope.jsonplaceholder.yaml
```

Or skip waiting for ENTER: `--auto-navigate` / `-a` runs an SPA-style crawler (BFS-like route discovery, safe clicks, form fills on allowed hosts, pagination, heartbeat logs). It skips destructive actions (log out, delete, purchase, …).

### IDOR replay (auth token)

**Authorized targets only** — set `RECON_AUTH_TOKEN` or use `--auth`.

```bash
npm run recon:replay -- --traffic-file ./output/traffic-raw-<timestamp>.json --scope-file ./examples/scope.example.yaml --auth "$RECON_AUTH_TOKEN"
```

Artifacts in `./output/` (default): `traffic-raw-*.json`, `auth-bundle-*.json`, `recon-report-*.json`, `recon-openapi-*.json`, `recon-graphql-*.json`, `idor-replay-*.json`. Replay entries include **`replayCurl`** (bash-safe one-liner).

---

## Cross-account diff (`recon:diff`) — IDOR **confirmation**

Detector output is a *hypothesis*. To look for a cross-tenant read you replay with **account A’s session** while swapping path/query/GraphQL variable IDs to **account B’s scope id** (or a known test id you are allowed to use).

### Preconditions

- **`auth-bundle-<ts>.json`** from the same browser run as the traffic (or refresh capture). Cookies and Cloudflare tokens **expire**; if baseline probes return `401` on replay, re-run `recon:browser` and run `recon:diff` while the session is still valid.
- **Real target ids:** use the other test account’s profile id (e.g. 16-char hex for `/p/.../`), not random placeholders.

### Commands (bash)

```bash
# Foreign scope IDs you are authorized to test (comma-separated)
npm run recon:diff -- \
  --traffic-file  ./output/traffic-raw-TIMESTAMP.json \
  --auth-bundle   ./output/auth-bundle-TIMESTAMP.json \
  --scope-file    ./examples/scope.23andme.yaml \
  --target        https://you.23andme.com \
  --target-scope-ids OTHER_PROFILE_ID16,SECOND_ID_IF_ANY

# Or: two captures / two bundles
npm run recon:diff -- \
  --traffic-file  ./output/traffic-raw-A.json \
  --auth-bundle   ./output/auth-bundle-A.json \
  --auth-bundle-b ./output/auth-bundle-B.json \
  --scope-file    ./examples/scope.23andme.yaml \
  --target        https://you.23andme.com
```

### Windows PowerShell

- **Do not** wrap example ids in angle brackets (PowerShell treats the opening bracket as redirection). Use real file names and hex ids, e.g. `--target-scope-ids a1b2c3d4e5f6789a`.
- **Line continuation** is backtick `` ` `` at end of line (see examples above in bash; same flags in PowerShell).

```powershell
npm run recon:diff -- `
  --traffic-file .\output\traffic-raw-1777044642169.json `
  --auth-bundle  .\output\auth-bundle-1777044642169.json `
  --scope-file   .\examples\scope.23andme.yaml `
  --target       https://you.23andme.com `
  --target-scope-ids a1b2c3d4e5f6789a
```

### Verdicts

- **`confirmed`** — swap response contains the target id or strong identity-hint.
- **`likely`** — 2xx, same JSON shape, meaningful PII/signal load (manual review).
- **`blocked`** — 401 / 403 / 404 (includes “no access” and **stale/broken replay auth** when baseline is also 401).
- **`public`** — same body as baseline (non-personalised / public data).
- **`inconclusive`** — rate-limits, redirects, 5xx, etc.

Console output includes a **baseline health** line, e.g. *Baseline probes: N/M returned HTTP 2xx* and a **swap status** histogram. If baseline is 0/M, refresh the auth bundle and retry.

**Outputs:** `./output/cross-account-replay-<ts>.json`, `bounty-report-<ts>.md`, **`bounty-report-<ts>.html`** (self-contained, copy-to-clipboard curls, field-level diff when applicable).

### Full pipeline (`recon:full` or `--mode full`)

Wires **traffic + bundle A + (bundle B or `--target-scope-ids`)** through detection, cross-account replay, and report generation in one go:

```bash
npm run recon:full -- \
  --traffic-file-a  ./output/traffic-raw-A.json \
  --auth-bundle-a   ./output/auth-bundle-A.json \
  --auth-bundle-b   ./output/auth-bundle-B.json \
  --scope-file      ./examples/scope.23andme.yaml
```

Or:

```bash
node bin/apirecon.mjs --mode full --traffic-file-a ... --auth-bundle-a ... --target-scope-ids OTHER_ID --scope-file ./examples/scope.23andme.yaml
```

### 23andMe: Chrome profile + OAuth

The tool **waits for `you.23andme.com`** after login by default. Close regular Chrome, then:

```bash
npm run recon:browser -- --target https://you.23andme.com --scope-file ./examples/scope.23andme.yaml --use-chrome-profile
```

Optional: `--chrome-user-data "C:\Users\YOU\AppData\Local\Google\Chrome\User Data"`, `--chrome-profile-dir Default`. Env: `APIRECON_CHROME_USER_DATA`, `APIRECON_CHROME_PROFILE_DIR`, `APIRECON_LOGIN_TIMEOUT_MS`. Use `--no-wait-for-you-app` only if you intend to start from `auth.23andme.com`.

The crawler **does not** re-enter signup/login on `auth.23andme.com` or fill credentials there by default; complete login until you are on **`you.23andme.com`**.

## Relationship to graphqlai

1. Use **apirecon** to find probable **GraphQL** URLs and REST patterns (`recon-graphql-*.json`, traffic analysis).
2. Feed those URLs and schema work into **graphqlai** per its `docs/REAL-TARGET-TESTING.md` (or project docs).

## Responsible use

See **`SECURITY.md`**. Only test systems you are authorized to test.
