# apirecon

Browser-driven **REST/JSON API recon** companion to [**graphqlai**](https://github.com/Crawford1982/graphqlai): capture traffic from Chromium, summarize endpoints, emit rough **OpenAPI** hints and **GraphQL placement** notes, then optionally run **slow, sequential IDOR replay** probes when you supply auth.

Forked from the workflow and YAML scope conventions used in `graphqlai`, but intentionally **broader than GraphQL-only** tooling.

## Quick start

```bash
npm install
npx playwright install chromium

# Capture (interactive — ENTER or `a` + ENTER runs an optional SPA auto-crawl after you log in)
# Use a JSON resource URL so the page actually issues JSON API traffic (the home page is HTML-only).
npm run recon:browser -- --target https://jsonplaceholder.typicode.com/posts/1 --scope-file ./examples/scope.jsonplaceholder.yaml --headless

# Or skip ENTER: `--auto-navigate` / `-a` waits 5s after login, then runs an SPA crawler that walks
# routes BFS-style, clicks nav/tabs/buttons, exercises forms/selects with safe values, paginates
# ("Load more" / "Next"), scrolls for lazy content, and prints a live traffic heartbeat. It skips
# destructive actions (log out, delete, remove, cancel subscription, purchase, etc.) by default.

# Analyze an existing capture
npm run recon:analyze -- --traffic-file ./output/traffic-raw-<ts>.json --scope-file ./examples/scope.example.yaml

# Replay ID probes (authorized targets only — uses RECON_AUTH_TOKEN or --auth)
npm run recon:replay -- --traffic-file ./output/traffic-raw-<ts>.json --scope-file ./examples/scope.example.yaml --auth "$RECON_AUTH_TOKEN"
```

Artifacts land in `./output/` by default: `traffic-raw-*.json`, `recon-report-*.json`, `recon-openapi-*.json`, `recon-graphql-*.json`, and replay `idor-replay-*.json`. Each replay result includes **`replayCurl`** (bash-safe `curl` one-liner matching the probe, including `Authorization` when you passed `--auth` / `RECON_AUTH_TOKEN`).

### 23andMe: Chrome profile + OAuth

For **`you.23andme.com`**, recon defaults to **waiting until the tab reaches `you.23andme.com`** (OAuth redirect dance). Close regular Chrome first, then reuse your Google session:

```bash
npm run recon:browser -- --target https://you.23andme.com --scope-file ./examples/scope.23andme.yaml --use-chrome-profile
```

Optional: `--chrome-user-data "C:\\Users\\YOU\\AppData\\Local\\Google\\Chrome\\User Data"` and `--chrome-profile-dir Default` (or `Profile 1`). Overrides: env `APIRECON_CHROME_USER_DATA`, `APIRECON_CHROME_PROFILE_DIR`. Use `--no-wait-for-you-app` only if you intentionally want to crawl from `auth.23andme.com`.

The tool never asks for Google passwords — it only opens the browser so you can finish OAuth / 2FA yourself; **`--use-chrome-profile`** makes **Sign in with Google** reuse cookies from disk when Playwright launches Chrome (`channel: 'chrome'`).

For **23andMe** targets, the auto-crawler **does not navigate back to `auth.23andme.com`** or **`/signup`** (so it won’t try to register a new account), and it **won’t fill dummy text into login/signup forms** on that host. You still must complete login yourself until the URL is **`you.23andme.com`** — otherwise the capture stays mostly auth noise.

## Relationship to graphqlai

1. Use **apirecon** to find probable **GraphQL HTTP** URLs (`recon-graphql-*.json`).
2. Feed those URLs plus schema/introspection into **graphqlai** per its `docs/REAL-TARGET-TESTING.md`.

## Responsible use

See **`SECURITY.md`**.
