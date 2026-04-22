# apirecon

Browser-driven **REST/JSON API recon** companion to [**graphqlai**](https://github.com/Crawford1982/graphqlai): capture traffic from Chromium, summarize endpoints, emit rough **OpenAPI** hints and **GraphQL placement** notes, then optionally run **slow, sequential IDOR replay** probes when you supply auth.

Forked from the workflow and YAML scope conventions used in `graphqlai`, but intentionally **broader than GraphQL-only** tooling.

## Quick start

```bash
npm install
npx playwright install chromium

# Capture (interactive — press ENTER when finished clicking around)
# Use a JSON resource URL so the page actually issues JSON API traffic (the home page is HTML-only).
npm run recon:browser -- --target https://jsonplaceholder.typicode.com/posts/1 --scope-file ./examples/scope.jsonplaceholder.yaml --headless

# Analyze an existing capture
npm run recon:analyze -- --traffic-file ./output/traffic-raw-<ts>.json --scope-file ./examples/scope.example.yaml

# Replay ID probes (authorized targets only — uses RECON_AUTH_TOKEN or --auth)
npm run recon:replay -- --traffic-file ./output/traffic-raw-<ts>.json --scope-file ./examples/scope.example.yaml --auth "$RECON_AUTH_TOKEN"
```

Artifacts land in `./output/` by default: `traffic-raw-*.json`, `recon-report-*.json`, `recon-openapi-*.json`, `recon-graphql-*.json`, and replay `idor-replay-*.json`. Each replay result includes **`replayCurl`** (bash-safe `curl` one-liner matching the probe, including `Authorization` when you passed `--auth` / `RECON_AUTH_TOKEN`).

## Relationship to graphqlai

1. Use **apirecon** to find probable **GraphQL HTTP** URLs (`recon-graphql-*.json`).
2. Feed those URLs plus schema/introspection into **graphqlai** per its `docs/REAL-TARGET-TESTING.md`.

## Responsible use

See **`SECURITY.md`**.
