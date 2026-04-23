import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert';

import { chromium } from 'playwright';

import { AutoNavigator } from '../src/recon/auto-navigator.mjs';

/**
 * Spins up a minimal multi-route site so AutoNavigator can exercise same-origin link discovery,
 * buttons, fetch(), and scroll — without contacting external targets.
 */
function startFixtureServer() {
  const server = http.createServer((req, res) => {
    const host = req.headers.host || '127.0.0.1';
    const u = new URL(req.url || '/', `http://${host}`);

    if (u.pathname === '/api/ping') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ pong: true }));
      return;
    }

    const label = u.pathname === '/' ? 'home' : u.pathname.slice(1).replace(/\//g, '-');
    const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${label}</title></head>
<body style="min-height:240vh">
  <nav>
    <a href="/page-a">Page A</a>
    <a href="/page-b">Page B</a>
    <a href="/">Home</a>
  </nav>
  <h1>${label}</h1>
  <button type="button" id="ping">Fetch API</button>
  <button type="button" id="more">Load more</button>
  <p style="margin-top:120vh">Bottom marker for scroll</p>
  <script>
    document.getElementById('ping').addEventListener('click', () => {
      fetch('/api/ping').then(function (r) { return r.json(); }).then(console.log);
    });
  </script>
</body></html>`;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  });

  return new Promise((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve(server));
    server.on('error', reject);
  });
}

test('AutoNavigator explores fixture site (integration)', async () => {
  /** @type {import('node:http').Server} */
  const server = /** @type {any} */ (await startFixtureServer());
  const { port } = /** @type {import('net').AddressInfo} */ (server.address());
  const base = `http://127.0.0.1:${port}`;

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  let totalReq = 0;
  page.on('requestfinished', () => {
    totalReq++;
  });

  await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: 15000 });

  const nav = new AutoNavigator(page, {
    verbose: false,
    maxRoutes: 6,
    maxTotalClicks: 80,
    maxClicksPerRoute: 25,
    maxDurationMs: 90_000,
    maxPaginationSteps: 2,
    clickDelay: 50,
    networkIdleMs: 400,
    getTrafficStats: () => ({ total: totalReq, inScope: totalReq, jsonApi: 0 }),
  });

  await nav.run();
  await browser.close();
  server.close();

  assert.ok(nav.stats.routesVisited >= 2, `expected ≥2 routes, got ${nav.stats.routesVisited}`);
  assert.ok(nav.stats.clicks >= 1, `expected ≥1 click, got ${nav.stats.clicks}`);
});
