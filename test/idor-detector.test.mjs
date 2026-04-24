import test from 'node:test';
import assert from 'node:assert';

import { EndpointInventory } from '../src/recon/endpoint-inventory.mjs';
import { IdorDetector } from '../src/recon/idor-detector.mjs';

function jsonRequest(url, overrides = {}) {
  return {
    type: 'request',
    url,
    method: 'GET',
    status: 200,
    resourceType: 'xhr',
    responseHeaders: { 'content-type': 'application/json; charset=utf-8' },
    responseBody: { ok: true },
    ...overrides,
  };
}

test('IDOR path segment: /posts/1 (terminal)', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://jsonplaceholder.typicode.com/posts/1'),
  ]);
  const c = IdorDetector.find(inv);
  const hit = c.find((x) => x.path === '/posts/1' && x.idValue === '1' && x.idorSource === 'path');
  assert.ok(hit, 'expected terminal path finding for /posts/1');
});

test('IDOR query param: user_id on path without numeric segment', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://api.example.com/v1/profile?user_id=7'),
  ]);
  const c = IdorDetector.find(inv);
  const hit = c.find((x) => x.path === '/v1/profile' && x.queryParam === 'user_id' && x.idValue === '7');
  assert.ok(hit, 'expected query-param candidate');
  assert.strictEqual(hit.idorSource, 'query');
  const urls = hit.testSuggestion?.testUrls || [];
  assert.ok(urls.some((u) => u.includes('user_id=8')), 'should suggest incremented id');
});

test('pagination query keys ignored (page, limit, page-size, per_page, pageSize)', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://api.example.com/items?page=2&limit=10'),
    jsonRequest('https://api.example.com/items2?page-size=10&per_page=20'),
    jsonRequest('https://api.example.com/items3?pageSize=15'),
  ]);
  const c = IdorDetector.find(inv);
  assert.strictEqual(c.length, 0, 'pagination-only URLs must produce 0 candidates');
});

test('scope-parent IDOR: /p/<hex16>/... recognised and promoted', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://you.23andme.com/p/c03abce18b5d5ddb/notifications/?page-size=10'),
    jsonRequest('https://you.23andme.com/p/c03abce18b5d5ddb/health/all_reports/'),
    jsonRequest('https://you.23andme.com/p/c03abce18b5d5ddb/dna/relatives/'),
  ]);
  const c = IdorDetector.find(inv);
  assert.ok(c.length >= 3, 'expected one scope finding per unique endpoint');

  const scope = c.find(
    (x) => x.scopeWord === 'p' && x.idValue === 'c03abce18b5d5ddb' && x.idorSource === 'path',
  );
  assert.ok(scope, 'expected scope finding with scopeWord=p');
  assert.ok(scope.idorRisk >= 7, `scope risk should be high; got ${scope.idorRisk}`);
  assert.ok(scope.scopeKey, 'scope finding must have scopeKey');
  assert.strictEqual(scope.pathTemplate.includes('{scope_id}'), true);

  const groups = IdorDetector.groupByScope(c);
  const real = groups.filter((g) => g.scopeKey !== '__orphan__');
  assert.strictEqual(real.length, 1, 'all three endpoints belong to ONE scope group');
  assert.strictEqual(real[0].findings.length, 3);
});

test('resource-name tokens are NOT classified as IDs', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://you.23andme.com/p/c03abce18b5d5ddb/research/question_stream_item/'),
    jsonRequest('https://you.23andme.com/p/c03abce18b5d5ddb/content-resource-ajax/?url=%2Fapi%2Fok'),
  ]);
  const c = IdorDetector.find(inv);
  // Must NOT produce a "terminal: question_stream_item" or "terminal: content-resource-ajax" finding.
  const badTerminal = c.filter(
    (x) =>
      x.idorSource === 'path' &&
      (x.idValue === 'question_stream_item' || x.idValue === 'content-resource-ajax'),
  );
  assert.strictEqual(badTerminal.length, 0, 'resource-name tokens must not be treated as IDs');
});

test('nested-url IDs inside proxy-style ?url= values are detected', () => {
  const inv = EndpointInventory.build([
    jsonRequest(
      'https://you.23andme.com/p/c03abce18b5d5ddb/content-resource-ajax/?url=%2Fapi%2Fv3%2Frecommended%2F%3Fprofile_id%3Ddeadbeefcafebabe%26location%3Dme_dash',
    ),
  ]);
  const c = IdorDetector.find(inv);
  const nested = c.find((x) => x.idorSource === 'nested-url' && x.idValue === 'deadbeefcafebabe');
  assert.ok(nested, 'expected nested-url finding for embedded profile_id');
  assert.ok(nested.queryParam?.includes('profile_id'), 'queryParam label should reference inner key');
  assert.ok(
    (nested.testSuggestion?.testUrls || []).some((u) => u.includes('profile_id%3D0')) ||
      (nested.testSuggestion?.testUrls || []).some((u) => u.includes('profile_id=0')),
    'should suggest a mutated nested url',
  );
});

test('hex-16 (23andMe-style opaque profile id) scored higher than generic 8-hex', () => {
  const invShort = EndpointInventory.build([
    jsonRequest('https://api.example.com/foo/deadbeef'),
  ]);
  const invLong = EndpointInventory.build([
    jsonRequest('https://api.example.com/foo/deadbeefdeadbeef'),
  ]);
  const shortHit = IdorDetector.find(invShort).find((x) => x.idValue === 'deadbeef');
  const longHit = IdorDetector.find(invLong).find((x) => x.idValue === 'deadbeefdeadbeef');
  assert.ok(shortHit && longHit);
  assert.ok(longHit.idorRisk > shortHit.idorRisk, '16-hex should score higher than 8-hex');
});

test('write methods (PATCH/PUT/DELETE) score higher than GET on same shape', () => {
  const invGet = EndpointInventory.build([
    jsonRequest('https://api.example.com/users/123', { method: 'GET' }),
  ]);
  const invDel = EndpointInventory.build([
    jsonRequest('https://api.example.com/users/123', { method: 'DELETE' }),
  ]);
  const g = IdorDetector.find(invGet).find((x) => x.idValue === '123');
  const d = IdorDetector.find(invDel).find((x) => x.idValue === '123');
  assert.ok(g && d);
  assert.ok(d.idorRisk > g.idorRisk, 'DELETE should outrank GET at same shape');
});

test('pathTemplate replaces scope_id and id segments consistently', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://api.example.com/p/deadbeefdeadbeef/reports/42'),
  ]);
  const c = IdorDetector.find(inv);
  assert.ok(c.length >= 1);
  // Every finding on this endpoint should describe the same template.
  for (const f of c) {
    assert.match(f.pathTemplate, /\{scope_id\}.*\{id\}$|\{id\}$|\{scope_id\}/);
  }
});

test('each finding carries human-readable riskReasons', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://api.example.com/p/deadbeefdeadbeef/health/raw_data'),
  ]);
  const c = IdorDetector.find(inv);
  assert.ok(c.length >= 1);
  assert.ok(Array.isArray(c[0].riskReasons) && c[0].riskReasons.length >= 2);
  assert.ok(c[0].riskReasons.some((r) => r.includes('shape=')));
});
