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

test('IDOR path segment: /posts/1', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://jsonplaceholder.typicode.com/posts/1'),
  ]);
  const c = IdorDetector.find(inv);
  assert.ok(c.some((x) => x.path === '/posts/1' && x.idValue === '1' && x.idorSource === 'path'));
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

test('pagination query keys are ignored', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://api.example.com/items?page=2&limit=10'),
  ]);
  const c = IdorDetector.find(inv);
  assert.strictEqual(c.length, 0);
});
