import test from 'node:test';
import assert from 'node:assert';

import { EndpointInventory } from '../src/recon/endpoint-inventory.mjs';
import { IdorDetector } from '../src/recon/idor-detector.mjs';
import { CrossAccountReplay } from '../src/recon/cross-account-replay.mjs';

function jsonRequest(url, overrides = {}) {
  return {
    type: 'request',
    url,
    method: 'GET',
    status: 200,
    resourceType: 'xhr',
    responseHeaders: { 'content-type': 'application/json' },
    responseBody: { ok: true },
    ...overrides,
  };
}

test('IdorDetector.substituteId swaps path-scope id into template URL', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://you.23andme.com/p/c03abce18b5d5ddb/dna/relatives/?page-size=25'),
  ]);
  const [finding] = IdorDetector.find(inv).filter((f) => f.idorSource === 'path');
  assert.ok(finding);

  const swapped = IdorDetector.substituteId(finding, 'deadbeefdeadbeef');
  assert.ok(swapped, 'must produce a swapped URL');
  assert.ok(swapped.includes('/p/deadbeefdeadbeef/'));
  assert.ok(swapped.includes('page-size=25'), 'must preserve query string');
});

test('IdorDetector.substituteId swaps query-param id', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://api.example.com/v1/profile?user_id=7&view=full'),
  ]);
  const [finding] = IdorDetector.find(inv).filter((f) => f.idorSource === 'query');
  assert.ok(finding);

  const swapped = IdorDetector.substituteId(finding, '999');
  assert.ok(swapped);
  const u = new URL(swapped);
  assert.strictEqual(u.searchParams.get('user_id'), '999');
  assert.strictEqual(u.searchParams.get('view'), 'full');
});

test('CrossAccountReplay.buildQueue creates swap probes against extra scope IDs', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://you.23andme.com/p/aaaaaaaaaaaaaaaa/health/lab_results/'),
    jsonRequest('https://you.23andme.com/p/aaaaaaaaaaaaaaaa/dna/relatives/'),
  ]);
  const findings = IdorDetector.find(inv).filter((f) => f.idorSource === 'path');

  const runner = new CrossAccountReplay({
    accountA: {
      label: 'A',
      bundle: { cookies: [], hostHeaders: {} },
      scopeIds: ['aaaaaaaaaaaaaaaa'],
    },
    extraScopeIds: ['bbbbbbbbbbbbbbbb'],
    verbose: false,
  });

  const queue = runner.buildQueue(findings);
  assert.ok(queue.length >= 2, 'expected swap probe per endpoint');
  for (const q of queue) {
    assert.ok(q.probes.own.url.includes('aaaaaaaaaaaaaaaa'));
    assert.ok(q.probes.swap.url.includes('bbbbbbbbbbbbbbbb'));
    assert.strictEqual(q.probes.own.auth, 'A');
    assert.strictEqual(q.probes.swap.auth, 'A');
  }
});

test('CrossAccountReplay.buildQueue also emits reverse probes when accountB present', () => {
  const inv = EndpointInventory.build([
    jsonRequest('https://you.23andme.com/p/aaaaaaaaaaaaaaaa/health/lab_results/'),
  ]);
  const findings = IdorDetector.find(inv).filter((f) => f.idorSource === 'path');

  const runner = new CrossAccountReplay({
    accountA: { label: 'A', bundle: { cookies: [], hostHeaders: {} }, scopeIds: ['aaaaaaaaaaaaaaaa'] },
    accountB: { label: 'B', bundle: { cookies: [], hostHeaders: {} }, scopeIds: ['bbbbbbbbbbbbbbbb'] },
    verbose: false,
  });

  const queue = runner.buildQueue(findings);
  assert.ok(queue.length >= 1);
  assert.ok(queue[0].probes.reverseOwn);
  assert.ok(queue[0].probes.reverseSwap);
  assert.strictEqual(queue[0].probes.reverseOwn.auth, 'B');
  assert.strictEqual(queue[0].probes.reverseSwap.auth, 'B');
});

test('CrossAccountReplay.verdict: blocked on 401/403', () => {
  const runner = new CrossAccountReplay({
    accountA: { label: 'A', bundle: { cookies: [], hostHeaders: {} }, scopeIds: ['a'] },
    verbose: false,
  });
  const r = runner.verdict(
    { status: 200, body: { user: { id: 1, name: 'Alice', email: 'a@x.com' } } },
    { status: 403, bodyText: 'forbidden' },
    null,
    null,
    null,
    'b',
  );
  assert.strictEqual(r.kind, 'blocked');
});

test('CrossAccountReplay.verdict: confirmed when target id appears in swap body', async () => {
  const { analyzeBody } = await import('../src/recon/response-analyzer.mjs');
  const { diffAnalyses } = await import('../src/recon/response-analyzer.mjs');
  const runner = new CrossAccountReplay({
    accountA: { label: 'A', bundle: { cookies: [], hostHeaders: {} }, scopeIds: ['aaaa'] },
    verbose: false,
  });

  const ownBody = { user: { id: 'aaaa', name: 'Alice', email: 'a@x.com' } };
  const swapBody = { user: { id: 'bbbb', name: 'Bob', email: 'b@x.com' } };

  const own = analyzeBody(ownBody, { identityHints: ['aaaa'] });
  const swap = analyzeBody(swapBody, { identityHints: ['bbbb'] });
  const diff = diffAnalyses(own, swap);

  const r = runner.verdict(
    { status: 200, body: ownBody },
    { status: 200, body: swapBody },
    own,
    swap,
    diff,
    'bbbb',
  );
  assert.strictEqual(r.kind, 'confirmed');
});

test('CrossAccountReplay.verdict: public when both responses are identical', async () => {
  const { analyzeBody, diffAnalyses } = await import('../src/recon/response-analyzer.mjs');
  const runner = new CrossAccountReplay({
    accountA: { label: 'A', bundle: { cookies: [], hostHeaders: {} }, scopeIds: ['aaaa'] },
    verbose: false,
  });

  const body = { public: true, features: ['x', 'y', 'z'], note: 'same for everyone' };
  const own = analyzeBody(body);
  const swap = analyzeBody(body);
  const diff = diffAnalyses(own, swap);

  const r = runner.verdict(
    { status: 200, body },
    { status: 200, body },
    own,
    swap,
    diff,
    'bbbb',
  );
  assert.strictEqual(r.kind, 'public');
});
