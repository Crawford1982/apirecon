import test from 'node:test';
import assert from 'node:assert';

import { RateGovernor } from '../src/recon/rate-governor.mjs';

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

test('RateGovernor spaces requests per host based on maxRps', async () => {
  const gov = new RateGovernor({ maxRps: 10 });
  const start = Date.now();
  await gov.acquire('https://a.example.com/1');
  await gov.acquire('https://a.example.com/2');
  await gov.acquire('https://a.example.com/3');
  const elapsed = Date.now() - start;
  assert.ok(elapsed >= 200, `expected ≥200ms for 3 reqs at 10rps (got ${elapsed})`);
});

test('RateGovernor halves rps and schedules cooldown on 429', () => {
  const gov = new RateGovernor({ maxRps: 8, minRps: 0.5 });
  gov.state('https://a.example.com/1'); // prime
  const r1 = gov.report('https://a.example.com/1', { status: 429, retryAfter: null });
  assert.ok(r1.backedOffMs >= 1000);
  assert.strictEqual(r1.newRps, 4);
  const r2 = gov.report('https://a.example.com/2', { status: 429, retryAfter: null });
  assert.ok(r2.backedOffMs >= 2000);
  assert.strictEqual(r2.newRps, 2);
});

test('RateGovernor respects Retry-After seconds header', () => {
  const gov = new RateGovernor({ maxRps: 8 });
  const r = gov.report('https://a.example.com/1', { status: 429, retryAfter: '5' });
  assert.ok(r.backedOffMs >= 5000);
});

test('RateGovernor restores rps on consecutive 2xx hits', () => {
  const gov = new RateGovernor({ maxRps: 10, minRps: 1, increaseEvery: 3, increaseBy: 1 });
  const url = 'https://a.example.com/ok';
  gov.report(url, { status: 429 });
  assert.strictEqual(gov.state(url).s.rps, 5);
  for (let i = 0; i < 3; i++) gov.report(url, { status: 200 });
  assert.strictEqual(gov.state(url).s.rps, 6);
});

test('RateGovernor tracks hosts independently', async () => {
  const gov = new RateGovernor({ maxRps: 10 });
  gov.report('https://a.example.com/x', { status: 429, retryAfter: '1' });
  gov.report('https://b.example.com/y', { status: 200 });
  assert.ok(gov.state('https://a.example.com/x').s.rps < 10);
  assert.strictEqual(gov.state('https://b.example.com/y').s.rps, 10);
});
