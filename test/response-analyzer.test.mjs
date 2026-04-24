import test from 'node:test';
import assert from 'node:assert';

import {
  analyzeBody,
  diffAnalyses,
  walkStrings,
} from '../src/recon/response-analyzer.mjs';

test('walkStrings collects key-annotated strings and JSON paths', () => {
  const { strings, paths } = walkStrings({
    name: 'Alice',
    meta: { ids: [1, 'two'] },
  });
  assert.ok(strings.some((s) => s.key === 'name' && s.value === 'Alice'));
  assert.ok(paths.some((p) => p.includes('meta.ids')));
});

test('analyzeBody flags PII in typical profile response', () => {
  const a = analyzeBody({
    first_name: 'Alice',
    last_name: 'Nguyen',
    email: 'alice@example.com',
    phone: '+1 415-555-0100',
    dob: '1990-05-17',
    address: {
      street: '123 Main Street',
      city: 'Palo Alto',
      zip: '94301',
    },
  });

  assert.ok(a.signals.email);
  assert.ok(a.signals.name);
  assert.ok(a.signals.phone);
  assert.ok(a.signals.dob || a.signals['dob-pattern']);
  assert.ok(a.signals.street);
  assert.ok(a.leakScore >= 30, `expected leakScore ≥ 30, got ${a.leakScore}`);
});

test('analyzeBody picks up rsIDs and haplogroups in genetic responses', () => {
  const a = analyzeBody({
    haplogroup: { y: 'R1b1a1a2', mt: 'H2a2a' },
    variants: [{ rsid: 'rs4988235', genotype: 'AA' }, { rsid: 'rs1801133' }],
  });
  assert.ok(a.signals.rsid && a.signals.rsid.count >= 2);
  assert.ok(a.signals['haplogroup-y'] || a.signals['haplogroup-mt']);
});

test('analyzeBody identity-hint hits boost leakScore significantly', () => {
  const baseline = analyzeBody({ id: 'abc123', notes: 'hello' });
  const withHint = analyzeBody(
    { id: 'abc123', notes: 'hello', owner: 'c03abce18b5d5ddb' },
    { identityHints: ['c03abce18b5d5ddb'] },
  );
  assert.ok(withHint.leakScore > baseline.leakScore);
  assert.ok(withHint.identityHintHits.includes('c03abce18b5d5ddb'));
});

test('diffAnalyses flags same-shape-data-returned for similar responses', () => {
  const a = analyzeBody({ user: { id: 1, name: 'Alice', email: 'a@x.com' } });
  const b = analyzeBody({ user: { id: 2, name: 'Bob', email: 'b@x.com' } });
  const d = diffAnalyses(a, b);
  assert.strictEqual(d.verdict, 'same-shape-data-returned');
  assert.ok(d.jaccard > 0.6);
});

test('diffAnalyses flags empty-or-error when replay body is tiny', () => {
  const a = analyzeBody({ user: { id: 1, name: 'Alice', email: 'a@x.com' } });
  const b = analyzeBody({ error: 'forbidden' });
  const d = diffAnalyses(a, b);
  assert.strictEqual(d.verdict, 'empty-or-error');
});

test('analyzeBody does not treat long numeric IDs as credit-card-like', () => {
  const a = analyzeBody({ id: '1234567890123456' });
  assert.ok(!a.signals['cc-like'], 'pure-digit ID should not match cc-like');
});
