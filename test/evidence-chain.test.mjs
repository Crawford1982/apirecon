import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sensitivityScore, buildEvidenceChain, deriveSeverity } from '../src/recon/evidence-chain.mjs';

describe('sensitivityScore', () => {
  it('critical keys score 4', () => {
    assert.equal(sensitivityScore('ssn', '123-45-6789'), 4);
    assert.equal(sensitivityScore('raw_genotype', 'ATCG...'), 4);
  });

  it('high keys score 3', () => {
    assert.equal(sensitivityScore('email', 'user@example.com'), 3);
    assert.equal(sensitivityScore('dob', '1990-01-15'), 3);
    assert.equal(sensitivityScore('haplogroup', 'H2a2a'), 3);
  });

  it('medium keys score 2', () => {
    assert.equal(sensitivityScore('user_id', 'abc123'), 2);
    assert.equal(sensitivityScore('profile_id', '999'), 2);
  });

  it('email pattern in value bumps score even for opaque key', () => {
    const s = sensitivityScore('data', 'alice@example.com');
    assert.ok(s >= 3, `expected >= 3, got ${s}`);
  });

  it('plain irrelevant key + value scores 0', () => {
    assert.equal(sensitivityScore('count', '42'), 0);
  });
});

describe('buildEvidenceChain', () => {
  const ownResult = {
    status: 200,
    body: {
      user: { id: 'aaa', email: 'alice@example.com', name: 'Alice', dob: '1985-03-12' },
    },
  };
  const swapResult = {
    status: 200,
    body: {
      user: { id: 'bbb', email: 'bob@example.com', name: 'Bob', dob: '1990-07-22' },
    },
  };

  it('detects changed email, name, dob, id', () => {
    const chain = buildEvidenceChain(ownResult, swapResult);
    const changedKeys = chain.changedFields.map((f) => f.key);
    assert.ok(changedKeys.includes('email'), 'email should be in changedFields');
    assert.ok(changedKeys.includes('dob'), 'dob should be in changedFields');
    assert.ok(changedKeys.includes('id'), 'id should be in changedFields');
  });

  it('sensitiveLeaks only contains sensitivity >= 2', () => {
    const chain = buildEvidenceChain(ownResult, swapResult);
    assert.ok(chain.sensitiveLeaks.every((f) => f.sensitivity >= 2));
  });

  it('evidenceScore is positive for high-sensitivity change', () => {
    const chain = buildEvidenceChain(ownResult, swapResult);
    assert.ok(chain.evidenceScore > 0, `expected > 0, got ${chain.evidenceScore}`);
  });

  it('identity hint in swap body boosts evidence score', () => {
    const chain = buildEvidenceChain(ownResult, swapResult, { swapHints: ['bbb'] });
    assert.ok(chain.evidenceScore >= 25, `expected >= 25, got ${chain.evidenceScore}`);
  });

  it('identical bodies produce zero changedFields and empty sensitiveLeaks', () => {
    const body = { x: 1, y: 'hello' };
    const chain = buildEvidenceChain({ body }, { body });
    assert.equal(chain.changedFields.length, 0);
    assert.equal(chain.sensitiveLeaks.length, 0);
    assert.equal(chain.evidenceScore, 0);
  });

  it('handles null/missing bodies gracefully', () => {
    const chain = buildEvidenceChain({}, {});
    assert.equal(chain.changedFields.length, 0);
    assert.equal(chain.evidenceScore, 0);
  });
});

describe('deriveSeverity', () => {
  it('inconclusive verdict → Informational', () => {
    const s = deriveSeverity('inconclusive', null, 5);
    assert.equal(s.label, 'Informational');
    assert.equal(s.cvss, 0);
  });

  it('confirmed + critical field → Critical', () => {
    const chain = { sensitiveLeaks: [{ sensitivity: 4 }], evidenceScore: 80 };
    const s = deriveSeverity('confirmed', chain, 10);
    assert.equal(s.label, 'Critical');
    assert.ok(s.cvss >= 9);
  });

  it('confirmed + high field (sensitivity=3, evidence>=50) → Critical', () => {
    const chain = { sensitiveLeaks: [{ sensitivity: 3 }], evidenceScore: 55 };
    const s = deriveSeverity('confirmed', chain, 10);
    assert.equal(s.label, 'Critical');
  });

  it('likely + medium sensitivity → at least Medium', () => {
    const chain = { sensitiveLeaks: [{ sensitivity: 2 }], evidenceScore: 20 };
    const s = deriveSeverity('likely', chain, 8);
    assert.ok(['Medium', 'High', 'Critical'].includes(s.label));
  });

  it('likely + no sensitive fields → Low', () => {
    const chain = { sensitiveLeaks: [], evidenceScore: 0 };
    const s = deriveSeverity('likely', chain, 3);
    assert.equal(s.label, 'Low');
  });
});
