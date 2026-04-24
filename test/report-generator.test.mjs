import test from 'node:test';
import assert from 'node:assert';

import { renderBountyReport } from '../src/recon/report-generator.mjs';

function finding() {
  return {
    method: 'GET',
    idorSource: 'path',
    path: '/p/aaaa/dna/relatives/',
    pathTemplate: '/p/{scope_id}/dna/relatives/',
    idType: 'hex-16',
    riskReasons: ['shape=hex-16', 'scope-parent', 'method=GET'],
  };
}

test('renderBountyReport produces markdown header and executive summary', () => {
  const md = renderBountyReport(
    {
      meta: {},
      stats: { confirmed: 1, likely: 0, blocked: 0, public: 0, inconclusive: 0 },
      confirmed: [
        {
          finding: finding(),
          ownId: 'aaaaaaaaaaaaaaaa',
          swapId: 'bbbbbbbbbbbbbbbb',
          probes: {
            own: { url: 'https://you.23andme.com/p/aaaa/dna/relatives/', status: 200, body: { user: { name: 'Alice', email: 'a@x.com' } } },
            swap: { url: 'https://you.23andme.com/p/bbbb/dna/relatives/', status: 200, body: { user: { name: 'Bob', email: 'b@x.com' } } },
          },
          analyses: {
            own: { leakScore: 20, signals: {}, identityHintHits: [] },
            swap: { leakScore: 22, signals: { email: { count: 1, samples: ['b@x.com'] } }, identityHintHits: ['bbbbbbbbbbbbbbbb'] },
          },
          diff: { jaccard: 0.9, sharedPaths: 9, totalPaths: 10, sizeRatio: 1.0, leakScoreDelta: 2 },
          verdict: { kind: 'confirmed', reason: 'target id present in swap body' },
          curl: {
            own: "curl -sS 'https://you.23andme.com/p/aaaa/...'",
            swap: "curl -sS 'https://you.23andme.com/p/bbbb/...'",
          },
        },
      ],
      likely: [],
      all: [],
    },
    { target: 'https://you.23andme.com', toolVersion: 'apirecon-test' },
  );

  assert.match(md, /^# IDOR findings — https:\/\/you\.23andme\.com/m);
  assert.match(md, /Confirmed cross-tenant reads:\*\* 1/);
  assert.match(md, /Severity:/);
  assert.match(md, /Verdict:/);
  assert.match(md, /target id present in swap body/);
  assert.match(md, /email.*b@x\.com/);
  assert.match(md, /curl -sS/);
});

test('renderBountyReport returns a bare header when there are no reportable findings', () => {
  const md = renderBountyReport(
    {
      meta: {},
      stats: { confirmed: 0, likely: 0, blocked: 3, public: 1, inconclusive: 1 },
      confirmed: [],
      likely: [],
      all: [],
    },
    { target: 'https://api.example.com' },
  );
  assert.match(md, /No confirmed or likely cross-tenant reads/);
  assert.ok(!md.includes('### Reproduction'));
});
