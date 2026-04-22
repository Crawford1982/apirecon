import test from 'node:test';
import assert from 'node:assert';

import { IdorReplay, shellSingleQuote } from '../src/recon/idor-replay.mjs';

test('shellSingleQuote escapes single quotes for bash', () => {
  assert.strictEqual(shellSingleQuote("a'b"), '\'a\'\\\'\'b\'');
});

test('buildReplayCurl GET with Bearer auth', () => {
  const curl = IdorReplay.buildReplayCurl({
    method: 'GET',
    testUrl: 'https://api.example.com/v1/users/2',
    auth: 'eyJhbGc',
  });
  assert.ok(curl.startsWith('curl -sS '), curl);
  assert.ok(curl.includes(shellSingleQuote('https://api.example.com/v1/users/2')));
  assert.ok(curl.includes('Authorization: Bearer eyJhbGc'));
});
