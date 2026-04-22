import test from 'node:test';
import assert from 'node:assert';
import { writeFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { loadScope } from '../src/safety/scope.mjs';

test('scope allows host + path prefix', () => {
  const f = join(tmpdir(), `apirecon-scope-${Date.now()}.yaml`);
  writeFileSync(
    f,
    `allowHosts:\n  - api.example.com\npathPrefixes:\n  - /v1\n`,
    'utf8',
  );
  try {
    const s = loadScope(f, 'https://api.example.com/v1/x');
    assert.strictEqual(s.isAllowed('https://api.example.com/v1/users'), true);
    assert.strictEqual(s.isAllowed('https://evil.com/v1/users'), false);
  } finally {
    unlinkSync(f);
  }
});
