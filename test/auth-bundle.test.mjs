import test from 'node:test';
import assert from 'node:assert';

import {
  cookieHeaderFor,
  extractAuthBundle,
  resolveAuthHeaders,
} from '../src/recon/auth-bundle.mjs';

/** Minimal stub that mimics {@link import('playwright').BrowserContext}. */
function fakeContext(cookies) {
  return { cookies: async () => cookies };
}

function req(url, headers = {}) {
  return {
    type: 'request',
    url,
    method: 'GET',
    status: 200,
    headers,
    responseHeaders: { 'content-type': 'application/json' },
  };
}

test('extractAuthBundle captures cookies, auth headers, and identities', async () => {
  const ctx = fakeContext([
    {
      name: 'sessionid',
      value: 'abc123',
      domain: 'you.23andme.com',
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
    },
  ]);

  const traffic = [
    req('https://you.23andme.com/p/c03abce18b5d5ddb/notifications/', {
      authorization: 'Bearer eyJ.xxx',
      'x-csrftoken': 'tok1',
      'x-requested-with': 'XMLHttpRequest',
    }),
    req('https://you.23andme.com/p/c03abce18b5d5ddb/dna/relatives/'),
  ];

  const bundle = await extractAuthBundle({
    context: ctx,
    target: 'https://you.23andme.com',
    traffic,
  });

  assert.strictEqual(bundle.cookies.length, 1);
  assert.strictEqual(bundle.cookies[0].name, 'sessionid');

  const hh = bundle.hostHeaders['you.23andme.com'];
  assert.ok(hh);
  assert.strictEqual(hh.authorization, 'Bearer eyJ.xxx');
  assert.strictEqual(hh['x-csrftoken'], 'tok1');

  const profile = bundle.identities.find(
    (i) => i.kind === 'profile_id' && i.value === 'c03abce18b5d5ddb',
  );
  assert.ok(profile, 'expected to infer profile_id from captured path');
  assert.strictEqual(profile.hits, 2);
});

test('cookieHeaderFor respects domain, path, and secure', () => {
  const bundle = {
    cookies: [
      { name: 'a', value: '1', domain: 'you.23andme.com', path: '/', secure: true },
      { name: 'b', value: '2', domain: '.23andme.com', path: '/', secure: false },
      { name: 'wrong', value: 'x', domain: 'example.com', path: '/' },
      { name: 'prefix', value: 'p', domain: 'you.23andme.com', path: '/api/' },
    ],
  };

  const header = cookieHeaderFor(bundle, 'https://you.23andme.com/p/abc/');
  const parts = header.split('; ');
  assert.ok(parts.includes('a=1'), 'include exact domain https cookie');
  assert.ok(parts.includes('b=2'), 'include wildcard parent-domain cookie');
  assert.ok(!parts.some((p) => p.startsWith('wrong=')), 'exclude other-domain cookie');
  assert.ok(!parts.some((p) => p.startsWith('prefix=')), 'exclude prefix-mismatched cookie');

  const http = cookieHeaderFor(bundle, 'http://you.23andme.com/');
  assert.ok(!http.includes('a=1'), 'secure cookie not sent over http');
});

test('resolveAuthHeaders merges host headers + cookies, preserves overrides', () => {
  const bundle = {
    cookies: [
      { name: 's', value: 'x', domain: 'you.23andme.com', path: '/', secure: true },
    ],
    hostHeaders: {
      'you.23andme.com': {
        authorization: 'Bearer old',
        'x-csrftoken': 'tok',
      },
    },
  };

  const merged = resolveAuthHeaders(bundle, 'https://you.23andme.com/x', {
    authorization: 'Bearer override',
  });
  assert.strictEqual(merged.authorization, 'Bearer override', 'caller override wins');
  assert.strictEqual(merged['x-csrftoken'], 'tok');
  assert.strictEqual(merged.Cookie, 's=x');
});
