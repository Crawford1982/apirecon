import test from 'node:test';
import assert from 'node:assert';

import {
  classifyValue,
  isIdName,
  isPaginationKey,
  isResourceWord,
  isScopeWord,
  looksLikeWord,
  normKey,
} from '../src/recon/id-shape.mjs';

test('normKey normalises separators and case', () => {
  assert.strictEqual(normKey('page-size'), 'pagesize');
  assert.strictEqual(normKey('page_size'), 'pagesize');
  assert.strictEqual(normKey('pageSize'), 'pagesize');
  assert.strictEqual(normKey('Page.Size'), 'pagesize');
});

test('isPaginationKey accepts common variants', () => {
  for (const k of ['page', 'page-size', 'page_size', 'pageSize', 'per_page', 'limit', 'offset', 'cursor', 'sort']) {
    assert.ok(isPaginationKey(k), `expected pagination: ${k}`);
  }
  assert.strictEqual(isPaginationKey('user_id'), false);
});

test('isIdName identifies common ID-carrying parameter names', () => {
  for (const k of ['id', 'user_id', 'profileId', 'account_id', 'kit_id', 'subscription_id']) {
    assert.ok(isIdName(k), `expected id-name: ${k}`);
  }
});

test('isScopeWord picks up path-scope nouns', () => {
  for (const w of ['p', 'profile', 'users', 'accounts', 'orders', 'relatives', 'organizations']) {
    assert.ok(isScopeWord(w), `expected scope word: ${w}`);
  }
  assert.strictEqual(isScopeWord('home'), false);
});

test('isResourceWord rejects common resource tokens', () => {
  for (const w of ['notifications', 'metadata', 'app-metadata', 'dashboard', 'question_stream_item']) {
    assert.ok(isResourceWord(w), `expected resource word: ${w}`);
  }
});

test('looksLikeWord recognises English-ish resource names', () => {
  assert.ok(looksLikeWord('recommended_surveys'));
  assert.ok(looksLikeWord('all_questions_dashboard'));
  assert.ok(!looksLikeWord('c03abce18b5d5ddb'));
  assert.ok(!looksLikeWord('deadbeefdeadbeef'));
});

test('classifyValue rejects pure resource-name tokens', () => {
  assert.strictEqual(classifyValue('notifications'), null);
  assert.strictEqual(classifyValue('dashboard'), null);
  assert.strictEqual(classifyValue('question_stream_item'), null);
  assert.strictEqual(classifyValue('all_questions_data_for_dashboard'), null);
});

test('classifyValue recognises numeric IDs with size-based risk', () => {
  const short = classifyValue('7');
  const long = classifyValue('1234567890');
  assert.strictEqual(short?.shape, 'numeric-short');
  assert.strictEqual(long?.shape, 'numeric-long');
  assert.ok(long.risk >= short.risk);
});

test('classifyValue recognises uuid and hex shapes', () => {
  assert.strictEqual(classifyValue('550e8400-e29b-41d4-a716-446655440000')?.shape, 'uuid');
  assert.strictEqual(classifyValue('deadbeef')?.shape, 'hex-8');
  assert.strictEqual(classifyValue('deadbeefdeadbeef')?.shape, 'hex-16');
  assert.strictEqual(classifyValue('deadbeefdeadbeefdeadbeefdeadbeef')?.shape, 'hex-32');
});

test('classifyValue rejects tokens containing URL delimiters', () => {
  assert.strictEqual(classifyValue('/something/weird'), null);
  assert.strictEqual(classifyValue('a?b=c'), null);
});

test('classifyValue rejects short alphabetic tokens', () => {
  assert.strictEqual(classifyValue('ok'), null);
  assert.strictEqual(classifyValue('data'), null);
  assert.strictEqual(classifyValue('v1'), null);
});
