import test from 'node:test';
import assert from 'node:assert';

import { isDestructiveAction } from '../src/recon/auto-navigator.mjs';

test('log out / sign out are destructive', () => {
  assert.strictEqual(isDestructiveAction({ text: 'Log out' }).destructive, true);
  assert.strictEqual(isDestructiveAction({ text: 'Sign Out' }).destructive, true);
  assert.strictEqual(isDestructiveAction({ aria: 'Sign out of account' }).destructive, true);
});

test('delete / remove / cancel subscription are destructive', () => {
  assert.strictEqual(isDestructiveAction({ text: 'Delete account' }).destructive, true);
  assert.strictEqual(isDestructiveAction({ text: 'Remove relative' }).destructive, true);
  assert.strictEqual(isDestructiveAction({ text: 'Cancel Subscription' }).destructive, true);
});

test('checkout / purchase / buy are destructive', () => {
  assert.strictEqual(isDestructiveAction({ text: 'Buy now' }).destructive, true);
  assert.strictEqual(isDestructiveAction({ text: 'Place order' }).destructive, true);
  assert.strictEqual(isDestructiveAction({ text: 'Confirm purchase' }).destructive, true);
});

test('destructive hrefs are flagged regardless of text', () => {
  assert.strictEqual(
    isDestructiveAction({ text: 'Open', href: '/account/delete' }).destructive,
    true,
  );
  assert.strictEqual(
    isDestructiveAction({ text: 'Click me', href: '/logout' }).destructive,
    true,
  );
});

test('benign actions are allowed', () => {
  assert.strictEqual(isDestructiveAction({ text: 'View Relatives' }).destructive, false);
  assert.strictEqual(isDestructiveAction({ text: 'Show more' }).destructive, false);
  assert.strictEqual(
    isDestructiveAction({ text: 'Load more', href: '/dna/relatives' }).destructive,
    false,
  );
  assert.strictEqual(isDestructiveAction({ text: 'Next page' }).destructive, false);
});

test('extra user-supplied destructive patterns apply', () => {
  const extra = { text: [/\btransfer\s*funds\b/i] };
  assert.strictEqual(
    isDestructiveAction({ text: 'Transfer Funds' }, extra).destructive,
    true,
  );
  assert.strictEqual(
    isDestructiveAction({ text: 'Open wallet' }, extra).destructive,
    false,
  );
});
