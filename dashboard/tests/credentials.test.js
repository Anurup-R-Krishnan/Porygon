// node --test 'dashboard/tests/*.test.js'   (or: make verify-unit)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createCredentialStore,
  LEGACY_KEYS,
  OPERATOR_TOKEN_TTL_MS,
} = require('../src/credentials.js');

function memoryStorage() {
  const data = new Map();
  return {
    data,
    getItem: (k) => (data.has(k) ? data.get(k) : null),
    setItem: (k, v) => { data.set(k, String(v)); },
    removeItem: (k) => { data.delete(k); },
  };
}

function throwingStorage() {
  const fail = () => { throw new Error('SecurityError: storage disabled'); };
  return { getItem: fail, setItem: fail, removeItem: fail };
}

function fixture() {
  let clock = 1_000_000;
  const session = memoryStorage();
  const persistent = memoryStorage();
  const store = createCredentialStore({ session, persistent, now: () => clock });
  return { store, session, persistent, advance: (ms) => { clock += ms; } };
}

test('a stored credential is written to session storage only', () => {
  const { store, session, persistent } = fixture();
  store.set('operator', 'tok-123', OPERATOR_TOKEN_TTL_MS);
  assert.equal(store.get('operator'), 'tok-123');
  assert.equal(persistent.data.size, 0, 'nothing may reach persistent storage');
  assert.equal(session.data.size, 1);
});

test('values are trimmed and an empty value clears the credential', () => {
  const { store } = fixture();
  store.set('operator', '  tok  ', OPERATOR_TOKEN_TTL_MS);
  assert.equal(store.get('operator'), 'tok');
  store.set('operator', '   ', OPERATOR_TOKEN_TTL_MS);
  assert.equal(store.get('operator'), '');
});

test('an idle-expiring credential disappears after its TTL', () => {
  const { store, session, advance } = fixture();
  store.set('operator', 'tok', 1000);
  advance(999);
  assert.equal(store.get('operator'), 'tok');
  advance(1);
  assert.equal(store.get('operator'), '');
  assert.equal(session.data.size, 0, 'an expired entry is removed, not just hidden');
});

test('touch slides the expiry forward from the time of use', () => {
  const { store, advance } = fixture();
  store.set('operator', 'tok', 1000);
  advance(900);
  store.touch('operator');
  advance(900);
  assert.equal(store.get('operator'), 'tok', 'should survive 1800ms of activity');
  advance(100);
  assert.equal(store.get('operator'), '');
});

test('a credential with no TTL never expires within the session', () => {
  const { store, advance } = fixture();
  store.set('aiKey', 'sk-abc', null);
  advance(365 * 24 * 60 * 60 * 1000);
  assert.equal(store.get('aiKey'), 'sk-abc');
  assert.equal(store.expiresAt('aiKey'), null);
  store.touch('aiKey');
  assert.equal(store.expiresAt('aiKey'), null, 'touch must not invent a TTL');
});

test('expiresAt reports the current deadline', () => {
  const { store } = fixture();
  store.set('operator', 'tok', 5000);
  assert.equal(store.expiresAt('operator'), 1_005_000);
  assert.equal(store.expiresAt('missing'), null);
});

test('migrateLegacy moves a persisted credential off disk', () => {
  const { store, persistent } = fixture();
  persistent.setItem(LEGACY_KEYS.operator, 'old-tok');
  assert.equal(store.migrateLegacy('operator', LEGACY_KEYS.operator, OPERATOR_TOKEN_TTL_MS), true);
  assert.equal(store.get('operator'), 'old-tok');
  assert.equal(persistent.getItem(LEGACY_KEYS.operator), null);
});

test('migrateLegacy never overwrites a newer session value but still deletes the old copy', () => {
  const { store, persistent } = fixture();
  store.set('operator', 'new-tok', OPERATOR_TOKEN_TTL_MS);
  persistent.setItem(LEGACY_KEYS.operator, 'stale-tok');
  store.migrateLegacy('operator', LEGACY_KEYS.operator, OPERATOR_TOKEN_TTL_MS);
  assert.equal(store.get('operator'), 'new-tok');
  assert.equal(persistent.getItem(LEGACY_KEYS.operator), null);
});

test('migrateLegacy is a no-op when nothing was persisted', () => {
  const { store } = fixture();
  assert.equal(store.migrateLegacy('aiKey', LEGACY_KEYS.aiKey, null), false);
  assert.equal(store.get('aiKey'), '');
});

test('a corrupt entry is treated as absent and removed', () => {
  const { store, session } = fixture();
  session.setItem('porygon.credential.operator', '{not json');
  assert.equal(store.get('operator'), '');
  session.setItem('porygon.credential.operator', JSON.stringify({ value: 42 }));
  assert.equal(store.get('operator'), '');
  assert.equal(session.data.size, 0);
});

test('throwing storage degrades to nothing stored instead of crashing the console', () => {
  const store = createCredentialStore({
    session: throwingStorage(),
    persistent: throwingStorage(),
  });
  assert.doesNotThrow(() => store.set('operator', 'tok', 1000));
  assert.equal(store.get('operator'), '');
  assert.doesNotThrow(() => store.touch('operator'));
  assert.doesNotThrow(() => store.clear('operator'));
  assert.equal(store.migrateLegacy('operator', LEGACY_KEYS.operator, 1000), false);
});

test('a store with no storage at all is inert', () => {
  const store = createCredentialStore({});
  store.set('operator', 'tok', 1000);
  assert.equal(store.get('operator'), '');
});
