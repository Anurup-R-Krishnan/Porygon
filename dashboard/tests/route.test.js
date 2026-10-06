// node --test 'dashboard/tests/*.test.js'   (or: make verify-unit)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseRoute, formatRoute, TABS } = require('../src/route.js');

const ID = '0f2c9a1e-7b3d-4c55-9e10-2a6b8c4d1f00';

test('every tab round-trips through the hash', () => {
  for (const tab of TABS) {
    assert.deepEqual(parseRoute(formatRoute({ tab })), { tab, incidentId: null });
  }
});

test('a pipeline route carries its incident', () => {
  assert.equal(formatRoute({ tab: 'pipeline', incidentId: ID }), `#pipeline/${ID}`);
  assert.deepEqual(parseRoute(`#pipeline/${ID}`), { tab: 'pipeline', incidentId: ID });
});

test('an incident id is only honoured on the pipeline tab', () => {
  assert.deepEqual(parseRoute(`#telemetry/${ID}`), { tab: 'telemetry', incidentId: null });
  assert.equal(formatRoute({ tab: 'incidents', incidentId: ID }), '#incidents');
});

test('unknown or empty routes fall back to the overview', () => {
  for (const hash of ['', '#', '#nope', '#PIPELINE', '#__proto__', undefined, null]) {
    assert.deepEqual(parseRoute(hash), { tab: 'overview', incidentId: null }, String(hash));
  }
});

test('an incident id that does not look like one is dropped, never passed on', () => {
  // These would otherwise be interpolated into /api/v1/incidents/<id>.
  for (const bad of ['../../internal/v1', 'x', 'abc%2F..', 'a b c d e f g h', `${ID}/extra`, '-leadingdash12']) {
    assert.equal(parseRoute(`#pipeline/${bad}`).incidentId, null, bad);
  }
});

test('formatRoute refuses a malformed incident id rather than encoding it', () => {
  assert.equal(formatRoute({ tab: 'pipeline', incidentId: '../x' }), '#pipeline');
  assert.equal(formatRoute({ tab: 'bogus' }), '#overview');
});
