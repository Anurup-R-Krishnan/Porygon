// node --test 'dashboard/tests/*.test.js'   (or: make verify-unit)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  KERNEL_FRESH_MS,
  formatTimestamp,
  formatShortTimestamp,
  formatAge,
  kernelTelemetryState,
} = require('../src/format.js');

const UTC = { locale: 'en-GB', timeZone: 'UTC' };
const NOW = Date.parse('2026-10-05T09:41:30Z');

test('a timestamp from today shows the time only', () => {
  assert.equal(formatTimestamp('2026-10-05T09:15:12Z', NOW, UTC), '09:15:12');
});

test('a timestamp from an earlier day keeps its date', () => {
  // The case that motivated this: an eleven-day-old event rendered as a bare
  // time looked as if it had just arrived.
  assert.equal(formatTimestamp('2026-09-24T10:45:12Z', NOW, UTC), '24 Sept 10:45:12');
});

test('a timestamp from another year includes the year', () => {
  assert.equal(formatTimestamp('2025-12-31T23:00:00Z', NOW, UTC), '31 Dec 2025 23:00:00');
});

test('"today" is decided in the display time zone, not UTC', () => {
  // 23:30 UTC on the 4th is already the 5th in Kolkata (+05:30).
  const kolkata = { locale: 'en-GB', timeZone: 'Asia/Kolkata' };
  assert.equal(formatTimestamp('2026-10-04T23:30:00Z', NOW, kolkata), '05:00:00');
  assert.equal(formatTimestamp('2026-10-04T23:30:00Z', NOW, UTC), '4 Oct 23:30:00');
});

test('missing and invalid timestamps render as a dash, not "Invalid Date"', () => {
  assert.equal(formatTimestamp(null, NOW, UTC), '—');
  assert.equal(formatTimestamp('', NOW, UTC), '—');
  assert.equal(formatTimestamp('not-a-date', NOW, UTC), '—');
  assert.equal(formatShortTimestamp(undefined, NOW, UTC), '—');
});

test('millisecond precision is available for the telemetry table', () => {
  const ms = { ...UTC, milliseconds: true };
  assert.equal(formatTimestamp('2026-10-05T09:15:12.295Z', NOW, ms), '09:15:12.295');
  assert.equal(formatTimestamp('2026-09-24T10:45:12.007Z', NOW, ms), '24 Sept 10:45:12.007');
  assert.equal(formatTimestamp('bad', NOW, ms), '—', 'no ".NaN" suffix on a bad value');
});

test('short timestamps for chart axes keep the date when it differs', () => {
  assert.equal(formatShortTimestamp('2026-10-05T09:15:12Z', NOW, UTC), '09:15');
  assert.equal(formatShortTimestamp('2026-09-24T10:45:12Z', NOW, UTC), '24 Sept 10:45');
});

test('ages are compact and saturate sensibly', () => {
  assert.equal(formatAge(0), '0s');
  assert.equal(formatAge(59_999), '59s');
  assert.equal(formatAge(60_000), '1m');
  assert.equal(formatAge(14 * 60_000 + 5_000), '14m');
  assert.equal(formatAge(3 * 3_600_000 + 7 * 60_000), '3h 7m');
  assert.equal(formatAge((10 * 24 + 22) * 3_600_000 + 56 * 60_000), '10d 22h');
  assert.equal(formatAge(-5_000), '0s', 'clock skew must not show a negative age');
  assert.equal(formatAge(NaN), '—');
});

const event = (iso) => ({ occurred_at: iso });

test('kernel telemetry is live when the newest event is recent', () => {
  const result = kernelTelemetryState({
    apiHealth: 'healthy',
    eventsSource: 'process',
    events: [event('2026-10-05T09:41:00Z'), event('2026-10-05T09:30:00Z')],
    now: NOW,
  });
  assert.equal(result.state, 'live');
  assert.equal(result.label, 'eBPF live');
});

test('kernel telemetry is stale once the newest event passes the threshold', () => {
  const result = kernelTelemetryState({
    apiHealth: 'healthy',
    eventsSource: 'process',
    events: [event('2026-09-24T10:45:12Z')],
    now: NOW,
  });
  assert.equal(result.state, 'stale');
  assert.equal(result.label, 'eBPF stale · 10d 22h');
});

test('freshness uses the newest event regardless of list order', () => {
  const result = kernelTelemetryState({
    apiHealth: 'healthy',
    eventsSource: 'process',
    events: [event('2026-09-24T10:45:12Z'), event('2026-10-05T09:41:20Z'), event('garbage')],
    now: NOW,
  });
  assert.equal(result.state, 'live');
});

test('the threshold boundary is inclusive', () => {
  const at = new Date(NOW - KERNEL_FRESH_MS).toISOString();
  const after = new Date(NOW - KERNEL_FRESH_MS - 1000).toISOString();
  const base = { apiHealth: 'healthy', eventsSource: 'process', now: NOW };
  assert.equal(kernelTelemetryState({ ...base, events: [event(at)] }).state, 'live');
  assert.equal(kernelTelemetryState({ ...base, events: [event(after)] }).state, 'stale');
});

test('no kernel events is reported as such, not as live', () => {
  const result = kernelTelemetryState({
    apiHealth: 'healthy', eventsSource: 'process', events: [], now: NOW,
  });
  assert.equal(result.state, 'none');
});

test('docker lifecycle events cannot vouch for kernel telemetry', () => {
  // fetchEvents falls back to /api/v1/events when process events fail; those
  // are Docker lifecycle events and say nothing about the eBPF sensor.
  const result = kernelTelemetryState({
    apiHealth: 'healthy',
    eventsSource: 'docker',
    events: [event('2026-10-05T09:41:20Z')],
    now: NOW,
  });
  assert.equal(result.state, 'unknown');
});

test('an unreachable API makes kernel telemetry unknown, never live', () => {
  const result = kernelTelemetryState({
    apiHealth: 'offline',
    eventsSource: 'process',
    events: [event('2026-10-05T09:41:20Z')],
    now: NOW,
  });
  assert.equal(result.state, 'unknown');
  assert.equal(result.label, 'API unreachable');
});

test('every state carries a short label that fits the nav pill', () => {
  const base = { now: NOW };
  const cases = [
    { ...base, apiHealth: 'offline', eventsSource: 'process', events: [] },
    { ...base, apiHealth: 'healthy', eventsSource: 'docker', events: [] },
    { ...base, apiHealth: 'healthy', eventsSource: 'process', events: [] },
    { ...base, apiHealth: 'healthy', eventsSource: 'process', events: [event('2026-10-05T09:41:20Z')] },
    { ...base, apiHealth: 'healthy', eventsSource: 'process', events: [event('2026-09-24T10:45:12Z')] },
  ];
  for (const input of cases) {
    const { shortLabel } = kernelTelemetryState(input);
    assert.ok(shortLabel, 'missing shortLabel');
    // "eBPF Active", the label this pill was sized for, is 11 characters.
    assert.ok(shortLabel.length <= 12, `${shortLabel} is too wide for the nav`);
  }
});
