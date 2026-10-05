// node --test 'dashboard/tests/*.test.js'   (or: make verify-unit)
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  createPoller,
  backoffDelay,
  healthFor,
  HEALTHY,
  DEGRADED,
  OFFLINE,
} = require('../src/poller.js');

// Deterministic timers: nothing runs until the test advances the clock.
function fakeClock() {
  let now = 0;
  let nextId = 1;
  const timers = new Map();
  return {
    setTimeout(fn, ms) {
      const id = nextId++;
      timers.set(id, { fn, at: now + ms });
      return id;
    },
    clearTimeout(id) { timers.delete(id); },
    pending() { return timers.size; },
    async advance(ms) {
      // Settle anything the test resolved before advancing, so a run that just
      // finished has rescheduled itself before due timers are collected.
      await flush();
      const target = now + ms;
      for (;;) {
        let due = null;
        for (const [id, t] of timers) {
          if (t.at <= target && (due === null || t.at < due[1].at)) due = [id, t];
        }
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].fn();
        await flush();
      }
      now = target;
      await flush();
    },
  };
}

async function flush() {
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
}

function fakeVisibility(hidden = false) {
  let listener = () => {};
  return {
    isHidden: () => hidden,
    onChange: (fn) => { listener = fn; },
    set(value) { hidden = value; listener(); },
  };
}

function fakeAbort() {
  const controllers = [];
  return {
    controllers,
    create() {
      const controller = { signal: { aborted: false }, abort() { this.signal.aborted = true; } };
      controllers.push(controller);
      return controller;
    },
  };
}

function setup({ tasks, hidden = false, ...rest }) {
  const clock = fakeClock();
  const visibility = fakeVisibility(hidden);
  const abort = fakeAbort();
  const healthEvents = [];
  const poller = createPoller({
    tasks,
    visibility,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
    random: () => 0.5, // jitter factor exactly 1.0
    createAbortController: abort.create,
    onHealthChange: (health, detail) => healthEvents.push({ health, ...detail }),
    ...rest,
  });
  return { clock, visibility, abort, healthEvents, poller };
}

function counter(result = true) {
  const task = { calls: 0, signals: [] };
  task.run = (signal) => { task.calls += 1; task.signals.push(signal); return Promise.resolve(result); };
  return task;
}

test('backoff doubles per failure, caps, and leaves the healthy interval alone', () => {
  const half = () => 0.5;
  assert.equal(backoffDelay(3000, 0, 60000, half), 3000);
  assert.equal(backoffDelay(3000, 1, 60000, half), 6000);
  assert.equal(backoffDelay(3000, 3, 60000, half), 24000);
  assert.equal(backoffDelay(3000, 10, 60000, half), 60000);
});

test('backoff jitter stays within +/-20% and never exceeds the cap', () => {
  assert.equal(backoffDelay(3000, 1, 60000, () => 0), 4800);
  assert.equal(backoffDelay(3000, 1, 60000, () => 1), 7200);
  assert.equal(backoffDelay(3000, 9, 60000, () => 1), 60000);
});

test('health: offline from a global failure streak, degraded from any one task', () => {
  assert.equal(healthFor({}, 0, 2, 6), HEALTHY);
  assert.equal(healthFor({ a: 0, b: 1 }, 1, 2, 6), HEALTHY);
  assert.equal(healthFor({ a: 2, b: 0 }, 0, 2, 6), DEGRADED, 'one task failing twice');
  assert.equal(healthFor({ a: 9, b: 0 }, 1, 2, 6), DEGRADED, 'a long-broken endpoint is not an outage');
  assert.equal(healthFor({ a: 1, b: 1 }, 6, 2, 6), OFFLINE, 'six failures in a row anywhere');
});

test('each task runs on its own interval', async () => {
  const fast = counter();
  const slow = counter();
  const { clock, poller } = setup({
    tasks: [
      { name: 'fast', intervalMs: 3000, run: fast.run },
      { name: 'slow', intervalMs: 10000, run: slow.run },
    ],
  });
  poller.start(false);
  await clock.advance(30000);
  assert.equal(fast.calls, 10);
  assert.equal(slow.calls, 3);
});

test('start(true) runs every task immediately', async () => {
  const task = counter();
  const { clock, poller } = setup({ tasks: [{ name: 't', intervalMs: 3000, run: task.run }] });
  poller.start(true);
  await clock.advance(0);
  assert.equal(task.calls, 1);
});

test('a slow run is never overlapped by the next tick', async () => {
  let resolveRun;
  let calls = 0;
  const run = () => { calls += 1; return new Promise((r) => { resolveRun = r; }); };
  const { clock, poller } = setup({
    tasks: [{ name: 't', intervalMs: 3000, run }],
    timeoutMs: 60000,
  });
  poller.start(true);
  await clock.advance(20000);
  assert.equal(calls, 1, 'must not start again while the first run is in flight');
  resolveRun(true);
  await clock.advance(3000);
  assert.equal(calls, 2);
});

test('nothing runs while the page is hidden, and returning refreshes at once', async () => {
  const task = counter();
  const { clock, visibility, poller } = setup({
    tasks: [{ name: 't', intervalMs: 3000, run: task.run }],
  });
  poller.start(true);
  await clock.advance(0);
  assert.equal(task.calls, 1);

  visibility.set(true);
  await clock.advance(120000);
  assert.equal(task.calls, 1, 'a hidden tab must issue no requests');
  assert.equal(clock.pending(), 0, 'and must hold no timers');

  visibility.set(false);
  await clock.advance(0);
  assert.equal(task.calls, 2, 'becoming visible refreshes immediately');
  await clock.advance(3000);
  assert.equal(task.calls, 3, 'and resumes the normal interval');
});

test('a page that starts hidden does not poll until shown', async () => {
  const task = counter();
  const { clock, visibility, poller } = setup({
    tasks: [{ name: 't', intervalMs: 3000, run: task.run }],
    hidden: true,
  });
  poller.start(true);
  await clock.advance(60000);
  assert.equal(task.calls, 0);
  visibility.set(false);
  await clock.advance(0);
  assert.equal(task.calls, 1);
});

test('a run that exceeds the timeout is aborted and counted as a failure', async () => {
  const { clock, abort, poller } = setup({
    tasks: [{ name: 't', intervalMs: 3000, run: () => new Promise(() => {}) }],
    timeoutMs: 5000,
  });
  poller.start(true);
  await clock.advance(4999);
  assert.equal(abort.controllers[0].signal.aborted, false);
  await clock.advance(1);
  assert.equal(abort.controllers[0].signal.aborted, true);
});

test('each run receives its abort signal', async () => {
  const task = counter();
  const { clock, abort, poller } = setup({ tasks: [{ name: 't', intervalMs: 3000, run: task.run }] });
  poller.start(true);
  await clock.advance(0);
  assert.equal(task.signals[0], abort.controllers[0].signal);
});

test('failures back off, and one success restores the normal interval', async () => {
  let succeed = false;
  let calls = 0;
  const run = () => { calls += 1; return Promise.resolve(succeed); };
  const { clock, poller } = setup({
    tasks: [{ name: 't', intervalMs: 3000, run }],
  });
  poller.start(true);
  await clock.advance(0);
  assert.equal(poller.snapshot().t.nextDelayMs, 6000);
  await clock.advance(6000);
  assert.equal(poller.snapshot().t.nextDelayMs, 12000);
  succeed = true;
  await clock.advance(12000);
  assert.equal(poller.snapshot().t.failures, 0);
  assert.equal(poller.snapshot().t.nextDelayMs, 3000);
  assert.equal(calls, 3);
});

test('a thrown or rejected run counts as a failure without stopping the chain', async () => {
  let mode = 'throw';
  const run = () => {
    if (mode === 'throw') throw new Error('sync boom');
    return Promise.reject(new Error('async boom'));
  };
  const { clock, poller } = setup({ tasks: [{ name: 't', intervalMs: 1000, run }] });
  poller.start(true);
  await clock.advance(0);
  assert.equal(poller.snapshot().t.failures, 1);
  mode = 'reject';
  await clock.advance(2000);
  assert.equal(poller.snapshot().t.failures, 2);
  assert.equal(poller.snapshot().t.scheduled, true);
});

test('health changes are reported once per transition, naming the failing tasks', async () => {
  let up = false;
  const run = () => Promise.resolve(up);
  const { clock, healthEvents, poller } = setup({
    tasks: [
      { name: 'a', label: 'container inventory', intervalMs: 1000, run },
      { name: 'b', label: 'incidents', intervalMs: 1000, run },
    ],
    degradedAfter: 2,
    offlineAfter: 3,
    maxBackoffMs: 2000,
  });
  poller.start(true);
  await clock.advance(30000);
  assert.deepEqual(healthEvents.map((e) => e.health), [OFFLINE],
    'a sustained outage is reported once, and nothing more while it lasts');
  assert.deepEqual(healthEvents[0].failing.sort(), ['container inventory', 'incidents']);

  up = true;
  await clock.advance(5000);
  assert.deepEqual(healthEvents.map((e) => e.health), [OFFLINE, HEALTHY],
    'recovery must go straight to healthy, not pass through a spurious degraded');
  assert.equal(healthEvents.at(-1).previous, OFFLINE);
});

test('an outage is detected in seconds even when a slow task has not run yet', async () => {
  let up = true;
  const run = () => Promise.resolve(up);
  // The console's real shape: four 3 s tasks and a 60 s one, default thresholds.
  const { clock, poller } = setup({
    tasks: [
      { name: 'containers', intervalMs: 3000, run },
      { name: 'events', intervalMs: 3000, run },
      { name: 'incidents', intervalMs: 3000, run },
      { name: 'scores', intervalMs: 3000, run },
      { name: 'scans', intervalMs: 60000, run },
    ],
  });
  poller.start(true);
  await clock.advance(1000);
  up = false;
  await clock.advance(10000);
  assert.equal(poller.health(), OFFLINE, 'must not wait for the 60 s task to fail');
});

test('recovery from offline refreshes every task at once instead of waiting out backoff', async () => {
  let up = false;
  const calls = { a: 0, b: 0 };
  const make = (name, intervalMs) => ({
    name,
    intervalMs,
    run: () => { calls[name] += 1; return Promise.resolve(up); },
  });
  const { clock, poller } = setup({
    tasks: [make('a', 1000), make('b', 7000)],
    degradedAfter: 1,
    offlineAfter: 2,
    maxBackoffMs: 60000,
  });
  poller.start(true);
  await clock.advance(30000);
  assert.equal(poller.health(), OFFLINE);
  const bBefore = calls.b;
  assert.ok(poller.snapshot().b.nextDelayMs >= 28000, 'b is deep in backoff');

  up = true;
  // Step until `a`'s backoff timer fires and the poller recovers. Steps are
  // far shorter than b's 7 s interval, so any extra b run is the recovery.
  let waited = 0;
  while (poller.health() !== HEALTHY) {
    await clock.advance(100);
    waited += 100;
    assert.ok(waited <= 60000, 'never recovered');
  }
  assert.equal(calls.b, bBefore + 1, 'b refreshed at the moment of recovery');
  assert.equal(poller.snapshot().b.nextDelayMs, 7000, 'and is back on its normal interval');
});

test('a genuinely broken endpoint returns to degraded after the backend recovers', async () => {
  let backendUp = false;
  const good = () => Promise.resolve(backendUp);
  const bad = () => Promise.resolve(false);
  const { clock, healthEvents, poller } = setup({
    tasks: [
      { name: 'good', intervalMs: 1000, run: good },
      { name: 'bad', label: 'image scans', intervalMs: 1000, run: bad },
    ],
    degradedAfter: 2,
    offlineAfter: 3,
    maxBackoffMs: 2000,
  });
  poller.start(true);
  await clock.advance(30000);
  assert.equal(poller.health(), OFFLINE);
  backendUp = true;
  await clock.advance(30000);
  assert.deepEqual(healthEvents.map((e) => e.health), [OFFLINE, HEALTHY, DEGRADED]);
  assert.deepEqual(healthEvents.at(-1).failing, ['image scans']);
});

test('one failing endpoint degrades without declaring the backend offline', async () => {
  const good = () => Promise.resolve(true);
  const bad = () => Promise.resolve(false);
  const { clock, healthEvents, poller } = setup({
    tasks: [
      { name: 'good', intervalMs: 1000, run: good },
      { name: 'bad', label: 'image scans', intervalMs: 1000, run: bad },
    ],
    degradedAfter: 2,
    offlineAfter: 3,
    maxBackoffMs: 2000,
  });
  poller.start(true);
  await clock.advance(30000);
  assert.deepEqual(healthEvents.map((e) => e.health), [DEGRADED]);
  assert.deepEqual(healthEvents[0].failing, ['image scans']);
});

test('runNow refreshes idle tasks and does not duplicate one in flight', async () => {
  let resolveSlow;
  let slowCalls = 0;
  const slow = () => { slowCalls += 1; return new Promise((r) => { resolveSlow = r; }); };
  const fast = counter();
  const { clock, poller } = setup({
    tasks: [
      { name: 'slow', intervalMs: 3000, run: slow },
      { name: 'fast', intervalMs: 3000, run: fast.run },
    ],
    timeoutMs: 60000,
  });
  poller.start(true);
  await clock.advance(0);
  poller.runNow();
  await clock.advance(0);
  assert.equal(slowCalls, 1);
  assert.equal(fast.calls, 2);
  resolveSlow(true);
});

test('stop cancels every timer and prevents further runs', async () => {
  const task = counter();
  const { clock, poller } = setup({ tasks: [{ name: 't', intervalMs: 1000, run: task.run }] });
  poller.start(true);
  await clock.advance(0);
  poller.stop();
  assert.equal(clock.pending(), 0);
  await clock.advance(10000);
  assert.equal(task.calls, 1);
});
