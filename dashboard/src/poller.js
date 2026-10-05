// Polling scheduler for the operator console.
//
// The console used two bare setInterval loops: every 3 s it fetched
// containers, process events, incidents and anomaly scores, and every 10 s
// system info plus anomaly scores again. That meant:
//
//   - a backgrounded tab kept polling forever, roughly 90 API requests a
//     minute measured against the live stack;
//   - a slow response could still be in flight when the next tick fired, so
//     requests stacked and could land out of order;
//   - a backend outage became a tight retry loop, with three fetchers each
//     raising a toast every 3 s faster than toasts expire;
//   - service health and image scans were fetched once at load and never
//     again, so a service that died after the page opened stayed "healthy".
//
// This schedules each task as its own chain -- the next run is scheduled only
// after the previous one settles, so a task never overlaps itself -- pauses
// entirely while the page is hidden, aborts runs that exceed a timeout, backs
// off exponentially with jitter on failure, and reports a single health state
// that changes only on transitions. See plans/040-console-feature-depth.md.
//
// Loaded as a plain script by index.html (window.PorygonPoller) and as
// CommonJS by the node:test suite in dashboard/tests/.
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PorygonPoller = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var HEALTHY = 'healthy';
  var DEGRADED = 'degraded';
  var OFFLINE = 'offline';

  // Delay before a task's next run after `failures` consecutive failures.
  // Doubles per failure up to maxMs, then is jittered by +/-20% so tasks that
  // failed together (a backend restart fails them all at once) do not retry in
  // lockstep and hit the recovering backend as a burst.
  function backoffDelay(intervalMs, failures, maxMs, random) {
    var base = failures > 0
      ? Math.min(intervalMs * Math.pow(2, failures), maxMs)
      : intervalMs;
    if (failures === 0) return base;
    var jitter = 0.8 + 0.4 * random();
    return Math.round(Math.min(base * jitter, maxMs));
  }

  // Health from two signals.
  //
  // Offline: `streak` -- consecutive failed runs across ALL tasks with no
  // success anywhere in between -- has reached offlineAfter. That is the
  // signature of the backend or gateway being unreachable. It is deliberately
  // not "every task has failed N times": tasks run on different intervals, so
  // that rule would let a slow 60 s task hold the console in "degraded" for
  // minutes during a real outage. A single broken endpoint never builds a
  // streak, because the healthy tasks' successes keep resetting it.
  //
  // Degraded: some task has failed degradedAfter times running.
  function healthFor(failureCounts, streak, degradedAfter, offlineAfter) {
    if (streak >= offlineAfter) return OFFLINE;
    var anyDegraded = Object.keys(failureCounts).some(function (k) {
      return failureCounts[k] >= degradedAfter;
    });
    return anyDegraded ? DEGRADED : HEALTHY;
  }

  function createPoller(options) {
    var tasks = options.tasks || [];
    var visibility = options.visibility || {
      isHidden: function () { return false; },
      onChange: function () {},
    };
    var setTimer = options.setTimeout || setTimeout;
    var clearTimer = options.clearTimeout || clearTimeout;
    var random = options.random || Math.random;
    var maxBackoffMs = options.maxBackoffMs || 60000;
    var timeoutMs = options.timeoutMs || 15000;
    var degradedAfter = options.degradedAfter || 2;
    var offlineAfter = options.offlineAfter || 6;
    var onHealthChange = options.onHealthChange || function () {};
    var createAbortController = options.createAbortController || function () {
      return typeof AbortController === 'function' ? new AbortController() : null;
    };

    var running = false;
    var health = HEALTHY;
    var streak = 0; // consecutive failed runs across all tasks
    var state = {};
    tasks.forEach(function (task) {
      state[task.name] = { failures: 0, timer: null, inFlight: false, nextDelayMs: task.intervalMs };
    });

    function failureCounts() {
      var counts = {};
      tasks.forEach(function (task) { counts[task.name] = state[task.name].failures; });
      return counts;
    }

    // Which tasks to name in a health notice. Degraded names the tasks that
    // crossed the threshold. Offline names every task whose latest attempt
    // failed: at the moment an outage is declared most tasks have failed only
    // once, and naming just the ones that failed twice would understate it.
    function failingTasks(forHealth) {
      var threshold = forHealth === OFFLINE ? 1 : degradedAfter;
      return tasks
        .filter(function (task) { return state[task.name].failures >= threshold; })
        .map(function (task) { return task.label || task.name; });
    }

    function publishHealth() {
      var next = healthFor(failureCounts(), streak, degradedAfter, offlineAfter);
      if (next === health) return;
      var previous = health;
      health = next;
      onHealthChange(next, { previous: previous, failing: failingTasks(next) });
    }

    function schedule(task, delayMs) {
      var entry = state[task.name];
      if (entry.timer !== null) clearTimer(entry.timer);
      entry.timer = null;
      if (!running || visibility.isHidden()) return;
      entry.nextDelayMs = delayMs;
      entry.timer = setTimer(function () {
        entry.timer = null;
        execute(task);
      }, delayMs);
    }

    function execute(task) {
      var entry = state[task.name];
      if (!running || entry.inFlight || visibility.isHidden()) return;
      entry.inFlight = true;

      var controller = createAbortController();
      var timedOut = false;
      var timeout = setTimer(function () {
        timedOut = true;
        if (controller) controller.abort();
      }, timeoutMs);

      var settle = function (ok) {
        clearTimer(timeout);
        entry.inFlight = false;
        var succeeded = ok && !timedOut;

        if (succeeded && health === OFFLINE) {
          // A success while offline proves the backend is reachable again. The
          // other tasks' failure counts describe the outage that just ended,
          // not their current state: left alone, the first task to recover
          // would compute health from them and report a spurious
          // offline -> degraded -> healthy, raising a "some endpoints are
          // failing" notice at the very moment things came back. And those
          // tasks would sit out backoff timers of up to maxBackoffMs before
          // refreshing. So clear the outage and refresh everything now. An
          // endpoint that is genuinely still broken fails again and climbs
          // back to degraded on its own.
          tasks.forEach(function (other) { state[other.name].failures = 0; });
          streak = 0;
          publishHealth();
          schedule(task, task.intervalMs);
          tasks.forEach(function (other) {
            if (other === task) return;
            var otherEntry = state[other.name];
            if (otherEntry.timer !== null) clearTimer(otherEntry.timer);
            otherEntry.timer = null;
            execute(other);
          });
          return;
        }

        entry.failures = succeeded ? 0 : entry.failures + 1;
        streak = succeeded ? 0 : streak + 1;
        publishHealth();
        schedule(task, backoffDelay(task.intervalMs, entry.failures, maxBackoffMs, random));
      };

      var result;
      try {
        result = task.run(controller ? controller.signal : undefined);
      } catch (error) {
        settle(false);
        return;
      }
      Promise.resolve(result).then(
        function (value) { settle(value !== false); },
        function () { settle(false); }
      );
    }

    function runAll() {
      tasks.forEach(function (task) {
        var entry = state[task.name];
        if (entry.timer !== null) {
          clearTimer(entry.timer);
          entry.timer = null;
        }
        execute(task);
      });
    }

    visibility.onChange(function () {
      if (!running) return;
      if (visibility.isHidden()) {
        // Stop scheduling. In-flight runs finish and simply do not reschedule.
        tasks.forEach(function (task) {
          var entry = state[task.name];
          if (entry.timer !== null) clearTimer(entry.timer);
          entry.timer = null;
        });
      } else {
        // Coming back: refresh everything now rather than show data that went
        // stale while the tab was in the background.
        runAll();
      }
    });

    return {
      start: function (runImmediately) {
        if (running) return;
        running = true;
        if (runImmediately) {
          runAll();
        } else {
          tasks.forEach(function (task) { schedule(task, task.intervalMs); });
        }
      },
      stop: function () {
        running = false;
        tasks.forEach(function (task) {
          var entry = state[task.name];
          if (entry.timer !== null) clearTimer(entry.timer);
          entry.timer = null;
        });
      },
      // Manual refresh: run every idle task now; tasks already in flight are
      // left alone rather than duplicated.
      runNow: runAll,
      health: function () { return health; },
      snapshot: function () {
        var out = {};
        tasks.forEach(function (task) {
          var entry = state[task.name];
          out[task.name] = {
            failures: entry.failures,
            inFlight: entry.inFlight,
            scheduled: entry.timer !== null,
            nextDelayMs: entry.nextDelayMs,
          };
        });
        return out;
      },
    };
  }

  return {
    createPoller: createPoller,
    backoffDelay: backoffDelay,
    healthFor: healthFor,
    HEALTHY: HEALTHY,
    DEGRADED: DEGRADED,
    OFFLINE: OFFLINE,
  };
});
