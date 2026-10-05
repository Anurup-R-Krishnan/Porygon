// Time formatting and kernel-telemetry freshness for the operator console.
//
// Every data timestamp in the console was rendered with toLocaleTimeString(),
// which drops the date. Against the live stack the newest process event was
// ten days and twenty-three hours old, and the Telemetry tab showed it as
// "16:15:12" -- indistinguishable from an event that arrived a minute ago.
// formatTimestamp keeps the bare time only for events from today.
//
// The nav also showed a hardcoded, pulsing "eBPF Active" regardless of state,
// including while Falco was crashlooping and while the backend was
// unreachable. kernelTelemetryState derives what can actually be known: how
// old the newest kernel event is.
//
// Loaded as a plain script by index.html (window.PorygonFormat) and as
// CommonJS by the node:test suite in dashboard/tests/.
(function (root, factory) {
  'use strict';
  var api = factory();
  if (typeof module === 'object' && module.exports) {
    module.exports = api;
  } else {
    root.PorygonFormat = api;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // A working Falco sensor on this stack sees a steady execve stream -- the
  // compose healthchecks alone exec a process in several containers every
  // 10 s -- so two minutes without a single kernel event means the pipeline
  // has stalled, not that the host went quiet.
  var KERNEL_FRESH_MS = 2 * 60 * 1000;

  function toDate(value) {
    if (value === null || value === undefined || value === '') return null;
    var date = value instanceof Date ? value : new Date(value);
    return isNaN(date.getTime()) ? null : date;
  }

  function parts(date, options) {
    var tz = options && options.timeZone;
    var fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit',
    });
    return fmt.format(date);
  }

  function sameDay(a, b, options) {
    return parts(a, options) === parts(b, options);
  }

  function sameYear(a, b, options) {
    return parts(a, options).slice(0, 4) === parts(b, options).slice(0, 4);
  }

  // options: { locale, timeZone, milliseconds } -- locale and timeZone default
  // to the browser's own and exist so the tests are deterministic.
  function formatTimestamp(value, nowMs, options) {
    var date = toDate(value);
    if (!date) return '—';
    var now = new Date(typeof nowMs === 'number' ? nowMs : Date.now());
    var locale = options && options.locale;
    var tz = options && options.timeZone;
    var timeOptions = { timeZone: tz };
    if (options && options.milliseconds) {
      timeOptions.hour = '2-digit';
      timeOptions.minute = '2-digit';
      timeOptions.second = '2-digit';
      timeOptions.fractionalSecondDigits = 3;
    }
    var time = date.toLocaleTimeString(locale, timeOptions);
    if (sameDay(date, now, options)) return time;
    var dateOptions = { timeZone: tz, month: 'short', day: 'numeric' };
    if (!sameYear(date, now, options)) dateOptions.year = 'numeric';
    return date.toLocaleDateString(locale, dateOptions) + ' ' + time;
  }

  // Compact form for chart axes: HH:MM today, date plus HH:MM otherwise.
  function formatShortTimestamp(value, nowMs, options) {
    var date = toDate(value);
    if (!date) return '—';
    var now = new Date(typeof nowMs === 'number' ? nowMs : Date.now());
    var locale = options && options.locale;
    var tz = options && options.timeZone;
    var time = date.toLocaleTimeString(locale, {
      timeZone: tz, hour: '2-digit', minute: '2-digit',
    });
    if (sameDay(date, now, options)) return time;
    return date.toLocaleDateString(locale, { timeZone: tz, month: 'short', day: 'numeric' }) + ' ' + time;
  }

  function formatAge(ms) {
    if (typeof ms !== 'number' || !isFinite(ms)) return '—';
    if (ms < 0) ms = 0; // clock skew between browser and sensor
    var seconds = Math.floor(ms / 1000);
    if (seconds < 60) return seconds + 's';
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return minutes + 'm';
    var hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + 'h ' + (minutes % 60) + 'm';
    var days = Math.floor(hours / 24);
    return days + 'd ' + (hours % 24) + 'h';
  }

  // State of the kernel telemetry pipeline as far as the console can know it.
  //   live    newest kernel event is within KERNEL_FRESH_MS
  //   stale   kernel events exist but the newest is older than that
  //   none    no kernel events returned at all
  //   unknown the API is unreachable, or only Docker lifecycle events (not
  //           kernel events) were available, so nothing can be said
  function kernelTelemetryState(input) {
    var apiHealth = input.apiHealth;
    var source = input.eventsSource;
    var events = input.events || [];
    var now = typeof input.now === 'number' ? input.now : Date.now();
    var freshMs = input.freshMs || KERNEL_FRESH_MS;

    if (apiHealth === 'offline') {
      return { state: 'unknown', label: 'API unreachable', shortLabel: 'API down', detail: 'Kernel telemetry state unknown: the backend is unreachable.' };
    }
    if (source !== 'process') {
      return { state: 'unknown', label: 'eBPF unknown', shortLabel: 'eBPF unknown', detail: 'Process events are unavailable, so kernel telemetry freshness cannot be determined.' };
    }
    var newest = null;
    for (var i = 0; i < events.length; i += 1) {
      var date = toDate(events[i] && events[i].occurred_at);
      if (date && (newest === null || date.getTime() > newest)) newest = date.getTime();
    }
    if (newest === null) {
      return { state: 'none', label: 'No eBPF events', shortLabel: 'eBPF none', detail: 'No kernel process events have been recorded.' };
    }
    var age = now - newest;
    if (age <= freshMs) {
      return { state: 'live', label: 'eBPF live', shortLabel: 'eBPF live', detail: 'Newest kernel event ' + formatAge(age) + ' ago.', ageMs: age };
    }
    return {
      state: 'stale',
      label: 'eBPF stale · ' + formatAge(age),
      // The nav pill shows this; the age is in its tooltip. The full label
      // was wide enough to push the nav's last tab out of view.
      shortLabel: 'eBPF stale',
      detail: 'No kernel process event for ' + formatAge(age) + '. Falco may be down or not delivering events.',
      ageMs: age,
    };
  }

  return {
    KERNEL_FRESH_MS: KERNEL_FRESH_MS,
    formatTimestamp: formatTimestamp,
    formatShortTimestamp: formatShortTimestamp,
    formatAge: formatAge,
    kernelTelemetryState: kernelTelemetryState,
  };
});
