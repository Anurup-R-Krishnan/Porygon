# 040 — Operator console feature depth

**Status:** 040.1, 040.2 and the truthfulness half of 040.3 done; 040.4 open.

**Corrections recorded after measuring.** Three claims below were wrong and
are kept, struck through, beside what was actually found:

- 040.1 estimated "nine-plus requests every three seconds". Measured against
  the live stack it was 46 per 30 s (~4.6 per 3 s), with anomaly scores
  double-scheduled. The defects were real -- polling while hidden, overlap,
  no backoff, a toast per failure, service health never refreshed -- but the
  load figure was an overestimate read off `refreshAllData`, which is not
  what the timers called.
- 040.2 said there was "no `prefers-reduced-motion` media query anywhere in
  `style.css`". There is one, at `style.css:133`, disabling transitions and
  animations globally. It also said the tabs were "not keyboard-operable";
  they were reachable with Tab and Enter. What was missing was the tab
  semantics and arrow-key movement.
- 040.4 said the active tab was "not reflected in the URL". The `activeTab`
  watcher already wrote `location.hash`, and init already read it.

**Found while doing this plan, and fixed:** the nav's hardcoded, pulsing
"eBPF Active" stayed green while Falco crashlooped and the newest kernel event
was 10 days 23 hours old, and every data timestamp dropped its date, so that
eleven-day-old stream read as live. See the commit "Schedule console polling
properly and stop it claiming eBPF is live".

## Problem

### 040.1 — Polling has no discipline

~~`dashboard/app.js:490-500` installs unconditional timers~~ (see corrections above):

```js
setInterval(() => { this.pollLiveTelemetry(); }, 3000);
setInterval(() => { this.fetchSystemInfo(); this.fetchAnomalyScores(); }, 10000);
```

`pollLiveTelemetry` fans out to `/api/v1/system/info`, `/services`,
`/containers?limit=100`, `/process-events?limit=40`, `/events?limit=40`,
`/anomaly-scores?limit=20`, `/incidents?limit=50`, and `/image-scans?limit=20`
— plus a per-scan detail fetch. That is nine-plus requests every three seconds,
forever, with:

- no `document.hidden` gating, so a backgrounded tab keeps hammering the API;
- no `AbortController`, so slow responses stack and can land out of order and
  overwrite newer state;
- no backoff or circuit breaker, so a backend outage becomes a tight retry loop
  that fills the terminal log with identical errors;
- no `ETag`/`If-None-Match`, so unchanged payloads are re-sent in full.

### 040.2 — Accessibility is absent

- Tabs are `x-show` divs switched by `activeTab`. There is no
  `role="tablist"`/`role="tab"`/`aria-selected`, so the primary navigation is
  invisible to assistive technology and not keyboard-operable.
- The add-rule modal (`index.html:900`) and the token/confirm modals have no
  focus trap and no focus restoration; only `@keydown.escape.window` is wired.
- ~~The console is built on heavy transitions with no
  `prefers-reduced-motion` media query anywhere in `style.css`.~~ Wrong; see
  corrections above.
- Status is encoded by colour alone in several panels (severity pills,
  reachability funnel) with no text or shape redundancy.

### 040.3 — State feedback is incomplete

Several panels render a single "empty" branch that cannot distinguish *no data
yet*, *no data matching the filter*, *request failed*, and *backend
unreachable*. An operator cannot tell a quiet system from a broken pipeline —
which, for a detection console, is the one distinction that matters most.

### 040.4 — No operator-workflow depth

Gaps that a reviewer of a runtime-security console would expect:

- No way to export an incident's evidence timeline for an external report.
- No deep-linking ~~: tab,~~ for selected container, selected incident, and
  filters. (The tab itself was already in `location.hash`.)
- No relative/absolute timestamp toggle; everything is `toLocaleTimeString()`,
  which loses the date entirely on anything older than today.
- The terminal log is capped at 120 entries with no filter, search, or
  severity level control.

## Approach

1. **A single polling scheduler** replacing the two `setInterval` calls: one
   loop that respects `document.hidden`, carries an `AbortController` per
   cycle, applies exponential backoff with jitter on failure, opens a circuit
   after repeated failures and surfaces that state in the UI, and coalesces
   identical consecutive errors in the terminal log.
2. **An ARIA tab implementation** with roving-tabindex keyboard navigation, a
   focus trap and focus restoration for every modal, a
   `prefers-reduced-motion` block that disables transitions, and text/icon
   redundancy wherever colour currently carries meaning alone.
3. **A four-state panel primitive** — loading / empty / filtered-empty / error
   — applied uniformly, with the error state naming the failed request and
   offering a retry.
4. **URL state sync** for tab, selection, and filters via `history.replaceState`,
   so a view is shareable; plus an absolute/relative timestamp toggle and an
   incident evidence export.

## Gates

- `make verify-static` and `make verify-unit` green, including the new console
  tests from plan 020 covering the scheduler's backoff and the panel-state
  selection logic.
- Keyboard-only traversal of every tab and modal, verified by capture.
- With the backend stopped, the console shows a distinguishable error state
  rather than an empty one — verified by capture.

## STOP conditions

- Depends on plan 020's module split. Do not start before it lands.
- No change to what any number means. Presentation only.
