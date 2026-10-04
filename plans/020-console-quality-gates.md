# 020 — Bring the operator console inside the quality gates

## Problem

`dashboard/` is 3,231 lines of operator-facing code:

| File | Lines |
|---|---|
| `dashboard/index.html` | 1,555 |
| `dashboard/app.js` | 1,534 |
| `dashboard/style.css` | 142 |

None of it is covered by anything:

- **No tests.** `scripts/verify_all.sh` runs `pytest` per Python service and the
  stdlib `experiments/tests`. It never touches `dashboard/`.
- **No lint.** Ruff is the only configured linter and it does not read
  JavaScript or HTML.
- **No type checking.**
- **Not in `compose.yaml`.** The nine services there are `postgres`, `backend`,
  `gateway`, `collector`, `falco-events-init`, `telemetry`, `responder`,
  `scanner`, `falco`. The console is absent, so it is never built, never
  health-checked, and never started by `make up`.
- **Not served by the gateway.** `gateway/nginx.conf` has a single
  `location /` that proxies everything to `backend:8000`. The console is only
  reachable through `scripts/serve_dashboard.py`, a stdlib `http.server` dev
  proxy on `127.0.0.1:3000` that is documented nowhere in the `Makefile`.

The result: the single component a human uses to authorise destructive action
is the least verified part of the system.

## Approach

1. **Add a console test suite.** Pure-function extraction first: the parts of
   `app.js` that transform API payloads into view state (score decomposition,
   reachability funnel, process-chain assembly, filter predicates) move into
   small testable modules under `dashboard/src/`, then get covered by Node's
   built-in `node:test` runner so no new dependency manager is required. `node`
   is already present on the host.
2. **Add a static console gate** to `scripts/verify_all.sh`: HTML parses, every
   `x-show` tab id referenced in `index.html` exists in `app.js`'s state, every
   `fetch()` path in `app.js` corresponds to a path in the backend's OpenAPI
   schema, and no external origin is referenced (shared with plan 010).
   The OpenAPI cross-check catches the class of defect where a console panel
   silently 404s after a backend route rename.
3. **Add the console to `compose.yaml`** as a static-asset service behind the
   gateway, with a healthcheck, `read_only: true`, `no-new-privileges`, and
   `cap_drop: ALL` to match the posture of the existing services. Add a
   `location /console/` to `gateway/nginx.conf`. The dev proxy stays for local
   iteration but stops being the only way to run the console.
4. **Split the monoliths.** `index.html` becomes a shell plus per-tab partials;
   `app.js` becomes an Alpine root plus the extracted modules. No behaviour
   change — this is the prerequisite that makes 040 reviewable.

## Gates

- `make verify-static` green, including the new console static gate.
- `make verify-unit` green, including the new `node:test` suite.
- `docker compose config --quiet` green with the console service added.
- Console reachable through the gateway, not only through the dev proxy.

## STOP conditions

- The split in step 4 is mechanical. If a module boundary would require
  changing what a panel displays, stop and defer it to plan 040.
