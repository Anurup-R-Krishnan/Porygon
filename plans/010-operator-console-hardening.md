# 010 — Operator console supply-chain and credential hardening

**Status:** done. 010.1-010.3 landed with the vendored, hash-verified asset set,
the CSP and response headers, and `scripts/check_console_supply_chain.py`.
010.4 landed with `dashboard/src/credentials.js`: both console secrets (the
operator token and the AI provider key) moved to sessionStorage, the operator
token given a 30-minute sliding idle expiry, and existing localStorage copies
migrated and deleted on first load.

## Problem

`dashboard/` is the operator console. It holds the credential that authorises
containment — `PORYGON_OPERATOR_API_TOKEN`, sent as `X-Porygon-Operator-Token`
to `/operator/v1/*`, which the backend checks in
`backend/src/porygon_api/security.py::require_operator_token`. Approving a
recommendation through that token causes `responder/` to pause, stop, or
disconnect a live container via the Docker socket.

That credential is currently protected by nothing.

### 010.1 — Unverified third-party code in the containment path

`dashboard/index.html` loads nine resources from four third-party origins with
**zero** `integrity` attributes:

| Origin | Resource |
|---|---|
| `cdn.tailwindcss.com` | Tailwind Play CDN (runtime CSS compiler) |
| `cdn.jsdelivr.net` | `alpinejs@3.14.8`, `chart.js@4.4.7` |
| `unpkg.com` | `@phosphor-icons/web@2.1.1` |
| `api.fontshare.com`, `fonts.googleapis.com` | four webfont families |

Any one of those origins — or a DNS hijack, or a compromised package version
republished under the same tag — executes attacker-controlled JavaScript on the
console origin, which can read the operator token out of `localStorage` and
drive containment actions against production containers.

This directly contradicts the project's own stated invariant. `compose.yaml`
pins every container image by `sha256` digest and `scripts/verify_all.sh`
enforces that in `verify-static`. The console that *drives* containment is held
to no equivalent standard. `unpkg.com/@phosphor-icons/web@2.1.1` is not even
version-exact — it is a tag range that resolves at request time.

### 010.2 — A restrictive CSP is currently impossible

`cdn.tailwindcss.com` is the Tailwind Play CDN. It is documented as
development-only: it compiles utility CSS in the browser at runtime, which
requires permissive `script-src`/`style-src`. While it is loaded, no useful
`Content-Security-Policy` can be set.

### 010.3 — No security response headers anywhere

Grep for `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`,
and `Referrer-Policy` across `gateway/nginx.conf`,
`scripts/serve_dashboard.py`, `backend/`, and `dashboard/` returns nothing. The
console is framable and content-type-sniffable.

### 010.4 — The token is stored with no boundary

`dashboard/app.js:386-394` reads and writes
`localStorage['porygon_operator_token']`. `localStorage` is readable by every
script on the origin, survives browser restarts indefinitely, and has no
expiry. Combined with 010.1 this is a complete credential-theft path.

## Approach

1. **Vendor and pin every third-party asset.** Add `dashboard/vendor/` holding
   Alpine, Chart.js, the Phosphor icon font, and the webfonts, fetched once at
   an exact version and committed with a recorded `sha384` alongside. Replace
   the CDN `<script>`/`<link>` tags with local paths. The console then has the
   same supply-chain property as the container images: a fixed, hash-recorded
   artifact set.
2. **Replace the Tailwind Play CDN with a build-free static stylesheet.** The
   console uses a bounded set of utilities; compile them once into
   `dashboard/vendor/tailwind.css` (or hand-author the equivalent) so no
   runtime compiler is needed and `script-src 'self'` becomes achievable.
3. **Add a strict CSP** to both `gateway/nginx.conf` and
   `scripts/serve_dashboard.py`, plus `X-Frame-Options: DENY`,
   `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and
   `Permissions-Policy` denying camera/microphone/geolocation.
4. **Move the operator token to `sessionStorage` with an explicit TTL** and a
   visible lock state, so a closed tab ends the credential's life and a stale
   token cannot sit on disk for weeks. Keep the existing styled token modal.
5. **Record the integrity manifest** in a checked file so a gate can assert the
   vendored bytes still match their recorded hashes.

## Gates

- `make verify-static` green.
- New: a static assertion that `dashboard/` references no external origin, and
  that every vendored asset matches its recorded `sha384`. Wired into
  `verify-static` so it is enforced on every run, in the same place the
  digest-pinning assertion lives.
- Console loads and every tab renders with the network blocked to all origins
  except the API — verified by screenshot capture (plan 050).

## STOP conditions

- Do not change any request path, header name, or token semantics the backend
  checks. `require_operator_token` is not modified by this plan.
- Do not alter scoring, profiling, or detection semantics. No measured number
  in `artifacts/` may move.
