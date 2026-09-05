# Porygon verification report — 2026-09-05

Every number in this report was produced by a command run against this
repository on the date above. Nothing is estimated, projected, or carried over
from a previous session's claims.

## Repository state

| Field | Value |
|---|---|
| Commit | `2d461047c7c5fba504a9a9606593a1fa0edf3576` |
| Branch | `main` |
| Working tree | dirty — pre-existing user work plus this session's changes; nothing was reset, cleaned, or checked out |
| Host | Linux 7.1.8 CachyOS, 12 threads, 23 GiB RAM |
| Docker | 29.7.2, overlayfs, cgroup v2 |
| Kernel BTF | `/sys/kernel/btf/vmlinux` readable |
| Free disk | 65 GiB on `/` |
| Stack | 8 containers up and healthy |

## Gates executed

| Gate | Command | Result |
|---|---|---|
| Static | `make verify-static` | **passed** (exit 0) — ruff, compose config, AST/TOML/YAML parse, network-isolation and digest-pinning invariants, backend build, OpenAPI size, Alembic `--sql` dry run, `falco --validate` |
| Unit | `make verify-unit` | **passed** (exit 0) |
| Live safe | `make verify-live-safe` | **passed** (exit 0, 258 s) — cumulative live acceptance: event capture through incident correlation; manifest `mode=live-safe`, `status=passed`, 2026-09-05T07:32:45Z→07:37:03Z |
| Real container | `make verify-experiment-live` | **passed** (exit 0, 29 s) — `scripts/verify_real_container.sh`; now part of `make verify` |
| Protocol structure | `python3 scripts/check_research_protocol.py` | **passed**; `status=review_pending`, security=pending, methodology=pending |
| Smoke artifacts | `make experiment-smoke` + validate | **passed** |
| Pilot replay | `make experiment-replay RUN_DIR=…/pilot-20260905a` | **passed** — `replay matched recorded summary` |
| Pilot validation | `make experiment-validate RUN_DIR=…/pilot-20260905a` | **passed** — `[PASS] validated experiment artifacts` |
| Confirmatory | `make experiment-confirmatory` | **refused, as designed** — `[blocked] confirmatory collection is refused until the protocol is frozen by human review` |
| Response live | `make verify-response-live` | **not run** — disruptive by design, requires explicit operator request |
| Scanner live | `make verify-scanner-live` | **not run this session** — requires threat-feed egress |

### Test counts

| Suite | Tests |
|---|---|
| backend | 74 |
| telemetry | 20 |
| collector | 8 |
| responder | 5 |
| scanner | 5 |
| **service total** | **112** |
| experiment harness (`experiments/tests`) | 41 |
| **total** | **153** |

The 41 harness tests are new this session and are now part of `make verify-unit`.

## Pilot results

Run `pilot-20260905a`: 3 workload families × 3 context variants × 1 replica.
Artifacts in `artifacts/experiments/local/` (git-ignored), every record
`research_eligible: false`.

| Measurement | Result |
|---|---|
| Trials completed | 9 / 9 |
| Canaries generated | 54 |
| Observed at Falco (`source` boundary) | 54 |
| Persisted in PostgreSQL (`database` boundary) | 54 |
| Measured loss fraction | 0.0 |
| Duplicates | 0 |
| Workload operations succeeded | 360 / 360 |
| Distinct runtime-context hashes | 9, from 3 image digests |
| Leftover containers / networks | 0 / 0 |
| Boundaries recorded `unmeasured` with a reason | `spool`, `api` |

Images used, all pulled by immutable digest from the frozen table in
`docs/PROFILE_SCOPE_EXPERIMENT_V1.md`:

- `nginx@sha256:1eadbb07…` (`nginx:1.26.3-alpine`, `WL-NGX-V1`)
- `redis@sha256:ddd16a9b…` (`redis:7.2.7-alpine`, `WL-RDS-V1`)
- `postgres@sha256:1d04b9ba…` (`postgres:16.6-alpine`, `WL-PG-V1`)

Workload latency, nearest rank over raw samples (p50 / p95 / p99, ms):

| Family | p50 | p95 | p99 |
|---|---|---|---|
| nginx | 0.29–0.33 | 0.64–0.84 | 1.07–1.39 |
| Redis | 0.13–0.67 | 0.29–1.18 | 0.34–2.16 |
| PostgreSQL | 40.4–41.7 | 50.1–51.9 | 51.9–56.7 |

The PostgreSQL figures are dominated by `docker exec psql` process startup, not
by PostgreSQL. The harness records this as `harness_induced_exec_count` rather
than presenting it as database performance.

### End-to-end chain verified on real pilot telemetry

1. Profile built from 479 real process events over 7 windows —
   `quality.passed: true`; activated as `profile_version: 2`.
2. An earlier attempt with a 30-second window was **refused** by the quality
   gate: `minimum_nonempty_windows required 3, actual 2`.
3. Scoring a window overlapping the training interval was **refused**:
   `HTTP 409 — Scoring windows must not overlap the profile training interval`.
4. A held-out window scored `baseline_like` over 106 events, with an
   explanation block naming top contributors, unseen tokens, and numeric
   deviations.
5. Detection produced 72 deterministic rule matches with
   `incident_created: false` and `incident_eligible: false`.

### Repeated-run identity check

Running `scripts/verify_real_container.sh` twice, before and after the `network_mode`
fix:

| Run | network_mode recorded | context hash |
|---|---|---|
| pre-fix run 1 | per-run network name | `4a1d23a090445b3f…` |
| pre-fix run 2 | a *different* per-run network name | `b0c80a196ad0816a…` |
| post-fix run 1 | `user-defined` | `680822ddba09d63d…` |
| post-fix run 2 | `user-defined` | `680822ddba09d63d…` |

Two independent runs of the same deployment now share one identity, which is the
precondition for accumulating fit runs in a stratum. Recomputing the 9-trial
pilot's fingerprints under the fix still yields 9 distinct hashes — that run
used a single shared network, so its headline result is unaffected.

### Measured findings

**The three tested context variants are behaviourally identical.** Comparing the
full `(process_name, executable)` multiset per container: nginx 46/46/46 events,
PostgreSQL 166/166/166, Redis 33/33/33 — identical multisets across `baseline`,
`dropped_capabilities`, and `tmpfs_scratch` in every family. `--cap-drop
NET_RAW` and `--tmpfs /scratch` change the context *identity* but not what
executes, so digest-plus-context would fragment the population with no
behavioural gain. The frozen variant list should be revised to changes that
alter *what executes* before confirmatory collection.

**execve-only telemetry is blind to application traffic.** 40 HTTP requests and
40 Redis operations each produced zero process events. Profiles are dominated by
container startup and by `exec`-ed activity.

**Container-runtime scaffolding is inside every profile.** `runc init` (surfaced
as `process_name: "6"`, `executable: /runc`) appears in every container, scales
with `docker exec` count, and carries no discriminative signal.

### Container-startup correlation gap

Across 1,067 pilot process events, 1,017 (95.3%) resolved to an image digest
and 50 (4.7%) did not. The unresolved set is systematic, not random: it is
container-startup processes (`docker-entrypoint`, `find`, `id`, `basename`,
`gosu`, `chmod`) that Falco observes before the collector has recorded the
container-create event binding the short container ID to a digest.

The events are persisted — this is an attribution gap, not capture loss — but
it biases the earliest moments of every profile. Not previously quantified.
Candidate remedies for the next planning wave: delayed re-correlation of
unresolved events, or an explicit lifecycle-stage exclusion in the feature
schema.

## Defects found and fixed this session

| Defect | Where | Consequence if unfixed |
|---|---|---|
| Container names truncated at 63 chars | new runner | Two trials differing only in the truncated suffix would have collided on one container name |
| `[0-9]*` matched the bare canary prefix | new runner | `int('')` crash during boundary reconciliation |
| Capability prefix not normalised (`CAP_NET_RAW` vs `net_raw`) | `experiments/context.py` | One deployment intent would produce two different context identities across Docker versions |
| tmpfs invisible to the fingerprint | `experiments/context.py` | A security-relevant writable mount would not change the context hash |
| **`network_mode` encoded the per-run network name** | `experiments/context.py` | **The most serious defect found.** Each experiment run creates its own network, so the same deployment produced a *different* context identity in every run. No context stratum could ever accumulate the 10 fit runs the protocol requires, so the digest-plus-context arm would have returned `insufficient_profile` forever — silently, and only under repeated real runs. Now normalised to its security class (`host` / `none` / `bridge` / `container` / `user-defined`). |
| Nearest-rank percentile off by one | `experiments/real.py` | p95 and p99 reported one rank too high |
| Secret scanner rejected its own redaction placeholders | `experiments/artifacts.py` | Any artifact containing a correctly redacted secret could not be written |
| Secret rejection named no location | `experiments/artifacts.py` | Undiagnosable failures; now reports the JSON path and matched marker, never the value |
| Two `E402` lint errors | `experiments/validate_artifacts.py` | Outside the gate's scope, so invisible; `experiments` is now inside the gate |

## Files added or changed

**Added**
- `experiments/context.py` — runtime-context fingerprint (specified but never implemented)
- `experiments/real.py` — real-container pilot runner
- `experiments/tests/test_context.py`, `experiments/tests/test_real.py` — 37 new tests
- `docs/execution-status.md` — evidence-based module matrix
- `docs/design-decisions.md` — why each decision, what was rejected, what is missed
- `docs/DEMO.md` — verified demonstration path

**Changed**
- `experiments/run.py` — `pilot` command, generalized validator, pilot replay, manifest writer
- `experiments/artifacts.py` — path-naming secret rejection, redaction allowlist, split assignment and leakage check
- `experiments/validate_artifacts.py` — lint fix
- `scripts/verify_all.sh` — `experiments` added to lint and AST scope; harness tests added to the unit gate
- `Makefile` — `experiment-pilot`, `experiment-validate`
- `README.md`, `docs/EXPERIMENT_ACCEPTANCE.md`, `docs/EXPERIMENT_REPRODUCIBILITY.md`, `docs/FINAL_PHASES.md`, `plans/README.md`

No commit and no push were made. No AI attribution, co-author trailer, or
generated-by line was added to any file.

## Demo sequence

See [`DEMO.md`](DEMO.md). Every command in it was executed and its real output
recorded.

## Limitations — what must not be claimed

- **No confirmatory data exists.** The protocol prohibits collecting it until a
  human security reviewer and a human methodology reviewer approve and freeze
  it. Pilot and smoke evidence both record `research_eligible: false`.
- **No detection-quality claim is supported.** No false-positive rate, recall,
  precision, F1, calibration coverage, or profile-scope comparison has been
  measured.
- **Telemetry is process execution only.** No file, socket, DNS, or
  privilege-transition evidence exists in v1.
- **Kernel-to-eBPF and Falco userspace drops remain unmeasured.** They are
  recorded as `unmeasured` with a reason, never as zero.
- **The v1 weighted score is still on the live path.** `scoring.py` retains its
  hand-selected `0.50 / 0.30 / 0.20` weights and the demo above exercises it.
  The calibrated v2 model exists and is tested but is disabled by default
  (`PORYGON_CALIBRATED_ENABLED=false`) and has never been fitted on real data.
- **One replica per cell, one host.** Nothing here supports an inferential
  claim; the frozen protocol requires 10–30 runs per cell.

## Blockers

1. **Protocol approval** — two human reviews outstanding. Blocks all
   confirmatory collection, and therefore every table, figure, and paper claim.
2. **Disk budget** — 65 GiB free against the 150 GiB that `PLAN.md` milestone 0
   specifies for the full confirmatory matrix. Sufficient for pilots only.
3. **Not implemented** — detector comparison arms (`DET-RULES` … `DET-HYBRID`),
   the six ablations, the four profile-scope arms fitted end to end, load
   regimes (25/100/250 events/s and the 1,000 events/s burst), backend
   outage/recovery timing, per-service CPU and RSS sampling, and every paper
   artifact.

## Honest current position

Porygon is a working, tested, reproducible runtime-security research prototype
with a genuine end-to-end pipeline demonstrated on real containers pinned by
immutable digest. Its central research question — whether digest-plus-context
profiling beats global, tag, and digest-only scoping — is now *measurable*: the
context fingerprint is implemented and verified against its specification, and
the runner can produce the evidence. The question is not yet *answered*, and
this repository does not claim otherwise.
