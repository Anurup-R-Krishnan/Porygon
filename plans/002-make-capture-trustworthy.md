# Plan 002: Make capture saturation, readiness, and dead letters trustworthy

> **Executor instructions**: Execute every step and gate in order. Stop instead of improvising when a STOP condition occurs. Update Plan 002 in `plans/README.md` when complete.
>
> **Drift check (run first)**: `test "$(sha256sum collector/src/porygon_collector/docker_source.py collector/src/porygon_collector/spool.py collector/src/porygon_collector/state.py collector/tests/test_spool.py telemetry/src/porygon_telemetry/config.py telemetry/src/porygon_telemetry/file_source.py telemetry/src/porygon_telemetry/main.py telemetry/src/porygon_telemetry/spool.py telemetry/src/porygon_telemetry/state.py telemetry/tests/test_config.py telemetry/tests/test_spool.py scanner/src/porygon_scanner/main.py docs/PHASE2_ACCEPTANCE.md docs/PHASE3_ARCHITECTURE.md docs/PHASE3_ACCEPTANCE.md | sha256sum | cut -d' ' -f1)" = d17bfd41aacfdf42d40658b8a5cff9db6c4c33b3124cd71c20a2051ed63cc85e`
>
> Expected: exit 0. Changes made only by Plan 001 outside these paths are expected; any mismatch here is a STOP condition until reconciled.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: Plan 001
- **Category**: bug, security, tests
- **Planned at**: `23dc2c5`, in-scope hash `d17bfd41aacf`, 2026-08-20

## Why this matters

The Docker collector promises durable at-least-once behavior but permanently skips an event when its outbox is full and later advances the cursor past the entire window. Telemetry readiness can report success without an available Falco file, scanner readiness accepts a stale backend heartbeat, and malformed raw Falco lines are retained without a bound. These defects can make an experiment look healthy while its evidence is incomplete or fill the sensor disk with sensitive raw command content.

## Current state

- `collector/src/porygon_collector/docker_source.py:101-128`: `SpoolFullError` increments a counter and `continue`s; after the stream finishes, the cursor is advanced to `until`.
- `telemetry/src/porygon_telemetry/file_source.py:110-115` is the correct replay exemplar: seek back to the failed line, wait, and break without advancing its cursor.
- `telemetry/src/porygon_telemetry/main.py:35-43` marks heartbeats healthy only when the source runs and the file exists, but `main.py:165-182` readiness currently checks only backend heartbeat freshness in the shown portion.
- `scanner/src/porygon_scanner/main.py:246-253` requires a historical backend success but does not reject a stale one.
- `telemetry/src/porygon_telemetry/spool.py:49-56,177-192` defines an unbounded dead-letter table and stores up to one million raw characters per row.
- `telemetry/src/porygon_telemetry/state.py:22-30` exposes process-local delivery and overflow counters; they are diagnostics, not experiment-wide proof of zero loss.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Collector tests | `docker compose run --rm --no-deps --entrypoint pytest collector -q` | all pass |
| Telemetry tests | `docker compose run --rm --no-deps --entrypoint pytest telemetry -q` | all pass |
| Scanner tests | `docker compose run --rm --no-deps --entrypoint pytest scanner -q` | all pass |
| Static gate | `make verify-static` | exit 0 |
| Safe live gate | `make verify-live-safe` | Phase 2/3 health and replay checks pass |

## Scope

**In scope**:

- `collector/src/porygon_collector/docker_source.py`
- `collector/src/porygon_collector/spool.py`
- `collector/src/porygon_collector/state.py`
- `collector/tests/` (targeted source/spool regression tests)
- `telemetry/src/porygon_telemetry/config.py`
- `telemetry/src/porygon_telemetry/file_source.py`
- `telemetry/src/porygon_telemetry/main.py`
- `telemetry/src/porygon_telemetry/spool.py`
- `telemetry/src/porygon_telemetry/state.py`
- `telemetry/tests/`
- `scanner/src/porygon_scanner/main.py`
- `scanner/tests/` (readiness regression test)
- `.env.example`, `compose.yaml` only for new non-secret dead-letter settings
- `docs/PHASE2_ACCEPTANCE.md`, `docs/PHASE3_ARCHITECTURE.md`, `docs/PHASE3_ACCEPTANCE.md`
- `plans/README.md`

**Out of scope**:

- Changing the normalized event schema or scoring/detection logic.
- Batching SQLite transactions or optimizing ingestion; first collect Plan 005 measurements.
- Claiming kernel/Falco loss is solved. This plan fixes known adapter/collector behavior; end-to-end loss attribution belongs to Plan 005.
- Storing full raw dead letters elsewhere.

## Git workflow

- Branch `codex/002-capture-trustworthy` from the Plan 001 commit.
- Use configured Git identity only; no AI attribution, co-author trailers, or generated-by lines.
- Commit logical units, e.g. `fix: preserve collector cursor on spool saturation` and `fix: bound telemetry dead letters`.
- Do not push.

## Steps

### Step 1: Preserve the Docker replay boundary on spool saturation

In `DockerEventSource._run`, distinguish a normally completed bounded stream from an incomplete one. On `SpoolFullError`, record the overflow, wait using `stop_event.wait(1.0)`, mark the window incomplete, and break the event loop. Do not update the failed event’s cursor and do not execute the quiet-window `until` cursor update for an incomplete stream. On the next iteration, resume from the last successfully committed event cursor; overlap plus event-ID deduplication handles replay.

Use the telemetry file-source behavior at `file_source.py:110-115` as the invariant exemplar. Never advance a source cursor before the durable enqueue commits.

**Verify**: add a source-level test with a deterministic fake Docker stream and one-event-capacity store. It must prove: first event persists, second saturates, cursor remains at the first event, the source stops consuming later events, and after acknowledgement the rejected event is replayed/deduplicated correctly.

`docker compose run --rm --no-deps --entrypoint pytest collector -q -k 'spool or cursor or source'` → all selected tests pass.

### Step 2: Make readiness represent the actual path

Telemetry `/health/ready` must require: source thread running, Falco source file available, successful non-stale backend heartbeat, and no unrecoverable source error. Return a structured 503 detail naming the failed condition. Do not require that an event was recently observed during an intentionally idle workload.

Scanner readiness must compute heartbeat age using the same three-interval rule already used by telemetry. Add a shared/helper-level unit where practical; otherwise mirror exact semantics and test boundary values at just below/equal/above three intervals.

**Verify**: tests cover missing file, stopped source, no heartbeat, stale heartbeat, healthy idle source, and timezone-aware timestamps.

`docker compose run --rm --no-deps --entrypoint pytest telemetry -q -k ready && docker compose run --rm --no-deps --entrypoint pytest scanner -q -k ready` → all selected tests pass.

### Step 3: Bound and minimize dead-letter retention

Add validated settings for maximum dead-letter records, total retained excerpt bytes, excerpt length, and retention age. Defaults must be conservative for a local research sensor and documented in `.env.example`; zero/negative limits are invalid.

Migrate existing SQLite stores additively during initialization. Each dead letter must store source coordinates, error class/message, record timestamp, SHA-256 of the original bytes/text, original byte length, and a small sanitized excerpt. Do not retain the complete raw line. Redact obvious secret-bearing command arguments and token/password/key assignment forms before writing the excerpt. Enforce count/byte/age limits transactionally by evicting oldest rows; expose cumulative inserted/evicted counters and current retained count/bytes in health metadata.

Preserve enough information to reproduce parser classes without preserving credentials. Document that dead letters are diagnostics, not canonical evidence.

**Verify**: tests cover empty input, Unicode, million-byte input, secret-like argument redaction, count eviction, byte eviction, age eviction, restart with the old schema, deterministic SHA-256, and bounded on-disk rows.

`docker compose run --rm --no-deps --entrypoint pytest telemetry -q -k 'dead_letter or spool or config'` → all selected tests pass.

### Step 4: Add live saturation and readiness acceptance evidence

Extend the Phase 2/3 acceptance docs and safe verification path with controlled checks that temporarily constrain spool capacity, interrupt backend delivery, generate uniquely identified canary Docker/process events, restore delivery, and prove all accepted source records reach PostgreSQL exactly once after deduplication. Record generated, source-seen, enqueued, delivered, inserted, duplicate, dead-letter, and overflow counts separately. A final equal count alone is insufficient if boundary counters disagree.

Do not claim measurement of kernel/Falco drops unless Falco’s own metrics are sampled. Label unmeasured boundaries explicitly.

**Verify**: `make verify-live-safe` → exit 0 and retained evidence names every measured and unmeasured boundary.

## Test plan

- Collector saturation regression with replay and no quiet-window cursor jump.
- Telemetry/scanner readiness state matrix and exact staleness boundary.
- Dead-letter schema-upgrade, retention, byte/count bounds, redaction, and counter tests.
- Live outage/recovery canary with an immutable run identifier and exact event IDs.
- Run all collector, telemetry, and scanner suites after targeted tests.

## Done criteria

- [ ] No source cursor advances past an event whose durable enqueue failed.
- [ ] Saturation replay regression passes and does not hot-loop.
- [ ] Readiness rejects unavailable Falco input and stale backend heartbeats.
- [ ] Dead-letter storage is bounded, sanitized, and upgrade-compatible.
- [ ] Acceptance evidence distinguishes measured boundaries from unmeasured kernel/Falco loss.
- [ ] All affected service tests and static checks pass.
- [ ] Only in-scope files changed; Plan 002 is marked `DONE`.

## STOP conditions

- Correct replay requires using Docker history older than Docker still retains; report the unavoidable history gap rather than claiming recovery.
- The SQLite change would make an existing spool unreadable or delete outbox events.
- Redaction cannot be performed before raw content reaches durable dead-letter storage.
- Readiness semantics would fail permanently on a valid idle deployment.
- A test requires real malware, external targets, or disruptive host behavior.

## Maintenance notes

Review the exact transaction/cursor ordering and stop-event behavior. Plan 005 will add durable experiment-wide loss attribution; do not reinterpret these process-local counters as zero-loss proof. Performance batching is intentionally deferred until the baseline demonstrates that SQLite is a bottleneck.
