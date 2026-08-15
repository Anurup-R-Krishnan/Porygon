# Audit Report: Porygon Phases 1–5

Audit date: 2026-07-21

Audited input: cumulative `porygon-phase5` package supplied in this project conversation.

## Verdict

The cumulative codebase contains real implementations for the core deliverables claimed in Phases 1–5. Its existing tests and static checks passed. The live Docker/Falco claims remain **host-verification pending** because the audit environment has no Docker executable or daemon.

The package required several corrections before it was safe to extend.

## Verification performed before Phase 6

| Check | Result |
|---|---|
| Backend unit tests | 22 passed |
| Docker collector tests | 5 passed |
| Telemetry adapter tests | 5 passed |
| Total original tests | 32 passed |
| Ruff | passed |
| Python compilation | passed |
| Bash syntax | passed |
| Compose/Falco YAML parsing | passed |
| TOML parsing | passed |
| OpenAPI generation | passed |
| Live Docker/Falco acceptance | not runnable in audit environment |

After audit corrections and Phase 6 implementation, the cumulative suite contains 43 passing tests.

## Phase-by-phase assessment

### Phase 1: platform foundation

Verified in code:

- PostgreSQL service and persistent volume
- FastAPI liveness/readiness
- Alembic migrations
- internal-token service authentication
- non-root/read-only application containers
- Compose health-gated startup

Host pending:

- actual container startup, restart, and PostgreSQL persistence test

### Phase 2: Docker identity and events

Verified in code/tests:

- normalized Docker events with raw payload preservation
- deterministic event IDs and PostgreSQL uniqueness
- image ID, tag/reference, and repository digest kept separate
- missing `RepoDigests` represented as unavailable
- SQLite outbox and retry controls
- environment variables excluded from stored snapshots

Host pending:

- live Docker event streaming and digest resolution
- outage/replay behaviour against a real daemon

Source limitation retained:

- Docker's own recent event history is bounded; Porygon cannot recover evidence that disappeared before the collector received it

### Phase 3: process execution telemetry

Verified in code/tests:

- Falco JSON normalization
- process and parent fields
- container identity enrichment
- durable cursor/outbox/retry path
- idempotent backend ingestion

Audit defect found:

- historical parent lookup used any older matching PID in the container, allowing PID-reuse mislinking

Correction:

- lookup is now restricted by `PORYGON_PARENT_CORRELATION_LOOKBACK_SECONDS`, default 600 seconds

Security correction:

- Falco capabilities were narrowed from `SYS_ADMIN` to modern-eBPF-specific `BPF`, `PERFMON`, `SYS_RESOURCE`, and `SYS_PTRACE`

Host pending:

- actual eBPF event capture, parent linkage, and replay

### Phase 4: digest-bound profiles

Verified in code/tests:

- explicit approved training interval
- no automatic continuous retraining
- deterministic event and model hashes
- versioned draft/active/retired profiles
- one active profile per digest
- quality gates and duplicate rejection
- process, executable, parent-child, UID, Docker-action, sequence, and numeric-window features

Host pending:

- live evidence collection and profile generation from an actual container workload

Research boundary:

- approved training metadata does not prove the selected activity is benign

### Phase 5: explainable scoring

Verified in code/tests:

- completed fixed windows
- training/evaluation overlap rejection
- Jensen–Shannon categorical distance
- unseen-mass novelty
- scaled numeric deviation
- missing-family weight renormalization
- insufficient-data state
- reproducible profile/event/config metadata
- idempotent exact scoring

Host pending:

- live normal-versus-novel experiment using Falco evidence

Research boundary:

- score bands and weights are provisional engineering settings, not validated classification thresholds

## Corrections applied to the cumulative release

### 1. Alembic local import path

Problem:

```text
ModuleNotFoundError: porygon_api
```

Cause: `backend/alembic.ini` prepended the repository directory rather than `backend/src`.

Fix: `prepend_sys_path = src`.

Result: complete offline PostgreSQL migration SQL renders from Phase 1 through Phase 6.

### 2. Parent PID reuse protection

Problem: a PID match had no maximum age.

Fix: configurable time-bounded parent lookup, default 600 seconds.

This reduces false linkage but does not turn parent correlation into a perfect kernel process-tree guarantee.

### 3. Cumulative acceptance compatibility

Problem: Phase 4 and Phase 5 scripts asserted that the API phase string had to equal the historical phase, causing valid newer cumulative builds to fail.

Fix: scripts now require a minimum compatible phase number.

### 4. Falco capability scope

Problem: Falco was granted broad `SYS_ADMIN`.

Fix: use the narrower capability set documented for modern eBPF operation.

## Dependency and image fact check

The pinned versions used by the cumulative package existed at audit time, including:

- PostgreSQL `17.10-bookworm`
- Python `3.13.13-slim-bookworm`
- Falco `0.44.1`
- FastAPI `0.139.2`
- SQLAlchemy `2.0.51`
- Alembic `1.18.5`
- Psycopg `3.3.4`
- Pydantic Settings `2.14.2`
- Docker SDK for Python `7.2.0`

A version existing does not prove the live stack works on the target host. The live acceptance script remains mandatory.

## Final conclusion

Phases 1–5 are credible cumulative implementations with passing local unit/static verification after the listed corrections. They are not yet experimentally validated until the full Docker/Falco acceptance chain runs on the user's Linux host and its artifacts are retained.
