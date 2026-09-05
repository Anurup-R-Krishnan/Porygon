# Porygon execution status

This file records what is **actually** implemented, verified, and validated in
this repository. It is evidence-based: a module is only advanced past
`IMPLEMENTED` when a named artifact, test run, or gate output proves the claim.
Historical agent transcripts and plan documents are clues, not evidence.

- Audit commit: `2d46104` (working tree dirty — see "Working tree" below)
- Audit date: 2026-09-05
- Host: Linux 7.1.8 CachyOS, 12 threads, 23 GiB RAM, Docker 29.7.2, cgroup v2,
  kernel BTF readable, 66 GiB free on `/`
- Live stack at audit time: 8 containers up and healthy for 16 h

## Status vocabulary

| Status | Meaning |
|---|---|
| `NOT STARTED` | No implementation exists |
| `IN PROGRESS` | Partial implementation; not usable end to end |
| `BROKEN` | Code exists but the integration path fails |
| `IMPLEMENTED` | Works through its real integration path |
| `TESTED` | Implemented plus automated tests that would catch regressions |
| `EXPERIMENTALLY VALIDATED` | Measured on real workloads with retained artifacts |
| `DEMO READY` | Reproducible on demand in front of an evaluator |
| `BLOCKED` | Cannot progress; blocker named |

## Evidence recorded during this audit

| Check | Command | Result |
|---|---|---|
| Service unit suites | `docker compose run --rm --no-deps --entrypoint pytest <svc> -q` | backend 74, collector 8, telemetry 20, responder 5, scanner 5 = **112 passed** |
| Experiment harness tests | `python3 -m pytest experiments/tests -q` | **4 passed** |
| Unit gate | `make verify-unit` | **passed** (exit 0) |
| Static gate | `make verify-static` | **passed** (exit 0) |
| Live-safe gate | `make verify-live-safe` | **passed** (exit 0, 258 s, cumulative live acceptance, event capture through incident correlation) |
| Real-container gate | `make verify-experiment-live` | **passed** (exit 0, 29 s) — `scripts/verify_real_container.sh` |
| Lint (gate scope) | `ruff check --select E4,E7,E9,F backend collector telemetry responder scanner scripts` | **All checks passed** |
| Lint (incl. experiments) | same + `experiments` | 2 × E402 in `experiments/validate_artifacts.py` — outside the gate's scope |
| Protocol structure | `python3 scripts/check_research_protocol.py` | **passed**; `status=review_pending`, security=pending, methodology=pending |
| Live API | `curl 127.0.0.1:8000/openapi.json` | **64 paths** served |

## Module matrix

| Module | Location | Purpose | State | Tests | Evidence / remaining work |
|---|---|---|---|---|---|
| Falco sensor rules | `falco/porygon_rules.yaml` | execve/execveat capture inside containers | `TESTED` | `falco --validate` in `verify-static` | Captures **process execution only**. No file, socket, DNS, capability, or namespace events — a deliberate v1 boundary (`FEATURE_SCHEMA_V1.md:62`). |
| Telemetry adapter | `telemetry/` | Falco JSONL → normalized process events | `TESTED` | 20 | Bounded/redacted dead letters, path-aware readiness, replay cursor safety all covered. |
| Docker collector | `collector/` | Docker lifecycle events + digest resolution | `TESTED` | 8 | Cursor no longer advances past a failed durable enqueue (Plan 002). |
| Event identity & normalization | `collector/…/event_identity.py`, both `normalizer.py` | deterministic event IDs, exec detail normalization | `TESTED` | covered in the above | Multicall (BusyBox) identity fix present. |
| Local outbox / spool | `collector/…/spool.py`, `telemetry/…/spool.py` | durable at-least-once buffering | `TESTED` | covered | Saturation + outage replay proven in capture-integrity acceptance artifacts. |
| Backend API | `backend/src/porygon_api/main.py` | control plane, 64 endpoints | `TESTED` | 74 | Single ~3.2 k-line composition module; decomposition deferred until characterization tests exist. |
| Persistence & migrations | `backend/alembic/versions/0001…0009` | PostgreSQL schema | `TESTED` | migration `--sql` dry run in `verify-static` | 9 sequential migrations; `0009` adds calibrated provenance additively. |
| Behavioural profiles (v1) | `backend/…/baseline.py` | digest-bound profile lifecycle | `IMPLEMENTED` | 74 (shared) | Draft/active/retire lifecycle exercised by `verify_phase4.sh` artifacts. |
| Anomaly scoring v1 | `backend/…/scoring.py` | Jensen–Shannon + weighted composite | `IMPLEMENTED` (**superseded, read-only**) | 74 (shared) | Still contains the hand-picked `0.50/0.30/0.20` weights. Retained **deliberately** for v1 read compatibility (Plan 004 is additive). Must not be presented as the current scoring model. |
| Calibrated rarity v2 | `calibrated_rarity.py`, `calibrated_provenance.py`, `run_calibration.py` | Hellinger / Markov surprisal / novelty mass / empirical tail ranks / split-conformal run-level p-value | `IMPLEMENTED` | 74 (shared) | **Disabled by default** (`PORYGON_CALIBRATED_ENABLED=false`). No calibration has been fit from real workload data. |
| Detection & incidents | `backend/…/detection.py` | deterministic rules → incident correlation | `IMPLEMENTED` | 74 (shared) | Still uses decimal severity/confidence composites on the v1 path (`detection.py:520`). |
| Response policy & executor | `backend/…/response.py`, `responder/` | human-approved containment | `IMPLEMENTED` | 5 | Live execution gate is disruptive and intentionally never run in `make verify`. |
| Scanner | `scanner/` | Trivy SBOM + EPSS/KEV enrichment | `IMPLEMENTED` | 5 | Requires network egress; `verify-scanner-live` not re-run during this audit. |
| Gateway | `gateway/nginx.conf` | only ingress-network component | `IMPLEMENTED` | invariant asserted in `verify-static` | Credential-free, loopback-published. |
| Operator CLI | `scripts/porygon_*.py` | baseline/score/detect/respond/scan | `IMPLEMENTED` | none directly | No automated coverage of the CLI wrappers themselves. |
| Verification gates | `scripts/verify_all.sh`, `verify_phase*.sh` (legacy names) | cumulative acceptance | `TESTED` | manifest at `artifacts/verification-manifest.json` | Last recorded manifest: `mode=unit`, `status=passed`, 2026-09-05T07:04Z, `git_dirty=true`. |
| Research protocol | `docs/RESEARCH_PROTOCOL_V1.md` + companions | frozen study design | `BLOCKED` | `check_research_protocol.py` passes | **Blocker**: needs one human security reviewer and one human methodology reviewer. Until then confirmatory collection is prohibited by the protocol itself. |
| Runtime-context fingerprint | `experiments/context.py` | canonical non-secret context hash | `TESTED` | 11 | Implemented to spec and verified **against the specification's own canonical examples**: reordered-equivalent documents hash identically, a security-relevant change does not. Two canonicalization gaps found and fixed (Docker's `CAP_` prefix varies by version; tmpfs was invisible to the fingerprint). |
| Experiment harness (synthetic) | `experiments/run.py`, `artifacts.py`, `validate_artifacts.py` | immutable artifacts, hashing, replay, boundary reconciliation | `TESTED` | 41 (shared) | Produces a **synthetic fixture only**, explicitly `research_eligible: false`. |
| Real-container experiment runner | `experiments/real.py` | pull pinned digests, run real nginx/Redis/PostgreSQL workloads, capture ground truth, reconcile boundaries | `EXPERIMENTALLY VALIDATED` (pilot) | 41 (shared) | 9-trial pilot completed 2026-09-05; see "Pilot evidence" below. Pilot data is **not** confirmatory evidence. |
| Detector / profile-scope comparison | — | 4 profile arms × 6 detectors × 6 ablations | `NOT STARTED` | — | Depends on confirmatory collection, which the protocol prohibits. |
| Paper tables & figures | — | generated from validated raw artifacts | `NOT STARTED` | — | No confirmatory data exists, so no table may be generated. |
| Dashboard | — | evidence viewer | `NOT STARTED` | — | Deliberately deferred until experiment artifacts are stable. |

## Pilot evidence (2026-09-05)

Run `pilot-20260905a`, 9 trials, 3 workload families × 3 context variants, one
replica each. Artifacts under `artifacts/experiments/local/` (git-ignored).
`research_eligible: false` on every record.

| Measurement | Result |
|---|---|
| Trials completed | 9 / 9 |
| Canaries generated | 54 |
| Observed at Falco (`source`) | 54 |
| Persisted in PostgreSQL (`database`) | 54 |
| Loss fraction (measured boundaries) | 0.0 |
| Duplicates | 0 |
| Workload operations succeeded | 360 / 360 |
| Distinct runtime-context hashes | 9, from 3 image digests |
| Leftover containers / networks after cleanup | 0 / 0 |
| Replay determinism | `replay matched recorded summary` |
| Artifact validation | `[PASS]` |

Workload latency p50 / p95 / p99 (nearest rank over raw samples): nginx
0.29–0.33 / 0.64–0.84 / 1.07–1.39 ms; Redis 0.13–0.67 / 0.29–1.18 /
0.34–2.16 ms; PostgreSQL 40.4–41.7 / 50.1–51.9 / 51.9–56.7 ms. The PostgreSQL
figures are dominated by `docker exec psql` process startup, which the harness
records as `harness_induced_exec_count`. They are **not** a PostgreSQL
performance measurement.

### End-to-end chain verified on pilot data

Pinned digest → real container → Falco (modern eBPF) → telemetry adapter →
PostgreSQL → digest-bound profile → anomaly score → deterministic detection:

- profile built from 479 real process events, 7 windows, `quality.passed: true`,
  activated as `profile_version: 2`;
- an earlier 30-second-window attempt was **refused** by the quality gate
  (2 non-empty windows, 3 required) — the guardrail works;
- scoring a window overlapping the training interval was **refused** with
  `HTTP 409 … must not overlap the profile training interval` — leakage is
  blocked at the API, not merely discouraged in a document;
- a genuinely held-out window scored `baseline_like` over 106 events;
- detection produced 72 deterministic rule matches with `incident_created:
  false` — rule evidence and anomaly evidence stay separate.

### Finding 1: the tested context variants are behaviourally identical

Comparing the full `(process_name, executable)` multiset per container across the
three context variants, for each family:

| Family | Variants | Events per trial | Distinct (process, exe) | Identical multiset? |
|---|---:|---:|---:|---|
| WL-NGX | 3 | 46, 46, 46 | 19 | **yes** |
| WL-PG | 3 | 166, 166, 166 | 19 | **yes** |
| WL-RDS | 3 | 33, 33, 33 | 9 | **yes** |

`--cap-drop NET_RAW` and `--tmpfs /scratch` change the context *identity*
(9 distinct hashes) but do not change *what processes execute*. For these
variants, digest-plus-context would fragment the profile population with **zero
behavioural gain** — pure cost, no benefit. `plans/README.md` already names
excessive fragmentation as a valid negative outcome; this is a first measured
instance of it.

**Methodological consequence.** To test the context hypothesis meaningfully, the
frozen variants must be ones that change *what executes* — entrypoint/command
shape, configured user (which changes the `gosu`/`su-exec` startup path), or a
configuration that alters the startup sequence. Capability and mount flags are
security-relevant for identity but behaviourally inert under an execve-only
feature set. This should be reconciled with
`docs/PROFILE_SCOPE_EXPERIMENT_V1.md` before confirmatory collection.

### Finding 2: execve-only telemetry is blind to application traffic

In the nginx trials, 40 HTTP requests produced **zero** process events. In the
Redis trials, 40 SET/GET operations produced **zero** process events. Serving
traffic does not fork.

Every profile is therefore dominated by container startup plus whatever is
`exec`-ed into the container. PostgreSQL is the exception only because the
harness drives it with `docker exec psql`, which spawns a process per query
(42 `psql` + 49 `runc init` of its 166 events).

This is a direct consequence of the deliberate v1 feature boundary
(`FEATURE_SCHEMA_V1.md:62`), not a defect — but it bounds what any behavioural
claim can mean, and it should be stated plainly in the presentation: the model
profiles *process-execution* behaviour, not workload behaviour.

### Finding 3: container-runtime scaffolding is inside every profile

`process_name: "6"`, `executable: /runc`, `command_line: "6 init"` is the
container runtime's own `runc init` helper. It appears in every container, scales
one-to-one with `docker exec` calls, and carries no discriminative signal — yet
it is counted in the categorical distributions that feed the distance model.
A candidate feature-schema refinement is to exclude runtime scaffolding
explicitly rather than let it dilute real signal.

### Finding 4: container-startup correlation gap

Across 1,067 pilot process events, **1,017 (95.3%) resolved to an image
digest and 50 (4.7%) did not**. The unresolved events are not random: they are
container-startup processes (`docker-entrypoint`, `find`, `id`, `basename`,
`gosu`, `chmod`). Falco observes these execs before the collector has recorded
the container-create event that binds the short container ID to a digest.

Implication for the research: the earliest processes in a container's life are
systematically under-attributed, so the earliest moments of any profile are biased.
This was not previously quantified. It is a candidate for the next planning
wave — either delayed re-correlation of unresolved events, or an explicit
lifecycle-stage exclusion in the feature schema. It is **not** a capture loss:
the events are persisted, only their digest binding is missing.

## Architecture: brief vs. repository

The completion brief describes **Tetragon** as the sensor and a **Go host
agent** as the collector. The repository implements **Falco 0.44.1 (modern
eBPF)** and a **Python collector**. This is a divergence in the brief, not stale
code:

- `Tetragon` appears exactly once in the repository, as a *future Kubernetes*
  note (`docs/FINAL_PHASES.md:237`).
- Custom eBPF and a Go rewrite were explicitly considered and **rejected** in
  `plans/README.md:49` on the grounds that they expand attack surface and scope
  without strengthening the core experiment.

Both stacks deliver the same evidence class (kernel process execution via
eBPF). Rewriting the sensor and collector would invalidate every existing test,
acceptance artifact, and pinned digest for no research gain. The repository
implementation is therefore retained, and the brief's diagram is treated as
"harmless variation" under its own §9 instruction not to force the repository
into the diagram blindly.

## Working tree

The tree is dirty at audit time and was left that way deliberately. Tracked
modifications (`Makefile`, `README.md`, `plans/README.md`, `docs/FINAL_PHASES.md`,
three artifact JSONs) and untracked files (`experiments/`, `docs/EXPERIMENT_*`,
profile, scoring, and detection acceptance artifacts, `.claude/`, `.codex/`, `.agents/`, `PORYGON_EXPLAINED.md`)
are pre-existing user work. Nothing was reset, cleaned, or checked out.

## Blockers

1. **Protocol approval** — confirmatory collection is prohibited until a human
   security reviewer and a human methodology reviewer sign off
   (`docs/RESEARCH_PROTOCOL_V1.md:9`, `plans/003:129`). Pilot data may be
   collected; it may never be presented as confirmatory evidence.
2. **Disk budget** — 66 GiB free. `PLAN.md` milestone 0 asks for ≥150 GiB for
   the full confirmatory matrix. Sufficient for a pilot; insufficient for the
   frozen confirmatory matrix as written.
3. **Telemetry breadth** — only process execution is captured. Any claim about
   file, network, or privilege-transition behaviour is out of scope for v1 and
   would require a new feature-schema version plus fresh fit/calibration.

## Change log

| Date | Change |
|---|---|
| 2026-09-05 | Initial evidence-based audit. |
