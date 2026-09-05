# Experiment acceptance

Status: **real-container pilot runner implemented; confirmatory collection not authorized**

Experiment work has three distinct evidence classes. Conflating them is the single
easiest way to make a dishonest claim, so they are separated here and in every
artifact the runner writes.

| Class | Command | `research_eligible` | May support a paper claim |
|---|---|---|---|
| Smoke fixture | `make experiment-smoke` | `false` | **No.** Synthetic; validates the artifact contract only. |
| Real-container pilot | `make experiment-pilot` | `false` | **No.** Real containers and real telemetry, but collected while the protocol is review-pending. Informs engineering and variance estimates. |
| Confirmatory | `make experiment-confirmatory` | `true` (when it exists) | Yes — and only then. |

The runner refuses confirmatory execution while
`docs/RESEARCH_PROTOCOL_V1.md` reports anything other than frozen status. That
refusal is a tested behaviour, not a convention.

## Checks

```bash
python3 -m pytest experiments/tests -q
make experiment-smoke
make experiment-replay RUN_DIR=artifacts/experiments/local/smoke-fixture
make experiment-validate RUN_DIR=artifacts/experiments/local/smoke-fixture
```

The repeatable real-container gate, which requires the stack to be up:

```bash
make up
make verify-experiment-live      # scripts/verify_real_container.sh, ~30 s, non-disruptive
```

It asserts that a mutable tag is refused before any container is created, that
the runtime-context identity matches the frozen canonical examples, that a real
container is pulled by digest and torn down, that every canary reconciles from
the generator through Falco to PostgreSQL with zero measured loss, that every
unmeasured boundary states a reason, that cleanup leaves nothing behind, and
that confirmatory collection is still refused. Evidence is retained at
`artifacts/real-container-acceptance.json`.

A larger pilot run:

```bash
make up
make experiment-pilot PILOT_ARGS="--workloads WL-NGX-V1 --scenarios SCN-EXEC --replicas 1"
make experiment-replay RUN_DIR=artifacts/experiments/local/<run-id>
make experiment-validate RUN_DIR=artifacts/experiments/local/<run-id>
```

## What the pilot runner does

- Reads the six frozen workload coordinates from
  `docs/PROFILE_SCOPE_EXPERIMENT_V1.md`; that table is the single source of
  truth and a mutable tag reference is refused outright.
- Pulls each image by immutable index digest and records repository, human tag,
  index digest, resolved platform manifest digest, local image ID,
  architecture, OS, and an image-config hash.
- Creates one labelled network and one labelled container per trial, published
  on loopback only, memory- and PID-capped.
- Computes the runtime-context fingerprint specified in
  `PROFILE_SCOPE_EXPERIMENT_V1.md` and stores the canonical document, its hash,
  and a hash of the raw inspection snapshot. Environment values, literal
  argument values, host paths, and container IDs are never part of it.
- Records setup, readiness, warm-up, measurement, ground-truth, teardown, and
  cleanup timestamps, using a monotonic clock for durations and UTC for
  cross-service traceability.
- Drives a deterministic, seeded workload and keeps **raw latency samples**, so
  percentiles are computed by nearest rank rather than from an average.
- Executes only the safe scenarios, each as a sequence-numbered canary carrying
  a run- and trial-scoped marker, and records the exact command template plus
  its SHA-256.
- Reconciles every canary across the boundaries this deployment can actually
  observe, and marks the rest `unmeasured` **with a reason** rather than zero.
- Removes only resources whose exact name and both labels match the current
  trial, and refuses ambiguous, unlabelled, or foreign targets.

## Boundary observability

| Boundary | Status | How |
|---|---|---|
| generator | measured | The runner knows exactly which canary executions succeeded. |
| source (Falco) | measured | Canary markers counted in `falco-events.jsonl` through the telemetry container's read-only mount. |
| spool | **unmeasured** | The spool exposes process-local counters that cannot be attributed to an individual canary sequence. |
| api | **unmeasured** | API receipt is not separately observable from outside the backend. |
| database | measured | Canary markers counted in persisted `process_exec_events` rows via the read API. |

Kernel-to-eBPF loss and Falco userspace drops remain unmeasured, exactly as
Plan 002 recorded. Nothing in the harness converts an unmeasured boundary into
a zero.

## Acceptance boundary

A passing pilot proves the capture and identity pipeline works on real
containers. It does **not** establish detection quality, calibration coverage,
profile-scope superiority, or overhead budgets. Those require the frozen
protocol, the full run counts in `RESEARCH_PROTOCOL_V1.md`, run-level splits,
detector comparisons, ablations, and tables generated from confirmatory raw
evidence.

## Not yet implemented

- Detector comparison arms (`DET-RULES` … `DET-HYBRID`) and the six ablations.
- Profile-scope arms fitted and scored end to end across all four scopes.
- Load regimes at 25/100/250 events/s and the 1,000 events/s burst.
- Backend outage and recovery timing during a real trial.
- Per-service CPU-seconds, peak RSS, and disk-growth sampling.
- Paper tables and figures — no confirmatory data exists, so none may be
  generated.
