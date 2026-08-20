# Plan 003: Freeze the research protocol and profile-identity experiment

> **Executor instructions**: This is a protocol-freeze plan, not permission to collect confirmatory results. Complete and review every document before Plan 004 changes the model. Update Plan 003 in `plans/README.md` when done.
>
> **Drift check (run first)**: `test "$(sha256sum docs/FINAL_PHASES.md docs/FEATURE_SCHEMA_V1.md | sha256sum | cut -d' ' -f1)" = a13928cbc24b8a0a3cb1f1d9e5da3fa957e681c64e89035de17f9d50ad8af975`
>
> Expected: exit 0. Plan 001 may have changed README only; any mismatch in these two files must be reconciled before proceeding.

## Status

- **Status**: IN PROGRESS — human security and methodology reviews pending
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: Plans 001 and 002
- **Category**: direction, docs, tests
- **Planned at**: `UNBORN`, in-scope hash `a13928cbc24b`, 2026-08-16

## Why this matters

Porygon already implements substantial infrastructure, but behavioural profiling itself is established prior art. The defensible contribution is a falsifiable experiment asking whether immutable image identity plus deployment context improves false-positive behavior without sacrificing detection compared with global, tag, and digest-only profiles. Freezing units, splits, hypotheses, exclusions, and claims before model work prevents leakage and post-hoc methodology.

## Current state

- `docs/FINAL_PHASES.md:5-18` requires a problem statement, threat model, research questions, hypotheses, experiment catalogue, and metric mapping, but no frozen protocol exists.
- `docs/FINAL_PHASES.md:190-204` requires repeated ground-truthed trials, rules/anomaly/hybrid comparison, detection/loss/latency/overhead metrics, ablations, and versioned artifacts.
- `docs/FEATURE_SCHEMA_V1.md:5-19` binds profiles only to an exact repository digest and explicitly rejects mutable tags as identity.
- `docs/FEATURE_SCHEMA_V1.md:52-60` calls existing quality thresholds engineering guardrails, not scientific constants.
- `docs/FEATURE_SCHEMA_V1.md:62-64` limits v1 evidence to Docker lifecycle and process execution; file, socket, DNS, and privilege-transition claims are out of scope.
- Candidate deterministic workloads from the prior audit are nginx, Redis, PostgreSQL, and a simple REST service. Safe scenarios include unexpected shell/tool execution, benign maintenance hard negatives, load/config changes, event flood, low-and-slow behavior, and baseline poisoning.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Required sections | `python3 scripts/check_research_protocol.py` | exit 0; all schema/traceability checks pass |
| Docs consistency | `rg -n 'global|mutable tag|digest-only|digest-plus-context|H_0|H_1|run-level' docs/RESEARCH_PROTOCOL_V1.md` | all required concepts present |
| Claim boundary | `rg -n 'not.*attack probability|not proof|prior art|falsif' docs/CLAIMS_V1.md` | explicit limitations present |
| Static gate | `make verify-static` | exit 0 |

## Scope

**In scope**:

- `docs/RESEARCH_PROTOCOL_V1.md` (create)
- `docs/THREAT_MODEL_V1.md` (create)
- `docs/CLAIMS_V1.md` (create)
- `docs/PROFILE_SCOPE_EXPERIMENT_V1.md` (create)
- `docs/FINAL_PHASES.md`
- `docs/FEATURE_SCHEMA_V1.md` (clarify v1 status only; do not redefine it)
- `scripts/check_research_protocol.py` (create; stdlib-only structural validator)
- `plans/README.md`

**Out of scope**:

- Runtime/model/database changes or data collection.
- Claiming Porygon invented behavioural profiling, Falco, eBPF telemetry, digest identity, conformal prediction, or any compared method.
- Choosing a winner among profile scopes before confirmatory results.
- File/network/DNS feature claims not captured by v1 telemetry.
- Real malware, public targets, or offensive deployment.

## Git workflow

- Branch `codex/003-freeze-research-protocol` from completed Plan 002.
- Configured Git identity only; no AI attribution, co-author trailers, or generated-by lines.
- Suggested commit: `docs: freeze Porygon research protocol`.
- Do not push.

## Steps

### Step 1: Freeze threat model and claim boundaries

Create `THREAT_MODEL_V1.md` defining assets, trusted components, high-privilege Docker-socket boundaries, attacker capabilities, telemetry/blind spots, baseline-poisoning risk, local single-host scope, and safety/ethics. Distinguish artifact identity (digest) from behavioural profile scope.

Create `CLAIMS_V1.md` with three lists: claims allowed before evaluation, claims allowed only if a named result supports them, and prohibited claims. Required wording: anomaly outputs are rarity/distance evidence rather than attack probability; deterministic matches are evidence rather than proof; scanner findings are not exploitation; behaviour profiling is prior art; profile-scope comparison is the proposed contribution.

**Verify**: the claim file maps every conditional claim to a table/metric identifier that will be produced by Plan 005.

### Step 2: Specify the profile-scope arms without selecting a winner

Define exactly four primary arms:

1. **Global**: one profile across all selected workloads.
2. **Mutable tag**: profile selected by the recorded tag as resolved at run start; record the resolved digest to expose tag drift.
3. **Digest-only**: current v1 identity.
4. **Digest-plus-context**: digest plus a canonical security-relevant runtime-context fingerprint.

Define the context fingerprint from normalized, non-secret configuration: entrypoint/command shape, configured user, privileged/read-only-rootfs flags, network mode, added/dropped capabilities, device exposure, published-port presence/shape, and mount destination/type/read-only state. Exclude environment values, secret-bearing arguments, host-specific mount source paths, container IDs/names, timestamps, and mutable runtime counters. Canonicalize sorted structures and version/hash the document. State how missing fields are represented.

Specify fragmentation safeguards: minimum independent training runs per stratum; unsupported contexts must return `insufficient_profile` rather than silently fall back in the primary analysis. A separately labelled fallback ablation may be evaluated.

**Verify**: the document includes canonical JSON examples for semantically equivalent reordered inputs producing one hash and one security-relevant change producing a different hash.

### Step 3: Freeze falsifiable questions, hypotheses, and independent units

The primary research question must be equivalent to: “Does conditioning runtime behavioural profiles on immutable image identity plus deployment context reduce benign false alarms while preserving controlled-scenario detection compared with global, tag, and digest-only baselines?”

State null and alternative hypotheses before data collection. Define the independent unit as a complete workload run/container trial, never an overlapping window. All fit/calibration/test assignment is by whole run. Predeclare random seeds and deterministic assignment. Use a pilot set only to estimate variance and finalize sample size; exclude pilot observations from confirmatory results.

Freeze at least three workload families (nginx, Redis, PostgreSQL) with at least two pinned image versions, multiple same-digest replicas, deterministic request/query generators, idle/load/configuration modes, and hard negatives such as maintenance shell, reload, backup, debug/admin action, traffic spike, and log rotation. Safe attack simulations must be isolated and ground-truthed.

Define primary metrics and confidence intervals: run-level false-positive rate, scenario recall, precision where prevalence is fixed and disclosed, time-to-first-evidence, occurrence-to-persistence latency, capture loss by boundary, CPU-seconds, peak RSS, disk writes, application p95 latency delta, and calibration coverage. Define family-wise/multiple-comparison handling and a run-level bootstrap or exact/binomial interval as appropriate. Do not use adjacent windows as independent samples.

**Verify**: every hypothesis maps to a workload/scenario, split, metric, statistical comparison, failure criterion, and output artifact path.

### Step 4: Freeze comparisons, ablations, failure criteria, and revision rules

Required detector comparisons: Falco/rules-only, novelty-only, frequency-only, sequence-only, calibrated Porygon anomaly-only, and hybrid. Required ablations: remove sequence, novelty, distribution shift, numeric/count features, and runtime context. Include cross-workload misapplication and same-image/different-context experiments.

Predeclare how a negative result is reported. Examples: digest-plus-context does not materially reduce run-level false positives; context fragmentation creates too many insufficient profiles; calibration fails under version drift; rules-only matches the hybrid; overhead exceeds the frozen budget. Negative results are valid project outcomes, not reasons to edit hypotheses.

Protocol revisions after freeze require a new version, rationale, timestamp, affected hypotheses, and an explicit exploratory/confirmatory reset. Never overwrite the original protocol.

**Verify**: `python3 scripts/check_research_protocol.py` validates unique IDs and complete links among questions, hypotheses, experiments, metrics, outputs, and claims.

## Test plan

- Structural validator tests malformed/missing IDs, duplicate IDs, unlinked claims, absent null hypothesis, window-level split leakage wording, and missing safety boundary.
- Canonical context examples prove order independence and security-relevant sensitivity without containing secret values.
- Human review must include one security reviewer and one methodology reviewer before marking the protocol frozen.

## Done criteria

- [x] Threat model, claims, profile-scope specification, and versioned protocol exist.
- [x] All fit/calibration/test splits are by independent run.
- [x] Four profile-scope arms, comparisons, ablations, metrics, and failure criteria are specified without selecting a winner.
- [x] Every conditional claim maps to a versioned Plan 005 artifact.
- [x] No confirmatory data was collected before freeze.
- [ ] One human security reviewer and one human methodology reviewer approve the protocol.
- [ ] After approval, status changes to `frozen`, static/structural checks pass, and Plan 003 is marked `DONE`.

## Execution record

The drift check passed on 2026-08-20 before editing. Six workload coordinates
were resolved to immutable OCI index digests without running workload trials.
The protocol package and stdlib-only structural validator were then created.
The validator includes negative fixtures for missing/duplicate IDs, unlinked
claims, absent null hypotheses, window-level split leakage, and a missing safety
boundary. No pilot or confirmatory workload data was collected.

Implementation is intentionally paused before Plan 004 because the required
human reviews are not administrative decoration: they are the independent
security and methodology checks required by this plan's test plan.

## STOP conditions

- Fewer than three reproducible workload families or two pinned versions can be specified.
- The protocol needs environment values, host paths, or command-line secrets in the context fingerprint.
- A hypothesis cannot be falsified by a named result.
- The proposed split allows windows from one run in more than one of fit/calibration/test.
- A reviewer asks to tune thresholds or exclusions after seeing confirmatory outcomes without versioning/resetting the protocol.

## Maintenance notes

This protocol is the scientific source of truth. Plan 004 must implement its calibration unit and semantics exactly; Plan 005 must emit its artifact IDs exactly. Any later feature addition needs a new protocol/model version and fresh confirmatory evaluation.
