# Porygon Research Protocol v1

Protocol identifier: `porygon.research.protocol.v1`

Document version: `1.0.0-review-pending`

Prepared: 2026-08-20

Status: **REVIEW PENDING — CONFIRMATORY COLLECTION PROHIBITED**

## Problem statement and contribution

Container runtime behaviour varies across workloads, image versions, replicas,
load, maintenance, and deployment security context. A profile that is too broad
may hide useful deviations; a profile that is too narrow may fragment its data
and fail on ordinary change. Porygon tests where that trade-off lands for its
current Docker lifecycle and process-execution evidence.

Behavioural profiling is prior art. The proposed contribution is a reproducible
profile-scope comparison, with explicit insufficient-profile outcomes, against
global, mutable-tag, digest-only, and digest-plus-context arms. The experiment
does not preselect a winning arm.

Primary research question (`RQ-001`): **Does conditioning runtime behavioural
profiles on immutable image identity plus deployment context reduce benign
false alarms while preserving controlled-scenario detection compared with
global, mutable tag, and digest-only baselines?**

Secondary questions test calibration/version drift (`RQ-002`) and whether the
measured capture path and overhead are acceptable for a single-host research
sensor (`RQ-003`).

## Scope and safety

The authoritative threat, trust, telemetry, ethics, and safety boundary is
[`THREAT_MODEL_V1.md`](THREAT_MODEL_V1.md). Only disposable local containers,
synthetic data, and deterministic safe actions are permitted. Real malware,
public targets, destructive actions, unauthorized destinations, and automated
disruptive response are prohibited.

Version 1 features are Docker lifecycle/exec evidence and Falco process
execution. File, DNS, socket, general network-flow, and dedicated
privilege-transition claims are excluded.

## Profile-scope arms

[`PROFILE_SCOPE_EXPERIMENT_V1.md`](PROFILE_SCOPE_EXPERIMENT_V1.md) defines the
four primary arms and `porygon.runtime-context.v1` canonicalization:

- `ARM-GLOBAL`: global;
- `ARM-TAG`: mutable tag, with resolved digest retained to expose drift;
- `ARM-DIGEST`: digest-only;
- `ARM-CONTEXT`: digest-plus-context.

Unsupported primary strata return `insufficient_profile`; they never silently
fall back. `ABL-FALLBACK` is separately labelled and secondary.

## Independent unit and leakage prevention

The sole independent unit is one **complete workload run/container trial**,
identified before execution. A run includes its setup, warm-up, measurement,
ground truth, teardown, and all windows. Adjacent or overlapping windows are
repeated observations within that run, never independent samples.

Every fit, calibration, pilot, confirmatory-test, or exploratory assignment is
made by whole run. A container and every window derived from it inherit exactly
one split. No event, window, container, replica trial, or retry crosses splits.
A failed run retains its assignment and failure record; a replacement receives
a new run ID and is not substituted after outcomes are inspected.

## Deterministic assignment and seeds

Frozen seeds:

| Use | Seed |
|---|---:|
| Run/split assignment | `20260820` |
| Workload-generator parameters | `20260821` |
| Scenario timing | `20260822` |
| Run-level bootstrap | `20260823` |
| Permutation/tie breaking | `20260824` |

Plan 005 constructs each planned run ID before execution, hashes
`"porygon.research.protocol.v1:<seed>:<run_id>"` with SHA-256, sorts within each
predeclared workload-version-mode-scenario stratum, and assigns the required
counts in fit, calibration, pilot, and confirmatory order. Assignment manifests
are immutable once written.

Pilot runs estimate duration, discordant-pair rates, and run-level variance and
test generators only. There are five pilot runs per
workload-version-mode/scenario cell. Pilot observations are excluded from fit,
calibration, threshold selection, and confirmatory results.

The minimum confirmatory counts below are increased, never decreased, by a
predeclared power rule. For each primary paired FPR and recall-noninferiority
contrast, Plan 005 enumerates candidate per-cell counts from the minimum through
120 and selects the smallest count whose exact binomial enumeration reaches 80%
power. Planning uses conservative two-sided alpha `0.05/3` for the three FPR
contrasts and one-sided alpha `0.05` for the co-primary recall gate; analysis
still reports the frozen Holm-adjusted FPR family. The material effect is
the frozen 25% relative FPR reduction or 5-percentage-point recall margin; it is
not replaced by a pilot effect. The nuisance discordant-pair probability is the
upper 95% binomial bound from pilot pairs, with 0.5 used when the bound is
undefined. The maximum across co-primary contrasts becomes the final per-cell
count in `ART-DES-001`. If no count through 120 reaches power, confirmatory
collection stops for a feasibility decision and protocol revision.

The versioned sample-size lock records inputs, enumeration code hash, results,
and both reviewer approvals before confirmatory execution. Once one
confirmatory run starts, v1 counts and criteria cannot change.

## Workloads and run counts

Three workload families and two immutable versions per family are frozen in the
profile-scope specification: nginx (`WL-NGX-V1/V2`), Redis (`WL-RDS-V1/V2`), and
PostgreSQL (`WL-PG-V1/V2`). Plan 005 must lock exact platform manifests and
local image IDs before pilots.

Every version uses at least three distinct same-digest replica containers per
split. Deterministic generators use fixture data and record seed, request/query
count, duration, concurrency, successes, failures, and latency distribution.

| Family | Benign modes | Required hard negatives |
|---|---|---|
| nginx | idle; steady HTTP; burst HTTP; alternate read-only config | config validation/reload, maintenance shell, traffic spike, log rotation |
| Redis | idle; steady SET/GET; burst pipeline; persistence-enabled context | `BGSAVE`, admin inspection, maintenance shell, traffic spike/log rotation |
| PostgreSQL | idle; read-only query mix; read/write transaction mix; alternate tuning context | `pg_dump` backup, config reload, admin query/debug, maintenance shell/log rotation |

Primary fit and calibration require 10 independent clean runs per supported
profile stratum in each split. Confirmatory benign evaluation requires 30 runs
per workload-version-mode cell. Confirmatory controlled-scenario evaluation
requires 20 runs per applicable workload-version-scenario cell. Hard negatives
are benign ground truth and remain in the false-positive denominator.

## Controlled scenarios and ground truth

Safe scenario families are:

- `SCN-EXEC`: unexpected shell followed by a fixture-only encoding or inspection
  tool;
- `SCN-LOW`: the same safe sequence spread over a low-and-slow schedule;
- `SCN-FLOOD`: a bounded exec-event flood used for capture and detector stress;
- `SCN-CROSS`: deliberate cross-workload profile misapplication;
- `SCN-CONTEXT`: same digest under a security-relevant context change;
- `SCN-POISON`: 1%, 5%, and 10% labelled contamination added only to copied
  fit sets for sensitivity analysis.

Each scenario has a prewritten manifest with run ID, scenario ID, expected
container/digest/context identity, planned start interval, ground-truth class,
and safe command template hash. The orchestrator records host realtime and
monotonic timestamps immediately before/after the action. Detector output never
defines ground truth. Aborted or mistimed actions are failed runs, not negatives.

## Comparators and ablations

Required detector comparisons use identical confirmatory runs:

- `DET-RULES`: Falco/Porygon deterministic rules-only;
- `DET-NOVELTY`: novelty-only;
- `DET-FREQUENCY`: frequency/distribution-only;
- `DET-SEQUENCE`: sequence-only;
- `DET-CALIBRATED`: calibrated Porygon anomaly-only;
- `DET-HYBRID`: calibrated anomaly evidence plus deterministic rules.

Required ablations are `ABL-NO-SEQUENCE`, `ABL-NO-NOVELTY`,
`ABL-NO-DISTRIBUTION`, `ABL-NO-NUMERIC`, `ABL-NO-CONTEXT`, and the separately
reported `ABL-FALLBACK`. Cross-workload misapplication and same-image,
different-context experiments are mandatory.

## Hypotheses and failure criteria

`H_0_001`: Relative to each simpler arm, digest-plus-context does not reduce
benign run-level false-positive rate by at least 25%, or its controlled-scenario
recall is more than 5 percentage points worse.

`H_1_001`: Digest-plus-context achieves at least a 25% relative benign FPR
reduction against at least digest-only, with the simultaneous interval excluding
zero, while recall is non-inferior within 5 percentage points.

`H_0_002`: Held-out benign calibration coverage misses its nominal 95% target by
more than 3 percentage points, or version/context drift is silently treated as
in-distribution.

`H_1_002`: Held-out benign run-level coverage is within 92%–98%, while drift and
unsupported strata are explicitly represented rather than silently accepted.

`H_0_003`: A mandatory capture boundary is unmeasured, downstream loss exceeds
0.1% outside a declared saturation test, or any frozen overhead budget is
exceeded.

`H_1_003`: Every available boundary is measured/labeled, downstream loss is at
most 0.1%, and all frozen overhead budgets are met.

Failure to reject a null is reported as a negative result. Context fragmentation
above 10% `insufficient_profile` on planned test runs, a calibration interval
outside tolerance, rules-only equivalence/superiority, or failure to meet an
overhead budget prevents the corresponding conditional claim.

## Metrics and estimands

- `MET-FPR-001`: fraction of independent benign runs with at least one
  unsuppressed detector-positive outcome. Report numerator/denominator and
  run-level interval; do not count windows as independent.
- `MET-REC-001`: fraction of successfully executed ground-truthed scenario runs
  with detector evidence inside the frozen scenario horizon.
- `MET-PREC-001`: true-positive runs divided by all positive runs only in the
  disclosed fixed evaluation prevalence; it is not deployment prevalence.
- `MET-TFE-001`: ground-truth action start to first qualifying persisted evidence.
- `MET-OTP-001`: source occurrence to durable PostgreSQL persistence latency,
  with clock source and boundary named.
- `MET-LOSS-001`: generated → source-observed → durably enqueued → accepted →
  inserted unique-event counts and loss fraction at each measurable boundary;
  unmeasured boundaries remain explicit.
- `MET-CPU-001`: sensor/control-plane CPU-seconds per run and normalized per
  workload-minute.
- `MET-RSS-001`: peak service and aggregate Porygon RSS per run.
- `MET-DISK-001`: bytes written by Porygon volumes/logs per run.
- `MET-LAT-001`: application p95 latency percentage delta versus a paired
  sensor-disabled control run with the same seed.
- `MET-CAL-001`: run-level benign calibration coverage at nominal 95%.
- `MET-INSUF-001`: fraction of planned test runs returning
  `insufficient_profile`, retained in the denominator.

Frozen overhead budgets for `H_1_003`: aggregate Porygon CPU no more than 1.0
CPU-second per workload-minute at steady load; aggregate peak RSS no more than
1.5 GiB; Porygon disk writes no more than 100 MiB per workload-hour excluding
explicit retained raw debug evidence; application p95 latency median delta no
more than 5% and simultaneous upper confidence bound no more than 10%.

## Statistical analysis

All comparisons are paired on the same independent runs where defined and
stratified by workload family and version. Primary pairwise FPR contrasts use
exact McNemar tests and paired effect intervals. Recall non-inferiority uses a
run-level stratified bootstrap with 10,000 resamples and seed `20260823`.
Proportions include exact/binomial intervals; medians and latency/overhead
effects include run-level bootstrap intervals.

The family of three primary `ARM-CONTEXT` FPR comparisons is controlled at
family-wise alpha 0.05 with Holm correction. Recall non-inferiority is a
co-primary gate and must pass; it cannot be traded for FPR. Detector-comparison
and ablation families each use Holm correction separately and are labelled
secondary. Report raw and adjusted p-values, effect sizes, denominators,
confidence intervals, missing/failed/insufficient counts, and all planned cells.

No result is promoted based only on a p-value. The frozen material thresholds,
intervals, and failure criteria determine conditional claims.

## Artifact and provenance contract

Plan 005 writes under `artifacts/experiments/protocol-v1/`:

- `ART-MAN-001`: `manifest/run-manifest.jsonl`, one immutable row per planned or
  attempted run plus hashes of protocol, images, configuration, rules, model,
  seeds, ground truth, and raw local evidence references;
- `ART-TBL-001`: `tables/profile-scope-primary.csv`;
- `ART-TBL-002`: `tables/detector-comparison.csv`;
- `ART-TBL-003`: `tables/calibration-and-drift.csv`;
- `ART-TBL-004`: `tables/capture-and-overhead.csv`;
- `ART-TBL-005`: `tables/poisoning-sensitivity.csv`;
- `ART-FIG-001`: `figures/run-level-effects.pdf` plus source table/hash.
- `ART-DES-001`: `design/sample-size-lock.json`, the pilot-derived pre-
  confirmatory count lock and exact-enumeration provenance.

Every table row includes protocol version/hash, implementation commit, image
coordinate/platform digest, profile arm, detector, ablation, split, workload,
version, context hash, run counts, exclusions/failures, metric definition, and
analysis revision. Tables and figures are generated, never hand-edited.

## Negative results, exclusions, and deviations

All planned runs appear in the manifest. Valid exclusions are limited to
predeclared infrastructure failure, image/artifact unavailable, generator failed
before ground-truth action, identity mismatch, clock failure, or corrupted raw
artifact. Detector disagreement, no detection, high overhead, loss, unexpected
benign behaviour, and insufficient profile are outcomes, not exclusions.

Digest-plus-context may fail by not reducing FPR, losing recall, fragmenting
support, or failing calibration under drift. Rules-only may match or outperform
the hybrid. Overhead may exceed budget. These are valid publishable conclusions
and never reasons to edit v1 after outcomes are observed.

## Protocol revision and freeze rule

After freeze, any change requires a new version, rationale, timestamp, affected
question/hypothesis/claim IDs, reviewer decisions, and an explicit reset of
exploratory and confirmatory status. The original protocol and artifacts are
never overwritten. Threshold/model changes after confirmatory start require a
new confirmatory dataset.

No confirmatory data has been collected for this protocol. Plan 004 and Plan 005
must not begin confirmatory execution until both required human reviews approve
this document and status becomes `frozen`.

## Human review record

| Role | Reviewer | Date | Decision | Notes |
|---|---|---|---|---|
| Security reviewer | **pending** | — | pending | Must review trust boundaries, scenarios, secret minimization, and Docker privilege. |
| Methodology reviewer | **pending** | — | pending | Must review independent units, splits, hypotheses, estimands, multiplicity, and failure criteria. |

## Machine-readable traceability manifest

```json protocol-manifest
{
  "schema_version": "porygon.research-protocol-manifest.v1",
  "protocol_id": "porygon.research.protocol.v1",
  "protocol_status": "review_pending",
  "independent_unit": "complete_workload_run",
  "split_policy": "whole-run assignment; no event, container, adjacent window, or overlapping window crosses fit/calibration/pilot/confirmatory splits",
  "safety_boundary": "disposable local containers and synthetic data only; no real malware, no public targets, no destructive payloads, no unauthorized destinations, and no automated disruptive response",
  "seeds": {
    "assignment": 20260820,
    "workload": 20260821,
    "scenario": 20260822,
    "bootstrap": 20260823,
    "permutation": 20260824
  },
  "arms": ["ARM-GLOBAL", "ARM-TAG", "ARM-DIGEST", "ARM-CONTEXT"],
  "detectors": ["DET-RULES", "DET-NOVELTY", "DET-FREQUENCY", "DET-SEQUENCE", "DET-CALIBRATED", "DET-HYBRID"],
  "ablations": ["ABL-NO-SEQUENCE", "ABL-NO-NOVELTY", "ABL-NO-DISTRIBUTION", "ABL-NO-NUMERIC", "ABL-NO-CONTEXT", "ABL-FALLBACK"],
  "workloads": [
    {"id": "WL-NGX", "versions": ["WL-NGX-V1", "WL-NGX-V2"], "modes": ["idle", "steady_http", "burst_http", "alternate_read_only_config"]},
    {"id": "WL-RDS", "versions": ["WL-RDS-V1", "WL-RDS-V2"], "modes": ["idle", "steady_set_get", "burst_pipeline", "persistence_context"]},
    {"id": "WL-PG", "versions": ["WL-PG-V1", "WL-PG-V2"], "modes": ["idle", "read_only_queries", "read_write_transactions", "alternate_tuning_context"]}
  ],
  "scenarios": [
    {"id": "SCN-EXEC", "ground_truth": "controlled_positive", "safe": true},
    {"id": "SCN-LOW", "ground_truth": "controlled_positive", "safe": true},
    {"id": "SCN-FLOOD", "ground_truth": "controlled_positive", "safe": true},
    {"id": "SCN-CROSS", "ground_truth": "scope_misapplication", "safe": true},
    {"id": "SCN-CONTEXT", "ground_truth": "context_shift", "safe": true},
    {"id": "SCN-POISON", "ground_truth": "labelled_fit_contamination", "safe": true}
  ],
  "questions": [
    {"id": "RQ-001", "text": "Does immutable image identity plus deployment context reduce benign false alarms while preserving controlled-scenario detection compared with global, mutable-tag, and digest-only profiles?"},
    {"id": "RQ-002", "text": "Does run-level calibration retain nominal benign coverage and expose version/context drift?"},
    {"id": "RQ-003", "text": "Is the measured capture path complete at named boundaries and within the frozen single-host overhead budget?"}
  ],
  "hypotheses": [
    {
      "id": "H_0_001",
      "kind": "null",
      "question_ids": ["RQ-001"],
      "experiment_ids": ["EXP-001", "EXP-002"],
      "metric_ids": ["MET-FPR-001", "MET-REC-001", "MET-TFE-001", "MET-INSUF-001"],
      "output_ids": ["ART-TBL-001", "ART-TBL-002", "ART-FIG-001", "ART-MAN-001", "ART-DES-001"],
      "failure_criterion": "Context does not achieve the frozen material FPR reduction, recall crosses the -5 percentage-point margin, or insufficient profiles exceed 10%."
    },
    {
      "id": "H_1_001",
      "kind": "alternative",
      "question_ids": ["RQ-001"],
      "experiment_ids": ["EXP-001", "EXP-002"],
      "metric_ids": ["MET-FPR-001", "MET-REC-001", "MET-TFE-001", "MET-INSUF-001"],
      "output_ids": ["ART-TBL-001", "ART-TBL-002", "ART-FIG-001", "ART-MAN-001", "ART-DES-001"],
      "failure_criterion": "Unsupported unless the simultaneous FPR effect and recall non-inferiority gates both pass."
    },
    {
      "id": "H_0_002",
      "kind": "null",
      "question_ids": ["RQ-002"],
      "experiment_ids": ["EXP-003"],
      "metric_ids": ["MET-CAL-001", "MET-INSUF-001"],
      "output_ids": ["ART-TBL-003", "ART-MAN-001", "ART-DES-001"],
      "failure_criterion": "Coverage lies outside 92%-98% or drift/unsupported strata are silently treated as in-distribution."
    },
    {
      "id": "H_1_002",
      "kind": "alternative",
      "question_ids": ["RQ-002"],
      "experiment_ids": ["EXP-003"],
      "metric_ids": ["MET-CAL-001", "MET-INSUF-001"],
      "output_ids": ["ART-TBL-003", "ART-MAN-001", "ART-DES-001"],
      "failure_criterion": "Unsupported unless run-level coverage meets tolerance and drift remains explicit."
    },
    {
      "id": "H_0_003",
      "kind": "null",
      "question_ids": ["RQ-003"],
      "experiment_ids": ["EXP-004"],
      "metric_ids": ["MET-LOSS-001", "MET-OTP-001", "MET-CPU-001", "MET-RSS-001", "MET-DISK-001", "MET-LAT-001"],
      "output_ids": ["ART-TBL-004", "ART-MAN-001", "ART-DES-001"],
      "failure_criterion": "A mandatory boundary is absent, loss exceeds 0.1%, or any frozen overhead budget is exceeded."
    },
    {
      "id": "H_1_003",
      "kind": "alternative",
      "question_ids": ["RQ-003"],
      "experiment_ids": ["EXP-004"],
      "metric_ids": ["MET-LOSS-001", "MET-OTP-001", "MET-CPU-001", "MET-RSS-001", "MET-DISK-001", "MET-LAT-001"],
      "output_ids": ["ART-TBL-004", "ART-MAN-001", "ART-DES-001"],
      "failure_criterion": "Unsupported unless every named measurement and every overhead budget passes."
    }
  ],
  "experiments": [
    {
      "id": "EXP-001",
      "question_ids": ["RQ-001"],
      "hypothesis_ids": ["H_0_001", "H_1_001"],
      "workload_ids": ["WL-NGX", "WL-RDS", "WL-PG"],
      "scenario_ids": ["SCN-EXEC", "SCN-LOW", "SCN-CONTEXT", "SCN-CROSS"],
      "split": "whole-run fit/calibration/confirmatory",
      "metric_ids": ["MET-FPR-001", "MET-REC-001", "MET-TFE-001", "MET-INSUF-001"],
      "output_ids": ["ART-TBL-001", "ART-FIG-001", "ART-MAN-001"],
      "failure_criterion": "No material FPR gain, recall inferiority, or context fragmentation above 10%."
    },
    {
      "id": "EXP-002",
      "question_ids": ["RQ-001"],
      "hypothesis_ids": ["H_0_001", "H_1_001"],
      "workload_ids": ["WL-NGX", "WL-RDS", "WL-PG"],
      "scenario_ids": ["SCN-EXEC", "SCN-LOW", "SCN-FLOOD"],
      "split": "whole-run confirmatory detector comparison",
      "metric_ids": ["MET-FPR-001", "MET-REC-001", "MET-PREC-001", "MET-TFE-001"],
      "output_ids": ["ART-TBL-002", "ART-FIG-001", "ART-MAN-001"],
      "failure_criterion": "Rules-only or component-only detector is equivalent or superior to hybrid under the frozen trade-off."
    },
    {
      "id": "EXP-003",
      "question_ids": ["RQ-002"],
      "hypothesis_ids": ["H_0_002", "H_1_002"],
      "workload_ids": ["WL-NGX", "WL-RDS", "WL-PG"],
      "scenario_ids": ["SCN-CONTEXT", "SCN-CROSS"],
      "split": "whole-run calibration and held-out confirmatory drift",
      "metric_ids": ["MET-CAL-001", "MET-INSUF-001"],
      "output_ids": ["ART-TBL-003", "ART-MAN-001"],
      "failure_criterion": "Calibration tolerance fails or unsupported drift is silently scored."
    },
    {
      "id": "EXP-004",
      "question_ids": ["RQ-003"],
      "hypothesis_ids": ["H_0_003", "H_1_003"],
      "workload_ids": ["WL-NGX", "WL-RDS", "WL-PG"],
      "scenario_ids": ["SCN-FLOOD"],
      "split": "whole-run paired sensor-on and sensor-disabled control",
      "metric_ids": ["MET-LOSS-001", "MET-OTP-001", "MET-CPU-001", "MET-RSS-001", "MET-DISK-001", "MET-LAT-001"],
      "output_ids": ["ART-TBL-004", "ART-MAN-001"],
      "failure_criterion": "Missing boundary measurement, loss above 0.1%, or any overhead budget failure."
    },
    {
      "id": "EXP-005",
      "question_ids": ["RQ-001", "RQ-002"],
      "hypothesis_ids": ["H_0_001", "H_1_001", "H_0_002", "H_1_002"],
      "workload_ids": ["WL-NGX", "WL-RDS", "WL-PG"],
      "scenario_ids": ["SCN-POISON"],
      "split": "copied fit sets only; clean confirmatory runs remain unchanged",
      "metric_ids": ["MET-FPR-001", "MET-REC-001", "MET-CAL-001"],
      "output_ids": ["ART-TBL-005", "ART-MAN-001"],
      "failure_criterion": "Contamination causes degradation beyond the predeclared clean-baseline comparison."
    }
  ],
  "metrics": [
    {"id": "MET-FPR-001", "unit": "independent benign run", "estimand": "run-level false-positive proportion"},
    {"id": "MET-REC-001", "unit": "independent controlled-scenario run", "estimand": "scenario recall"},
    {"id": "MET-PREC-001", "unit": "independent run at disclosed prevalence", "estimand": "precision"},
    {"id": "MET-TFE-001", "unit": "independent detected run", "estimand": "time to first qualifying evidence"},
    {"id": "MET-OTP-001", "unit": "event nested in independent run", "estimand": "occurrence-to-persistence latency"},
    {"id": "MET-LOSS-001", "unit": "measurement boundary nested in run", "estimand": "capture loss by named boundary"},
    {"id": "MET-CPU-001", "unit": "independent run", "estimand": "CPU-seconds and normalized CPU cost"},
    {"id": "MET-RSS-001", "unit": "independent run", "estimand": "peak RSS"},
    {"id": "MET-DISK-001", "unit": "independent run", "estimand": "Porygon bytes written"},
    {"id": "MET-LAT-001", "unit": "paired independent run", "estimand": "application p95 latency delta"},
    {"id": "MET-CAL-001", "unit": "independent benign run", "estimand": "nominal 95% calibration coverage"},
    {"id": "MET-INSUF-001", "unit": "planned independent test run", "estimand": "insufficient-profile proportion"}
  ],
  "outputs": [
    {"id": "ART-MAN-001", "path": "artifacts/experiments/protocol-v1/manifest/run-manifest.jsonl"},
    {"id": "ART-TBL-001", "path": "artifacts/experiments/protocol-v1/tables/profile-scope-primary.csv"},
    {"id": "ART-TBL-002", "path": "artifacts/experiments/protocol-v1/tables/detector-comparison.csv"},
    {"id": "ART-TBL-003", "path": "artifacts/experiments/protocol-v1/tables/calibration-and-drift.csv"},
    {"id": "ART-TBL-004", "path": "artifacts/experiments/protocol-v1/tables/capture-and-overhead.csv"},
    {"id": "ART-TBL-005", "path": "artifacts/experiments/protocol-v1/tables/poisoning-sensitivity.csv"},
    {"id": "ART-FIG-001", "path": "artifacts/experiments/protocol-v1/figures/run-level-effects.pdf"},
    {"id": "ART-DES-001", "path": "artifacts/experiments/protocol-v1/design/sample-size-lock.json"}
  ],
  "conditional_claims": [
    {"id": "CLM-C001", "metric_ids": ["MET-FPR-001", "MET-INSUF-001"], "output_ids": ["ART-TBL-001", "ART-FIG-001", "ART-MAN-001"]},
    {"id": "CLM-C002", "metric_ids": ["MET-REC-001", "MET-FPR-001", "MET-TFE-001"], "output_ids": ["ART-TBL-001", "ART-FIG-001", "ART-MAN-001"]},
    {"id": "CLM-C003", "metric_ids": ["MET-CAL-001"], "output_ids": ["ART-TBL-003", "ART-MAN-001"]},
    {"id": "CLM-C004", "metric_ids": ["MET-LOSS-001", "MET-OTP-001", "MET-CPU-001", "MET-RSS-001", "MET-DISK-001", "MET-LAT-001"], "output_ids": ["ART-TBL-004", "ART-MAN-001"]},
    {"id": "CLM-C005", "metric_ids": ["MET-PREC-001", "MET-REC-001", "MET-FPR-001"], "output_ids": ["ART-TBL-002", "ART-FIG-001", "ART-MAN-001"]},
    {"id": "CLM-C006", "metric_ids": ["MET-FPR-001", "MET-REC-001", "MET-CAL-001"], "output_ids": ["ART-TBL-005", "ART-MAN-001"]}
  ],
  "reviewers": [
    {"role": "security", "status": "pending", "name": null, "date": null},
    {"role": "methodology", "status": "pending", "name": null, "date": null}
  ]
}
```
