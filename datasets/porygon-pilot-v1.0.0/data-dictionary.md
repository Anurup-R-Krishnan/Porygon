# Data dictionary

CSV booleans use Python spelling `True`/`False`; JSON booleans use `true`/`false`.

| Index column | Meaning |
|---|---|
| `trial_id` | Unique complete-container-trial identifier; join key to trials/<trial_id>.json. |
| `run_id` | Collection session identifier. Historical naming does not establish evidence class. |
| `workload_id` | WL-NGX-V1 (nginx), WL-RDS-V1 (Redis), or WL-PG-V1 (PostgreSQL). |
| `scenario_id` | SCN-EXEC, SCN-LOG4SHELL-SIM, or SCN-RUNC-ESCAPE-SIM. |
| `context_variant` | baseline or dropped_capabilities; latter drops NET_RAW. |
| `replica_index` | Integer replicate 1–12 within a workload/scenario/context cell. |
| `image_digest` | Repository@sha256 identity copied from ground truth. |
| `runtime_context_hash` | Source hash of canonical runtime context; retain original value. |
| `source_split` | Original trial split (pilot for all records). |
| `release_split` | Conservative reuse split: pilot for every record. |
| `evidence_class` | pilot; not confirmatory evidence. |
| `research_eligible` | False; eligibility for confirmatory study, not a ban on exploratory reuse. |
| `label` | Harness-derived controlled_attack_like or controlled_non_attack_like. |
| `simulation_only` | True; inert controlled scenario. |
| `exploit_executed` | False; no exploit was executed. |

## Source JSON structures

Original trial files retain the `porygon.experiment.trial.v2` schema.

| Field/group | Interpretation |
|---|---|
| `schema_version`, `status` | Artifact schema and collection outcome. All packaged trials completed. |
| `image`, `human_tag` | Image inventory, platform and digest identifiers. Tags are mutable descriptions. |
| `runtime_context`, `runtime_context_source_hash` | Canonical capability, mount, port, command, user, network and privilege configuration and source hash. |
| `context_variant_kind` | Historical probe classification; not an attack label. |
| `container_id`, `container_name` | Historical disposable-container identifiers; not active targets. |
| `ground_truth` | Harness scenario, action timestamps, canary IDs, safety flags and expected outcome. |
| `load` | Requested/completed workload operations and request-path latency samples in milliseconds. These include harness/connection overhead and do not measure detector latency. |
| `timeline` | UTC wall-clock timestamps and explicitly named monotonic nanosecond fields. Monotonic values only compare within their clock domain. |
| `measurement_duration_ns` | Harness measurement interval in nanoseconds; not end-to-end detection latency. |
| `reconciliation` | Generated canary sequences and per-boundary observations, duplicates, missing sequences and loss fractions. `unmeasured` is missing evidence, never zero loss. |
| `readiness` | Readiness probe and delay in milliseconds. |
| `cleanup` | Original exact container name and removal outcome. |
| `mode`, `seed`, `workload_family` | Workload execution mode, source PRNG seed and workload family. |
| `eligibility_reason` | Historical reason string; may describe an earlier protocol state. |

Nested source objects are preserved unchanged; field names ending `_utc`, `_ns`,
`_ms`, `_sha256` and `_hash` specify timestamp, unit or identity semantics. Empty
arrays mean observed empty configuration when recorded; absent fields are not
imputed. Ground truth's action interval is the scenario interval; the separate
measurement interval can precede it and must not be used as an attack window.
