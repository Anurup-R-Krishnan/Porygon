# Annotation guidelines

Labels are derived mechanically from the original `ground_truth.attack_like`
boolean, never from the detector's prediction or a process executable name.

| Source | Release label | Meaning |
|---|---|---|
| `attack_like = false` | `controlled_non_attack_like` | Controlled SCN-EXEC harness execution; not evidence of a real attack. |
| `attack_like = true` | `controlled_attack_like` | SCN-LOG4SHELL-SIM or SCN-RUNC-ESCAPE-SIM inert simulated behavior; not successful exploitation. |

Every record must declare `simulation_only = true` and `exploit_executed = false`.
The builder refuses unexpected eligibility, split, status, count or matrix values.
The verifier cross-checks index labels against original trial ground truth.

Preserve `ground_truth.expected_outcome` and `context_variant_kind` as historical
harness annotations. They are not replacements for the release label. In particular,
`controlled_positive` in an SCN-EXEC record must not turn that record into an attack.
Dropping NET_RAW is a configuration change, not itself an attack label.

Known quality limits: harness-authored labels; no independent adjudication;
inert scenarios only; one host and collection session; no source event-level
annotation or classifier labels. Correct errors through a new version with an
explicit correction log; retain source records and their original hashes.
