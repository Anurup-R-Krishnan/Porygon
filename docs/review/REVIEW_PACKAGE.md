# Independent review package

This package is generated. Regenerate it with `python3 scripts/review_gate.py prepare`.

The study design requires two independent reviews before confirmatory results
may be collected. Everything else in the pipeline is automated; this is the one
step that is deliberately a human decision.

## What the reviewer is approving

- Protocol: `docs/RESEARCH_PROTOCOL_V1.md`
- Protocol SHA-256: `af5db33ca2fe153dbbe5dfe1f563890b0e6c9c224c191b18fea111dc93584759`
- Repository commit: `a7749ef251ab724d7e2b90530a15c19d876e7fc9`  (working tree has uncommitted changes)

A decision applies to the exact protocol bytes above. If the protocol changes
afterwards, the review is re-run against the new digest.

## Evidence available to the reviewer

- Trial records collected: 19 (19 completed, 0 failed)
- Structural validation of the protocol:
  - `[PASS] protocol schema, unique IDs, traceability, claims, split leakage, safety boundary, context canonicalization, and negative validator fixtures`
  - `[INFO] protocol status=review_pending; reviewers: security=pending, methodology=pending`

Supporting documents:

- `docs/THREAT_MODEL_V1.md` — assets, trust boundaries, attacker capabilities
- `docs/CLAIMS_V1.md` — what may and may not be claimed
- `docs/PROFILE_SCOPE_EXPERIMENT_V1.md` — profile arms and the context identity
- `docs/design-decisions.md` — why each decision was taken and what it costs
- `docs/execution-status.md` — measured state of every module
- `docs/final-verification-report.md` — gate results and measured findings

## Security reviewer checklist

1. Container privilege: every experiment container is disposable, memory and PID capped, published on loopback only, and removed by exact name plus label match.
2. Docker socket exposure: which services hold it, read-only or read-write, and why each needs it.
3. Scenario safety: the controlled scenarios execute only inert, fixture-only commands inside disposable containers. No malware, no external target, no destructive host action.
4. Secret minimisation: command arguments are reduced to a shape before storage; the artifact writer refuses to persist a secret-like value and names only the location when it does.
5. Containment authority: response stays observe-only by default and no disruptive action is reachable without explicit human approval.
6. Blast radius: confirm cleanup cannot touch a resource outside the current trial, and that the refusal paths are tested rather than assumed.
7. Data retention: confirm the capture scope and retention settings keep only what the study needs.

Record the decision in `docs/review/security-review.json`: set `reviewer_name`,
`date`, `decision`, and mark each checklist entry `ok` or describe the concern.

## Methodology reviewer checklist

1. Independent unit: the unit of analysis is a complete workload run, never an observation window inside a run.
2. Split isolation: fit, calibration and test assignment is by whole run, computed from the run identifier before execution, and leakage fails validation rather than warning.
3. Hypotheses and failure criteria: the null and alternative hypotheses, the effect size, and the conditions under which the result is reported as negative, are all fixed before collection.
4. Estimands and multiplicity: the primary contrasts, the family-wise correction, and the interval method are stated and match the analysis code.
5. Calibration validity: the conformal procedure's exchangeability assumption is stated, and drift is surfaced rather than absorbed.
6. Context variants: each runtime-context variant is classified as a positive or negative control from measured evidence, not assumed.
7. Claim boundaries: no output is described as a probability of attack, and deterministic rule matches are evidence rather than proof.
8. Sample size: the recorded counts per cell support the stated power, or the limitation is reported instead of a superiority claim.

Record the decision in `docs/review/methodology-review.json`: set `reviewer_name`,
`date`, `decision`, and mark each checklist entry `ok` or describe the concern.

## Applying the decisions

```bash
python3 scripts/review_gate.py status
python3 scripts/review_gate.py apply
```

`apply` moves the protocol to frozen only when both files record a genuine
approval with a reviewer name and a date. It then re-runs structural validation.
A decision of `changes_requested` or `rejected` leaves the protocol unchanged.
