# Pilot Result Summary

> **Evidence class: pilot, not confirmatory.** These are real Docker-container
> trials with real measured statistics, but every trial and run record for
> both rounds below carries `kind: "real_container_pilot"` and
> `research_eligible: false`. An earlier version of this document, and the
> study-level summary manifest it was generated from, mislabeled this result
> `evidence_class: confirmatory` / `research_eligible: true` due to a bug in
> the study-summary step (now fixed). No confirmatory-grade run has ever been
> collected: a confirmatory run requires the frozen protocol's full
> conformance machinery (not yet built) in addition to protocol freeze and
> review sign-off. The numbers below (p-values, confidence intervals, trial
> counts) are unchanged and were independently re-verified as arithmetically
> correct — only the evidence-class label was wrong.

**Latest run:** `study-confirmatory-200-20260906t071234Z` (216 real Docker-container trials, `evidence_class: pilot`, `research_eligible: false`; the run ID retains its original `confirmatory` naming for provenance/traceability, not as a claim about evidence class)
**Analysis artifact:** `artifacts/experiments/protocol-v1/tables/profile-scope-primary-216.json`
**First round (superseded, kept for provenance):** `study-20260905t181654Z` (144 trials, also `evidence_class: pilot`, `research_eligible: false`) — `artifacts/experiments/protocol-v1/tables/profile-scope-primary.json`
**Protocol:** `porygon.research.protocol.v1`, status `FROZEN`, both reviews approved (`docs/review/*.json`) — freeze and review are necessary but not sufficient for confirmatory status; see the evidence-class note above
**Reproduce the analysis:** `python3 -m experiments.analyze_scope_run <run_dir> --out <path>`

## Question

Does conditioning a behavioral profile on immutable image digest + deployment context (`ARM-CONTEXT`) reduce benign false-alarm rate while preserving detection recall, versus a global profile (`ARM-GLOBAL`), a mutable-tag profile (`ARM-TAG`), or a digest-only profile (`ARM-DIGEST`)?

## Result (216-trial round, n roughly 1.5x the first round)

| Arm | FPR (benign, n=53) | Recall (real attack scenarios, n=96) |
|---|---|---|
| `ARM-GLOBAL` | 53/53 = 100% [95% CI 93.3–100%] | 96/96 = 100% [95% CI 96.2–100%] |
| `ARM-TAG` | 0/53 = 0% [95% CI 0–6.7%] | 96/96 = 100% |
| `ARM-DIGEST` | 0/53 = 0% [95% CI 0–6.7%] | 96/96 = 100% |
| `ARM-CONTEXT` | 0/53 = 0% [95% CI 0–6.7%] | 96/96 = 100% |

**`CONTEXT` vs `GLOBAL`:** exact McNemar p = 2.2×10⁻¹⁶ (Holm-adjusted 6.7×10⁻¹⁶), relative FPR reduction 100% (≫ the frozen 25% material-effect threshold), recall non-inferior. **H1 supported** (`experiments/analysis.py:decide_primary_contrast`). This reproduces the first round's result (p was 5.8×10⁻¹¹ at n=35) at larger n with an even smaller p-value — the pooled-baseline finding is robust, not a small-sample artifact.

**`CONTEXT` vs `DIGEST` (the paper's actual thesis) is again a null result: p = 1.0, zero
discordant pairs, arms agree on all 53 held-out trials.** This replicates the first round's null result exactly, at 1.5x the sample size. `CONTEXT` beating `GLOBAL` must not be read as, or cited as, support for the paper's headline claim that digest-plus-context outperforms digest-alone — the contrast that actually tests that claim is a confirmed, reproduced null result, not an artifact of the smaller first round.

The root cause traced in the first round holds here too: the tested context variant (dropping Linux capability `NET_RAW`) changes container privilege, not which processes execute, so a process-name-only Jensen-Shannon feature cannot reflect it by construction, independent of scope or sample size.

## Recall non-inferiority: a caveat on "properly powered"

The 216-trial run was sized to `n≈179`/arm based on `experiments/sample_size.py`'s power calculation for a 95%-reference-recall, 5-point-margin non-inferiority test. **That calculation assumed real variance in recall around 95%.** In both rounds, recall was actually 100% in every arm with zero variance (96/96, 62/62), so the stratified-bootstrap non-inferiority gate trivially passes regardless of n — it is not meaningfully "more powered" than the first round for this specific outcome, because there was never any recall difference to detect. The 216-trial run is properly justified for, and materially strengthens, the `CONTEXT_vs_GLOBAL` and `CONTEXT_vs_DIGEST` FPR contrasts (which did have real, measurable outcomes), not the recall gate.

## Follow-on exploratory finding: a direct context-delta feature does separate these cases

`experiments/context_delta.py` scores the structured runtime-context document itself (privileged, capabilities, read-only-rootfs, network mode, mounts, devices) against each digest's fit-split reference context, instead of inferring context changes through process-name distance.

Result on the 216-trial dataset (`artifacts/experiments/protocol-v1/exploratory/context-delta-finding-216.json`): **0/26 false positives on baseline trials [95% CI 0–13.2%], 27/27 correct detections of the `dropped_capabilities` variant [95% CI 87.2–100%]** — reproducing the first round's finding (0/18, 17/17) at larger n, with a change the frozen protocol's process-name JS-distance feature could not see at all (p=1.0, reported above).

This is explicitly **exploratory, not confirmatory**: the delta weights (`experiments/context_delta.py:DELTA_FIELDS`) are fixed by hand rather than fit or calibrated, and it has not been tested against any real attack scenario. It should not be cited as a confirmed result. Promoting it to confirmatory requires a new protocol version with a pre-registered sample size and its own frozen threshold, per the revision rule in `CLAIMS_V1.md`.

Real attack scenarios: `SCN-LOG4SHELL-SIM` (CVE-2021-44228-shaped, harmless), `SCN-RUNC-ESCAPE-SIM` (CVE-2019-5736-shaped, harmless).

## Honest limits

- **The recall non-inferiority gate has not been meaningfully stress-tested** in either round: both arms detected 100% of planted scenarios with zero variance, so the statistical machinery for detecting a recall trade-off has never actually been exercised against a real trade-off. A scenario design that produces some misses in at least one arm would be needed to validate the gate itself.
- **`ARM-TAG` and `ARM-DIGEST` remain indistinguishable** in both rounds — every human_tag maps to exactly one digest. The `experiments/tag_drift.py` mutable-tag-drift experiment (nginx 1.26.3-alpine → 1.28.0-alpine behind one shared local alias) found process-name-level Jensen-Shannon distance is exactly 0.0 between the two versions — a genuine same-behavior patch upgrade invisible to this specific signal.
- **The `CONTEXT` vs `DIGEST` null result has now been reproduced twice** (n=35 and n=53), which strengthens confidence it is a real property of the process-name feature and the tested context variant (capability-only changes), not a first-round sampling artifact. It does not rule out that a context variant which does change process behavior (e.g. a different entrypoint script, not tested here) could still show a difference.
- Six real bugs were found and fixed to get the first pilot result (wrong API field name blocking all detections, dead code blocking attack scenarios, a fit-reference contamination bug, and an infinite-recursion bug in the Clopper-Pearson statistics code itself) — see git log `c137a89`..`e73c2d7`.
- This is a single-reviewer self-review (both security and methodology), not independent peer review — state that plainly in any external write-up.

## Reproduce

```
python3 -m experiments.run study --workloads WL-NGX-V1,WL-RDS-V1,WL-PG-V1 \
  --scenarios SCN-EXEC,SCN-LOG4SHELL-SIM,SCN-RUNC-ESCAPE-SIM \
  --variants baseline,dropped_capabilities --replicas 12 --operations 10
python3 -m experiments.analyze_scope_run artifacts/experiments/local/<run_id> --out <path>
python3 -m experiments.context_delta artifacts/experiments/local/<run_id>
```
