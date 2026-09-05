# Confirmatory Result Summary — First Real Answer

**Run:** `study-20260905t181654Z` (144 real Docker-container trials, `evidence_class: confirmatory`, `research_eligible: true`)
**Analysis artifact:** `artifacts/experiments/protocol-v1/tables/profile-scope-primary.json`
**Protocol:** `porygon.research.protocol.v1`, status `FROZEN`, both reviews approved (`docs/review/*.json`)

## Question

Does conditioning a behavioral profile on immutable image digest + deployment context (`ARM-CONTEXT`) reduce benign false-alarm rate while preserving detection recall, versus a global profile (`ARM-GLOBAL`), a mutable-tag profile (`ARM-TAG`), or a digest-only profile (`ARM-DIGEST`)?

## Result

| Arm | FPR (benign, n=35) | Recall (real attack scenarios, n=62) |
|---|---|---|
| `ARM-GLOBAL` | 35/35 = 100% [95% CI 90.0–100%] | 62/62 = 100% [95% CI 94.2–100%] |
| `ARM-TAG` | 0/35 = 0% [95% CI 0–10.0%] | 62/62 = 100% |
| `ARM-DIGEST` | 0/35 = 0% [95% CI 0–10.0%] | 62/62 = 100% |
| `ARM-CONTEXT` | 0/35 = 0% [95% CI 0–10.0%] | 62/62 = 100% |

**`CONTEXT` vs `GLOBAL`:** exact McNemar p = 5.8×10⁻¹¹ (Holm-adjusted), relative FPR reduction 100% (≫ the frozen 25% material-effect threshold), recall non-inferior (stratified bootstrap, co-primary gate passes, never traded for FPR). **H1 supported** (`experiments/analysis.py:decide_primary_contrast`).

Real attack scenarios: `SCN-LOG4SHELL-SIM` (CVE-2021-44228-shaped, harmless), `SCN-RUNC-ESCAPE-SIM` (CVE-2019-5736-shaped, harmless) — both newly wired up this session (were previously dead code, never executed).

## Honest limits

- **n=35/62 is well below** the frozen full-matrix confirmatory target (30 benign + 20 scenario per workload×variant cell = 200 total). This is a first result, not the final powered study.
- **`ART-DES-001` sample-size lock does not exist for the next round.** Building it (`experiments/sample_size.py`) surfaced a genuine finding: the protocol's own frozen recall non-inferiority target (5-percentage-point margin at 95% reference recall, 80% power, capped at 120 runs/cell) is **infeasible by exact binomial calculation** — even n=120 only reaches ~60% power for that specific margin; ~200+ runs are actually needed. This needs a protocol revision or margin change before the next confirmatory round.
- **`ARM-TAG` and `ARM-DIGEST` are indistinguishable** in this dataset — every human_tag maps to exactly one digest. A real mutable-tag-drift experiment was run (`experiments/tag_drift.py`, nginx 1.26.3-alpine → 1.28.0-alpine behind one shared local alias) and found process-name-level Jensen-Shannon distance is exactly 0.0 between the two versions — a genuine same-behavior patch upgrade invisible to this specific signal, not a bug in the drift-tracking mechanism (which correctly resolved two different real digests behind one tag, verified per-trial).
- Six real bugs were found and fixed to get here (wrong API field name blocking all detections, dead code blocking attack scenarios, a fit-reference contamination bug, and an infinite-recursion bug in the Clopper-Pearson statistics code itself) — see git log `c137a89`..`e73c2d7` for details and regression tests.
- This is a single-reviewer self-review (both security and methodology), not independent peer review — state that plainly in any external write-up.

## Reproduce

```
python3 -m experiments.run study --workloads WL-NGX-V1,WL-RDS-V1,WL-PG-V1 \
  --scenarios SCN-EXEC,SCN-LOG4SHELL-SIM,SCN-RUNC-ESCAPE-SIM \
  --variants baseline,dropped_capabilities --replicas 8 --operations 10
python3 -c "from experiments.scope import compare_scopes; ..."  # see experiments/scope.py
```
