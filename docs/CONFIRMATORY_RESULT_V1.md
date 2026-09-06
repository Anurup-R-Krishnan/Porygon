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

**`CONTEXT` vs `DIGEST` (the paper's actual thesis) is a null result: p = 1.0, zero
discordant pairs, arms agree on every single trial.** This dataset's fit split
pools three services (nginx, redis, postgres) with almost no process-name
overlap into one `ARM-GLOBAL` reference, so `ARM-GLOBAL` losing to every
per-image scope (TAG, DIGEST, and CONTEXT alike) is close to a mathematical
inevitability of that pooling, not evidence for context conditioning
specifically. **`CONTEXT` beating `GLOBAL` must not be read as, or cited as,
support for the paper's headline claim that digest-plus-context outperforms
digest-alone** — the data that actually tests that claim (`CONTEXT` vs
`DIGEST`) shows no measurable difference at process-name-distance granularity
in this dataset. The only informative reading of this round is: (a) do not
pool unrelated services into one anomaly baseline (unsurprising), and (b)
context conditioning beyond exact digest identity adds nothing detectable
here (the paper's real, more interesting hypothesis, currently unsupported).

This is not a "no variation to test" artifact: the runtime-context hash did
vary independently of digest in this dataset (each digest has trials under
both a `baseline` and a `dropped_capabilities` context variant). The finding
is genuinely that dropping a capability does not change which process names
execute, so a process-name-only JS-distance feature cannot see a
security-relevant context change of this kind. That is a real, specific,
publishable negative result about the current feature's blind spot, not
proof context conditioning is worthless in general — a feature that also
used capability/mount/privileged-flag deltas directly (rather than only
inferring them indirectly through process names) might still separate these
cases. That is future work, not demonstrated here.

## Follow-on exploratory finding: a direct context-delta feature does separate these cases

That "future work" was tested, on the same already-collected data, no new
trials run: `experiments/context_delta.py` scores the structured
runtime-context document itself (privileged, capabilities, read-only-rootfs,
network mode, mounts, devices) against each digest's fit-split reference
context, instead of inferring context changes through process-name distance.

Result (`artifacts/experiments/protocol-v1/exploratory/context-delta-finding.json`):
**0/18 false positives on baseline trials [95% CI 0–18.5%], 17/17 correct
detections of the `dropped_capabilities` variant [95% CI 80.5–100%]** — a
change the frozen protocol's process-name JS-distance feature could not see
at all (p=1.0, zero discordant pairs, reported above).

This is explicitly **exploratory, not confirmatory**: it reuses
`study-20260905t181654Z`'s existing 35 held-out benign/context trials rather
than a new pre-registered dataset, the delta weights
(`experiments/context_delta.py:DELTA_FIELDS`) are fixed by hand rather than
fit or calibrated, and it has not been tested against any real attack
scenario. It should not be cited as a confirmed result. It is reported here
because it is the one genuinely novel, falsifiable idea this project has
produced that the process-name-only literature this project builds on does
not already cover: **combine an immutable-digest process-name baseline with
a direct, structured comparison of the container's security-relevant runtime
configuration**, rather than hoping process-name distance will indirectly
reveal a capability/privilege/mount change. Promoting this from exploratory
to confirmatory requires a new protocol version with a pre-registered sample
size and its own frozen threshold, per the revision rule in `CLAIMS_V1.md`.

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
