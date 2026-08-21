# Plan 004: Replace weighted pseudo-scores with calibrated rarity and explicit evidence semantics

> **Executor instructions**: This is a versioned replacement, not an in-place rewrite of historical records. Preserve v1 read compatibility, implement v2 alongside it, and execute every gate. Stop on any protocol ambiguity. Update Plan 004 in `plans/README.md` when done.
>
> **Drift check (run first)**: `test "$(sha256sum backend/src/porygon_api/baseline.py backend/src/porygon_api/scoring.py backend/src/porygon_api/models.py backend/src/porygon_api/schemas.py backend/src/porygon_api/main.py backend/tests/test_baseline.py backend/tests/test_scoring.py backend/tests/test_scoring_schema.py backend/tests/test_phase5_api.py docs/FEATURE_SCHEMA_V1.md docs/SCORING_MODEL_V1.md docs/PHASE5_ACCEPTANCE.md | sha256sum | cut -d' ' -f1)" = 4906cc51540608f632a891fe586b5a31ae492be42acca0d69c2a30d903380e17`
>
> Expected: exit 0. Plan 003 intentionally changes two docs in this list; reconcile those documented changes, recompute and record the accepted pre-implementation hash in the PR/commit notes, then stop on any other semantic drift.

## Status

- **Status**: IN PROGRESS — exploratory implementation authorized; confirmatory collection remains prohibited until Plan 003 review is complete
- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: Plan 003
- **Category**: migration, correctness, tests, direction
- **Planned at**: `UNBORN`, pre-Plan-003 hash `4906cc515406`, 2026-08-16
- **Accepted drift anchor before implementation**: `2ea24afff2ce5525ddf59fe9faf10057e39cc957058469cd30325f47c5546d7d` (Plan 003 intentionally changed `docs/FEATURE_SCHEMA_V1.md`; no runtime files were changed by that plan)

## Why this matters

Phase 5 currently combines hand-selected 0.50/0.30/0.20 group weights, family weights, z-score tolerances, saturation constants, and UI bands. Phase 6 then adds more arbitrary rule, confidence, coverage, and severity weights, and Phase 7 gates actions on those composites. The values are reproducible but not empirically justified. This plan keeps historical v1 evidence readable while making v2’s primary scientific output calibrated rarity under explicit assumptions, with deterministic rule evidence, impact, confidence/completeness, and response authority kept separate.

## Current state

- `backend/src/porygon_api/scoring.py:10-50` defines `porygon.distance.v1` and fixed top-level, categorical, numeric, z-tolerance, saturation, and score-band constants.
- `scoring.py:76-112` implements Jensen–Shannon distance; `133-151` converts numeric deviation through hand-selected floors/tolerances.
- `docs/SCORING_MODEL_V1.md:64-79` publishes categorical weights; `180-189` labels provisional bands.
- `backend/src/porygon_api/baseline.py` stores aggregate distributions and numeric summaries but not independent per-run fit/calibration nonconformity blocks.
- `backend/src/porygon_api/detection.py:31-95` assigns rule severity/confidence weights; `461-482` combines them with 0.50/0.25/0.25 and 0.65/0.35 formulas.
- `backend/src/porygon_api/response.py:41-46,81-107` uses arbitrary severity/confidence thresholds to allow disruptive actions, although human approval is required.
- `docs/DETECTION_RULESET_V1.md:82-90` correctly says severity/confidence are not compromise probabilities and admits the correlation window/rule weights are engineering defaults.

## Target semantics

- **Categorical shift**: Hellinger distance per eligible family: `sqrt(0.5 * sum((sqrt(p_i)-sqrt(q_i))^2))` over the union support.
- **Sequence evidence**: smoothed first-order Markov negative log surprisal for within-container transitions; never cross containers. Store smoothing/version and expose unseen transitions.
- **Novelty**: explicit unseen observed mass and unseen-token evidence, separate from distribution shift.
- **Count/numeric evidence**: empirical two-sided tail ranks from held-out benign calibration observations; no arbitrary z floors/tolerances.
- **Fusion**: convert eligible components to empirical percentile ranks, aggregate with a documented unweighted rank rule over a fixed component registry, and record missing components. Do not add user-tuned weights.
- **Calibration**: split by complete runs. For confirmatory coverage, compute one predeclared block statistic per held-out run (for example maximum window nonconformity) and split-conformal `p = (1 + count(calibration_stat >= test_stat)) / (n_calibration_runs + 1)`. Store p-value and `rarity = 1 - p`; neither is attack probability. Window percentiles may be exposed as descriptive diagnostics but must not inherit block-level coverage claims.
- **Rules**: deterministic match records with rule version and evidence; anomaly rarity does not automatically create an incident.
- **Impact/severity**: categorical, policy-defined potential impact with provenance, not a decimal pseudo-probability.
- **Confidence**: categorical evidence completeness/quality (`insufficient`, `partial`, `corroborated`) driven by measured source availability, canary/loss state, and rule prerequisites—not the count of matching rules.
- **Response**: default `observe_only`. Pause/stop availability requires an explicit rule/policy allowlist, adequate evidence quality, exact target, and human approval; it must not be unlocked by a composite score threshold.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Backend targeted tests | `docker compose run --rm --no-deps --entrypoint pytest backend -q -k 'baseline or scoring or detection or response or phase5 or phase6 or phase7'` | all pass |
| Full backend tests | `docker compose run --rm --no-deps --entrypoint pytest backend -q` | all pass |
| Migration chain/drift | `make verify-static` | migrations render; ORM drift gate passes |
| Live non-disruptive | `make verify-live-safe` | v1 read and v2 build/score/detect paths pass |
| Remove arbitrary v2 weights | `rg -n 'top_level_weights|categorical_weights|numeric_weights|numeric_z_tolerance|numeric_z_saturation' backend/src/porygon_api` | matches only in preserved v1 compatibility module/migration fixtures |

## Scope

**In scope**:

- `backend/src/porygon_api/baseline.py` plus a separate `baseline_v2.py` if clearer
- `backend/src/porygon_api/scoring.py` plus a separate `scoring_v2.py`
- `backend/src/porygon_api/detection.py` plus a separate `detection_v2.py`
- `backend/src/porygon_api/response.py`
- `backend/src/porygon_api/models.py`, `schemas.py`, `main.py`
- one new sequential Alembic migration after current head
- affected backend tests and new deterministic property/contract fixtures
- `docs/FEATURE_SCHEMA_V2.md`, `docs/SCORING_MODEL_V2.md`, `docs/DETECTION_RULESET_V2.md`, `docs/RESPONSE_POLICY_V2.md` (create)
- v1 docs only for clear superseded/read-compatible status
- Phase 4–7 acceptance docs/scripts as needed for v2 gates
- `plans/README.md`

**Out of scope**:

- Deleting or rewriting v1 rows, hashes, APIs, docs, or migrations.
- Claiming conformal validity when run exchangeability/stability assumptions are not met.
- Fitting/calibrating on attack-labelled data for the primary benign-rarity model.
- Adding file/network/DNS features not captured by current telemetry.
- Automatic response or removal of human approval.
- Performance optimization beyond preventing obvious accidental quadratic work in new code; Plan 005 measures first.

## Git workflow

- Branch `codex/004-calibrated-rarity-v2` from completed Plan 003.
- Configured Git identity only; no AI attribution, co-author trailers, or generated-by lines.
- Commit by stable layer: schema/migration, pure math/tests, API workflow, detection/response semantics, docs/acceptance.
- Do not push.

## Steps

### Step 1: Add immutable v2 fit/calibration provenance

Add versioned models/schemas for profile scope, fit run IDs, calibration run IDs, per-run/window feature summaries needed for replay, component registry version, calibration block statistics, calibration hash, and protocol ID. Store sorted IDs and canonical SHA-256 hashes. Enforce disjoint fit/calibration runs and a minimum calibration-run setting from the frozen protocol. An observation/test run may not appear in fit or calibration.

Migration must be additive. Keep v1 constraints and rows intact. API serializers must return v1 and v2 records without fabricating unavailable v2 fields.

**Verify**: migration from empty and current head; rollback only if the project convention supports it. Tests reject overlapping splits, duplicate run roles, mismatched profile scope/context hash, insufficient calibration, and late mutation of an active model.

### Step 2: Implement pure deterministic v2 feature evidence

Implement Hellinger, Markov surprisal, novelty mass, and empirical numeric/count tail ranks as pure functions with no database access. Establish a fixed ordered component registry and explicit missingness rules. The unweighted rank fusion must be invariant to dictionary ordering, bounded, and fail with `insufficient_data` when protocol-required components are absent.

Use smoothing only for Markov transition likelihood; document its deterministic formula and fit-data dependence. Do not choose constants by looking at confirmatory attack results. Retain full explanation: support sizes, top shifted tokens, unseen tokens/transitions, numeric ranks, eligible/missing components, hashes, and versions.

**Verify**: property tests cover identity, symmetry/bounds for Hellinger, order invariance, empty families, unseen transitions, zero counts, ties, deterministic hashes, monotonic empirical ranks, and exact hand-computed fixtures.

### Step 3: Implement run-block calibration and versioned scoring APIs

Fit on training runs, produce calibration block statistics only from held-out benign runs, then freeze the calibration artifact. Implement the finite-sample conformal p-value exactly as specified in the protocol. Keep descriptive window rank distinct in names, schemas, docs, and UI labels from confirmatory run-block p-value.

Create v2 endpoints or an explicit version selector; never silently change v1 endpoint semantics. Idempotency keys include protocol, profile scope/context, fit/calibration hashes, algorithm/component-registry versions, observation/run IDs, evidence set hash, and window/run bounds.

**Verify**: deterministic fixture returns exact p-value; ties use `>=`; minimum p-value is `1/(n+1)`; test-run leakage is rejected; exact retry returns the same record; changed evidence creates a new immutable record.

### Step 4: Replace composite detection/confidence/severity semantics in v2

Keep each deterministic rule result boolean/evidence-based and versioned. Replace decimal severity/confidence composites with categorical impact and evidence-quality records carrying reasons. Any anomaly-only observation remains anomaly evidence and does not become an incident by a provisional cutoff. Optimize shell-to-tool correlation with per-container time ordering/sliding lookup while preserving exact v1 fixture matches before changing v2 semantics.

**Verify**: randomized equivalence test proves the optimized correlation finds the same inclusive 120-second pairs as v1; v2 tests prove evidence quality degrades on telemetry health gaps and never increases merely because duplicate rules are added.

### Step 5: Version response policy around explicit authority

Create response policy v2. `observe_only` remains universally safe. Disruptive options require explicit named eligible rules, categorical impact, adequate evidence quality, exact target binding, non-stale evidence, and human approval. Remove decimal severity/confidence thresholds from v2. Preserve v1 recommendation records and policy hashes.

**Verify**: tests prove anomaly rarity alone, duplicated matches, stale/incomplete telemetry, absent target, or internal-service token cannot unlock pause/stop; exact qualifying evidence still requires operator approval before execution.

### Step 6: Document assumptions and run cumulative gates

Document equations, fit/calibration/test roles, block statistic, exchangeability/stability assumptions, drift failure modes, claim boundaries, version compatibility, and why outputs are not probabilities of attack. Update acceptance scripts to verify exact model/calibration hashes and both v1-read/v2-write behavior.

**Verify**: targeted tests, full backend suite, static/migration gate, and safe live gate all pass. Phase 7 disruptive execution remains explicit and is not needed to accept the mathematical model.

## Test plan

- Pure-math golden fixtures and property tests.
- Split/provenance/migration/idempotency/API compatibility tests.
- Block-calibration ties, small-sample boundary, missingness, drift labels, and leakage rejection.
- Detection correlation equivalence and evidence-quality degradation tests.
- Response authority regression tests.
- PostgreSQL integration for uniqueness/locking paths; do not rely solely on in-memory SQLite/direct handler calls.

## Done criteria

- [ ] v1 evidence remains readable and immutable.
- [ ] v2 contains no hand-selected feature/group/severity/confidence weights.
- [ ] Primary confirmatory output is run-block conformal p-value/rarity with explicit assumptions.
- [ ] Window diagnostics cannot be mistaken for block-level calibrated results.
- [ ] Deterministic evidence, impact, evidence quality, and response authority are separate fields.
- [ ] No disruptive action is unlocked by anomaly rarity or a composite decimal score.
- [ ] Migration, all tests, static checks, and safe live acceptance pass.
- [ ] Only in-scope files changed; Plan 004 is marked `DONE`.

## STOP conditions

- Plan 003 does not define independent run IDs, block statistic, minimum calibration runs, or missingness rules clearly enough to implement exactly.
- Existing stored v1 hashes/records would need mutation.
- A proposed formula or threshold is being tuned against confirmatory attack/test outcomes.
- PostgreSQL migration drift or v1 API compatibility cannot be resolved within scope.
- Evidence-quality computation requires durable telemetry metrics Plan 002/003 did not define.

## Maintenance notes

Reviewers should audit scientific semantics before code style. The calibration guarantee is conditional on the frozen protocol assumptions; drift must be surfaced, not hidden. Any new feature family changes the registry/model version and requires new fit/calibration artifacts and confirmatory evaluation.

The first implementation work on this branch is exploratory and test-only until
Plan 003 is independently reviewed. It must not collect pilot or confirmatory
workload data, mutate v1 rows, or expose v2 as the default API path.
