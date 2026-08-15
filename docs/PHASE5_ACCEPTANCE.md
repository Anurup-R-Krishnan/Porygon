# Phase 5 Acceptance Criteria

Phase 5 is accepted only when the implementation, static checks, database migration, and live controlled experiment all pass.

## A. Schema and migration

- [ ] Alembic migration `0005_phase5` follows `0004_phase4`.
- [ ] `anomaly_scores` is created with a foreign key to `behavior_profiles`.
- [ ] Observation keys are unique.
- [ ] Total scores are either null or bounded in `[0, 1]`.
- [ ] Status and score-band values are constrained.
- [ ] Query indexes exist for digest/window, profile, status, score, and creation time.

## B. Fixed-window and profile controls

- [ ] The server derives window end from the profile's `window_seconds`.
- [ ] Unfinished windows are rejected.
- [ ] Training-overlap windows are rejected.
- [ ] Digest/profile mismatches are rejected.
- [ ] Draft or quality-failing profiles are rejected.
- [ ] Active and retired quality-passing profiles can be scored.
- [ ] The configured event limit is enforced before loading all events.

## C. Scoring correctness

- [ ] Jensen-Shannon distance is symmetric, bounded, and zero for identical distributions.
- [ ] Disjoint categorical distributions produce maximum distance.
- [ ] Identical feature documents produce score zero.
- [ ] Unseen behaviour contributes to novelty.
- [ ] Numeric deviations are bounded.
- [ ] Missing feature families are excluded and weights are renormalized.
- [ ] A document with no scoreable features is rejected.
- [ ] Score-band boundaries are explicit and tested.
- [ ] Scoring configuration weights sum to one.

## D. Evidence sufficiency and integrity

- [ ] A window below the process-evidence minimum is persisted as `insufficient_data`.
- [ ] `insufficient_data` has no numeric total score.
- [ ] Missing evidence is not described as normal.
- [ ] Observation manifests include a selected-event-set SHA-256.
- [ ] Every result stores algorithm version, profile version, profile hash, and scoring config.
- [ ] Exact rescoring returns the existing record.
- [ ] Changed evidence produces a changed observation key.

## E. Explainability

- [ ] Scored records contain all component scores.
- [ ] Effective renormalized weights are visible.
- [ ] Top weighted contributors are persisted.
- [ ] Unseen tokens and proportions are persisted.
- [ ] Numeric observations, baseline summaries, effective scales, and z values are persisted.
- [ ] The result states that distance is not proof of maliciousness.

## F. API and CLI

- [ ] `POST /internal/v1/anomaly-scores/compute` requires internal authentication.
- [ ] `GET /api/v1/anomaly-scores/config` exposes the immutable v1 definition.
- [ ] `GET /api/v1/anomaly-scores` supports digest, profile, status, and minimum-score filters.
- [ ] `GET /api/v1/anomaly-scores/{score_id}` returns one record.
- [ ] `scripts/porygon_score.py` can compute, list, and retrieve scores.
- [ ] System information reports total, scored, and insufficient observations.

## G. Automated unit and static checks

Run:

```bash
cd backend && PYTHONPATH=src pytest -q
cd ../collector && PYTHONPATH=src pytest -q
cd ../telemetry && PYTHONPATH=src pytest -q

cd ..
ruff check backend/src backend/tests collector/src collector/tests telemetry/src telemetry/tests scripts/porygon_score.py
python3 -m compileall -q backend/src backend/tests collector/src collector/tests telemetry/src telemetry/tests scripts
bash -n scripts/*.sh
```

Expected package test totals at release:

```text
backend:   22 passed
collector:  5 passed
telemetry:  5 passed
```

## H. Live controlled acceptance

Run on a compatible Linux Docker host:

```bash
./scripts/verify_phase5.sh | tee artifacts/phase5-verification.txt
```

The script must prove:

1. all Phase 4 acceptance checks still pass
2. the scoring config endpoint exposes version and warning metadata
3. the selected probe resolves to the active profile's immutable digest
4. an empty window becomes `insufficient_data`
5. a controlled baseline-like process tree is scored
6. a controlled novel process mix produces a larger score than the baseline-like window
7. novelty and contributor evidence are present
8. an exact retry returns the same score UUID and observation key
9. a training-overlap request returns HTTP 409
10. system score counters and uniqueness invariants hold

The live script does not establish detection accuracy. It validates plumbing, reproducibility, ordering, and directional behaviour in one controlled scenario.

## I. Research sign-off

Before using Phase 5 results in the paper:

- [ ] call the values behavioural-distance scores, not maliciousness probabilities
- [ ] state that bands are provisional
- [ ] record the exact profile, algorithm version, and experiment interval
- [ ] separate training, validation, and test data
- [ ] do not report precision, recall, or false-positive rates until Phase 9
- [ ] include failed and insufficient-data observations in experiment logs
