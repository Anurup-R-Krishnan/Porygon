# Porygon calibrated Fit and Calibration Provenance Schema

Status: **exploratory additive schema — not exposed by the default API**

Schema identifier: `porygon.rarity.provenance.calibrated`

The calibrated model stores provenance separately from the historical
`porygon.behaviour.v1` profile. A model artifact is bound to a protocol ID,
profile scope/context, algorithm identifier, component registry, sorted whole-run
sets, and canonical SHA-256 hashes.

## Split contract

Each complete workload run has exactly one role for a model artifact: `fit`,
`calibration`, or held-out `test`. Fit and calibration membership is persisted
in `calibrated_model_runs`; test runs are supplied only to an evaluation request
and are never inserted into the model membership table. A run ID may not occur
in more than one role, and windows from a run inherit that role.

The current protocol requires at least 10 independent calibration runs per
supported stratum. The minimum is represented in the artifact and is not
silently reduced by an API caller. If a later reviewed protocol changes this
requirement, it must use a new protocol/model identifier.

## Stored artifacts

- `calibrated_rarity_models`: immutable model identity, scope/context, algorithm and
  component identifiers, split hashes, calibration hash, status, and canonical
  provenance document.
- `calibrated_model_runs`: one row per model/run with `fit` or `calibration`
  role, feature hash, window count, and replayable feature summary.
- `calibrated_calibration_blocks`: one held-out benign block statistic per
  calibration run, its statistic identifier, hash, and window summary.

All tables are additive after migration `0008_phase8`; v1 tables and rows are
not rewritten. Active-model mutation is intentionally not implemented in this
exploratory slice. The next workflow layer must freeze an artifact before any
test-run score is accepted, and must reject test leakage and hash mismatches.
