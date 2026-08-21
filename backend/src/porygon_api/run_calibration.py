"""Run-block calibration artifacts for the calibrated rarity model."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from typing import Any

from porygon_api.calibrated_provenance import MIN_CALIBRATION_RUNS
from porygon_api.calibrated_rarity import empirical_upper_tail_pvalue, sha256_json

BLOCK_STATISTIC_ID = "porygon.rarity.block.max-window"


def max_window_nonconformity(window_values: Iterable[float]) -> float:
    """Return one non-negative block statistic for a complete workload run."""

    values = [float(value) for value in window_values]
    if not values:
        raise ValueError("a calibration block requires at least one window value")
    if any(not math.isfinite(value) or value < 0.0 for value in values):
        raise ValueError("window nonconformities must be finite and non-negative")
    return max(values)


def build_calibration_artifact(
    run_block_statistics: Mapping[str, float],
    *,
    minimum_calibration_runs: int = MIN_CALIBRATION_RUNS,
    statistic_id: str = BLOCK_STATISTIC_ID,
) -> dict[str, Any]:
    """Freeze sorted run-level statistics and their canonical artifact hash."""

    if minimum_calibration_runs < 1:
        raise ValueError("minimum_calibration_runs must be positive")
    if len(run_block_statistics) < minimum_calibration_runs:
        raise ValueError(
            f"calibration requires at least {minimum_calibration_runs} complete runs"
        )
    rows = []
    for run_id, statistic in run_block_statistics.items():
        value = float(statistic)
        if not run_id:
            raise ValueError("calibration run IDs must be non-empty")
        if not math.isfinite(value) or value < 0.0:
            raise ValueError("block statistics must be finite and non-negative")
        rows.append({"run_id": str(run_id), "block_statistic": value})
    rows.sort(key=lambda row: row["run_id"])
    if len({row["run_id"] for row in rows}) != len(rows):
        raise ValueError("calibration run IDs must be unique")
    unsigned = {
        "statistic_id": statistic_id,
        "minimum_calibration_runs": minimum_calibration_runs,
        "runs": rows,
    }
    return {**unsigned, "calibration_hash": sha256_json(unsigned)}


def score_test_block(
    artifact: Mapping[str, Any],
    *,
    test_run_id: str,
    test_statistic: float,
) -> dict[str, Any]:
    """Score a held-out run against a frozen artifact without leakage."""

    calibration_ids = {str(row["run_id"]) for row in artifact.get("runs", [])}
    if test_run_id in calibration_ids:
        raise ValueError("test run must not appear in calibration artifact")
    expected_hash = sha256_json(
        {
            "statistic_id": artifact.get("statistic_id"),
            "minimum_calibration_runs": artifact.get("minimum_calibration_runs"),
            "runs": artifact.get("runs"),
        }
    )
    if artifact.get("calibration_hash") != expected_hash:
        raise ValueError("calibration artifact hash mismatch")
    result = empirical_upper_tail_pvalue(
        (float(row["block_statistic"]) for row in artifact.get("runs", [])),
        float(test_statistic),
    )
    return {
        "test_run_id": test_run_id,
        "statistic_id": artifact.get("statistic_id"),
        "test_block_statistic": float(test_statistic),
        "calibration_hash": artifact["calibration_hash"],
        **result,
    }
