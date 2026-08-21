from __future__ import annotations

import pytest

from porygon_api.calibration_v2 import (
    BLOCK_STATISTIC_VERSION,
    build_calibration_artifact,
    max_window_nonconformity,
    score_test_block,
)
from porygon_api.provenance_v2 import MIN_CALIBRATION_RUNS


def _blocks() -> dict[str, float]:
    return {f"run-{index:02d}": float(index) for index in range(MIN_CALIBRATION_RUNS)}


def test_block_statistic_is_maximum_and_requires_complete_windows() -> None:
    assert max_window_nonconformity([0.2, 1.5, 0.7]) == pytest.approx(1.5)
    with pytest.raises(ValueError, match="at least one"):
        max_window_nonconformity([])
    with pytest.raises(ValueError, match="finite"):
        max_window_nonconformity([float("inf")])


def test_calibration_artifact_is_sorted_and_hash_bound() -> None:
    artifact = build_calibration_artifact({"b": 2.0, "a": 1.0}, minimum_calibration_runs=2)
    assert artifact["statistic_version"] == BLOCK_STATISTIC_VERSION
    assert [row["run_id"] for row in artifact["runs"]] == ["a", "b"]
    assert len(artifact["calibration_hash"]) == 64


def test_test_block_uses_inclusive_tail_and_finite_sample_floor() -> None:
    artifact = build_calibration_artifact(_blocks())
    result = score_test_block(artifact, test_run_id="test-run", test_statistic=100.0)
    assert result["status"] == "calibrated"
    assert result["p_value"] == pytest.approx(1 / (MIN_CALIBRATION_RUNS + 1))
    tied = score_test_block(artifact, test_run_id="test-run-2", test_statistic=9.0)
    assert tied["inclusive_exceedances"] == 1


def test_calibration_rejects_small_or_tampered_or_leaking_artifacts() -> None:
    with pytest.raises(ValueError, match="at least"):
        build_calibration_artifact({"run-1": 1.0})
    artifact = build_calibration_artifact(_blocks())
    with pytest.raises(ValueError, match="must not appear"):
        score_test_block(artifact, test_run_id="run-01", test_statistic=1.0)
    artifact["runs"][0]["block_statistic"] = 999.0
    with pytest.raises(ValueError, match="hash mismatch"):
        score_test_block(artifact, test_run_id="new-test", test_statistic=1.0)
