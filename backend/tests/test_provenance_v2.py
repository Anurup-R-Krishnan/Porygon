from __future__ import annotations

import pytest
from pydantic import ValidationError

from porygon_api.provenance_v2 import (
    MIN_CALIBRATION_RUNS,
    build_provenance_document,
    validate_run_split,
    verify_provenance_document,
)
from porygon_api.schemas import RarityModelV2CreateIn


def _calibration_ids() -> list[str]:
    return [f"cal-{index:02d}" for index in range(MIN_CALIBRATION_RUNS)]


def test_split_is_sorted_hashed_and_disjoint() -> None:
    result = validate_run_split(["fit-b", "fit-a"], _calibration_ids(), ["test-a"])
    assert result["fit_run_ids"] == ["fit-a", "fit-b"]
    assert len(result["fit_run_set_hash"]) == 64
    assert len(result["calibration_run_ids"]) == MIN_CALIBRATION_RUNS


@pytest.mark.parametrize(
    "fit, calibration, test, message",
    [
        (["same"], _calibration_ids(), ["same"], "overlap"),
        (["same"], ["same"] + _calibration_ids()[1:], [], "overlap"),
        (["duplicate", "duplicate"], _calibration_ids(), [], "unique"),
        ([], _calibration_ids()[:-1], [], "at least"),
    ],
)
def test_split_rejects_leakage_duplicates_and_small_calibration(
    fit: list[str], calibration: list[str], test: list[str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_run_split(fit, calibration, test)


def test_provenance_hash_is_canonical_and_tamper_evident() -> None:
    document = build_provenance_document(
        protocol_id="porygon.research.protocol.v1",
        profile_scope_id="digest-plus-context",
        profile_context_hash="a" * 64,
        algorithm_version="porygon.rarity.v2",
        component_registry_version="porygon.rarity.components.v1",
        fit_run_ids=["fit-b", "fit-a"],
        calibration_run_ids=_calibration_ids(),
    )
    verify_provenance_document(document)
    document["fit_run_ids"] = ["tampered"]
    with pytest.raises(ValueError, match="hash mismatch"):
        verify_provenance_document(document)


def test_v2_create_schema_reuses_split_integrity_rules() -> None:
    valid = RarityModelV2CreateIn(
        protocol_id="porygon.research.protocol.v1",
        profile_scope_id="digest-plus-context",
        profile_context_hash="a" * 64,
        algorithm_version="porygon.rarity.v2",
        component_registry_version="porygon.rarity.components.v1",
        calibration_run_ids=_calibration_ids(),
    )
    assert valid.minimum_calibration_runs == MIN_CALIBRATION_RUNS
    with pytest.raises(ValidationError, match="overlap"):
        RarityModelV2CreateIn(
            protocol_id="porygon.research.protocol.v1",
            profile_scope_id="digest-plus-context",
            profile_context_hash="a" * 64,
            algorithm_version="porygon.rarity.v2",
            component_registry_version="porygon.rarity.components.v1",
            fit_run_ids=["shared"],
            calibration_run_ids=["shared"] + _calibration_ids(),
        )
