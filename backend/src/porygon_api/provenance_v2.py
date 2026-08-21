"""Immutable split and provenance helpers for exploratory rarity model v2."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from porygon_api.scoring_v2 import sha256_json

PROTOCOL_ID = "porygon.research.protocol.v1"
MIN_CALIBRATION_RUNS = 10


def _sorted_unique(run_ids: Iterable[str], *, label: str) -> list[str]:
    values = [str(run_id) for run_id in run_ids]
    if any(not value for value in values):
        raise ValueError(f"{label} run IDs must be non-empty")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} run IDs must be unique")
    return sorted(values)


def validate_run_split(
    fit_run_ids: Iterable[str],
    calibration_run_ids: Iterable[str],
    test_run_ids: Iterable[str] = (),
    *,
    minimum_calibration_runs: int = MIN_CALIBRATION_RUNS,
) -> dict[str, Any]:
    """Validate whole-run split membership and return canonical split hashes."""

    if minimum_calibration_runs < 1:
        raise ValueError("minimum_calibration_runs must be positive")
    fit = _sorted_unique(fit_run_ids, label="fit")
    calibration = _sorted_unique(calibration_run_ids, label="calibration")
    test = _sorted_unique(test_run_ids, label="test")
    groups = {"fit": set(fit), "calibration": set(calibration), "test": set(test)}
    for left_name, left_ids in groups.items():
        for right_name, right_ids in groups.items():
            if left_name >= right_name:
                continue
            overlap = sorted(left_ids & right_ids)
            if overlap:
                raise ValueError(f"run IDs overlap between {left_name} and {right_name}: {overlap}")
    if len(calibration) < minimum_calibration_runs:
        raise ValueError(
            f"calibration requires at least {minimum_calibration_runs} complete runs"
        )
    return {
        "fit_run_ids": fit,
        "calibration_run_ids": calibration,
        "test_run_ids": test,
        "fit_run_set_hash": sha256_json(fit),
        "calibration_run_set_hash": sha256_json(calibration),
        "test_run_set_hash": sha256_json(test),
        "minimum_calibration_runs": minimum_calibration_runs,
    }


def build_provenance_document(
    *,
    protocol_id: str,
    profile_scope_id: str,
    profile_context_hash: str,
    algorithm_version: str,
    component_registry_version: str,
    fit_run_ids: Iterable[str],
    calibration_run_ids: Iterable[str],
    test_run_ids: Iterable[str] = (),
    minimum_calibration_runs: int = MIN_CALIBRATION_RUNS,
) -> dict[str, Any]:
    """Build a canonical, hashable model provenance document."""

    split = validate_run_split(
        fit_run_ids,
        calibration_run_ids,
        test_run_ids,
        minimum_calibration_runs=minimum_calibration_runs,
    )
    document = {
        "protocol_id": protocol_id,
        "profile_scope_id": profile_scope_id,
        "profile_context_hash": profile_context_hash,
        "algorithm_version": algorithm_version,
        "component_registry_version": component_registry_version,
        **split,
    }
    document["provenance_hash"] = sha256_json(document)
    return document


def verify_provenance_document(document: Mapping[str, Any]) -> None:
    """Reject a document whose stored canonical hash no longer matches."""

    stored_hash = document.get("provenance_hash")
    if not isinstance(stored_hash, str):
        raise ValueError("provenance_hash is required")
    unsigned = dict(document)
    unsigned.pop("provenance_hash", None)
    if sha256_json(unsigned) != stored_hash:
        raise ValueError("provenance document hash mismatch")
