from __future__ import annotations

import json

import pytest

from experiments.artifacts import ArtifactError, atomic_write_json, reconcile_boundaries


def test_atomic_json_is_immutable(tmp_path) -> None:
    path = tmp_path / "artifact.json"
    atomic_write_json(path, {"b": 2, "a": 1})
    atomic_write_json(path, {"a": 1, "b": 2})
    with pytest.raises(ArtifactError):
        atomic_write_json(path, {"a": 2})
    assert json.loads(path.read_text()) == {"a": 1, "b": 2}


def test_secret_like_values_are_rejected(tmp_path) -> None:
    with pytest.raises(ArtifactError):
        atomic_write_json(tmp_path / "secret.json", {"operator_token": "not-recorded"})


def test_reconciliation_reports_loss_not_zero() -> None:
    events = [
        {"sequence": 1, "observed_at": ["generator", "api"]},
        {"sequence": 2, "observed_at": ["generator", "api"]},
    ]
    result = reconcile_boundaries(events, ["generator", "api"])
    assert result["boundaries"]["generator"]["loss_fraction"] == 0
    assert result["boundaries"]["api"]["loss_fraction"] == 0

