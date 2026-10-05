from __future__ import annotations

import json

import pytest

from experiments import run as run_module
from experiments.artifacts import (
    ArtifactError,
    atomic_write_json,
    canonical_json,
    reconcile_boundaries,
    versioned_artifact_paths,
    write_versioned_json,
)


def test_canonical_json_rejects_non_finite_floats() -> None:
    """json.dumps's default (allow_nan=True) would silently emit the bare tokens
    NaN/Infinity, which are not valid JSON; canonical_json must raise instead of
    producing a file that looks like JSON but a conformant parser would reject."""
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})
    with pytest.raises(ValueError):
        canonical_json({"x": float("inf")})
    with pytest.raises(ValueError):
        canonical_json({"x": float("-inf")})


def test_canonical_json_still_encodes_ordinary_floats() -> None:
    assert canonical_json({"x": 0.25}) == '{"x":0.25}'


def test_atomic_write_json_rejects_non_finite_floats(tmp_path) -> None:
    with pytest.raises(ValueError):
        atomic_write_json(tmp_path / "bad.json", {"score": float("nan")})


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


# ---------------------------------------------------------------------------
# Versioned writes: a completed artifact must never be silently rewritten
# ---------------------------------------------------------------------------


def test_write_versioned_json_is_idempotent_and_versions_on_real_changes(tmp_path) -> None:
    first = write_versioned_json(tmp_path, "manifest", {"a": 1})
    assert first.name == "manifest.json"

    # Re-writing identical content is a no-op: no new file, same path returned.
    again = write_versioned_json(tmp_path, "manifest", {"a": 1})
    assert again == first
    assert [p.name for p in versioned_artifact_paths(tmp_path, "manifest")] == ["manifest.json"]

    # Different content: the original is left byte-for-byte untouched, a new version
    # appears instead of the old one being unlinked and overwritten.
    second = write_versioned_json(tmp_path, "manifest", {"a": 2})
    assert second.name == "manifest.v2.json"
    assert json.loads(first.read_text(encoding="utf-8")) == {"a": 1}
    assert json.loads(second.read_text(encoding="utf-8")) == {"a": 2}
    assert [p.name for p in versioned_artifact_paths(tmp_path, "manifest")] == [
        "manifest.json",
        "manifest.v2.json",
    ]

    # A third change versions again rather than touching either prior file.
    third = write_versioned_json(tmp_path, "manifest", {"a": 3})
    assert third.name == "manifest.v3.json"
    assert json.loads(first.read_text(encoding="utf-8")) == {"a": 1}
    assert json.loads(second.read_text(encoding="utf-8")) == {"a": 2}


def _pilot_fixture(run_dir) -> None:
    (run_dir / "trials").mkdir(parents=True)
    atomic_write_json(
        run_dir / "run.json",
        {"schema_version": "porygon.experiment.run.v2", "run_id": "run-1",
         "kind": "real_container_pilot", "research_eligible": False},
    )
    trial = {
        "trial_id": "t-1", "run_id": "run-1", "status": "completed",
        "workload_id": "WL-NGX-V1", "human_tag": "nginx:1.26.3-alpine",
        "mode": "steady_http", "scenario_id": "SCN-EXEC", "context_variant": "baseline",
        "replica_index": 1, "research_eligible": False,
    }
    atomic_write_json(run_dir / "trials" / "t-1.json", trial)
    run_module._write_pilot_summary(run_dir / "summary.csv", [trial])


def test_run_py_manifest_write_cannot_silently_overwrite_a_completed_manifest(tmp_path) -> None:
    """run.py's `_write_manifest` used to `unlink()` artifact-manifest.json before
    rewriting it, which let anyone silently change a "completed" manifest in place --
    defeating the whole point of atomic_write_bytes's immutability guard. It must now
    version instead: the original stays exactly as written, and a legitimate later change
    (e.g. a new file appearing in the run directory) produces a new version."""
    run_dir = tmp_path / "pilot"
    _pilot_fixture(run_dir)

    first = run_module._write_manifest(run_dir, "run-1", "pilot_only", "trials/")
    assert first.name == "artifact-manifest.json"
    original_hashes = json.loads(first.read_text(encoding="utf-8"))["artifact_hashes"]
    assert "study-manifest.json" not in original_hashes

    # A later stage adds a new artifact to the same run directory (this is what
    # experiments/study.py does when it adds study-manifest.json after the pilot run
    # already completed).
    (run_dir / "study-manifest.json").write_text("{}\n", encoding="utf-8")
    second = run_module._write_manifest(run_dir, "run-1", "pilot_plus_study", "trials/")

    assert second.name == "artifact-manifest.v2.json"
    # The original, completed manifest is untouched.
    assert json.loads(first.read_text(encoding="utf-8"))["artifact_hashes"] == original_hashes
    updated_hashes = json.loads(second.read_text(encoding="utf-8"))["artifact_hashes"]
    assert "study-manifest.json" in updated_hashes


def test_study_manifest_write_cannot_silently_overwrite_a_completed_manifest(tmp_path) -> None:
    """The same guard-bypass bug existed in experiments/study.py's own
    study-manifest.json write; it must version too rather than unlink-and-rewrite."""
    out_dir = tmp_path / "study-1"
    first = write_versioned_json(out_dir, "study-manifest", {"status": "completed", "evidence_class": "pilot"})
    second = write_versioned_json(out_dir, "study-manifest", {"status": "failed", "evidence_class": "pilot"})
    assert first.name == "study-manifest.json"
    assert second.name == "study-manifest.v2.json"
    assert json.loads(first.read_text(encoding="utf-8"))["status"] == "completed"
    assert json.loads(second.read_text(encoding="utf-8"))["status"] == "failed"

