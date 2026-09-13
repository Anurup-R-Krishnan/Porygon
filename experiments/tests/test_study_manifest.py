from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import run, study
from experiments.artifacts import ArtifactError, atomic_write_json, versioned_artifact_paths


def _build_pilot_run(run_dir: Path, run_id: str) -> None:
    """A minimal, real-shaped pilot run directory: what run_pilot leaves behind once a
    real-container pilot completes, without needing Docker or a live API."""
    (run_dir / "trials").mkdir(parents=True)
    atomic_write_json(
        run_dir / "run.json",
        {
            "schema_version": "porygon.experiment.run.v2",
            "run_id": run_id,
            "kind": "real_container_pilot",
            "research_eligible": False,
        },
    )
    trial = {
        "schema_version": "porygon.experiment.trial.v2",
        "run_id": run_id,
        "trial_id": "t-1",
        "workload_id": "WL-NGX-V1",
        "human_tag": "nginx:1.26.3-alpine",
        "mode": "steady_http",
        "scenario_id": "SCN-EXEC",
        "context_variant": "baseline",
        "replica_index": 1,
        "status": "completed",
        "research_eligible": False,
        "runtime_context_hash": "a" * 64,
        "image": {"reference": "nginx@sha256:" + "b" * 64},
        "load": {
            "operations_planned": 2, "successes": 2, "failures": 0,
            "latency_ms_samples": [1.0, 2.0], "harness_induced_exec_count": 0,
        },
        "reconciliation": {
            "generated": 1,
            "boundaries": {
                "generator": {"status": "measured", "observed": 1, "missing_sequences": []},
            },
        },
    }
    atomic_write_json(run_dir / "trials" / "t-1.json", trial)
    run._write_pilot_summary(run_dir / "summary.csv", [trial])
    run._write_manifest(run_dir, run_id, "pilot_only", "trials/")


# ---------------------------------------------------------------------------
# Item 1: evidence class must follow the run's own recorded facts
# ---------------------------------------------------------------------------


def test_evidence_class_is_pilot_when_no_run_directory_was_produced() -> None:
    assert study._run_evidence_class(None) == ("pilot", False)


def test_evidence_class_follows_the_runs_own_flag_not_protocol_status(tmp_path) -> None:
    run_dir = tmp_path / "pilot"
    _build_pilot_run(run_dir, "run-1")
    # run_pilot always records research_eligible=false on run.json. The study manifest
    # must report pilot/False here regardless of whether the protocol document happens to
    # be frozen -- protocol-frozen status alone must never be sufficient to claim
    # confirmatory evidence.
    assert study._run_evidence_class(run_dir) == ("pilot", False)


def test_evidence_class_would_follow_a_run_that_actually_declares_confirmatory(tmp_path) -> None:
    # No such run exists yet (run.py's confirmatory() is an intentional stub), but the
    # derivation itself should be driven by the run's own declaration, not hardcoded to
    # always say pilot.
    run_dir = tmp_path / "confirmatory"
    run_dir.mkdir()
    atomic_write_json(run_dir / "run.json", {"run_id": "run-2", "research_eligible": True})
    assert study._run_evidence_class(run_dir) == ("confirmatory", True)


# ---------------------------------------------------------------------------
# Item 3: the study pipeline must leave a validate()-clean run directory
# ---------------------------------------------------------------------------


def test_run_study_manifest_consistency_leaves_a_validatable_run_directory(tmp_path, monkeypatch) -> None:
    """A lightweight stand-in for the full pipeline: the live-infra stages
    (environment/protocol/harness/analysis/results) need Docker and a running API, so
    replace STAGES with a single fake collection stage that hands run_study an
    already-completed pilot run directory, and only exercise what's under test here --
    that after study.py writes study-manifest.json into it, run.py's own validate()
    actually passes end to end. It used to always fail with "artifacts present but absent
    from the manifest: ['study-manifest.json']" because nothing re-ran the validator (or
    regenerated the manifest) after that file was added.
    """
    run_id = "study-fixture"
    run_dir = tmp_path / run_id
    _build_pilot_run(run_dir, run_id)
    monkeypatch.setattr(study, "STUDY_ROOT", tmp_path)
    monkeypatch.setattr(study, "ROOT", tmp_path)  # so path.relative_to(ROOT) resolves under tmp_path

    def fake_collect(ctx):
        ctx["run_dir"] = run_dir
        ctx["trial_count"] = 1
        return {"run_dir": str(run_dir)}

    monkeypatch.setattr(study, "STAGES", [study.Stage("collection", fake_collect)])

    path = study.run_study(run_id=run_id)

    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["evidence_class"] == "pilot"
    assert manifest["research_eligible"] is False

    run.validate(run_dir)  # must not raise

    latest_artifact_manifest = versioned_artifact_paths(run_dir, "artifact-manifest")[-1]
    hashes = json.loads(latest_artifact_manifest.read_text(encoding="utf-8"))["artifact_hashes"]
    assert "study-manifest.json" in hashes


def test_run_study_raises_if_the_final_revalidation_fails(tmp_path, monkeypatch) -> None:
    """The manifest-consistency check is a required final stage: if it fails, that means
    the pipeline's own artifact bookkeeping is broken, so run_study must not silently
    report success -- it must propagate the failure rather than swallow it."""
    run_id = "study-broken"
    run_dir = tmp_path / run_id
    _build_pilot_run(run_dir, run_id)
    monkeypatch.setattr(study, "STUDY_ROOT", tmp_path)
    monkeypatch.setattr(study, "ROOT", tmp_path)

    def fake_collect(ctx):
        ctx["run_dir"] = run_dir
        ctx["trial_count"] = 1
        return {"run_dir": str(run_dir)}

    monkeypatch.setattr(study, "STAGES", [study.Stage("collection", fake_collect)])

    def broken_validate(_run_dir):
        raise ArtifactError("forced failure for test")

    monkeypatch.setattr(run, "validate", broken_validate)

    with pytest.raises(ArtifactError, match="forced failure"):
        study.run_study(run_id=run_id)
