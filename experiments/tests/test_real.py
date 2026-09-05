from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import real, run
from experiments.artifacts import (
    ArtifactError,
    assign_split,
    atomic_write_json,
    check_split_isolation,
)

ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------
# Workload catalogue and matrix
# --------------------------------------------------------------------------


def test_image_coordinates_come_from_the_frozen_document():
    coordinates = real.load_image_coordinates()
    assert set(coordinates) == {
        "WL-NGX-V1", "WL-NGX-V2", "WL-RDS-V1", "WL-RDS-V2", "WL-PG-V1", "WL-PG-V2",
    }
    for workload_id, entry in coordinates.items():
        assert "@sha256:" in entry["index_digest_ref"], workload_id
        assert len(entry["index_digest_ref"].split("@sha256:")[1]) == 64


def test_mutable_references_are_refused():
    with pytest.raises(real.PilotError, match="mutable"):
        real.pull_pinned_image("nginx:latest")


def test_matrix_refuses_analysis_only_scenarios():
    with pytest.raises(real.PilotError, match="no runtime action"):
        real.build_matrix(["WL-NGX-V1"], None, ["SCN-POISON"], ["baseline"], 1)
    with pytest.raises(real.PilotError, match="no runtime action"):
        real.build_matrix(["WL-NGX-V1"], None, ["SCN-CROSS"], ["baseline"], 1)


def test_matrix_refuses_modes_outside_the_frozen_catalogue():
    with pytest.raises(real.PilotError, match="not a frozen mode"):
        real.build_matrix(["WL-NGX-V1"], ["steady_set_get"], ["SCN-EXEC"], ["baseline"], 1)


def test_matrix_trial_ids_are_deterministic_and_unique():
    first = real.build_matrix(["WL-NGX-V1", "WL-RDS-V1"], None, ["SCN-EXEC"], ["baseline"], 2)
    second = real.build_matrix(["WL-NGX-V1", "WL-RDS-V1"], None, ["SCN-EXEC"], ["baseline"], 2)
    assert first == second
    identifiers = [entry["trial_id"] for entry in first]
    assert len(identifiers) == len(set(identifiers)) == 4


# --------------------------------------------------------------------------
# Cleanup safety
# --------------------------------------------------------------------------


def test_cleanup_refuses_an_ambiguous_target(monkeypatch):
    monkeypatch.setattr(real, "docker", lambda *args, **kwargs: "a\na-extra")
    with pytest.raises(real.PilotError, match="ambiguous"):
        real.remove_container("a", "run-1", "trial-1")


def test_cleanup_refuses_a_container_that_is_not_labelled_for_this_trial(monkeypatch):
    monkeypatch.setattr(real, "docker", lambda *args, **kwargs: "victim")
    monkeypatch.setattr(real, "_labels_of", lambda name: {real.LABEL_RUN: "another-run"})
    with pytest.raises(real.PilotError, match="foreign"):
        real.remove_container("victim", "run-1", "trial-1")


def test_cleanup_is_a_no_op_when_nothing_matches(monkeypatch):
    monkeypatch.setattr(real, "docker", lambda *args, **kwargs: "")
    assert real.remove_container("gone", "run-1", "trial-1")["removed"] is False


# --------------------------------------------------------------------------
# Measurement semantics
# --------------------------------------------------------------------------


def test_percentiles_come_from_raw_samples_not_averages():
    samples = [float(value) for value in range(1, 101)]
    assert real.percentile(samples, 0.50) == 50.0
    assert real.percentile(samples, 0.95) == 95.0
    assert real.percentile(samples, 0.99) == 99.0
    assert real.percentile([], 0.95) is None
    assert real.percentile([7.0], 0.99) == 7.0


def test_reconciliation_marks_unobservable_boundaries_unmeasured_never_zero(monkeypatch):
    monkeypatch.setattr(real, "_falco_observed", lambda *a: {"status": "measured", "sequences": [1, 2]})
    monkeypatch.setattr(
        real, "_database_observed",
        lambda *a: {"status": "unmeasured", "reason": "backend query failed"},
    )
    result = real.reconcile_trial("http://x", "abc", "run", "trial", [1, 2, 3])
    boundaries = result["boundaries"]
    assert boundaries["source"]["missing_sequences"] == [3]
    assert boundaries["source"]["loss_fraction"] == pytest.approx(1 / 3)
    for name in ("spool", "api", "database"):
        assert boundaries[name]["status"] == "unmeasured"
        assert boundaries[name]["reason"]
        assert "observed" not in boundaries[name], f"{name} must not imply a count it never made"


def test_duplicates_are_reported_separately_from_loss(monkeypatch):
    monkeypatch.setattr(real, "_falco_observed", lambda *a: {"status": "measured", "sequences": [1, 2]})
    monkeypatch.setattr(
        real, "_database_observed",
        lambda *a: {"status": "measured", "sequences": [1, 2], "duplicates": 3},
    )
    boundaries = real.reconcile_trial("http://x", "abc", "run", "trial", [1, 2])["boundaries"]
    assert boundaries["database"]["duplicates"] == 3
    assert boundaries["database"]["loss_fraction"] == 0.0


def test_protocol_status_is_read_from_the_document(tmp_path):
    pending = tmp_path / "pending.md"
    pending.write_text("Status: **REVIEW PENDING — PROHIBITED**\n", encoding="utf-8")
    assert real.protocol_status(pending) == "review_pending"
    frozen = tmp_path / "frozen.md"
    frozen.write_text("Status: **FROZEN**\n", encoding="utf-8")
    assert real.protocol_status(frozen) == "frozen"
    assert real.protocol_status(ROOT / "docs/RESEARCH_PROTOCOL_V1.md") == "review_pending"


# --------------------------------------------------------------------------
# Split isolation — leakage must fail loudly
# --------------------------------------------------------------------------


def test_reusing_one_run_across_splits_fails_validation():
    records = [
        {"run_id": "run-a", "split": "fit"},
        {"run_id": "run-b", "split": "calibration"},
        {"run_id": "run-a", "split": "test"},
    ]
    with pytest.raises(ArtifactError, match="split leakage"):
        check_split_isolation(records)


def test_clean_split_assignment_passes():
    records = [{"run_id": f"run-{index}", "split": assign_split(f"run-{index}")} for index in range(20)]
    check_split_isolation(records)
    assert len({record["split"] for record in records}) > 1


def test_split_assignment_is_deterministic_and_run_level():
    assert assign_split("run-a") == assign_split("run-a")
    assert {assign_split(f"run-{index}") for index in range(50)} <= {"fit", "calibration", "test"}


def test_unknown_split_is_rejected():
    with pytest.raises(ArtifactError, match="unknown split"):
        check_split_isolation([{"run_id": "r", "split": "train_test_mixed"}])


# --------------------------------------------------------------------------
# Pilot artifact contract
# --------------------------------------------------------------------------


def _pilot_run(tmp_path: Path, trial: dict) -> Path:
    run_dir = tmp_path / "pilot"
    (run_dir / "trials").mkdir(parents=True)
    atomic_write_json(
        run_dir / "run.json",
        {"schema_version": "porygon.experiment.run.v2", "run_id": "run-1",
         "kind": "real_container_pilot", "research_eligible": False},
    )
    atomic_write_json(run_dir / "trials" / f"{trial['trial_id']}.json", trial)
    run._write_pilot_summary(run_dir / "summary.csv", [trial])
    run._write_manifest(run_dir, "run-1", "pilot_only", "trials/")
    return run_dir


def _completed_trial(**overrides) -> dict:
    trial = {
        "schema_version": "porygon.experiment.trial.v2",
        "run_id": "run-1", "trial_id": "t-1", "workload_id": "WL-NGX-V1",
        "human_tag": "nginx:1.26.3-alpine", "mode": "steady_http", "scenario_id": "SCN-EXEC",
        "context_variant": "baseline", "replica_index": 1, "status": "completed",
        "research_eligible": False, "runtime_context_hash": "a" * 64,
        "image": {"reference": "nginx@sha256:" + "b" * 64},
        "load": {"operations_planned": 2, "successes": 2, "failures": 0,
                 "latency_ms_samples": [1.0, 2.0], "harness_induced_exec_count": 0},
        "reconciliation": {"generated": 1, "boundaries": {
            "generator": {"status": "measured", "observed": 1, "missing_sequences": []},
            "spool": {"status": "unmeasured", "reason": "process-local counters"},
        }},
    }
    return trial | overrides


def test_valid_pilot_run_passes_validation(tmp_path):
    run.validate(_pilot_run(tmp_path, _completed_trial()))


def test_pilot_run_claiming_research_eligibility_is_rejected(tmp_path):
    run_dir = _pilot_run(tmp_path, _completed_trial(research_eligible=True))
    with pytest.raises(ArtifactError, match="research_eligible=false"):
        run.validate(run_dir)


def test_mutable_image_reference_in_a_trial_is_rejected(tmp_path):
    run_dir = _pilot_run(tmp_path, _completed_trial(image={"reference": "nginx:latest"}))
    with pytest.raises(ArtifactError, match="immutable digest"):
        run.validate(run_dir)


def test_unmeasured_boundary_without_a_reason_is_rejected(tmp_path):
    trial = _completed_trial()
    trial["reconciliation"]["boundaries"]["spool"] = {"status": "unmeasured"}
    with pytest.raises(ArtifactError, match="records no reason"):
        run.validate(_pilot_run(tmp_path, trial))


def test_failed_trial_is_retained_and_must_state_why(tmp_path):
    run.validate(_pilot_run(tmp_path, {
        "run_id": "run-1", "trial_id": "t-1", "status": "failed",
        "research_eligible": False, "failure_reason": "PilotError: image pull failed",
        "workload_id": "WL-NGX-V1", "human_tag": "nginx:1.26.3-alpine", "mode": "idle",
        "scenario_id": "SCN-EXEC", "context_variant": "baseline", "replica_index": 1,
    }))
    with pytest.raises(ArtifactError, match="records no reason"):
        run.validate(_pilot_run(tmp_path / "second", {
            "run_id": "run-1", "trial_id": "t-1", "status": "failed",
            "research_eligible": False, "workload_id": "WL-NGX-V1",
            "human_tag": "nginx:1.26.3-alpine", "mode": "idle", "scenario_id": "SCN-EXEC",
            "context_variant": "baseline", "replica_index": 1,
        }))


def test_an_artifact_missing_from_the_manifest_is_rejected(tmp_path):
    run_dir = _pilot_run(tmp_path, _completed_trial())
    (run_dir / "sneaked-in.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ArtifactError, match="absent from the manifest"):
        run.validate(run_dir)


def test_pilot_replay_is_deterministic(tmp_path):
    run_dir = _pilot_run(tmp_path, _completed_trial())
    run.replay(run_dir)
    tampered = json.loads((run_dir / "trials" / "t-1.json").read_text(encoding="utf-8"))
    tampered["load"]["successes"] = 99
    (run_dir / "trials" / "t-1.json").write_text(json.dumps(tampered), encoding="utf-8")
    run._write_manifest(run_dir, "run-1", "pilot_only", "trials/")
    with pytest.raises(ArtifactError, match="replay differs"):
        run.replay(run_dir)


def test_confirmatory_stays_refused_while_the_protocol_is_review_pending():
    with pytest.raises(ArtifactError, match="frozen"):
        run.confirmatory(ROOT / "docs/RESEARCH_PROTOCOL_V1.md")


def test_long_trial_names_stay_unique_instead_of_colliding():
    run_id = "pilot-20260905t120000z"
    first = real.container_name_for(run_id, real.trial_id_for(
        "WL-NGX-V1", "alternate_read_only_config", "SCN-CONTEXT", "dropped_capabilities", 1))
    second = real.container_name_for(run_id, real.trial_id_for(
        "WL-NGX-V1", "alternate_read_only_config", "SCN-CONTEXT", "read_only_rootfs", 1))
    assert len(first) <= 63 and len(second) <= 63
    assert first != second, "truncated container names must not collide across trials"


def test_short_names_are_left_alone():
    assert real.container_name_for("r1", "t1") == "porygon-exp-r1-t1"
