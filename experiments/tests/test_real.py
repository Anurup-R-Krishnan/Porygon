from __future__ import annotations

import json
import subprocess
import types
from pathlib import Path

import pytest

from experiments import conformance, real, run, sample_size
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
    # The live protocol document's status is a project decision, not a fixed
    # fixture value: this only checks the function returns one of the two
    # values the parser recognizes, not which one, so a legitimate freeze
    # (scripts/review_gate.py apply) never breaks this test.
    assert real.protocol_status(ROOT / "docs/RESEARCH_PROTOCOL_V1.md") in {"review_pending", "frozen"}


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


def test_confirmatory_stays_refused_while_the_review_gate_is_not_satisfied(tmp_path, monkeypatch):
    # confirmatory() consults scripts/review_gate.py:gate_state() rather than
    # grepping the passed-in protocol path's raw text, so a real (unfrozen) protocol
    # document is not what drives the refusal here -- an unsatisfied review gate is.
    fake_module = types.SimpleNamespace(
        gate_state=lambda: {
            "confirmatory_permitted": False,
            "protocol_status": "review_pending",
            "approval_problems": {"security": [], "methodology": []},
            "independence": {"independent": True, "reason": "reviewers are distinct"},
        }
    )
    monkeypatch.setattr(sample_size, "_load_review_gate", lambda: fake_module)
    pending = tmp_path / "pending.md"
    pending.write_text("Status: **REVIEW PENDING — PROHIBITED**\n", encoding="utf-8")
    with pytest.raises(ArtifactError, match="frozen"):
        run.confirmatory(pending)


def test_confirmatory_stays_refused_even_once_frozen_until_the_matrix_is_implemented(tmp_path, monkeypatch):
    """confirmatory() is a deliberate two-stage gate: the review gate reporting
    confirmatory_permitted=true is necessary but not sufficient. It must also stay
    refused until the approved workload matrix runner actually exists, so a fully
    satisfied review gate alone can never accidentally start collecting confirmatory
    data."""
    fake_module = types.SimpleNamespace(
        gate_state=lambda: {
            "confirmatory_permitted": True,
            "protocol_status": "frozen",
            "approval_problems": {"security": [], "methodology": []},
            "independence": {"independent": True, "reason": "reviewers are distinct"},
        }
    )
    monkeypatch.setattr(sample_size, "_load_review_gate", lambda: fake_module)
    frozen = tmp_path / "frozen.md"
    frozen.write_text("Status: **FROZEN**\n", encoding="utf-8")
    with pytest.raises(ArtifactError, match="workload matrix"):
        run.confirmatory(frozen)


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


# --------------------------------------------------------------------------
# Runtime-context variants must be validated for the family they run against
# --------------------------------------------------------------------------


def test_every_declared_variant_has_a_measured_classification():
    for variant in real.CONTEXT_VARIANTS:
        assert variant in real.CONTEXT_VARIANT_KIND, variant
        assert real.CONTEXT_VARIANT_KIND[variant] in {"baseline", "positive", "negative"}


def test_a_variant_not_validated_for_a_family_is_refused():
    # nonroot_user was measured only on Redis; nginx does not survive it.
    assert real.variant_available("nonroot_user", "WL-RDS")
    assert not real.variant_available("nonroot_user", "WL-NGX")
    with pytest.raises(real.PilotError, match="not validated for"):
        real.build_matrix(["WL-NGX-V1"], None, ["SCN-EXEC"], ["nonroot_user"], 1)


def test_every_family_has_a_baseline_and_at_least_one_positive_variant():
    for family in real.FAMILY_SPECS:
        assert real.variant_available("baseline", family), family
        positives = [
            v for v, kind in real.CONTEXT_VARIANT_KIND.items()
            if kind == "positive" and real.variant_available(v, family)
        ]
        assert positives, f"{family} has no behaviourally distinct variant"


def test_bypassing_the_entrypoint_supplies_its_own_command():
    # A container started without its image entrypoint must be given a command,
    # or it exits immediately and the trial measures nothing.
    for family in real.CONTEXT_VARIANTS["direct_entrypoint"]:
        assert family in real.VARIANT_COMMAND["direct_entrypoint"], family


# --------------------------------------------------------------------------
# Benign collection path (BENIGN_SENTINEL / "SCN-NONE")
# --------------------------------------------------------------------------


def test_build_matrix_accepts_the_benign_sentinel():
    matrix = real.build_matrix(["WL-NGX-V1"], ["idle"], [real.BENIGN_SENTINEL], ["baseline"], 1)
    assert len(matrix) == 1
    assert matrix[0]["scenario_id"] == real.BENIGN_SENTINEL


def test_run_benign_ground_truth_is_unambiguously_benign():
    ground_truth = real.run_benign("cnt", "abc123", "nginx@sha256:" + "a" * 64, "run-1", "trial-1")
    assert ground_truth["attack_like"] is False
    assert ground_truth["scenario_id"] == real.BENIGN_SENTINEL
    assert ground_truth["expected_outcome"] == "benign_no_action"
    assert "expected_outcome" in ground_truth  # CONF-GT-001's exact requirement
    assert ground_truth["canary_sequences_planned"] == []
    assert ground_truth["canary_sequences_executed"] == []
    assert ground_truth["exploit_executed"] is False


def test_no_canary_reconciliation_is_explicit_never_a_fabricated_pass():
    result = real._no_canary_reconciliation("benign trial: no canary was injected")
    assert result["generated"] == 0
    assert result["generated_sequences"] == []
    for name in ("generator", "spool", "api", "source", "database"):
        boundary = result["boundaries"][name]
        assert boundary["status"] == "unmeasured"
        assert boundary["reason"]
        # A fabricated pass would report a measured, zero-loss outcome; this must not.
        assert "loss_fraction" not in boundary
        assert "missing_sequences" not in boundary


# --------------------------------------------------------------------------
# Hard-negative registry and collection path
# --------------------------------------------------------------------------


def test_hard_negatives_match_the_frozen_protocol_table_exactly():
    # experiments/conformance.py:_parse_hard_negatives parses
    # docs/RESEARCH_PROTOCOL_V1.md's "Required hard negatives" column with the
    # exact regex CONF-HN-001 uses to decide what is required; HARD_NEGATIVES'
    # keys must be drawn from that same text, verbatim (including backticks
    # and slashes), or a real hard-negative trial could never satisfy the gate.
    text = (ROOT / "docs/RESEARCH_PROTOCOL_V1.md").read_text(encoding="utf-8")
    required = conformance._parse_hard_negatives(text)
    assert set(required) == set(real.HARD_NEGATIVES)
    for family, names in required.items():
        assert set(names) == set(real.HARD_NEGATIVES[family]), family


def test_build_matrix_accepts_every_familys_hard_negative_ids():
    for workload_id in real.FAMILY_SPECS:
        for hard_negative_id in real.HARD_NEGATIVES[workload_id]:
            matrix = real.build_matrix(
                [f"{workload_id}-V1"], ["idle"], [hard_negative_id], ["baseline"], 1
            )
            assert matrix[0]["scenario_id"] == hard_negative_id


def test_build_matrix_refuses_a_hard_negative_id_for_the_wrong_family():
    with pytest.raises(real.PilotError, match="not a frozen scenario"):
        real.build_matrix(["WL-NGX-V1"], ["idle"], ["`BGSAVE`"], ["baseline"], 1)


def test_run_hard_negative_rejects_an_id_not_declared_for_the_family():
    with pytest.raises(real.PilotError, match="not a declared hard negative"):
        real.run_hard_negative(
            "cnt", "abc123", "nginx@sha256:" + "a" * 64, "run-1", "trial-1",
            "WL-NGX", "`BGSAVE`", 8080,
        )


def test_run_hard_negative_executes_the_registered_container_command(monkeypatch):
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(real.subprocess, "run", fake_run)
    ground_truth = real.run_hard_negative(
        "cnt", "abc123", "nginx@sha256:" + "a" * 64, "run-1", "trial-1",
        "WL-NGX", "config validation/reload", 8080,
    )
    assert captured["cmd"][:3] == ["docker", "exec", "cnt"]
    assert captured["cmd"][-1] == real.HARD_NEGATIVES["WL-NGX"]["config validation/reload"]["command"]
    assert ground_truth["attack_like"] is False
    assert ground_truth["hard_negative_id"] == "config validation/reload"
    assert ground_truth["expected_outcome"] == "hard_negative_config_reload"
    assert ground_truth["execution"]["kind"] == "container_exec"
    assert ground_truth["canary_sequences_executed"] == []


def test_run_hard_negative_driver_only_variant_never_execs_into_the_container(monkeypatch):
    def refuse_exec(*args, **kwargs):
        raise AssertionError("a driver-only hard negative must never call docker exec")

    monkeypatch.setattr(real.subprocess, "run", refuse_exec)
    monkeypatch.setattr(
        real, "drive_load",
        lambda container, family, port, mode, operations, seed: {
            "mode": mode, "operations_planned": operations, "successes": operations,
            "failures": 0, "seed": seed, "latency_ms_samples": [], "harness_induced_exec_count": 0,
        },
    )
    ground_truth = real.run_hard_negative(
        "cnt", "abc123", "nginx@sha256:" + "a" * 64, "run-1", "trial-1",
        "WL-NGX", "traffic spike", 8080,
    )
    assert ground_truth["attack_like"] is False
    assert ground_truth["hard_negative_id"] == "traffic spike"
    assert ground_truth["execution"]["kind"] == "driver_burst"
    assert ground_truth["canary_sequences_executed"] == []


# --------------------------------------------------------------------------
# run_trial dispatch: benign / hard-negative trials never call run_scenario or
# reconcile_trial, and always carry hard_negative_id at the top level.
# --------------------------------------------------------------------------


def _mock_container_plumbing(monkeypatch):
    monkeypatch.setattr(real, "start_container", lambda *a, **k: "deadbeefcafe0")
    monkeypatch.setattr(real, "docker", lambda *a, **k: json.dumps([{"Id": "deadbeefcafe0"}]))
    monkeypatch.setattr(real, "runtime_context", lambda inspection: {"fake": True})
    monkeypatch.setattr(real, "context_hash", lambda document: "c" * 64)
    monkeypatch.setattr(real, "_published_port", lambda *a, **k: 18080)
    monkeypatch.setattr(real, "wait_ready", lambda *a, **k: {"ready_after_ms": 1.0, "probe": "WL-NGX"})
    monkeypatch.setattr(
        real, "drive_load",
        lambda container, family, port, mode, operations, seed: {
            "mode": mode, "operations_planned": operations, "successes": operations,
            "failures": 0, "seed": seed, "latency_ms_samples": [], "harness_induced_exec_count": 0,
        },
    )
    monkeypatch.setattr(real, "remove_container", lambda *a, **k: {"removed": True, "name": a[0]})


def test_run_trial_dispatches_the_benign_sentinel_without_a_canary(monkeypatch):
    _mock_container_plumbing(monkeypatch)
    monkeypatch.setattr(
        real, "run_scenario",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("run_scenario must not be called for SCN-NONE")),
    )
    monkeypatch.setattr(
        real, "reconcile_trial",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("reconcile_trial must not be called for SCN-NONE")),
    )
    record = real.run_trial(
        run_id="run-1", trial_id="t-1", workload_id="WL-NGX-V1", mode="idle",
        scenario_id=real.BENIGN_SENTINEL, variant="baseline", replica=1,
        image={"human_tag": "nginx:1.26.3-alpine", "reference": "nginx@sha256:" + "a" * 64},
        network="net", base_url="http://x", seed=1, warmup_seconds=0, operations=0, settle_seconds=0,
    )
    assert record["status"] == "completed"
    assert record["hard_negative_id"] is None
    assert record["ground_truth"]["attack_like"] is False
    assert record["ground_truth"]["expected_outcome"] == "benign_no_action"
    for boundary in record["reconciliation"]["boundaries"].values():
        assert boundary["status"] == "unmeasured"
        assert boundary["reason"]


def test_run_trial_dispatches_a_hard_negative_and_tags_ground_truth_benign(monkeypatch):
    _mock_container_plumbing(monkeypatch)
    monkeypatch.setattr(real.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, b"", b""))
    monkeypatch.setattr(
        real, "run_scenario",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("run_scenario must not be called for a hard negative")),
    )
    monkeypatch.setattr(
        real, "reconcile_trial",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("reconcile_trial must not be called for a hard negative")),
    )
    record = real.run_trial(
        run_id="run-1", trial_id="t-2", workload_id="WL-NGX-V1", mode="idle",
        scenario_id="config validation/reload", variant="baseline", replica=1,
        image={"human_tag": "nginx:1.26.3-alpine", "reference": "nginx@sha256:" + "a" * 64},
        network="net", base_url="http://x", seed=1, warmup_seconds=0, operations=0, settle_seconds=0,
    )
    assert record["status"] == "completed"
    assert record["hard_negative_id"] == "config validation/reload"
    assert record["ground_truth"]["attack_like"] is False
    assert record["ground_truth"]["hard_negative_id"] == "config validation/reload"
    assert "expected_outcome" in record["ground_truth"]
    for boundary in record["reconciliation"]["boundaries"].values():
        assert boundary["status"] == "unmeasured"
        assert boundary["reason"]


def test_run_trial_leaves_hard_negative_id_none_for_an_ordinary_scenario(monkeypatch):
    _mock_container_plumbing(monkeypatch)
    monkeypatch.setattr(
        real, "run_scenario",
        lambda container, container_id, image_digest, run_id, trial_id, scenario_id: {
            "schema_version": "porygon.experiment.ground-truth.v1", "run_id": run_id, "trial_id": trial_id,
            "scenario_id": scenario_id, "expected_outcome": "controlled_positive", "attack_like": False,
            "canary_sequences_executed": [1, 2],
        },
    )
    monkeypatch.setattr(
        real, "reconcile_trial",
        lambda base_url, container_id, run_id, trial_id, generated: {
            "generated": len(generated), "generated_sequences": generated,
            "boundaries": {"generator": {"status": "measured", "observed": len(generated),
                                          "missing_sequences": [], "duplicates": 0, "loss_fraction": 0.0}},
        },
    )
    record = real.run_trial(
        run_id="run-1", trial_id="t-3", workload_id="WL-NGX-V1", mode="idle",
        scenario_id="SCN-EXEC", variant="baseline", replica=1,
        image={"human_tag": "nginx:1.26.3-alpine", "reference": "nginx@sha256:" + "a" * 64},
        network="net", base_url="http://x", seed=1, warmup_seconds=0, operations=0, settle_seconds=0,
    )
    assert record["status"] == "completed"
    assert record["hard_negative_id"] is None
    assert record["reconciliation"]["boundaries"]["generator"]["status"] == "measured"


# --------------------------------------------------------------------------
# trial_id_for / container naming stays Docker-safe for hard-negative IDs
# --------------------------------------------------------------------------


def test_trial_id_for_is_docker_name_safe_for_every_hard_negative_and_the_benign_sentinel():
    docker_safe = __import__("re").compile(r"^[a-z0-9][a-z0-9_.-]*$")
    for workload_id, negatives in real.HARD_NEGATIVES.items():
        for hard_negative_id in negatives:
            trial_id = real.trial_id_for(f"{workload_id}-V1", "idle", hard_negative_id, "baseline", 1)
            assert docker_safe.match(trial_id), trial_id
    trial_id = real.trial_id_for("WL-NGX-V1", "idle", real.BENIGN_SENTINEL, "baseline", 1)
    assert docker_safe.match(trial_id), trial_id


def test_trial_id_for_is_unchanged_for_ordinary_scenario_ids():
    # Backward compatibility: no existing scenario/mode/variant identifier
    # contains a character outside Docker's name charset, so sanitization
    # must be a byte-for-byte no-op for them.
    assert (
        real.trial_id_for("WL-NGX-V1", "alternate_read_only_config", "SCN-CONTEXT", "dropped_capabilities", 1)
        == "wl-ngx-v1-alternate_read_only_config-scn-context-dropped_capabilities-r01"
    )


# --------------------------------------------------------------------------
# CONF-HN-001 integration: a synthetic run built from these new trial types
# must satisfy the conformance gate's hard-negative check.
# --------------------------------------------------------------------------


def _tiny_hn_manifest() -> dict:
    return {
        "protocol_id": "test.protocol",
        "protocol_status": "frozen",
        "protocol_sha256": "test-protocol-sha256",
        "workloads": [{"id": "WL-NGX", "versions": ["WL-NGX-V1"], "modes": ["idle"]}],
        "scenario_ids": ["SCN-EXEC"],
        "runtime_scenario_ids": ["SCN-EXEC"],
        "analysis_only_scenario_ids": [],
        "hard_negatives": {"WL-NGX": list(real.HARD_NEGATIVES["WL-NGX"])},
        "image_coordinates": {"WL-NGX-V1": {"human_tag": "nginx:1.26.3-alpine", "index_digest_ref": "nginx@sha256:" + "a" * 64}},
        "min_replicas_per_split": 1,
        "min_fit_calibration_per_stratum": 1,
        "min_confirmatory_benign_per_cell": 1,
        "min_confirmatory_scenario_per_cell": 1,
    }


def test_conf_hn_001_is_satisfied_by_a_run_built_from_the_new_trial_types(tmp_path):
    run_dir = tmp_path / "study-fake"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    for index, hard_negative_id in enumerate(real.HARD_NEGATIVES["WL-NGX"], start=1):
        trial_id = f"hn-{index}"
        record = {
            "trial_id": trial_id,
            "status": "completed",
            "workload_id": "WL-NGX-V1",
            "mode": "idle",
            "scenario_id": hard_negative_id,
            "hard_negative_id": hard_negative_id,
            "context_variant": "baseline",
            "replica_index": index,
            "human_tag": "nginx:1.26.3-alpine",
            "image": {"reference": "nginx@sha256:" + "a" * 64},
            "ground_truth": {"expected_outcome": "hard_negative", "attack_like": False},
        }
        (trials_dir / f"{trial_id}.json").write_text(json.dumps(record), encoding="utf-8")

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_hn_manifest())
    hn_finding = next(f for f in report.findings if f.check_id == "CONF-HN-001")
    assert hn_finding.satisfied is True, hn_finding.detail
