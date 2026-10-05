"""Tests for experiments/context_delta.py, the exploratory direct
runtime-context-delta feature.
"""
from __future__ import annotations

import json

import pytest

from experiments import context_delta


def _write_trial(
    trials_dir,
    trial_id,
    *,
    image_ref,
    context_variant,
    runtime_context,
    attack_like=False,
    status="completed",
    container_id=None,
):
    record = {
        "trial_id": trial_id,
        "container_id": container_id if container_id is not None else f"c-{trial_id}",
        "status": status,
        "image": {"reference": image_ref},
        "context_variant": context_variant,
        "runtime_context": runtime_context,
        "ground_truth": {"attack_like": attack_like},
    }
    (trials_dir / f"{trial_id}.json").write_text(json.dumps(record), encoding="utf-8")


BASELINE_CTX = {
    "privileged": False,
    "capabilities": {"add": [], "drop": []},
    "read_only_rootfs": False,
    "network_mode": "user-defined",
    "mounts": [],
    "devices": [],
}
DROPPED_CAP_CTX = {**BASELINE_CTX, "capabilities": {"add": [], "drop": ["NET_RAW"]}}
PRIVILEGED_CTX = {**BASELINE_CTX, "privileged": True}


def test_context_delta_score_is_zero_for_identical_documents():
    score, diffs = context_delta.context_delta_score(BASELINE_CTX, BASELINE_CTX)
    assert score == 0.0
    assert not any(diffs.values())


def test_context_delta_score_detects_capability_drop():
    score, diffs = context_delta.context_delta_score(BASELINE_CTX, DROPPED_CAP_CTX)
    assert score > 0.0
    assert diffs["capabilities"] is True
    assert diffs["privileged"] is False


def test_context_delta_score_weighs_privileged_highest():
    cap_score, _ = context_delta.context_delta_score(BASELINE_CTX, DROPPED_CAP_CTX)
    priv_score, _ = context_delta.context_delta_score(BASELINE_CTX, PRIVILEGED_CTX)
    assert priv_score > cap_score


@pytest.fixture
def trials_dir(tmp_path):
    directory = tmp_path / "trials"
    directory.mkdir()
    return tmp_path


def test_evaluate_separates_baseline_from_dropped_capabilities(trials_dir):
    _write_trial(
        trials_dir / "trials", "fit-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    _write_trial(
        trials_dir / "trials", "test-baseline-r02", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    _write_trial(
        trials_dir / "trials", "test-dropped-r03", image_ref="nginx@sha256:abc",
        context_variant="dropped_capabilities", runtime_context=DROPPED_CAP_CTX,
    )

    # Force deterministic split assignment via monkeypatched assign_split
    import experiments.context_delta as module

    original = module.assign_split
    module.assign_split = lambda trial_id: "fit" if trial_id.startswith("fit") else "test"
    try:
        result = module.evaluate(trials_dir)
    finally:
        module.assign_split = original

    by_variant = result["by_context_variant"]
    assert by_variant.get("baseline", {"positive": 0})["positive"] == 0
    assert by_variant["dropped_capabilities"]["positive"] == 1


def test_evaluate_reports_insufficient_profile_for_unknown_digest(trials_dir):
    _write_trial(
        trials_dir / "trials", "test-r01", image_ref="unseen@sha256:zzz",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    import experiments.context_delta as module

    original = module.assign_split
    module.assign_split = lambda trial_id: "test"
    try:
        result = module.evaluate(trials_dir)
    finally:
        module.assign_split = original

    assert result["trials"][0]["insufficient_profile"] is True


# ---------------------------------------------------------------------------
# Split-leak regression tests and MET-CAL-001 calibration-coverage tests.
# ---------------------------------------------------------------------------


def test_evaluate_never_scores_a_calibration_trial_as_test(trials_dir):
    """Regression test for the calibration-into-test pooling bug: a
    calibration-split trial_id must never appear among the test-scored trials."""
    _write_trial(
        trials_dir / "trials", "fit-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    _write_trial(
        trials_dir / "trials", "cal-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    _write_trial(
        trials_dir / "trials", "test-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )

    import experiments.context_delta as module

    split_map = {"fit-r01": "fit", "cal-r01": "calibration", "test-r01": "test"}
    original = module.assign_split
    module.assign_split = lambda trial_id: split_map[trial_id]
    try:
        result = module.evaluate(trials_dir)
    finally:
        module.assign_split = original

    scored_ids = {t["trial_id"] for t in result["trials"]}
    assert "cal-r01" not in scored_ids
    assert scored_ids == {"test-r01"}
    assert result["calibration_coverage"]["calibration_trials"] == 1


def test_calibration_coverage_returns_a_sane_interval(trials_dir):
    _write_trial(
        trials_dir / "trials", "fit-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    _write_trial(
        trials_dir / "trials", "cal-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )

    import experiments.context_delta as module

    split_map = {"fit-r01": "fit", "cal-r01": "calibration"}
    original = module.assign_split
    module.assign_split = lambda trial_id: split_map[trial_id]
    try:
        result = module.evaluate(trials_dir)
    finally:
        module.assign_split = original

    coverage = result["calibration_coverage"]
    assert coverage["alpha"] == module.CALIBRATION_COVERAGE_ALPHA
    interval = coverage["coverage"]
    assert interval["trials"] == 1
    assert 0.0 <= interval["lower"] <= interval["upper"] <= 1.0
    # Identical context documents -> zero delta -> maximal p-value -> covered.
    assert coverage["covered"] == 1
    assert coverage["trials"][0]["status"] == "scored"


def test_calibration_coverage_reports_drift_for_a_different_context_variant(trials_dir):
    """A calibration trial whose context_variant differs from the variant
    that produced its digest's fit-split reference is drift, not an ordinary
    scored outcome."""
    _write_trial(
        trials_dir / "trials", "fit-r01", image_ref="nginx@sha256:abc",
        context_variant="baseline", runtime_context=BASELINE_CTX,
    )
    _write_trial(
        trials_dir / "trials", "cal-r01", image_ref="nginx@sha256:abc",
        context_variant="dropped_capabilities", runtime_context=DROPPED_CAP_CTX,
    )

    import experiments.context_delta as module

    split_map = {"fit-r01": "fit", "cal-r01": "calibration"}
    original = module.assign_split
    module.assign_split = lambda trial_id: split_map[trial_id]
    try:
        result = module.evaluate(trials_dir)
    finally:
        module.assign_split = original

    coverage = result["calibration_coverage"]
    assert coverage["drift_detected_runs"] == 1
    assert coverage["trials"][0]["status"] == "drift_detected"
    assert coverage["trials"][0]["covered"] is False


def test_check_calibration_test_isolation_raises_on_container_id_collision():
    """The isolation check must be capable of catching a real cross-split
    leak: two records sharing the same container_id (the real Docker runtime
    identity) but disagreeing on split is exactly that, unlike keying by
    trial_id, whose split is a pure function of itself."""
    from experiments.artifacts import ArtifactError

    calibration = [
        context_delta.ContextTrial(
            trial_id="cal-r01", container_id="shared-container", image_digest="nginx@sha256:abc",
            context_variant="baseline", split="calibration", is_scenario=False, runtime_context=BASELINE_CTX,
        )
    ]
    test = [
        context_delta.ContextTrial(
            trial_id="test-r01", container_id="shared-container", image_digest="nginx@sha256:abc",
            context_variant="baseline", split="test", is_scenario=False, runtime_context=BASELINE_CTX,
        )
    ]
    with pytest.raises(ArtifactError, match="split leakage"):
        context_delta.check_calibration_test_isolation([], calibration, test)


def test_check_calibration_test_isolation_passes_when_containers_are_distinct():
    calibration = [
        context_delta.ContextTrial(
            trial_id="cal-r01", container_id="c-cal", image_digest="nginx@sha256:abc",
            context_variant="baseline", split="calibration", is_scenario=False, runtime_context=BASELINE_CTX,
        )
    ]
    test = [
        context_delta.ContextTrial(
            trial_id="test-r01", container_id="c-test", image_digest="nginx@sha256:abc",
            context_variant="baseline", split="test", is_scenario=False, runtime_context=BASELINE_CTX,
        )
    ]
    context_delta.check_calibration_test_isolation([], calibration, test)
