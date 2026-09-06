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
):
    record = {
        "trial_id": trial_id,
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
