"""Tests for analyze_scope_run.py's degeneracy-detection layer.

The frozen protocol's own math (experiments/analysis.py) is not under test
here -- it is independently verified elsewhere (experiments/tests/test_analysis.py)
-- this covers only the interpretive post-processing analyze_scope_run.py adds
on top: detect_degenerate_contrast, detect_constant_recall_across_arms, and
analyze()'s use of both to override a decision's h1_supported without hiding
any raw statistic.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments import analyze_scope_run as asr
from experiments.analysis import BinomialInterval

# ---------------------------------------------------------------------------
# detect_degenerate_contrast
# ---------------------------------------------------------------------------


def test_constant_arm_a_is_flagged_non_informative() -> None:
    check = asr.detect_degenerate_contrast(
        "X_vs_Y",
        arm_a_positive=[True, True, True, True],
        arm_b_positive=[False, True, False, True],
        arm_a_label="ARM-GLOBAL",
        arm_b_label="ARM-CONTEXT",
    )
    assert check.arm_a_constant is True
    assert check.arm_b_constant is False
    assert check.zero_discordant_pairs is False
    assert check.informative is False
    assert "ARM-GLOBAL" in check.reason
    assert "every one of 4" in check.reason


def test_constant_arm_b_is_flagged_non_informative() -> None:
    check = asr.detect_degenerate_contrast(
        "X_vs_Y",
        arm_a_positive=[False, True, False, True],
        arm_b_positive=[False, False, False, False],
        arm_a_label="A",
        arm_b_label="B",
    )
    assert check.arm_a_constant is False
    assert check.arm_b_constant is True
    assert check.informative is False
    assert "B" in check.reason


def test_zero_discordant_pairs_with_varying_arms_is_flagged_vacuous() -> None:
    check = asr.detect_degenerate_contrast(
        "X_vs_Y",
        arm_a_positive=[True, False, True, False],
        arm_b_positive=[True, False, True, False],
        arm_a_label="A",
        arm_b_label="B",
    )
    assert check.arm_a_constant is False
    assert check.arm_b_constant is False
    assert check.zero_discordant_pairs is True
    assert check.informative is False
    assert "agree on every" in check.reason


def test_both_arms_constant_is_still_flagged_via_arm_a_branch() -> None:
    check = asr.detect_degenerate_contrast(
        "X_vs_Y",
        arm_a_positive=[False] * 10,
        arm_b_positive=[True] * 10,
        arm_a_label="ARM-CONTEXT",
        arm_b_label="ARM-GLOBAL",
    )
    assert check.arm_a_constant is True
    assert check.arm_b_constant is True
    assert check.informative is False


def test_varying_discordant_contrast_is_informative() -> None:
    check = asr.detect_degenerate_contrast(
        "X_vs_Y",
        arm_a_positive=[True, False, True, False, True],
        arm_b_positive=[False, False, True, True, True],
        arm_a_label="A",
        arm_b_label="B",
    )
    assert check.arm_a_constant is False
    assert check.arm_b_constant is False
    assert check.zero_discordant_pairs is False
    assert check.informative is True
    assert check.reason == "contrast is informative: both arms vary and discordant pairs exist"


def test_empty_contrast_is_not_informative() -> None:
    check = asr.detect_degenerate_contrast("X_vs_Y", [], [])
    assert check.informative is False


def test_mismatched_lengths_rejected() -> None:
    with pytest.raises(ValueError):
        asr.detect_degenerate_contrast("X_vs_Y", [True], [True, False])


# ---------------------------------------------------------------------------
# detect_constant_recall_across_arms
# ---------------------------------------------------------------------------


def _interval(point: float) -> BinomialInterval:
    n = 10
    successes = round(point * n)
    return BinomialInterval(
        successes=successes, trials=n, point_estimate=point, lower=0.0, upper=1.0, confidence=0.95
    )


def test_recall_constant_at_one_across_every_arm_is_flagged() -> None:
    result = asr.detect_constant_recall_across_arms(
        {"ARM-GLOBAL": _interval(1.0), "ARM-TAG": _interval(1.0), "ARM-CONTEXT": _interval(1.0)}
    )
    assert result["constant_across_arms"] is True
    assert "1.0" in result["reason"]


def test_recall_constant_at_zero_across_every_arm_is_flagged() -> None:
    result = asr.detect_constant_recall_across_arms({"ARM-GLOBAL": _interval(0.0), "ARM-TAG": _interval(0.0)})
    assert result["constant_across_arms"] is True
    assert "0.0" in result["reason"]


def test_recall_varying_across_arms_is_not_flagged() -> None:
    result = asr.detect_constant_recall_across_arms({"ARM-GLOBAL": _interval(1.0), "ARM-CONTEXT": _interval(0.8)})
    assert result["constant_across_arms"] is False


# ---------------------------------------------------------------------------
# analyze(): reproduce the real committed profile-scope-primary-216.json shape
# -- ARM-GLOBAL constant-positive on every benign run, every other arm
# constant-negative, recall 1.0 everywhere -- and confirm the degenerate
# CONTEXT_vs_GLOBAL decision is overridden without hiding the raw statistics.
# compare_scopes() itself needs a live backend, so it is monkeypatched here;
# only analyze()'s own post-processing is under test.
# ---------------------------------------------------------------------------


def _make_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "study-degenerate"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    for i in range(10):
        record = {"trial_id": f"benign-{i}", "status": "completed", "workload_family": "WL-NGX-V1", "scenario_id": "SCN-EXEC"}
        (trials_dir / f"benign-{i}.json").write_text(json.dumps(record), encoding="utf-8")
    for i in range(5):
        record = {"trial_id": f"scenario-{i}", "status": "completed", "workload_family": "WL-NGX-V1", "scenario_id": "SCN-EXEC"}
        (trials_dir / f"scenario-{i}.json").write_text(json.dumps(record), encoding="utf-8")
    return run_dir


def _synthetic_scope_result() -> dict:
    def rows(benign_positive: bool, scenario_positive: bool) -> list[dict]:
        out = [
            {"trial_id": f"benign-{i}", "reference_key_present": True, "positive": benign_positive, "is_scenario": False}
            for i in range(10)
        ]
        out += [
            {"trial_id": f"scenario-{i}", "reference_key_present": True, "positive": scenario_positive, "is_scenario": True}
            for i in range(5)
        ]
        return out

    return {
        "scopes": {
            "ARM-GLOBAL": {"trials": rows(True, True)},
            "ARM-TAG": {"trials": rows(False, True)},
            "ARM-DIGEST": {"trials": rows(False, True)},
            "ARM-CONTEXT": {"trials": rows(False, True)},
        }
    }


def test_analyze_overrides_h1_supported_for_a_degenerate_constant_positive_comparator(tmp_path, monkeypatch) -> None:
    run_dir = _make_run_dir(tmp_path)
    monkeypatch.setattr(asr, "compare_scopes", lambda base_url, rd, threshold=0.25: _synthetic_scope_result())

    result = asr.analyze(run_dir)

    # Raw stats: this really does look "significant" by the numbers alone.
    global_mcnemar = result["primary_contrasts"]["mcnemar"]["CONTEXT_vs_ARM-GLOBAL"]
    assert global_mcnemar["p_value"] < 0.01

    global_degeneracy = result["degeneracy"]["contrasts"]["CONTEXT_vs_ARM-GLOBAL"]
    assert global_degeneracy["arm_a_constant"] is True  # ARM-CONTEXT: constant-negative
    assert global_degeneracy["arm_b_constant"] is True  # ARM-GLOBAL: constant-positive
    assert global_degeneracy["informative"] is False

    decision = result["decisions"]["CONTEXT_vs_GLOBAL"]
    assert decision["h1_supported"] is False
    # The raw statistics feeding the decision must still be reported, not hidden.
    assert decision["mcnemar"]["p_value"] == global_mcnemar["p_value"]
    assert decision["mcnemar"]["p_value"] < 0.01
    assert "carries no information" in decision["reason"] or "vacuous" in decision["reason"]

    # CONTEXT_vs_DIGEST: both arms agree on every run here, a different-flavoured
    # degeneracy (zero discordant pairs), also overridden.
    digest_degeneracy = result["degeneracy"]["contrasts"]["CONTEXT_vs_ARM-DIGEST"]
    assert digest_degeneracy["informative"] is False
    assert result["decisions"]["CONTEXT_vs_DIGEST"]["h1_supported"] is False

    assert result["degeneracy"]["recall_across_arms"]["constant_across_arms"] is True


def test_analyze_reports_degeneracy_for_every_mcnemar_contrast(tmp_path, monkeypatch) -> None:
    run_dir = _make_run_dir(tmp_path)
    monkeypatch.setattr(asr, "compare_scopes", lambda base_url, rd, threshold=0.25: _synthetic_scope_result())

    result = asr.analyze(run_dir)

    assert set(result["degeneracy"]["contrasts"]) == {
        "CONTEXT_vs_ARM-GLOBAL",
        "CONTEXT_vs_ARM-TAG",
        "CONTEXT_vs_ARM-DIGEST",
    }
