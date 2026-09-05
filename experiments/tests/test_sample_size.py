"""Tests for experiments/sample_size.py, the ART-DES-001 power-lock builder."""
from __future__ import annotations

import math

import pytest

from experiments.sample_size import (
    MAX_CANDIDATE_COUNT,
    assert_no_confirmatory_contamination,
    build_sample_size_lock,
    enumerate_fpr_power,
    enumerate_recall_power,
    upper_95_binomial_bound,
)


def test_upper_95_binomial_bound_matches_clopper_pearson_upper():
    from experiments.analysis import clopper_pearson_interval

    ci = clopper_pearson_interval(5, 10, confidence=0.90)
    assert math.isclose(upper_95_binomial_bound(5, 10), ci.upper, abs_tol=1e-9)


def test_upper_95_binomial_bound_uses_max_variance_when_undefined():
    assert upper_95_binomial_bound(0, 0) == 0.5


def test_enumerate_fpr_power_rejects_baseline_fpr_outside_open_unit_interval():
    with pytest.raises(ValueError, match="baseline_fpr"):
        enumerate_fpr_power("c", baseline_fpr=0.0, nuisance_discordant_p=0.5)
    with pytest.raises(ValueError, match="baseline_fpr"):
        enumerate_fpr_power("c", baseline_fpr=1.0, nuisance_discordant_p=0.5)


def test_enumerate_fpr_power_finds_a_real_count_for_a_strong_effect():
    """A large baseline FPR (70%, matching this project's real measured
    GLOBAL-arm FPR) with a high discordant-pair rate should reach power well
    within the candidate range, not silently return None."""
    result = enumerate_fpr_power("strong", baseline_fpr=0.70, nuisance_discordant_p=0.9)
    assert result.required_count is not None
    assert result.required_count <= MAX_CANDIDATE_COUNT
    assert result.achieved_power >= 0.80


def test_enumerate_fpr_power_needs_more_runs_for_a_weaker_baseline():
    """A modest baseline FPR (20%) needs materially more runs to reach the
    same power as a strong 70% baseline, for the same relative reduction."""
    strong = enumerate_fpr_power("strong", baseline_fpr=0.70, nuisance_discordant_p=0.9)
    weak = enumerate_fpr_power("weak", baseline_fpr=0.20, nuisance_discordant_p=0.9)
    assert weak.required_count is None or strong.required_count is None or weak.required_count >= strong.required_count


def test_enumerate_recall_power_reports_infeasibility_honestly():
    """The protocol's frozen recall non-inferiority target (5pp margin at a
    95% reference, 80% power, max 120 per cell) is genuinely infeasible by
    exact binomial power calculation: even n=120 only reaches ~60% power for
    this margin. This must be reported as None/infeasible, never silently
    rounded up to a false confident count."""
    result = enumerate_recall_power("recall", reference_recall=0.95)
    assert result.required_count is None
    assert result.achieved_power is None


def test_enumerate_recall_power_is_feasible_for_a_wider_margin():
    """A materially wider margin (e.g. 15pp) at the same reference recall
    should be achievable within the candidate range, confirming the
    infeasibility above is about the specific frozen margin, not a bug that
    makes every recall calculation return None."""
    result = enumerate_recall_power("recall", reference_recall=0.95, margin_pp=0.15)
    assert result.required_count is not None
    assert result.achieved_power >= 0.80


def test_assert_no_confirmatory_contamination_refuses_when_confirmatory_exists():
    with pytest.raises(ValueError, match="confirmatory-eligible"):
        assert_no_confirmatory_contamination(["pilot", "confirmatory"])


def test_assert_no_confirmatory_contamination_allows_pilot_only_history():
    assert_no_confirmatory_contamination(["pilot", "pilot"]) is None


def test_build_sample_size_lock_reports_feasibility_failure_honestly():
    """End-to-end: with this project's actual measured pilot-style inputs
    (a strong GLOBAL-vs-CONTEXT effect but a materially weaker TAG/DIGEST
    effect, plus the infeasible frozen recall target), the lock must report
    feasibility_failure=True and locked_per_cell_count=None rather than
    silently averaging over a contrast that never reached power."""
    lock = build_sample_size_lock(
        pilot_discordant_pairs={
            "CONTEXT_vs_GLOBAL": (4, 5),
            "CONTEXT_vs_TAG": (2, 5),
            "CONTEXT_vs_DIGEST": (2, 5),
        },
        pilot_baseline_fpr={
            "CONTEXT_vs_GLOBAL": 0.70,
            "CONTEXT_vs_TAG": 0.20,
            "CONTEXT_vs_DIGEST": 0.20,
        },
        reference_recall=0.95,
    )
    assert lock.feasibility_failure is True
    assert lock.locked_per_cell_count is None
    strong_contrast = next(r for r in lock.contrasts if r.contrast_id == "CONTEXT_vs_GLOBAL")
    assert strong_contrast.required_count is not None
