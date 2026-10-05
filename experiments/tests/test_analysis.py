"""Tests for experiments/analysis.py against known reference values.

Reference values for exact McNemar, Clopper-Pearson, and Holm correction are
independently computed by direct binomial summation / matched against R's
binom.test and p.adjust semantics in the test comments, not just re-derived
from the implementation under test.
"""
from __future__ import annotations

import math

from experiments.analysis import (
    clopper_pearson_interval,
    decide_primary_contrast,
    exact_mcnemar_p,
    holm_adjust,
    stratified_bootstrap_recall_interval,
)


def test_clopper_pearson_matches_known_reference_intervals() -> None:
    # Reference values from R's binom.test(x, n)$conf.int
    cases = [
        (5, 20, 0.08657781, 0.49104968),
        (0, 10, 0.0, 0.30849710779148154),
        (10, 10, 0.6915028922085185, 1.0),
        (50, 100, 0.3983211295271758, 0.6016788704728242),
    ]
    for successes, trials, expected_lower, expected_upper in cases:
        result = clopper_pearson_interval(successes, trials)
        assert math.isclose(result.lower, expected_lower, abs_tol=1e-4)
        assert math.isclose(result.upper, expected_upper, abs_tol=1e-4)


def test_clopper_pearson_zero_trials_returns_full_uncertainty_interval() -> None:
    result = clopper_pearson_interval(0, 0)
    assert result.point_estimate is None
    assert result.lower == 0.0
    assert result.upper == 1.0


def test_clopper_pearson_does_not_recurse_infinitely_at_confidence_0_9() -> None:
    """Regression test: the original incomplete-beta continued-fraction
    implementation recursed infinitely for several (successes, trials)
    combinations at confidence=0.90 (e.g. successes=0, trials=5), because its
    symmetry-relation switch condition was not guaranteed to terminate under
    the swapped call. Found while building experiments/sample_size.py, which
    is the first caller to actually use a non-0.95 confidence level. Fixed by
    replacing the incomplete-beta machinery with direct bisection on the
    binomial CDF over p. This test exhaustively exercises the previously
    failing region."""
    for n in range(1, 20):
        for successes in range(0, n + 1):
            for confidence in (0.80, 0.90, 0.95, 0.99):
                result = clopper_pearson_interval(successes, n, confidence=confidence)
                assert 0.0 <= result.lower <= result.upper <= 1.0


def test_exact_mcnemar_matches_direct_binomial_summation() -> None:
    """b10=3, b01=9 discordant pairs (5 concordant positive, 5 concordant
    negative pairs padded in to test that only discordant pairs matter)."""
    a = [True] * 3 + [False] * 9 + [True] * 5 + [False] * 5
    b = [False] * 3 + [True] * 9 + [True] * 5 + [False] * 5
    result = exact_mcnemar_p(contrast_id="t", arm_a_positive=a, arm_b_positive=b)

    assert result.discordant_a_only == 3
    assert result.discordant_b_only == 9

    n = 12
    expected_p = sum(math.comb(n, k) * 0.5**n for k in range(9, 13)) * 2
    assert math.isclose(result.p_value, expected_p, rel_tol=1e-9)


def test_exact_mcnemar_no_discordant_pairs_is_p_one() -> None:
    a = [True, False, True]
    b = [True, False, True]
    result = exact_mcnemar_p(contrast_id="t", arm_a_positive=a, arm_b_positive=b)
    assert result.p_value == 1.0
    assert result.discordant_a_only == 0
    assert result.discordant_b_only == 0


def test_exact_mcnemar_rejects_unpaired_lengths() -> None:
    try:
        exact_mcnemar_p(contrast_id="t", arm_a_positive=[True], arm_b_positive=[True, False])
    except ValueError:
        return
    raise AssertionError("expected ValueError for mismatched pair lengths")


def test_holm_adjust_matches_r_p_adjust_holm_reference() -> None:
    # R: p.adjust(c(a=0.01, b=0.04, c=0.03, d=0.005), method="holm")
    #   -> a=0.03, b=0.06, c=0.06, d=0.02
    pvalues = {"a": 0.01, "b": 0.04, "c": 0.03, "d": 0.005}
    results = {r.contrast_id: r.adjusted_p for r in holm_adjust(pvalues)}
    assert math.isclose(results["a"], 0.03, abs_tol=1e-9)
    assert math.isclose(results["b"], 0.06, abs_tol=1e-9)
    assert math.isclose(results["c"], 0.06, abs_tol=1e-9)
    assert math.isclose(results["d"], 0.02, abs_tol=1e-9)


def test_holm_adjust_is_monotonic_non_decreasing_in_sorted_order() -> None:
    pvalues = {f"c{i}": p for i, p in enumerate([0.2, 0.001, 0.15, 0.049, 0.3, 0.01])}
    results = sorted(holm_adjust(pvalues), key=lambda r: r.raw_p)
    adjusted = [r.adjusted_p for r in results]
    assert adjusted == sorted(adjusted)


def test_holm_adjust_empty_family_returns_empty() -> None:
    assert holm_adjust({}) == []


def test_stratified_bootstrap_is_deterministic_given_frozen_seed() -> None:
    detections = {
        "WL-NGX-V1:SCN-EXEC": [True, True, True, False, True],
        "WL-RDS-V1:SCN-EXEC": [True, False, True, True],
    }
    r1 = stratified_bootstrap_recall_interval(detections, reference_recall=0.9, resamples=500)
    r2 = stratified_bootstrap_recall_interval(detections, reference_recall=0.9, resamples=500)
    assert r1.lower == r2.lower
    assert r1.upper == r2.upper
    assert r1.point_estimate == r2.point_estimate


def test_stratified_bootstrap_point_estimate_is_plain_recall() -> None:
    detections = {"only": [True, True, False, False]}
    r = stratified_bootstrap_recall_interval(detections, reference_recall=0.5, resamples=1000)
    assert r.point_estimate == 0.5


def test_stratified_bootstrap_non_inferiority_gate() -> None:
    # All runs detected: recall = 1.0, should be trivially non-inferior to
    # any reference within a reasonable margin.
    detections = {"s": [True] * 20}
    r = stratified_bootstrap_recall_interval(detections, reference_recall=0.95, margin_pp=0.05, resamples=1000)
    assert r.lower == 1.0
    assert r.non_inferior is True

    # All runs missed: recall = 0.0, must fail non-inferiority against any
    # meaningful reference.
    detections_fail = {"s": [False] * 20}
    r_fail = stratified_bootstrap_recall_interval(detections_fail, reference_recall=0.95, margin_pp=0.05, resamples=1000)
    assert r_fail.upper == 0.0
    assert r_fail.non_inferior is False


def test_stratified_bootstrap_rejects_empty_input() -> None:
    try:
        stratified_bootstrap_recall_interval({}, reference_recall=0.9)
    except ValueError:
        return
    raise AssertionError("expected ValueError for empty detections")


def test_decide_primary_contrast_supports_h1_only_when_all_three_gates_pass() -> None:
    fpr_a = clopper_pearson_interval(20, 100)  # 20% FPR
    fpr_b = clopper_pearson_interval(5, 100)  # 5% FPR: 75% relative reduction, clears 25% material threshold
    a_positive = [True] * 20 + [False] * 80
    b_positive = [True] * 5 + [False] * 95
    mcnemar = exact_mcnemar_p(contrast_id="c1", arm_a_positive=a_positive, arm_b_positive=b_positive)
    holm = holm_adjust({"c1": mcnemar.p_value})[0]
    recall = stratified_bootstrap_recall_interval({"s": [True] * 19 + [False]}, reference_recall=0.95, resamples=500)

    decision = decide_primary_contrast(
        contrast_id="c1",
        fpr_a=fpr_a,
        fpr_b=fpr_b,
        mcnemar=mcnemar,
        holm_adjusted_p=holm.adjusted_p,
        recall=recall,
    )

    assert decision.material_effect_met is True
    assert decision.relative_fpr_reduction is not None and decision.relative_fpr_reduction >= 0.25


def test_decide_primary_contrast_never_promotes_on_significance_alone() -> None:
    """Statistically significant but below the material effect threshold must
    not report h1_supported=True. This is the protocol's explicit prohibition
    on promoting a result from a p-value alone."""
    fpr_a = clopper_pearson_interval(20, 1000)
    fpr_b = clopper_pearson_interval(18, 1000)  # only 10% relative reduction, below 25% material threshold
    a_positive = [True] * 20 + [False] * 980
    b_positive = [True] * 18 + [False] * 982
    mcnemar = exact_mcnemar_p(contrast_id="c2", arm_a_positive=a_positive, arm_b_positive=b_positive)
    holm = holm_adjust({"c2": mcnemar.p_value})[0]
    recall = stratified_bootstrap_recall_interval({"s": [True] * 20}, reference_recall=0.95, resamples=500)

    decision = decide_primary_contrast(
        contrast_id="c2",
        fpr_a=fpr_a,
        fpr_b=fpr_b,
        mcnemar=mcnemar,
        holm_adjusted_p=holm.adjusted_p,
        recall=recall,
    )

    assert decision.material_effect_met is False
    assert decision.h1_supported is False
    assert "material" in decision.reason.lower()


def test_decide_primary_contrast_recall_gate_cannot_be_traded_for_fpr() -> None:
    """A huge FPR win with a real recall loss below the margin must not be
    reported as H1-supported: recall non-inferiority is co-primary."""
    fpr_a = clopper_pearson_interval(50, 100)
    fpr_b = clopper_pearson_interval(5, 100)  # 90% relative reduction, easily material
    a_positive = [True] * 50 + [False] * 50
    b_positive = [True] * 5 + [False] * 95
    mcnemar = exact_mcnemar_p(contrast_id="c3", arm_a_positive=a_positive, arm_b_positive=b_positive)
    holm = holm_adjust({"c3": mcnemar.p_value})[0]
    # recall drops from a 95% reference to 80% observed (15pp below margin of 5pp)
    recall = stratified_bootstrap_recall_interval(
        {"s": [True] * 16 + [False] * 4}, reference_recall=0.95, margin_pp=0.05, resamples=1000
    )

    decision = decide_primary_contrast(
        contrast_id="c3",
        fpr_a=fpr_a,
        fpr_b=fpr_b,
        mcnemar=mcnemar,
        holm_adjusted_p=holm.adjusted_p,
        recall=recall,
    )

    assert decision.material_effect_met is True
    assert decision.recall_non_inferior is False
    assert decision.h1_supported is False
    assert "recall" in decision.reason.lower()
