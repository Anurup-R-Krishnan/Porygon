"""Statistical analysis for the profile-scope protocol, as specified in
docs/RESEARCH_PROTOCOL_V1.md's "Statistical analysis" section.

Every function here is pure and stdlib-only (no numpy/scipy dependency),
matching the rest of experiments/. Each function corresponds directly to a
sentence in the frozen protocol:

- exact_mcnemar_p:      "Primary pairwise FPR contrasts use exact McNemar tests"
- holm_adjust:          "controlled at family-wise alpha 0.05 with Holm correction"
- clopper_pearson_interval: "Proportions include exact/binomial intervals"
- stratified_bootstrap_recall_interval: "Recall non-inferiority uses a
  run-level stratified bootstrap with 10,000 resamples and seed 20260823"

Every public function takes and returns plain dicts/tuples of primitives so
results can be written straight into a JSON/CSV artifact without a bespoke
serializer, matching experiments/artifacts.py conventions.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Sequence

# Frozen seed for recall bootstrap resampling, from RESEARCH_PROTOCOL_V1.md
# "Deterministic assignment and seeds" table (bootstrap seed).
FROZEN_BOOTSTRAP_SEED = 20260823
FROZEN_BOOTSTRAP_RESAMPLES = 10_000

# Frozen family-wise alpha for the three primary ARM-CONTEXT FPR contrasts.
FROZEN_FAMILY_ALPHA = 0.05

# Frozen material effect sizes from H_1_001.
MATERIAL_RELATIVE_FPR_REDUCTION = 0.25
MATERIAL_RECALL_MARGIN_PP = 0.05


# ---------------------------------------------------------------------------
# Exact McNemar test (paired binary outcomes on the same independent runs)
# ---------------------------------------------------------------------------


def _binom_sf_ge(k: int, n: int, p: float = 0.5) -> float:
    """Exact P(X >= k) for X ~ Binomial(n, p), by direct summation.

    n is bounded by the discordant-pair count in one contrast, which is at
    most the confirmatory per-cell run count (<=120 by the protocol's own
    sample-size search bound), so direct summation is exact and fast; no
    normal approximation is used anywhere in this module.
    """
    if k > n:
        return 0.0
    if k <= 0:
        return 1.0
    total = 0.0
    for i in range(k, n + 1):
        total += math.comb(n, i) * (p**i) * ((1 - p) ** (n - i))
    return min(1.0, total)


@dataclass(frozen=True)
class McNemarResult:
    contrast_id: str
    n_pairs: int
    discordant_a_only: int
    discordant_b_only: int
    p_value: float
    note: str


def exact_mcnemar_p(
    *,
    contrast_id: str,
    arm_a_positive: Sequence[bool],
    arm_b_positive: Sequence[bool],
) -> McNemarResult:
    """Exact two-sided McNemar test on paired binary run outcomes.

    arm_a_positive[i] and arm_b_positive[i] must both describe run i (the
    same independent run scored under each arm) — the protocol's independent
    unit and pairing requirement. Discordant pairs (a positive, b negative)
    and (a negative, b positive) are counted; the exact two-sided p-value is
    2 * P(Binomial(n_discordant, 0.5) >= max(b10, b01)), capped at 1.0,
    which is the standard exact-conditional-test formulation and requires no
    normal approximation.
    """
    if len(arm_a_positive) != len(arm_b_positive):
        raise ValueError("arm_a_positive and arm_b_positive must be paired (same length)")
    n_pairs = len(arm_a_positive)
    b10 = sum(1 for a, b in zip(arm_a_positive, arm_b_positive) if a and not b)
    b01 = sum(1 for a, b in zip(arm_a_positive, arm_b_positive) if b and not a)
    n_discordant = b10 + b01
    if n_discordant == 0:
        return McNemarResult(
            contrast_id=contrast_id,
            n_pairs=n_pairs,
            discordant_a_only=b10,
            discordant_b_only=b01,
            p_value=1.0,
            note="no discordant pairs; arms agree on every run",
        )
    larger = max(b10, b01)
    p_value = min(1.0, 2 * _binom_sf_ge(larger, n_discordant, 0.5))
    return McNemarResult(
        contrast_id=contrast_id,
        n_pairs=n_pairs,
        discordant_a_only=b10,
        discordant_b_only=b01,
        p_value=p_value,
        note="exact two-sided conditional binomial test",
    )


# ---------------------------------------------------------------------------
# Holm-Bonferroni family-wise correction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HolmResult:
    contrast_id: str
    raw_p: float
    adjusted_p: float
    rejected_at_alpha: bool


def holm_adjust(
    p_values: dict[str, float],
    *,
    family_alpha: float = FROZEN_FAMILY_ALPHA,
) -> list[HolmResult]:
    """Holm-Bonferroni step-down correction across one family of contrasts.

    Each family (the three primary ARM-CONTEXT FPR contrasts; each detector-
    comparison family; each ablation family) is corrected separately, as the
    protocol's "Statistical analysis" section requires. Monotonicity is
    enforced (an adjusted p-value never decreases going down the sorted
    order), which is the standard Holm guarantee.
    """
    if not p_values:
        return []
    ordered = sorted(p_values.items(), key=lambda item: item[1])
    m = len(ordered)
    adjusted: list[tuple[str, float, float]] = []
    running_max = 0.0
    for rank, (contrast_id, raw_p) in enumerate(ordered):
        candidate = min(1.0, raw_p * (m - rank))
        running_max = max(running_max, candidate)
        adjusted.append((contrast_id, raw_p, running_max))
    return [
        HolmResult(
            contrast_id=contrast_id,
            raw_p=raw_p,
            adjusted_p=adjusted_p,
            rejected_at_alpha=adjusted_p < family_alpha,
        )
        for contrast_id, raw_p, adjusted_p in adjusted
    ]


# ---------------------------------------------------------------------------
# Exact (Clopper-Pearson) binomial interval for a proportion
# ---------------------------------------------------------------------------


def _incomplete_beta(x: float, a: float, b: float, *, iterations: int = 200) -> float:
    """Regularized incomplete beta function I_x(a, b) via continued fraction
    (Lentz's algorithm), sufficient precision for confidence-interval bounds
    without a scipy/numpy dependency."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0

    ln_beta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(math.log(x) * a + math.log(1.0 - x) * b - ln_beta) / a

    f, c, d = 1.0, 1.0, 0.0
    tiny = 1e-30
    for i in range(iterations):
        m = i // 2
        if i == 0:
            numerator = 1.0
        elif i % 2 == 0:
            numerator = (m * (b - m) * x) / ((a + 2 * m - 1) * (a + 2 * m))
        else:
            numerator = -((a + m) * (a + b + m) * x) / ((a + 2 * m) * (a + 2 * m + 1))
        d = 1.0 + numerator * d
        if abs(d) < tiny:
            d = tiny
        d = 1.0 / d
        c = 1.0 + numerator / c
        if abs(c) < tiny:
            c = tiny
        f *= d * c
        if abs(1.0 - d * c) < 1e-12:
            break

    result = front * (f - 1.0)
    if x < (a + 1.0) / (a + b + 2.0):
        return result
    return 1.0 - _regularized_incomplete_beta_complement(x, a, b, front, f)


def _regularized_incomplete_beta_complement(x: float, a: float, b: float, front: float, f: float) -> float:
    # Symmetry relation I_x(a,b) = 1 - I_(1-x)(b,a); used when x is on the
    # slow-converging side of the continued fraction.
    return _incomplete_beta(1.0 - x, b, a)


@dataclass(frozen=True)
class BinomialInterval:
    successes: int
    trials: int
    point_estimate: float | None
    lower: float
    upper: float
    confidence: float


def clopper_pearson_interval(successes: int, trials: int, *, confidence: float = 0.95) -> BinomialInterval:
    """Exact Clopper-Pearson binomial confidence interval.

    This is the "exact/binomial interval" the protocol's Metrics and
    Statistical-analysis sections require for MET-FPR-001, MET-REC-001, and
    every other run-level proportion; it never falls back to a normal
    approximation regardless of denominator size.
    """
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError("successes must be between 0 and trials")
    alpha = 1.0 - confidence
    if trials == 0:
        return BinomialInterval(successes=0, trials=0, point_estimate=None, lower=0.0, upper=1.0, confidence=confidence)

    point = successes / trials
    lower = 0.0 if successes == 0 else _beta_inv(alpha / 2, successes, trials - successes + 1)
    upper = 1.0 if successes == trials else _beta_inv(1 - alpha / 2, successes + 1, trials - successes)
    return BinomialInterval(successes=successes, trials=trials, point_estimate=point, lower=lower, upper=upper, confidence=confidence)


def _beta_inv(p: float, a: float, b: float, *, tol: float = 1e-10, max_iter: int = 200) -> float:
    """Invert the regularized incomplete beta function by bisection.

    Bisection over a monotone function on [0, 1] is exact to `tol` and needs
    no external numerical library; adequate for confidence-interval bounds
    reported to a handful of significant figures.
    """
    lo, hi = 0.0, 1.0
    for _ in range(max_iter):
        mid = (lo + hi) / 2
        if _incomplete_beta(mid, a, b) < p:
            lo = mid
        else:
            hi = mid
        if hi - lo < tol:
            break
    return (lo + hi) / 2


# ---------------------------------------------------------------------------
# Run-level stratified bootstrap for recall non-inferiority
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BootstrapRecallResult:
    strata: tuple[str, ...]
    n_runs: int
    point_estimate: float
    lower: float
    upper: float
    resamples: int
    seed: int
    non_inferior: bool
    margin_pp: float


def stratified_bootstrap_recall_interval(
    detections: dict[str, Sequence[bool]],
    *,
    reference_recall: float,
    margin_pp: float = MATERIAL_RECALL_MARGIN_PP,
    resamples: int = FROZEN_BOOTSTRAP_RESAMPLES,
    seed: int = FROZEN_BOOTSTRAP_SEED,
) -> BootstrapRecallResult:
    """Run-level stratified bootstrap confidence interval for recall.

    detections maps a stratum key (e.g. "WL-NGX-V1:SCN-EXEC") to the
    per-run detection outcomes within that stratum. Each bootstrap resample
    draws, with replacement, the same number of runs as observed within each
    stratum independently (stratified resampling), matching "stratified by
    workload family and version" in the protocol. The interval is used for
    the recall non-inferiority co-primary gate: non-inferior means the lower
    bound of the interval does not fall more than margin_pp below
    reference_recall.

    Uses Python's random.Random seeded deterministically, matching the
    protocol's frozen bootstrap seed (20260823) and 10,000-resample count,
    so a rerun with the same input data reproduces the identical interval.
    """
    strata = tuple(sorted(detections))
    all_runs: list[bool] = [outcome for key in strata for outcome in detections[key]]
    n_runs = len(all_runs)
    if n_runs == 0:
        raise ValueError("stratified_bootstrap_recall_interval requires at least one run")

    point_estimate = sum(all_runs) / n_runs

    rng = random.Random(seed)
    stratum_arrays = {key: list(detections[key]) for key in strata}
    resample_means: list[float] = []
    for _ in range(resamples):
        resampled: list[bool] = []
        for key in strata:
            arr = stratum_arrays[key]
            n = len(arr)
            if n == 0:
                continue
            resampled.extend(arr[rng.randrange(n)] for _ in range(n))
        if resampled:
            resample_means.append(sum(resampled) / len(resampled))

    resample_means.sort()
    lower = resample_means[int(0.025 * len(resample_means))]
    upper = resample_means[min(len(resample_means) - 1, int(0.975 * len(resample_means)))]

    non_inferior = lower >= (reference_recall - margin_pp)

    return BootstrapRecallResult(
        strata=strata,
        n_runs=n_runs,
        point_estimate=point_estimate,
        lower=lower,
        upper=upper,
        resamples=resamples,
        seed=seed,
        non_inferior=non_inferior,
        margin_pp=margin_pp,
    )


# ---------------------------------------------------------------------------
# H_0_001 / H_1_001 decision: material FPR reduction plus non-inferior recall
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PrimaryContrastDecision:
    contrast_id: str
    fpr_a: BinomialInterval
    fpr_b: BinomialInterval
    relative_fpr_reduction: float | None
    mcnemar: McNemarResult
    holm_adjusted_p: float
    recall: BootstrapRecallResult
    material_effect_met: bool
    significant_after_correction: bool
    recall_non_inferior: bool
    h1_supported: bool
    reason: str


def decide_primary_contrast(
    *,
    contrast_id: str,
    fpr_a: BinomialInterval,
    fpr_b: BinomialInterval,
    mcnemar: McNemarResult,
    holm_adjusted_p: float,
    recall: BootstrapRecallResult,
    family_alpha: float = FROZEN_FAMILY_ALPHA,
    material_relative_reduction: float = MATERIAL_RELATIVE_FPR_REDUCTION,
) -> PrimaryContrastDecision:
    """Apply H_0_001/H_1_001's exact failure/support criteria to one primary
    ARM-CONTEXT-vs-simpler-arm contrast, from already-computed statistics.

    This function makes no promotion decision from a p-value alone (the
    protocol's explicit prohibition): H1 is only supported when the material
    relative FPR reduction is met AND the Holm-adjusted McNemar test clears
    family_alpha AND recall is non-inferior. Any one of these failing means
    H0 is not rejected for this contrast, which is reported, not hidden.
    """
    if fpr_a.point_estimate is None or fpr_b.point_estimate is None or fpr_a.point_estimate == 0:
        relative_reduction: float | None = None
    else:
        relative_reduction = (fpr_a.point_estimate - fpr_b.point_estimate) / fpr_a.point_estimate

    material_effect_met = relative_reduction is not None and relative_reduction >= material_relative_reduction
    significant = holm_adjusted_p < family_alpha
    recall_ok = recall.non_inferior

    h1_supported = material_effect_met and significant and recall_ok
    if h1_supported:
        reason = "material FPR reduction achieved, significant after Holm correction, recall non-inferior"
    elif not material_effect_met:
        reason = "relative FPR reduction below the frozen 25% material threshold"
    elif not significant:
        reason = "Holm-adjusted McNemar p-value does not clear family-wise alpha"
    else:
        reason = "recall non-inferiority gate failed; cannot be traded for FPR"

    return PrimaryContrastDecision(
        contrast_id=contrast_id,
        fpr_a=fpr_a,
        fpr_b=fpr_b,
        relative_fpr_reduction=relative_reduction,
        mcnemar=mcnemar,
        holm_adjusted_p=holm_adjusted_p,
        recall=recall,
        material_effect_met=material_effect_met,
        significant_after_correction=significant,
        recall_non_inferior=recall_ok,
        h1_supported=h1_supported,
        reason=reason,
    )
