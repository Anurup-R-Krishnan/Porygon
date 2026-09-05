"""ART-DES-001: the pre-confirmatory sample-size lock.

RESEARCH_PROTOCOL_V1.md's "Deterministic assignment and seeds" section
specifies this exactly: enumerate candidate per-cell counts from a minimum
through 120, pick the smallest count whose exact binomial power calculation
reaches 80% power for the frozen 25% relative-FPR-reduction / 5-percentage-
point recall-margin material effect, using the upper 95% binomial bound on
the pilot discordant-pair rate as the nuisance parameter. The maximum across
co-primary contrasts becomes the locked per-cell count.

Ordering matters and is enforced by the protocol text, not just convention:
"The versioned sample-size lock records inputs... before confirmatory
execution. Once one confirmatory run starts, v1 counts and criteria cannot
change." A lock computed after confirmatory data already exists cannot serve
as that document — it would not have constrained the collection it claims to
govern. This module is therefore built to be run BEFORE the next real
confirmatory collection round, using only pilot-split discordant-pair data,
and its output is refused if run against a dataset that already contains
confirmatory-eligible test-split evidence for the same contrasts (see
`assert_no_confirmatory_contamination`).
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

MIN_CANDIDATE_COUNT = 5
MAX_CANDIDATE_COUNT = 120
TARGET_POWER = 0.80
MATERIAL_RELATIVE_FPR_REDUCTION = 0.25
MATERIAL_RECALL_MARGIN_PP = 0.05
FPR_FAMILY_ALPHA = 0.05 / 3  # three primary FPR contrasts, conservative planning alpha
RECALL_ALPHA = 0.05  # one-sided for the co-primary recall gate


def _binom_sf_ge(k: int, n: int, p: float) -> float:
    if k > n:
        return 0.0
    if k <= 0:
        return 1.0
    return min(1.0, sum(math.comb(n, i) * (p**i) * ((1 - p) ** (n - i)) for i in range(k, n + 1)))


def upper_95_binomial_bound(successes: int, trials: int) -> float:
    """Upper 95% Clopper-Pearson bound on a proportion, used as the nuisance
    discordant-pair probability. 0.5 (maximum variance, most conservative) is
    used when the bound is undefined, matching the protocol text exactly."""
    if trials == 0:
        return 0.5
    from experiments.analysis import clopper_pearson_interval

    return clopper_pearson_interval(successes, trials, confidence=0.90).upper  # 90% two-sided = 95% one-sided upper


@dataclass(frozen=True)
class PowerEnumerationResult:
    contrast_id: str
    nuisance_discordant_p: float
    required_count: int | None  # None if no count through MAX_CANDIDATE_COUNT reaches target power
    achieved_power: float | None
    alpha: float


def enumerate_fpr_power(
    contrast_id: str,
    *,
    baseline_fpr: float,
    nuisance_discordant_p: float,
    alpha: float = FPR_FAMILY_ALPHA,
    material_relative_reduction: float = MATERIAL_RELATIVE_FPR_REDUCTION,
    target_power: float = TARGET_POWER,
) -> PowerEnumerationResult:
    """Exact binomial power enumeration for one paired FPR contrast.

    Models the McNemar test's power at a given per-cell run count n. Under
    the alternative, the coarser arm has false-positive rate baseline_fpr and
    the finer-scope arm has baseline_fpr * (1 - material_relative_reduction);
    treating the two arms' positive calls on the same run as approximately
    independent Bernoulli outcomes, the probability a discordant pair favours
    the coarser arm (the direction the material effect predicts) is

        p_effect = p_a * (1 - p_b) / (p_a * (1 - p_b) + (1 - p_a) * p_b)

    where p_a = baseline_fpr, p_b = baseline_fpr * (1 - material_relative_reduction).
    This requires an actual pilot-estimated baseline_fpr; without one, "a 25%
    relative reduction" has no absolute meaning and any power number would be
    an artifact of an arbitrary placeholder, not a real planning estimate.
    Discordant pairs are modelled as Binomial(n * nuisance_discordant_p,
    p_effect); power is P(reject H0) under that alternative, using the same
    exact two-sided test as experiments.analysis.exact_mcnemar_p.
    """
    if not (0.0 < baseline_fpr < 1.0):
        raise ValueError("baseline_fpr must be a real pilot-estimated proportion strictly between 0 and 1")
    target_fpr = baseline_fpr * (1 - material_relative_reduction)
    p_effect = (baseline_fpr * (1 - target_fpr)) / (
        baseline_fpr * (1 - target_fpr) + (1 - baseline_fpr) * target_fpr
    )
    for n in range(MIN_CANDIDATE_COUNT, MAX_CANDIDATE_COUNT + 1):
        n_discordant = max(1, round(n * nuisance_discordant_p))
        # Power = P(exact two-sided McNemar rejects | discordant pairs ~ Binomial(n_discordant, p_effect))
        power = 0.0
        for b10 in range(0, n_discordant + 1):
            b01 = n_discordant - b10
            prob = math.comb(n_discordant, b10) * (p_effect**b10) * ((1 - p_effect) ** b01)
            larger = max(b10, b01)
            p_value = min(1.0, 2 * _binom_sf_ge(larger, n_discordant, 0.5))
            if p_value < alpha:
                power += prob
        if power >= target_power:
            return PowerEnumerationResult(
                contrast_id=contrast_id, nuisance_discordant_p=nuisance_discordant_p,
                required_count=n, achieved_power=power, alpha=alpha,
            )
    return PowerEnumerationResult(
        contrast_id=contrast_id, nuisance_discordant_p=nuisance_discordant_p,
        required_count=None, achieved_power=None, alpha=alpha,
    )


def enumerate_recall_power(
    contrast_id: str,
    *,
    reference_recall: float,
    alpha: float = RECALL_ALPHA,
    margin_pp: float = MATERIAL_RECALL_MARGIN_PP,
    target_power: float = TARGET_POWER,
) -> PowerEnumerationResult:
    """Exact binomial power enumeration for the co-primary recall
    non-inferiority gate: power to conclude observed recall is within
    margin_pp of reference_recall, one-sided, at count n."""
    for n in range(MIN_CANDIDATE_COUNT, MAX_CANDIDATE_COUNT + 1):
        # Under the alternative (true recall == reference_recall, i.e. no
        # real degradation), power is the probability the exact one-sided
        # lower confidence bound clears (reference_recall - margin_pp).
        power = 0.0
        for successes in range(0, n + 1):
            prob = math.comb(n, successes) * (reference_recall**successes) * ((1 - reference_recall) ** (n - successes))
            from experiments.analysis import clopper_pearson_interval

            ci = clopper_pearson_interval(successes, n, confidence=1 - 2 * alpha)
            if ci.lower >= reference_recall - margin_pp:
                power += prob
        if power >= target_power:
            return PowerEnumerationResult(
                contrast_id=contrast_id, nuisance_discordant_p=reference_recall,
                required_count=n, achieved_power=power, alpha=alpha,
            )
    return PowerEnumerationResult(
        contrast_id=contrast_id, nuisance_discordant_p=reference_recall,
        required_count=None, achieved_power=None, alpha=alpha,
    )


@dataclass(frozen=True)
class SampleSizeLock:
    schema_version: str
    contrasts: list[PowerEnumerationResult]
    locked_per_cell_count: int | None
    feasibility_failure: bool
    note: str


def assert_no_confirmatory_contamination(evidence_classes: Sequence[str]) -> None:
    """Refuse to build a sample-size lock if any confirmatory-eligible run
    already exists for this protocol.

    evidence_classes is the list of `evidence_class` values recorded on every
    prior study-manifest.json (see experiments/study.py: manifest["evidence_class"]).
    A lock built after confirmatory data already exists could not have
    constrained the collection it claims to govern; the protocol text
    requires the lock before confirmatory execution, not after.
    """
    if "confirmatory" in evidence_classes:
        raise ValueError(
            "cannot build a fresh ART-DES-001 sample-size lock: confirmatory-eligible "
            "data already exists for this protocol. A lock computed now would not have "
            "constrained the collection it claims to govern (RESEARCH_PROTOCOL_V1.md: "
            "'the versioned sample-size lock records inputs... before confirmatory "
            "execution. Once one confirmatory run starts, v1 counts and criteria cannot "
            "change.'). This lock may only be used to plan a genuinely new confirmatory "
            "round under a revised protocol version, never to retroactively justify data "
            "already collected."
        )


def build_sample_size_lock(
    pilot_discordant_pairs: dict[str, tuple[int, int]],
    pilot_baseline_fpr: dict[str, float],
    reference_recall: float,
) -> SampleSizeLock:
    """Build ART-DES-001 from pilot-split discordant-pair counts only.

    pilot_discordant_pairs maps each of the three primary FPR contrast IDs to
    (successes, trials) for the discordant-pair rate observed in the pilot
    split, exactly as the protocol specifies. pilot_baseline_fpr maps the
    same contrast IDs to the coarser arm's observed pilot-split FPR, needed
    to give "25% relative reduction" an absolute meaning. Never pass test-split or
    confirmatory-split data here: doing so would make this a post-hoc
    justification rather than a pre-registered lock, which the protocol
    explicitly prohibits by requiring the lock before confirmatory execution.
    """
    results: list[PowerEnumerationResult] = []
    for contrast_id, (successes, trials) in pilot_discordant_pairs.items():
        nuisance = upper_95_binomial_bound(successes, trials)
        results.append(enumerate_fpr_power(
            contrast_id, baseline_fpr=pilot_baseline_fpr[contrast_id], nuisance_discordant_p=nuisance,
        ))
    results.append(enumerate_recall_power("recall_non_inferiority", reference_recall=reference_recall))

    feasible = [r for r in results if r.required_count is not None]
    if len(feasible) < len(results):
        return SampleSizeLock(
            schema_version="porygon.sample-size-lock.v1",
            contrasts=results,
            locked_per_cell_count=None,
            feasibility_failure=True,
            note=(
                "At least one contrast did not reach 80% power through the maximum "
                f"candidate count ({MAX_CANDIDATE_COUNT}); per the protocol, confirmatory "
                "collection stops here for a feasibility decision and protocol revision, "
                "rather than proceeding with an underpowered count."
            ),
        )

    locked = max(r.required_count for r in results)
    return SampleSizeLock(
        schema_version="porygon.sample-size-lock.v1",
        contrasts=results,
        locked_per_cell_count=locked,
        feasibility_failure=False,
        note=(
            f"Locked per-cell count is {locked}, the maximum across all co-primary "
            "contrasts' required counts. This value only governs confirmatory "
            "collection that has not yet started; per the protocol, it cannot be "
            "applied retroactively to justify data already collected."
        ),
    )
