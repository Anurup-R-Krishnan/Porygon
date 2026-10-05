"""Compute the frozen protocol's primary statistical analysis
(experiments/analysis.py: exact McNemar, Holm correction, Clopper-Pearson
intervals, stratified bootstrap recall non-inferiority, decide_primary_contrast)
from an experiments.scope.compare_scopes() result, matching exactly the
method first used to produce study-20260905t181654Z's
profile-scope-primary.json (git log f0654e8).

Usage:
    python3 -m experiments.analyze_scope_run <run_dir> [--base-url URL] [--out PATH]

Computes the scope comparison itself (fetching per-container process
distributions from the backend, so the backend must be reachable and the
run's containers' events must still be in the database), then applies the
full statistical pipeline and writes the resulting table.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Sequence

from experiments.analysis import (
    BinomialInterval,
    BootstrapRecallResult,
    HolmResult,
    McNemarResult,
    PrimaryContrastDecision,
    clopper_pearson_interval,
    decide_primary_contrast,
    exact_mcnemar_p,
    holm_adjust,
    stratified_bootstrap_recall_interval,
)
from experiments.artifacts import write_versioned_json
from experiments.scope import SCOPES, compare_scopes

ARM_NAMES = SCOPES  # ("ARM-GLOBAL", "ARM-TAG", "ARM-DIGEST", "ARM-CONTEXT")


# ---------------------------------------------------------------------------
# Degeneracy detection: flag contrasts that carry no real statistical
# information even though decide_primary_contrast's raw math may report an
# extreme p-value.
#
# This is deliberately a post-processing layer on top of experiments/analysis.py's
# already-verified statistics, not a change to the statistics themselves: every
# raw number decide_primary_contrast/exact_mcnemar_p produced is still reported
# untouched, this only adds an interpretive flag and (when degenerate) overrides
# the *decision*, not the underlying evidence.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DegeneracyCheck:
    contrast_id: str
    arm_a_constant: bool
    arm_b_constant: bool
    zero_discordant_pairs: bool
    informative: bool
    reason: str


def _constant_direction(values: Sequence[bool]) -> bool | None:
    """True if every value is True, False if every value is False, None if the
    values are mixed (or there are none to judge)."""
    if not values:
        return None
    if all(values):
        return True
    if not any(values):
        return False
    return None


def detect_degenerate_contrast(
    contrast_id: str,
    arm_a_positive: Sequence[bool],
    arm_b_positive: Sequence[bool],
    *,
    arm_a_label: str = "arm A",
    arm_b_label: str = "arm B",
    unit: str = "paired runs",
) -> DegeneracyCheck:
    """Flag a paired McNemar contrast that carries no real information.

    A McNemar test conditions entirely on discordant pairs. If one arm never
    varies across the paired runs (always positive, or always negative), every
    discordant pair is forced to point in the same direction by construction --
    the comparison never had a chance to disagree the other way -- which can
    produce an arbitrarily small p-value with zero actual statistical content
    (this is exactly what happens for ARM-GLOBAL: constant-positive on every
    benign run, so any contrast against it is "significant" by construction).
    Zero discordant pairs at all (the two arms simply agree on every run) is a
    differently-flavoured degeneracy: exact_mcnemar_p already and correctly
    reports p=1.0 for that case, but the comparison is still uninformative and
    is flagged here too, for the same reason.
    """
    if len(arm_a_positive) != len(arm_b_positive):
        raise ValueError("arm_a_positive and arm_b_positive must be paired (same length)")
    n = len(arm_a_positive)
    a_direction = _constant_direction(arm_a_positive)
    b_direction = _constant_direction(arm_b_positive)
    arm_a_constant = n > 0 and a_direction is not None
    arm_b_constant = n > 0 and b_direction is not None
    zero_discordant_pairs = n > 0 and all(a == b for a, b in zip(arm_a_positive, arm_b_positive))

    informative = n > 0 and not arm_a_constant and not arm_b_constant and not zero_discordant_pairs

    if n == 0:
        reason = f"{contrast_id}: no paired {unit} available; this contrast carries no information"
    elif arm_a_constant:
        word = "positive" if a_direction else "negative"
        reason = (
            f"{arm_a_label} called every one of {n} {unit} {word}; "
            "this contrast carries no information"
        )
    elif arm_b_constant:
        word = "positive" if b_direction else "negative"
        reason = (
            f"{arm_b_label} called every one of {n} {unit} {word}; "
            "this contrast carries no information"
        )
    elif zero_discordant_pairs:
        reason = (
            f"{arm_a_label} and {arm_b_label} agree on every one of {n} {unit}; "
            "the paired contrast is vacuous"
        )
    else:
        reason = "contrast is informative: both arms vary and discordant pairs exist"

    return DegeneracyCheck(
        contrast_id=contrast_id,
        arm_a_constant=arm_a_constant,
        arm_b_constant=arm_b_constant,
        zero_discordant_pairs=zero_discordant_pairs,
        informative=informative,
        reason=reason,
    )


def detect_constant_recall_across_arms(recall_by_arm: dict[str, BinomialInterval]) -> dict:
    """The recall analogue: if every arm's recall point estimate is 1.0 (or every
    arm's is 0.0), the recall non-inferiority comparison is vacuous for the same
    reason a constant-positive FPR arm makes an FPR contrast vacuous -- there is
    no variation across arms for the comparison to be informative about."""
    arms = sorted(recall_by_arm)
    points = [recall_by_arm[arm].point_estimate for arm in arms]
    known_points = [p for p in points if p is not None]
    constant = bool(known_points) and len(known_points) == len(points) and (
        all(p == 1.0 for p in known_points) or all(p == 0.0 for p in known_points)
    )
    if constant:
        value = "1.0" if known_points[0] == 1.0 else "0.0"
        reason = (
            f"recall is {value} in every arm ({', '.join(arms)}); the recall "
            "non-inferiority comparison is vacuous"
        )
    else:
        reason = "recall varies across arms; the non-inferiority comparison is informative"
    return {"arms": arms, "constant_across_arms": constant, "reason": reason}


def _degeneracy_dict(d: DegeneracyCheck) -> dict:
    return {
        "contrast_id": d.contrast_id,
        "arm_a_constant": d.arm_a_constant,
        "arm_b_constant": d.arm_b_constant,
        "zero_discordant_pairs": d.zero_discordant_pairs,
        "informative": d.informative,
        "reason": d.reason,
    }


def _apply_degeneracy_override(
    decision: PrimaryContrastDecision, degeneracy: DegeneracyCheck
) -> PrimaryContrastDecision:
    """Override a decision's h1_supported to False when its contrast is
    degenerate, regardless of the raw p-value -- but leave every raw statistic
    (mcnemar, holm_adjusted_p, recall, relative_fpr_reduction, ...) exactly as
    decide_primary_contrast computed it. This is an interpretive flag layered
    on top of already-correct math, not a hidden or recomputed number."""
    if degeneracy.informative:
        return decision
    return replace(
        decision,
        h1_supported=False,
        reason=(
            f"{degeneracy.reason} (raw decide_primary_contrast verdict before this "
            f"override: h1_supported={decision.h1_supported}, reason={decision.reason!r})"
        ),
    )


def load_trial_workload_scenario(run_dir: Path) -> dict[str, tuple[str, str]]:
    """trial_id -> (workload_family, scenario_id), for bootstrap stratification."""
    mapping: dict[str, tuple[str, str]] = {}
    for path in sorted((run_dir / "trials").glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") != "completed":
            continue
        mapping[record["trial_id"]] = (
            record.get("workload_family", "unknown"),
            record.get("scenario_id", "unknown"),
        )
    return mapping


def _interval_dict(iv: BinomialInterval) -> dict:
    return {
        "successes": iv.successes, "trials": iv.trials,
        "point_estimate": iv.point_estimate, "lower": iv.lower,
        "upper": iv.upper, "confidence": iv.confidence,
    }


def _mcnemar_dict(m: McNemarResult) -> dict:
    return {
        "contrast_id": m.contrast_id, "n_pairs": m.n_pairs,
        "discordant_a_only": m.discordant_a_only, "discordant_b_only": m.discordant_b_only,
        "p_value": m.p_value, "note": m.note,
    }


def _holm_dict(h: HolmResult) -> dict:
    return {
        "contrast_id": h.contrast_id, "raw_p": h.raw_p,
        "adjusted_p": h.adjusted_p, "rejected_at_alpha": h.rejected_at_alpha,
    }


def _recall_dict(r: BootstrapRecallResult) -> dict:
    return {
        "strata": list(r.strata), "n_runs": r.n_runs, "point_estimate": r.point_estimate,
        "lower": r.lower, "upper": r.upper, "resamples": r.resamples, "seed": r.seed,
        "non_inferior": r.non_inferior, "margin_pp": r.margin_pp,
    }


def _decision_dict(d: PrimaryContrastDecision) -> dict:
    return {
        "contrast_id": d.contrast_id,
        "fpr_a": _interval_dict(d.fpr_a),
        "fpr_b": _interval_dict(d.fpr_b),
        "relative_fpr_reduction": d.relative_fpr_reduction,
        "mcnemar": _mcnemar_dict(d.mcnemar),
        "holm_adjusted_p": d.holm_adjusted_p,
        "recall": _recall_dict(d.recall),
        "material_effect_met": d.material_effect_met,
        "significant_after_correction": d.significant_after_correction,
        "recall_non_inferior": d.recall_non_inferior,
        "h1_supported": d.h1_supported,
        "reason": d.reason,
    }


def analyze(run_dir: Path, base_url: str = "http://127.0.0.1:8000", threshold: float = 0.25) -> dict:
    scope_result = compare_scopes(base_url, run_dir, threshold=threshold)
    trial_context = load_trial_workload_scenario(run_dir)
    scopes = scope_result["scopes"]

    per_arm_benign: dict[str, dict[str, bool]] = {}
    per_arm_scenario: dict[str, dict[str, bool]] = {}
    for arm in ARM_NAMES:
        benign, scenario = {}, {}
        for row in scopes[arm]["trials"]:
            if not row["reference_key_present"]:
                continue
            (scenario if row["is_scenario"] else benign)[row["trial_id"]] = row["positive"]
        per_arm_benign[arm] = benign
        per_arm_scenario[arm] = scenario

    fpr_by_arm = {
        arm: clopper_pearson_interval(
            sum(1 for v in per_arm_benign[arm].values() if v), len(per_arm_benign[arm])
        )
        for arm in ARM_NAMES
    }
    recall_by_arm = {
        arm: clopper_pearson_interval(
            sum(1 for v in per_arm_scenario[arm].values() if v), len(per_arm_scenario[arm])
        )
        for arm in ARM_NAMES
    }

    contrast_pairs = [
        ("CONTEXT_vs_ARM-GLOBAL", "ARM-CONTEXT", "ARM-GLOBAL"),
        ("CONTEXT_vs_ARM-TAG", "ARM-CONTEXT", "ARM-TAG"),
        ("CONTEXT_vs_ARM-DIGEST", "ARM-CONTEXT", "ARM-DIGEST"),
    ]
    mcnemar_results = {}
    degeneracy_results: dict[str, DegeneracyCheck] = {}
    for contrast_id, arm_a, arm_b in contrast_pairs:
        common = sorted(set(per_arm_benign[arm_a]) & set(per_arm_benign[arm_b]))
        arm_a_positive = [per_arm_benign[arm_a][t] for t in common]
        arm_b_positive = [per_arm_benign[arm_b][t] for t in common]
        mcnemar_results[contrast_id] = exact_mcnemar_p(
            contrast_id=contrast_id,
            arm_a_positive=arm_a_positive,
            arm_b_positive=arm_b_positive,
        )
        degeneracy_results[contrast_id] = detect_degenerate_contrast(
            contrast_id,
            arm_a_positive,
            arm_b_positive,
            arm_a_label=arm_a,
            arm_b_label=arm_b,
            unit="benign runs",
        )

    holm_results = {r.contrast_id: r for r in holm_adjust({c: r.p_value for c, r in mcnemar_results.items()})}

    def stratified_detections(arm: str) -> dict[str, list[bool]]:
        buckets: dict[str, list[bool]] = {}
        for trial_id, positive in per_arm_scenario[arm].items():
            wf, scn = trial_context.get(trial_id, ("unknown", "unknown"))
            buckets.setdefault(f"{wf}:{scn}", []).append(positive)
        return buckets

    context_recall_bootstrap = stratified_bootstrap_recall_interval(
        stratified_detections("ARM-CONTEXT"),
        reference_recall=recall_by_arm["ARM-GLOBAL"].point_estimate or 1.0,
    )

    decisions = {
        "CONTEXT_vs_GLOBAL": decide_primary_contrast(
            contrast_id="CONTEXT_vs_GLOBAL", fpr_a=fpr_by_arm["ARM-GLOBAL"], fpr_b=fpr_by_arm["ARM-CONTEXT"],
            mcnemar=mcnemar_results["CONTEXT_vs_ARM-GLOBAL"],
            holm_adjusted_p=holm_results["CONTEXT_vs_ARM-GLOBAL"].adjusted_p, recall=context_recall_bootstrap,
        ),
        "CONTEXT_vs_DIGEST": decide_primary_contrast(
            contrast_id="CONTEXT_vs_DIGEST", fpr_a=fpr_by_arm["ARM-DIGEST"], fpr_b=fpr_by_arm["ARM-CONTEXT"],
            mcnemar=mcnemar_results["CONTEXT_vs_ARM-DIGEST"],
            holm_adjusted_p=holm_results["CONTEXT_vs_ARM-DIGEST"].adjusted_p, recall=context_recall_bootstrap,
        ),
    }
    # Every decision above is keyed by its own id ("CONTEXT_vs_GLOBAL") but was built
    # from a differently-named mcnemar contrast ("CONTEXT_vs_ARM-GLOBAL"); map decision
    # id -> mcnemar/degeneracy contrast id so the right degeneracy check overrides the
    # right decision.
    decision_to_contrast_id = {
        "CONTEXT_vs_GLOBAL": "CONTEXT_vs_ARM-GLOBAL",
        "CONTEXT_vs_DIGEST": "CONTEXT_vs_ARM-DIGEST",
    }
    decisions = {
        decision_id: _apply_degeneracy_override(decision, degeneracy_results[decision_to_contrast_id[decision_id]])
        for decision_id, decision in decisions.items()
    }

    recall_degeneracy = detect_constant_recall_across_arms(recall_by_arm)

    return {
        "schema_version": "porygon.profile-scope-analysis.v1",
        "source_run": run_dir.name,
        "threshold": threshold,
        "fpr_by_arm": {arm: _interval_dict(fpr_by_arm[arm]) for arm in ARM_NAMES},
        "recall_by_arm": {arm: _interval_dict(recall_by_arm[arm]) for arm in ARM_NAMES},
        "primary_contrasts": {
            "mcnemar": {cid: _mcnemar_dict(r) for cid, r in mcnemar_results.items()},
            "holm_adjusted": {cid: _holm_dict(r) for cid, r in holm_results.items()},
        },
        "decisions": {cid: _decision_dict(d) for cid, d in decisions.items()},
        "recall_non_inferiority_context": _recall_dict(context_recall_bootstrap),
        "sample_sizes": {
            arm: {"benign_n": len(per_arm_benign[arm]), "scenario_n": len(per_arm_scenario[arm])}
            for arm in ARM_NAMES
        },
        "degeneracy": {
            "contrasts": {cid: _degeneracy_dict(d) for cid, d in degeneracy_results.items()},
            "recall_across_arms": recall_degeneracy,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--threshold", type=float, default=0.25)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    result = analyze(args.run_dir, base_url=args.base_url, threshold=args.threshold)
    print(json.dumps(result, indent=2))
    if args.out:
        # Routed through the same atomic/versioned/secret-scanned artifact writer as
        # every other experiment artifact (experiments/artifacts.py:write_versioned_json)
        # instead of a bare Path.write_text: a completed result table must never be
        # silently overwritten with different content, and this gets that guarantee,
        # canonical JSON formatting, and reject_secrets() scanning for free.
        suffix = args.out.suffix or ".json"
        written = write_versioned_json(args.out.parent, args.out.stem, result, suffix=suffix)
        print(f"wrote {written}")


if __name__ == "__main__":
    main()
