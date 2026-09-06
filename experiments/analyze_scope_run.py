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
from pathlib import Path

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
from experiments.scope import SCOPES, compare_scopes

ARM_NAMES = SCOPES  # ("ARM-GLOBAL", "ARM-TAG", "ARM-DIGEST", "ARM-CONTEXT")


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
    for contrast_id, arm_a, arm_b in contrast_pairs:
        common = sorted(set(per_arm_benign[arm_a]) & set(per_arm_benign[arm_b]))
        mcnemar_results[contrast_id] = exact_mcnemar_p(
            contrast_id=contrast_id,
            arm_a_positive=[per_arm_benign[arm_a][t] for t in common],
            arm_b_positive=[per_arm_benign[arm_b][t] for t in common],
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
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--threshold", type=float, default=0.25)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    result = analyze(args.run_dir, base_url=args.base_url, threshold=args.threshold)
    text = json.dumps(result, indent=2)
    if args.out:
        args.out.write_text(text)
    print(text)


if __name__ == "__main__":
    main()
