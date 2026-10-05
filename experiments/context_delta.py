"""Direct runtime-context-delta feature: exploratory follow-on to the
CONTEXT-vs-DIGEST null result in docs/CONFIRMATORY_RESULT_V1.md.

The frozen protocol's ARM-CONTEXT only uses the runtime-context hash to
*select which reference distribution* to score against; the score itself is
still pure process-name Jensen-Shannon distance. The confirmatory run found
this cannot distinguish a `dropped_capabilities` context change from
`baseline`, because dropping a Linux capability does not change which
processes execute.

This module tests a different, more direct idea: score the structured
runtime-context document itself (capabilities, privileged, read-only-rootfs,
mounts, network mode, ports) against a digest's fit-split reference context,
independently of process-name behaviour. This is exploratory, not
confirmatory: it reuses an already-collected study run's data (no new
trial collection triggered by this analysis), so it is reported as a
secondary/exploratory finding, never substituted for the frozen protocol's
own primary result.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from porygon_api.calibrated_rarity import empirical_upper_tail_pvalue  # noqa: E402

from experiments.analysis import clopper_pearson_interval  # noqa: E402
from experiments.artifacts import assign_split, check_split_isolation  # noqa: E402

# One-sided rejection level for MET-CAL-001 ("run-level benign calibration
# coverage at nominal 95%", RESEARCH_PROTOCOL_V1.md). Matches
# experiments/scope.py's CALIBRATION_COVERAGE_ALPHA.
CALIBRATION_COVERAGE_ALPHA = 0.05


@dataclass(frozen=True)
class ContextTrial:
    trial_id: str
    container_id: str
    image_digest: str
    context_variant: str | None
    split: str
    is_scenario: bool
    runtime_context: dict[str, Any]


def load_context_trials(run_dir: Path) -> list[ContextTrial]:
    trials_dir = run_dir / "trials"
    out: list[ContextTrial] = []
    for path in sorted(trials_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") != "completed":
            continue
        image = record.get("image") or {}
        ground_truth = record.get("ground_truth") or {}
        out.append(
            ContextTrial(
                trial_id=record["trial_id"],
                container_id=record.get("container_id", ""),
                image_digest=image.get("reference", ""),
                context_variant=record.get("context_variant"),
                split=assign_split(record["trial_id"]),
                is_scenario=bool(ground_truth.get("attack_like")),
                runtime_context=record.get("runtime_context") or {},
            )
        )
    return out


def _isolation_records(trials: list[ContextTrial]) -> list[dict[str, Any]]:
    """Mirrors experiments/scope.py:_isolation_records. Keyed by container_id,
    not trial_id: trial_id's split is assign_split(trial_id), a pure function
    of the key itself, so a records list keyed by trial_id can never disagree
    with itself and the check can never actually trigger. container_id is the
    real Docker runtime identity, so a real cross-split leak (the same
    physical container double-counted under two different split labels) is
    something this can actually catch."""
    return [{"run_id": t.container_id, "split": t.split} for t in trials]


def check_calibration_test_isolation(
    fit: list[ContextTrial], calibration: list[ContextTrial], test: list[ContextTrial]
) -> None:
    """Raise if any physical container is double-counted across the
    fit/calibration/test partition this module scores."""
    check_split_isolation(_isolation_records(fit) + _isolation_records(calibration) + _isolation_records(test))


# Fields considered security-relevant deltas. Each contributes a fixed weight
# if it differs from the reference; kept simple and auditable rather than
# statistically fit, since n is far too small to fit weights honestly.
DELTA_FIELDS: dict[str, float] = {
    "privileged": 0.35,
    "capabilities": 0.30,
    "read_only_rootfs": 0.15,
    "network_mode": 0.10,
    "mounts": 0.05,
    "devices": 0.05,
}


def context_delta_score(reference: dict[str, Any], observed: dict[str, Any]) -> tuple[float, dict[str, bool]]:
    """Simple deterministic delta score in [0, 1]: sum of fixed weights for
    every field that differs between reference and observed context
    documents. Not a statistical distance, not fit to data, and not claimed
    to be calibrated -- it exists to answer one falsifiable yes/no question:
    can a direct context feature see what process-name distance cannot."""
    diffs: dict[str, bool] = {}
    score = 0.0
    for field, weight in DELTA_FIELDS.items():
        differs = reference.get(field) != observed.get(field)
        diffs[field] = differs
        if differs:
            score += weight
    return round(min(1.0, score), 6), diffs


def compute_calibration_coverage(
    fit: list[ContextTrial],
    calibration: list[ContextTrial],
    references: dict[str, dict[str, Any]],
    reference_variants: dict[str, str | None],
    alpha: float = CALIBRATION_COVERAGE_ALPHA,
) -> dict[str, Any]:
    """MET-CAL-001 for the context-delta feature: score every calibration-
    split benign trial's delta_score against its digest's fit-split reference
    through empirical_upper_tail_pvalue, using the fit-split trials' own
    delta_scores against that same reference as the calibration values
    (mirrors experiments/scope.py:compute_calibration_coverage). A calibration
    trial whose context_variant differs from the variant that produced its
    digest's reference is reported as drift rather than scored against a
    mismatched reference; insufficient_profile/drift_detected runs stay in
    the denominator."""
    fit_values: dict[str, list[float]] = {}
    for t in fit:
        reference = references.get(t.image_digest)
        if reference is None:
            continue
        score, _ = context_delta_score(reference, t.runtime_context)
        fit_values.setdefault(t.image_digest, []).append(score)

    rows: list[dict[str, Any]] = []
    for t in calibration:
        reference = references.get(t.image_digest)
        if reference is None:
            rows.append({"trial_id": t.trial_id, "status": "insufficient_profile",
                          "delta_score": None, "p_value": None, "covered": False})
            continue
        score, diffs = context_delta_score(reference, t.runtime_context)
        training_variant = reference_variants.get(t.image_digest)
        if training_variant is not None and t.context_variant != training_variant:
            rows.append({"trial_id": t.trial_id, "status": "drift_detected",
                         "delta_score": score, "p_value": None, "covered": False})
            continue
        pvalue_result = empirical_upper_tail_pvalue(fit_values.get(t.image_digest, []), score)
        p_value = pvalue_result.get("p_value")
        covered = p_value is not None and p_value > alpha
        rows.append({
            "trial_id": t.trial_id, "status": "scored", "delta_score": score,
            "differing_fields": [k for k, v in diffs.items() if v],
            "p_value": p_value, "covered": covered,
        })

    covered_n = sum(1 for r in rows if r["status"] == "scored" and r["covered"])
    denominator = len(rows)
    interval = clopper_pearson_interval(covered_n, denominator)

    return {
        "alpha": alpha,
        "calibration_trials": denominator,
        "covered": covered_n,
        "drift_detected_runs": sum(1 for r in rows if r["status"] == "drift_detected"),
        "insufficient_profile_runs": sum(1 for r in rows if r["status"] == "insufficient_profile"),
        "coverage": {
            "successes": interval.successes, "trials": interval.trials,
            "point_estimate": interval.point_estimate, "lower": interval.lower,
            "upper": interval.upper, "confidence": interval.confidence,
        },
        "trials": rows,
    }


def evaluate(run_dir: Path) -> dict[str, Any]:
    """For every digest, use the first fit-split trial's runtime_context as
    the reference (mirroring ARM-DIGEST's fit strategy), then score every
    test-split benign trial's context delta and every calibration-split
    benign trial's MET-CAL-001 coverage. A positive call is delta_score > 0
    (any recorded security-relevant field differs)."""
    trials = load_context_trials(run_dir)
    fit = [t for t in trials if t.split == "fit" and not t.is_scenario]
    test = [t for t in trials if t.split == "test" and not t.is_scenario]
    # The calibration split is disjoint from test: pooling it into the
    # test-split evaluation set (t.split in ("test", "calibration")) silently
    # skipped MET-CAL-001 entirely and violated this project's own no-data-
    # crosses-split-boundaries rule. Calibration is scored separately, below.
    calibration = [t for t in trials if t.split == "calibration" and not t.is_scenario]

    check_calibration_test_isolation(fit, calibration, test)

    references: dict[str, dict[str, Any]] = {}
    reference_variants: dict[str, str | None] = {}
    for t in fit:
        if t.image_digest not in references:
            references[t.image_digest] = t.runtime_context
            reference_variants[t.image_digest] = t.context_variant

    results = []
    for t in test:
        reference = references.get(t.image_digest)
        if reference is None:
            results.append({"trial_id": t.trial_id, "insufficient_profile": True})
            continue
        score, diffs = context_delta_score(reference, t.runtime_context)
        results.append(
            {
                "trial_id": t.trial_id,
                "context_variant": t.context_variant,
                "delta_score": score,
                "differing_fields": [k for k, v in diffs.items() if v],
                "positive": score > 0.0,
            }
        )

    by_variant: dict[str, dict[str, int]] = {}
    for r in results:
        if r.get("insufficient_profile"):
            continue
        variant = r["context_variant"] or "unknown"
        bucket = by_variant.setdefault(variant, {"total": 0, "positive": 0})
        bucket["total"] += 1
        if r["positive"]:
            bucket["positive"] += 1

    calibration_coverage = compute_calibration_coverage(fit, calibration, references, reference_variants)

    return {
        "schema_version": "porygon.context-delta-exploratory.v1",
        "source_run": run_dir.name,
        "note": (
            "Exploratory, non-confirmatory: reuses an already-collected study "
            "run's data (no new trials run for this analysis). Not a "
            "substitute for the frozen protocol's process-name-based primary "
            "result."
        ),
        "fit_digests": sorted(references.keys()),
        "by_context_variant": by_variant,
        "trials": results,
        "calibration_coverage": calibration_coverage,
    }


if __name__ == "__main__":
    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "artifacts/experiments/local/study-20260905t181654Z"
    )
    print(json.dumps(evaluate(run_dir), indent=2))
