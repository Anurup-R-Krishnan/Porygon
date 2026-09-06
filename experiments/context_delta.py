"""Direct runtime-context-delta feature: exploratory follow-on to the
CONTEXT-vs-DIGEST null result in docs/CONFIRMATORY_RESULT_V1.md.

The frozen protocol's ARM-CONTEXT only uses the runtime-context hash to
*select which reference distribution* to score against; the score itself is
still pure process-name Jensen-Shannon distance. The confirmatory run found
this cannot distinguish a `dropped_capabilities` context change from
`baseline`, because dropping a Linux capability does not change which
processes execute.

This module tests a different, more direct idea: score the structured
runtime-context *document* itself (capabilities, privileged, read-only-rootfs,
mounts, network mode, ports) against a digest's fit-split reference context,
independently of process-name behaviour. This is exploratory, not
confirmatory: it reuses the same 144-trial study-20260905t181654Z dataset the
frozen protocol already collected (no new data collection, no protocol
change), so it is reported as a secondary/exploratory finding, never
substituted for the frozen protocol's own primary result.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from experiments.artifacts import assign_split


@dataclass(frozen=True)
class ContextTrial:
    trial_id: str
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
                image_digest=image.get("reference", ""),
                context_variant=record.get("context_variant"),
                split=assign_split(record["trial_id"]),
                is_scenario=bool(ground_truth.get("attack_like")),
                runtime_context=record.get("runtime_context") or {},
            )
        )
    return out


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


def evaluate(run_dir: Path) -> dict[str, Any]:
    """For every digest, use the first fit-split trial's runtime_context as
    the reference (mirroring ARM-DIGEST's fit strategy), then score every
    test-split benign trial's context delta. A positive call is delta_score
    > 0 (any recorded security-relevant field differs)."""
    trials = load_context_trials(run_dir)
    fit = [t for t in trials if t.split == "fit" and not t.is_scenario]
    test = [t for t in trials if t.split in ("test", "calibration") and not t.is_scenario]

    references: dict[str, dict[str, Any]] = {}
    for t in fit:
        references.setdefault(t.image_digest, t.runtime_context)

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

    return {
        "schema_version": "porygon.context-delta-exploratory.v1",
        "note": (
            "Exploratory, non-confirmatory: reuses study-20260905t181654Z's "
            "already-collected data. Not a substitute for the frozen "
            "protocol's process-name-based primary result."
        ),
        "fit_digests": sorted(references.keys()),
        "by_context_variant": by_variant,
        "trials": results,
    }


if __name__ == "__main__":
    import sys

    run_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
        "artifacts/experiments/local/study-20260905t181654Z"
    )
    print(json.dumps(evaluate(run_dir), indent=2))
