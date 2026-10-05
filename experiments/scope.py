"""Profile-scope comparison: GLOBAL vs TAG vs DIGEST vs CONTEXT.

This module builds the actual comparison the research protocol
(docs/RESEARCH_PROTOCOL_V1.md, PROFILE_SCOPE_EXPERIMENT_V1.md) asks for, which
nothing in the codebase computed until now: for the same real trial data,
build a reference process-name distribution under each of the four scoping
strategies from the fit-split trials only, then score every test-split trial
against each scope's reference using the exact same Jensen-Shannon distance
function the production anomaly scorer uses
(backend/src/porygon_api/scoring.py:jensen_shannon_distance), imported
directly rather than reimplemented, so this can never silently drift from
what the real detector does.

Scopes, matching PROFILE_SCOPE_EXPERIMENT_V1.md exactly:
- ARM-GLOBAL:  one reference pooling every fit-split trial regardless of image
- ARM-TAG:     one reference per human_tag (mutable alias)
- ARM-DIGEST:  one reference per exact image digest (immutable)
- ARM-CONTEXT: one reference per (image digest, runtime_context_hash) pair

A trial is a positive call under a scope if its JS distance against that
scope's fit-split reference is at or above a threshold. False positive rate
is then "positive call on a benign (non-scenario) held-out trial"; recall is
"positive call on a scenario trial with planted ground truth". Both feed
directly into experiments/analysis.py's exact_mcnemar_p / holm_adjust /
clopper_pearson_interval / decide_primary_contrast, matching the protocol's
frozen Statistical analysis section.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND_SRC = ROOT / "backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from porygon_api.scoring import jensen_shannon_distance  # noqa: E402
from porygon_api.calibrated_rarity import empirical_upper_tail_pvalue  # noqa: E402

from experiments.analysis import clopper_pearson_interval  # noqa: E402
from experiments.artifacts import assign_split, check_split_isolation  # noqa: E402

SCOPES = ("ARM-GLOBAL", "ARM-TAG", "ARM-DIGEST", "ARM-CONTEXT")

# Default positive-call threshold. Matches SCORING_CONFIG's baseline_like_max
# in backend/src/porygon_api/scoring.py: at or above this JS distance is
# outside the "baseline_like" band the production scorer itself uses.
DEFAULT_THRESHOLD = 0.25

# One-sided rejection level for MET-CAL-001 ("run-level benign calibration
# coverage at nominal 95%", RESEARCH_PROTOCOL_V1.md). A calibration-split run
# is "covered" when its empirical upper-tail p-value against the fit-split
# calibration values exceeds this alpha; H_1_002's acceptance band is a
# 92%-98% run-level coverage fraction of runs clearing that bar.
CALIBRATION_COVERAGE_ALPHA = 0.05


@dataclass(frozen=True)
class TrialIdentity:
    trial_id: str
    container_id: str
    image_digest: str
    human_tag: str
    runtime_context_hash: str
    split: str
    is_scenario: bool  # True if this trial carries planted ground truth (a scenario, not benign)


def load_trial_identities(run_dir: Path) -> list[TrialIdentity]:
    """Read every trial record's identity fields directly from the pilot/study
    run's own trial JSON files (real.py:run_trial's schema), never re-derived."""
    trials_dir = run_dir / "trials"
    identities: list[TrialIdentity] = []
    for path in sorted(trials_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("status") != "completed":
            continue
        image = record.get("image") or {}
        ground_truth = record.get("ground_truth") or {}
        trial_id = record["trial_id"]
        identities.append(
            TrialIdentity(
                trial_id=trial_id,
                container_id=record["container_id"],
                image_digest=image.get("reference", ""),
                human_tag=record.get("human_tag", ""),
                runtime_context_hash=record.get("runtime_context_hash", ""),
                # The trial record's own "split" field is fixed at pilot-time
                # ("pilot") and never rewritten; study.py's split_assignment
                # stage computes fit/calibration/test in memory only. Recompute
                # the same deterministic assignment here from the trial_id
                # (experiments/artifacts.py:assign_split), so this module's
                # split labels always match what a real study run assigned,
                # not a stale on-disk placeholder.
                split=assign_split(trial_id),
                # attack_like is the real ground-truth field real.py writes
                # (True only for SCN-LOG4SHELL-SIM/SCN-RUNC-ESCAPE-SIM-style
                # scenarios). SCN-EXEC's canary echo is expected_outcome
                # "controlled_positive" but attack_like=False: it is a
                # capture-integrity marker, not a behavioural deviation, so
                # it must not be scored as a positive-ground-truth run.
                is_scenario=bool(ground_truth.get("attack_like")),
            )
        )
    return identities


def fetch_process_name_distribution(base_url: str, container_id: str, page_size: int = 500) -> dict[str, float]:
    """Pull every process-exec event for one container and return a raw
    (unnormalised) process_name count distribution. jensen_shannon_distance
    normalises internally, so raw counts are the correct input.

    page_size is capped by the backend's own limit (main.py:723: le=500);
    passing a larger value causes every page to 422 and silently return an
    empty distribution, so it is validated here rather than trusted."""
    if not (1 <= page_size <= 500):
        raise ValueError("page_size must be between 1 and 500 (backend API limit)")
    counts: Counter[str] = Counter()
    before: int | None = None
    for _ in range(50):  # bounded paging; far beyond any single trial's event volume
        url = f"{base_url}/api/v1/process-events?container_id={container_id}&limit={page_size}"
        if before is not None:
            url += f"&before_time_nano={before}"
        with urllib.request.urlopen(url, timeout=30) as response:
            page = json.loads(response.read())
        if not page:
            break
        for event in page:
            name = event.get("process_name")
            if name:
                counts[name] += 1
        before = min(event["time_nano"] for event in page)
        if len(page) < page_size:
            break
    return dict(counts)


def scope_key(identity: TrialIdentity, scope: str) -> str:
    """The reference-group key a trial belongs to under one scoping strategy."""
    if scope == "ARM-GLOBAL":
        return "global"
    if scope == "ARM-TAG":
        return identity.human_tag
    if scope == "ARM-DIGEST":
        return identity.image_digest
    if scope == "ARM-CONTEXT":
        return f"{identity.image_digest}::{identity.runtime_context_hash}"
    raise ValueError(f"unknown scope: {scope}")


def build_scope_references(
    base_url: str,
    fit_identities: list[TrialIdentity],
    scope: str,
) -> dict[str, dict[str, float]]:
    """Pool process-name counts across every fit-split trial sharing a scope
    key, producing one reference distribution per key for this scope."""
    pooled: dict[str, Counter[str]] = {}
    for identity in fit_identities:
        key = scope_key(identity, scope)
        distribution = fetch_process_name_distribution(base_url, identity.container_id)
        bucket = pooled.setdefault(key, Counter())
        bucket.update(distribution)
    return {key: dict(counter) for key, counter in pooled.items()}


@dataclass(frozen=True)
class ScoredTrial:
    trial_id: str
    scope: str
    reference_key: str
    reference_key_present: bool
    js_distance: float | None
    positive: bool
    is_scenario: bool


def score_trial_under_scope(
    base_url: str,
    identity: TrialIdentity,
    scope: str,
    references: dict[str, dict[str, float]],
    threshold: float = DEFAULT_THRESHOLD,
) -> ScoredTrial:
    key = scope_key(identity, scope)
    reference = references.get(key)
    observed = fetch_process_name_distribution(base_url, identity.container_id)
    if reference is None:
        # No fit-split coverage for this reference key under this scope: this
        # is the "insufficient_profile" outcome the protocol requires to be
        # reported explicitly, never silently treated as either a pass or a
        # detection.
        return ScoredTrial(
            trial_id=identity.trial_id, scope=scope, reference_key=key,
            reference_key_present=False, js_distance=None, positive=False,
            is_scenario=identity.is_scenario,
        )
    distance = jensen_shannon_distance(reference, observed)
    positive = distance is not None and distance >= threshold
    return ScoredTrial(
        trial_id=identity.trial_id, scope=scope, reference_key=key,
        reference_key_present=True, js_distance=distance, positive=bool(positive),
        is_scenario=identity.is_scenario,
    )


def _isolation_records(identities: list[TrialIdentity]) -> list[dict[str, Any]]:
    """Build experiments/artifacts.py:check_split_isolation input keyed by
    container_id, not trial_id.

    trial_id's split is assign_split(trial_id): a pure function of the key
    itself, so a records list built as {"run_id": trial_id, "split":
    assign_split(trial_id)} can never disagree with itself -- the same
    trial_id always hashes to the same split, by construction, so the check
    can never actually trigger. container_id is the real Docker runtime
    identity, assigned independently of trial_id; if the same physical
    container were ever double-counted across two differently-split trial
    records (a container-reuse bug in experiments/real.py, or two records
    mistakenly sharing a container id), that is a genuine cross-split leak,
    and keying by container_id lets check_split_isolation actually catch it.
    """
    return [{"run_id": identity.container_id, "split": identity.split} for identity in identities]


def check_calibration_test_isolation(
    fit: list[TrialIdentity], calibration: list[TrialIdentity], test: list[TrialIdentity]
) -> None:
    """Raise if any physical container is double-counted across the
    fit/calibration/test partition this module scores. Guards specifically
    against a regression of the calibration-into-test pooling bug this module
    once had (a calibration-split trial silently scored as a test-split
    trial), but checks all three splits pairwise for the same reason."""
    check_split_isolation(_isolation_records(fit) + _isolation_records(calibration) + _isolation_records(test))


@dataclass(frozen=True)
class CalibrationScoredTrial:
    trial_id: str
    scope: str
    reference_key: str
    reference_key_present: bool
    js_distance: float | None
    p_value: float | None
    covered: bool
    drift_detected: bool
    status: str  # "scored" | "insufficient_profile" | "drift_detected"


def _fit_reference_distances(
    base_url: str,
    fit_identities: list[TrialIdentity],
    scope: str,
    references: dict[str, dict[str, float]],
    threshold: float,
) -> dict[str, list[float]]:
    """The "fit-split calibration values" MET-CAL-001 requires: each
    fit-split trial's own JS distance against its scope's fit-split
    reference, forming the empirical null distribution a held-out
    calibration-split run's distance is compared against. Reuses
    score_trial_under_scope -- the exact function that scores test-split
    trials -- so this can never silently drift from that scoring logic."""
    values: dict[str, list[float]] = {}
    for identity in fit_identities:
        scored = score_trial_under_scope(base_url, identity, scope, references, threshold)
        if scored.reference_key_present and scored.js_distance is not None:
            values.setdefault(scored.reference_key, []).append(scored.js_distance)
    return values


def _training_fingerprints(fit_identities: list[TrialIdentity], scope: str) -> dict[str, set[tuple[str, str]]]:
    """Every (image_digest, runtime_context_hash) identity that contributed to
    each scope key's fit-split reference. A calibration run whose own identity
    never appeared in training is drift, not an ordinary calibrated outcome:
    MET-CAL-001's exchangeability assumption -- the held-out run's statistic
    is exchangeable with the fit-split calibration values it is compared
    against -- does not hold for it."""
    fingerprints: dict[str, set[tuple[str, str]]] = {}
    for identity in fit_identities:
        key = scope_key(identity, scope)
        fingerprints.setdefault(key, set()).add((identity.image_digest, identity.runtime_context_hash))
    return fingerprints


def score_calibration_trial(
    base_url: str,
    identity: TrialIdentity,
    scope: str,
    references: dict[str, dict[str, float]],
    fit_reference_distances: dict[str, list[float]],
    training_fingerprints: dict[str, set[tuple[str, str]]],
    threshold: float = DEFAULT_THRESHOLD,
    alpha: float = CALIBRATION_COVERAGE_ALPHA,
) -> CalibrationScoredTrial:
    scored = score_trial_under_scope(base_url, identity, scope, references, threshold)
    if not scored.reference_key_present:
        return CalibrationScoredTrial(
            trial_id=identity.trial_id, scope=scope, reference_key=scored.reference_key,
            reference_key_present=False, js_distance=None, p_value=None,
            covered=False, drift_detected=False, status="insufficient_profile",
        )
    fingerprint = (identity.image_digest, identity.runtime_context_hash)
    if fingerprint not in training_fingerprints.get(scored.reference_key, set()):
        # Never scored against a reference this identity never trained --
        # reported as drift rather than silently scored against a mismatched
        # calibration set (RESEARCH_PROTOCOL_V1.md MET-CAL-001).
        return CalibrationScoredTrial(
            trial_id=identity.trial_id, scope=scope, reference_key=scored.reference_key,
            reference_key_present=True, js_distance=scored.js_distance, p_value=None,
            covered=False, drift_detected=True, status="drift_detected",
        )
    calibration_values = fit_reference_distances.get(scored.reference_key, [])
    pvalue_result = empirical_upper_tail_pvalue(calibration_values, scored.js_distance)
    p_value = pvalue_result.get("p_value")
    covered = p_value is not None and p_value > alpha
    return CalibrationScoredTrial(
        trial_id=identity.trial_id, scope=scope, reference_key=scored.reference_key,
        reference_key_present=True, js_distance=scored.js_distance, p_value=p_value,
        covered=covered, drift_detected=False, status="scored",
    )


def compute_calibration_coverage(
    base_url: str,
    fit: list[TrialIdentity],
    calibration: list[TrialIdentity],
    scope: str,
    references: dict[str, dict[str, float]],
    threshold: float = DEFAULT_THRESHOLD,
    alpha: float = CALIBRATION_COVERAGE_ALPHA,
) -> dict[str, Any]:
    """MET-CAL-001 for one scope: score every calibration-split benign trial's
    JS distance against the scope's fit-split reference through
    empirical_upper_tail_pvalue, using the fit-split trials' own distances
    against that same reference as the calibration values. insufficient_profile
    and drift_detected runs are retained in the denominator (never dropped);
    only runs sharing calibration-set identity ("scored") can contribute to
    the coverage numerator, per RESEARCH_PROTOCOL_V1.md."""
    fit_reference_distances = _fit_reference_distances(base_url, fit, scope, references, threshold)
    training_fingerprints = _training_fingerprints(fit, scope)
    rows = [
        score_calibration_trial(
            base_url, identity, scope, references, fit_reference_distances, training_fingerprints, threshold, alpha
        )
        for identity in calibration
    ]

    covered = sum(1 for r in rows if r.status == "scored" and r.covered)
    denominator = len(rows)
    interval = clopper_pearson_interval(covered, denominator)

    return {
        "alpha": alpha,
        "calibration_trials": denominator,
        "covered": covered,
        "drift_detected_runs": sum(1 for r in rows if r.status == "drift_detected"),
        "insufficient_profile_runs": sum(1 for r in rows if r.status == "insufficient_profile"),
        "coverage": {
            "successes": interval.successes, "trials": interval.trials,
            "point_estimate": interval.point_estimate, "lower": interval.lower,
            "upper": interval.upper, "confidence": interval.confidence,
        },
        "trials": [
            {
                "trial_id": r.trial_id, "reference_key": r.reference_key,
                "reference_key_present": r.reference_key_present, "js_distance": r.js_distance,
                "p_value": r.p_value, "covered": r.covered, "drift_detected": r.drift_detected,
                "status": r.status,
            }
            for r in rows
        ],
    }


def compare_scopes(
    base_url: str,
    run_dir: Path,
    threshold: float = DEFAULT_THRESHOLD,
    alpha: float = CALIBRATION_COVERAGE_ALPHA,
) -> dict[str, Any]:
    """Full comparison: build every scope's fit-split reference, score every
    test-split trial under every scope, compute MET-CAL-001 calibration
    coverage from the calibration split, and return per-scope FPR/recall/
    coverage raw counts ready for experiments/analysis.py."""
    identities = load_trial_identities(run_dir)
    # A behavior-profile fit set must only ever contain benign evidence.
    # assign_split() assigns purely by trial_id hash and has no notion of
    # scenario vs benign, so a scenario (attack-like) trial can land in the
    # "fit" split by chance; if it is used to build the reference, "normal"
    # becomes contaminated with attack-shaped processes (id, cat, etc.),
    # which was verified to inflate JS distance on ordinary benign test
    # trials and produce false positives that had nothing to do with scope.
    # Every real behavior-profile pipeline (backend/baseline.py) has the same
    # requirement implicitly, since it is only ever pointed at a training
    # interval a human has already confirmed is benign; here, where scenario
    # trials are deliberately interleaved for scheduling reasons, filtering
    # is mandatory rather than implicit.
    fit = [i for i in identities if i.split == "fit" and not i.is_scenario]
    # The calibration split is disjoint from test: pooling it into the
    # test-split evaluation set (i.split in ("test", "calibration")) silently
    # skipped MET-CAL-001 entirely and violated this project's own no-data-
    # crosses-split-boundaries rule. Calibration is scored separately, below,
    # against its own metric (compute_calibration_coverage).
    test = [i for i in identities if i.split == "test"]
    # MET-CAL-001 is specified over benign runs only ("held-out benign
    # calibration coverage"); mirror the fit filter for the same reason.
    calibration = [i for i in identities if i.split == "calibration" and not i.is_scenario]

    check_calibration_test_isolation(fit, calibration, test)

    results: dict[str, Any] = {
        "threshold": threshold,
        "fit_trials": len(fit),
        "test_trials": len(test),
        "calibration_trials": len(calibration),
        "scopes": {},
    }

    for scope in SCOPES:
        references = build_scope_references(base_url, fit, scope)
        scored = [score_trial_under_scope(base_url, identity, scope, references, threshold) for identity in test]

        benign = [s for s in scored if not s.is_scenario and s.reference_key_present]
        scenario = [s for s in scored if s.is_scenario and s.reference_key_present]
        insufficient = [s for s in scored if not s.reference_key_present]

        false_positives = sum(1 for s in benign if s.positive)
        true_positives = sum(1 for s in scenario if s.positive)

        calibration_coverage = compute_calibration_coverage(
            base_url, fit, calibration, scope, references, threshold, alpha
        )

        results["scopes"][scope] = {
            "reference_keys": sorted(references.keys()),
            "benign_runs": len(benign),
            "false_positives": false_positives,
            "scenario_runs": len(scenario),
            "true_positives": true_positives,
            "insufficient_profile_runs": len(insufficient),
            "calibration_coverage": calibration_coverage,
            "trials": [
                {
                    "trial_id": s.trial_id, "reference_key": s.reference_key,
                    "reference_key_present": s.reference_key_present,
                    "js_distance": s.js_distance, "positive": s.positive,
                    "is_scenario": s.is_scenario,
                }
                for s in scored
            ],
        }

    return results
