from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from porygon_api.baseline import FEATURE_SCHEMA_VERSION

ALGORITHM_VERSION = "porygon.distance.v1"

# Top-level weights are intentionally fixed in v1 and stored with every score.
# Changing any value requires a new algorithm version so historical scores remain reproducible.
SCORING_CONFIG: dict[str, Any] = {
    "algorithm_version": ALGORITHM_VERSION,
    "feature_schema_version": FEATURE_SCHEMA_VERSION,
    "top_level_weights": {
        "categorical_distance": 0.50,
        "novelty": 0.30,
        "numeric_deviation": 0.20,
    },
    "categorical_weights": {
        "process_name": 0.15,
        "executable": 0.25,
        "parent_child": 0.20,
        "user_uid": 0.10,
        "runtime_action": 0.10,
        "process_sequence_bigram": 0.20,
    },
    "numeric_weights": {
        "process_events_per_minute": 0.25,
        "runtime_events_per_minute": 0.10,
        "distinct_processes_per_window": 0.25,
        "root_process_ratio": 0.20,
        "shell_process_ratio": 0.20,
    },
    "numeric_scale_floors": {
        "process_events_per_minute": 1.0,
        "runtime_events_per_minute": 1.0,
        "distinct_processes_per_window": 1.0,
        "root_process_ratio": 0.05,
        "shell_process_ratio": 0.05,
    },
    "numeric_z_tolerance": 2.0,
    "numeric_z_saturation": 6.0,
    "score_bands": {
        "baseline_like_max": 0.25,
        "elevated_max": 0.50,
        "high_max": 0.75,
    },
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _round(value: float) -> float:
    return round(float(value), 12)


def _weighted_average(values: dict[str, float], weights: dict[str, float]) -> tuple[float | None, dict[str, float]]:
    available = {name: value for name, value in values.items() if name in weights}
    denominator = sum(weights[name] for name in available)
    if not available or denominator <= 0:
        return None, {}
    effective = {name: weights[name] / denominator for name in available}
    result = sum(available[name] * effective[name] for name in available)
    return _round(result), {name: _round(weight) for name, weight in effective.items()}


def jensen_shannon_distance(
    baseline: dict[str, float],
    observed: dict[str, float],
) -> float | None:
    """Return base-2 Jensen-Shannon distance in [0, 1].

    An empty observation means that the feature family was not observable in this
    window, so it is excluded rather than treated as maximally anomalous. A nonempty
    observation against an empty baseline is maximally unsupported.
    """

    if not observed:
        return None
    if not baseline:
        return 1.0

    support = sorted(set(baseline) | set(observed))
    p_total = sum(max(0.0, float(baseline.get(token, 0.0))) for token in support)
    q_total = sum(max(0.0, float(observed.get(token, 0.0))) for token in support)
    if q_total <= 0:
        return None
    if p_total <= 0:
        return 1.0

    p = [max(0.0, float(baseline.get(token, 0.0))) / p_total for token in support]
    q = [max(0.0, float(observed.get(token, 0.0))) / q_total for token in support]
    midpoint = [(left + right) / 2.0 for left, right in zip(p, q)]

    def _kl(left: list[float], right: list[float]) -> float:
        return sum(
            probability * math.log2(probability / reference)
            for probability, reference in zip(left, right)
            if probability > 0.0 and reference > 0.0
        )

    divergence = 0.5 * _kl(p, midpoint) + 0.5 * _kl(q, midpoint)
    return _round(math.sqrt(max(0.0, min(1.0, divergence))))


def _novelty(
    baseline: dict[str, float],
    observed: dict[str, float],
) -> tuple[float | None, list[dict[str, Any]]]:
    if not observed:
        return None, []
    total = sum(max(0.0, float(value)) for value in observed.values())
    if total <= 0:
        return None, []
    unseen = [
        {"token": token, "proportion": _round(max(0.0, float(proportion)) / total)}
        for token, proportion in observed.items()
        if token not in baseline
    ]
    unseen.sort(key=lambda item: (-item["proportion"], item["token"]))
    return _round(sum(item["proportion"] for item in unseen)), unseen


def _numeric_deviation(
    feature_name: str,
    baseline_summary: dict[str, Any],
    observed_summary: dict[str, Any],
) -> dict[str, Any] | None:
    if not baseline_summary or not observed_summary:
        return None

    observed = float(observed_summary.get("mean", 0.0))
    median = float(baseline_summary.get("median", 0.0))
    p95 = float(baseline_summary.get("p95", median))
    stddev = max(0.0, float(baseline_summary.get("stddev", 0.0)))
    robust_sigma = abs(p95 - median) / 1.6448536269514722
    floor = float(SCORING_CONFIG["numeric_scale_floors"][feature_name])
    scale = max(stddev, robust_sigma, abs(median) * 0.10, floor)
    z_score = abs(observed - median) / scale
    tolerance = float(SCORING_CONFIG["numeric_z_tolerance"])
    saturation = float(SCORING_CONFIG["numeric_z_saturation"])
    score = max(0.0, min(1.0, (z_score - tolerance) / (saturation - tolerance)))

    return {
        "score": _round(score),
        "observed": _round(observed),
        "baseline_median": _round(median),
        "baseline_p95": _round(p95),
        "baseline_stddev": _round(stddev),
        "effective_scale": _round(scale),
        "absolute_z": _round(z_score),
    }


def score_band(total_score: float) -> str:
    bands = SCORING_CONFIG["score_bands"]
    if total_score < bands["baseline_like_max"]:
        return "baseline_like"
    if total_score < bands["elevated_max"]:
        return "elevated"
    if total_score < bands["high_max"]:
        return "high"
    return "extreme"


def build_observation_key(
    *,
    profile_id: str,
    profile_model_hash: str,
    window_start: str,
    window_end: str,
    selected_event_ids_sha256: str,
) -> str:
    return sha256_json(
        {
            "profile_id": profile_id,
            "profile_model_hash": profile_model_hash,
            "window_start": window_start,
            "window_end": window_end,
            "selected_event_ids_sha256": selected_event_ids_sha256,
            "scoring_config": SCORING_CONFIG,
        }
    )


def score_feature_documents(
    *,
    baseline_features: dict[str, Any],
    observation_features: dict[str, Any],
) -> tuple[float, str, dict[str, Any], dict[str, Any]]:
    if baseline_features.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("Unsupported baseline feature schema")
    if observation_features.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError("Unsupported observation feature schema")

    baseline_categories = baseline_features.get("categorical_distributions", {})
    observed_categories = observation_features.get("categorical_distributions", {})

    categorical_values: dict[str, float] = {}
    novelty_values: dict[str, float] = {}
    category_details: dict[str, Any] = {}
    novelty_details: dict[str, Any] = {}

    for family in SCORING_CONFIG["categorical_weights"]:
        baseline = baseline_categories.get(family, {})
        observed = observed_categories.get(family, {})
        distance = jensen_shannon_distance(baseline, observed)
        novelty_mass, unseen = _novelty(baseline, observed)
        if distance is not None:
            categorical_values[family] = distance
        if novelty_mass is not None:
            novelty_values[family] = novelty_mass
        category_details[family] = {
            "available": distance is not None,
            "distance": distance,
            "baseline_support_size": len(baseline),
            "observed_support_size": len(observed),
            "top_observed": [
                {"token": token, "proportion": _round(proportion)}
                for token, proportion in sorted(
                    observed.items(), key=lambda item: (-item[1], item[0])
                )[:10]
            ],
        }
        novelty_details[family] = {
            "available": novelty_mass is not None,
            "unseen_probability_mass": novelty_mass,
            "unseen": unseen[:25],
        }

    categorical_score, categorical_effective = _weighted_average(
        categorical_values,
        SCORING_CONFIG["categorical_weights"],
    )
    novelty_score, novelty_effective = _weighted_average(
        novelty_values,
        SCORING_CONFIG["categorical_weights"],
    )

    baseline_numeric = baseline_features.get("numeric_summaries", {})
    observed_numeric = observation_features.get("numeric_summaries", {})
    numeric_values: dict[str, float] = {}
    numeric_details: dict[str, Any] = {}
    for feature_name in SCORING_CONFIG["numeric_weights"]:
        detail = _numeric_deviation(
            feature_name,
            baseline_numeric.get(feature_name, {}),
            observed_numeric.get(feature_name, {}),
        )
        if detail is not None:
            numeric_values[feature_name] = detail["score"]
            numeric_details[feature_name] = detail
        else:
            numeric_details[feature_name] = {"available": False}

    numeric_score, numeric_effective = _weighted_average(
        numeric_values,
        SCORING_CONFIG["numeric_weights"],
    )

    group_values = {
        name: value
        for name, value in {
            "categorical_distance": categorical_score,
            "novelty": novelty_score,
            "numeric_deviation": numeric_score,
        }.items()
        if value is not None
    }
    total_score, group_effective = _weighted_average(
        group_values,
        SCORING_CONFIG["top_level_weights"],
    )
    if total_score is None:
        raise ValueError("No scoreable feature groups were present")

    components = {
        "categorical_distance": {
            "score": categorical_score,
            "effective_family_weights": categorical_effective,
            "families": category_details,
        },
        "novelty": {
            "score": novelty_score,
            "effective_family_weights": novelty_effective,
            "families": novelty_details,
        },
        "numeric_deviation": {
            "score": numeric_score,
            "effective_feature_weights": numeric_effective,
            "features": numeric_details,
        },
        "effective_group_weights": group_effective,
    }

    contributors: list[dict[str, Any]] = []
    for family, raw_score in categorical_values.items():
        contribution = (
            group_effective.get("categorical_distance", 0.0)
            * categorical_effective.get(family, 0.0)
            * raw_score
        )
        contributors.append(
            {
                "kind": "categorical_distance",
                "feature": family,
                "raw_score": _round(raw_score),
                "weighted_contribution": _round(contribution),
            }
        )
    for family, raw_score in novelty_values.items():
        contribution = (
            group_effective.get("novelty", 0.0)
            * novelty_effective.get(family, 0.0)
            * raw_score
        )
        contributors.append(
            {
                "kind": "novelty",
                "feature": family,
                "raw_score": _round(raw_score),
                "weighted_contribution": _round(contribution),
            }
        )
    for feature_name, raw_score in numeric_values.items():
        contribution = (
            group_effective.get("numeric_deviation", 0.0)
            * numeric_effective.get(feature_name, 0.0)
            * raw_score
        )
        contributors.append(
            {
                "kind": "numeric_deviation",
                "feature": feature_name,
                "raw_score": _round(raw_score),
                "weighted_contribution": _round(contribution),
            }
        )
    contributors.sort(key=lambda item: (-item["weighted_contribution"], item["kind"], item["feature"]))

    unseen_tokens: list[dict[str, Any]] = []
    for family, detail in novelty_details.items():
        for item in detail["unseen"]:
            unseen_tokens.append(
                {
                    "feature": family,
                    "token": item["token"],
                    "proportion": item["proportion"],
                }
            )
    unseen_tokens.sort(key=lambda item: (-item["proportion"], item["feature"], item["token"]))

    band = score_band(total_score)
    explanation = {
        "band": band,
        "interpretation": (
            "The score measures behavioural distance from the selected immutable-digest profile. "
            "It is not proof of malicious activity and must be evaluated with event evidence."
        ),
        "top_contributors": contributors[:12],
        "unseen_tokens": unseen_tokens[:25],
        "highest_numeric_deviations": sorted(
            [
                {"feature": name, **detail}
                for name, detail in numeric_details.items()
                if detail.get("score") is not None
            ],
            key=lambda item: (-item["score"], item["feature"]),
        )[:10],
    }
    return _round(total_score), band, components, explanation
