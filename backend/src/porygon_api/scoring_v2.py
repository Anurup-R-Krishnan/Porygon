"""Pure v2 behavioural evidence and calibration primitives.

This module deliberately has no database or HTTP dependencies.  It is an
exploratory implementation of the Plan 004 mathematics; v1 scoring remains the
production/default path until v2 provenance and API contracts are complete.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from typing import Any, Iterable, Mapping

ALGORITHM_VERSION = "porygon.rarity.v2"
COMPONENT_REGISTRY_VERSION = "porygon.rarity.components.v1"
MARKOV_SMOOTHING_ALPHA = 1.0
COMPONENT_REGISTRY = (
    "categorical_shift",
    "sequence_surprisal",
    "novelty_mass",
    "numeric_tail",
)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalise_distribution(values: Mapping[str, float]) -> dict[str, float]:
    cleaned = {str(key): max(0.0, float(value)) for key, value in values.items()}
    total = sum(cleaned.values())
    if total <= 0.0:
        return {}
    return {key: value / total for key, value in sorted(cleaned.items())}


def hellinger_distance(
    baseline: Mapping[str, float],
    observed: Mapping[str, float],
) -> float | None:
    """Return bounded Hellinger distance over the union support.

    Empty observations are missing evidence, not an anomalous zero-valued
    observation.  A non-empty observation against an empty baseline returns the
    maximum distance and records unsupported baseline evidence to the caller.
    """

    observed_distribution = _normalise_distribution(observed)
    if not observed_distribution:
        return None
    baseline_distribution = _normalise_distribution(baseline)
    if not baseline_distribution:
        return 1.0
    support = sorted(set(baseline_distribution) | set(observed_distribution))
    distance = math.sqrt(
        0.5
        * sum(
            (
                math.sqrt(baseline_distribution.get(token, 0.0))
                - math.sqrt(observed_distribution.get(token, 0.0))
            )
            ** 2
            for token in support
        )
    )
    return max(0.0, min(1.0, distance))


def novelty_mass(
    baseline_support: Iterable[str],
    observed: Mapping[str, float],
) -> dict[str, Any]:
    """Return observed probability mass absent from the fit support."""

    observed_distribution = _normalise_distribution(observed)
    unseen = [
        {"token": token, "proportion": proportion}
        for token, proportion in observed_distribution.items()
        if token not in set(baseline_support)
    ]
    unseen.sort(key=lambda item: (-item["proportion"], item["token"]))
    return {
        "score": sum(item["proportion"] for item in unseen),
        "unseen": unseen,
        "available": bool(observed_distribution),
    }


def markov_surprisal(
    baseline_transitions: Mapping[str, Mapping[str, int]],
    observed_transitions: Iterable[tuple[str, str]],
    *,
    alpha: float = MARKOV_SMOOTHING_ALPHA,
) -> dict[str, Any]:
    """Calculate mean negative-log transition surprisal with Laplace smoothing."""

    if alpha <= 0.0:
        raise ValueError("alpha must be positive")
    rows = {
        str(source): {str(target): max(0, int(count)) for target, count in targets.items()}
        for source, targets in baseline_transitions.items()
    }
    transitions = [(str(source), str(target)) for source, target in observed_transitions]
    if not transitions:
        return {
            "score": None,
            "available": False,
            "transition_count": 0,
            "unseen": [],
            "smoothing_alpha": alpha,
        }

    targets = sorted({target for target_map in rows.values() for target in target_map})
    targets.extend(target for _, target in transitions if target not in targets)
    targets = sorted(set(targets))
    if not targets:
        return {
            "score": None,
            "available": False,
            "transition_count": len(transitions),
            "unseen": [],
            "smoothing_alpha": alpha,
        }

    scores: list[float] = []
    unseen: Counter[str] = Counter()
    for source, target in transitions:
        row = rows.get(source, {})
        denominator = sum(row.values()) + alpha * len(targets)
        probability = (row.get(target, 0) + alpha) / denominator
        scores.append(-math.log2(probability))
        if target not in row:
            unseen[f"{source} -> {target}"] += 1
    return {
        "score": sum(scores) / len(scores),
        "available": True,
        "transition_count": len(transitions),
        "unseen": [
            {"transition": token, "count": count}
            for token, count in sorted(unseen.items(), key=lambda item: (-item[1], item[0]))
        ],
        "smoothing_alpha": alpha,
    }


def empirical_upper_tail_pvalue(
    calibration_values: Iterable[float],
    test_value: float,
) -> dict[str, Any]:
    """Return the finite-sample upper-tail p-value using inclusive ties."""

    values = sorted(float(value) for value in calibration_values)
    if not values:
        return {"status": "insufficient_data", "p_value": None, "rarity": None, "n": 0}
    exceedances = sum(value >= float(test_value) for value in values)
    p_value = (1 + exceedances) / (len(values) + 1)
    return {
        "status": "calibrated",
        "p_value": p_value,
        "rarity": 1.0 - p_value,
        "n": len(values),
        "inclusive_exceedances": exceedances,
    }


def fuse_component_ranks(
    component_rarities: Mapping[str, float | None],
    *,
    required_components: Iterable[str] = COMPONENT_REGISTRY,
) -> dict[str, Any]:
    """Aggregate eligible component rarities with an unweighted mean.

    Missing components are retained explicitly.  No component or group weight
    is accepted by this function, preventing accidental reintroduction of the
    v1 hand-selected weighted composite.
    """

    required = tuple(required_components)
    if len(set(required)) != len(required):
        raise ValueError("required component registry contains duplicates")
    missing = sorted(name for name in required if component_rarities.get(name) is None)
    eligible = {
        name: float(component_rarities[name])
        for name in required
        if component_rarities.get(name) is not None
    }
    if not eligible:
        return {
            "status": "insufficient_data",
            "rarity": None,
            "eligible_components": [],
            "missing_components": missing,
            "component_registry_version": COMPONENT_REGISTRY_VERSION,
        }
    if any(not 0.0 <= value <= 1.0 for value in eligible.values()):
        raise ValueError("component rarities must be in [0, 1]")
    return {
        "status": "calibrated",
        "rarity": sum(eligible.values()) / len(eligible),
        "eligible_components": sorted(eligible),
        "missing_components": missing,
        "component_registry_version": COMPONENT_REGISTRY_VERSION,
    }
