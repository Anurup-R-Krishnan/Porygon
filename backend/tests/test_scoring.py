from __future__ import annotations

import copy

import pytest

from porygon_api.baseline import FEATURE_SCHEMA_VERSION
from porygon_api.scoring import (
    SCORING_CONFIG,
    build_observation_key,
    jensen_shannon_distance,
    score_band,
    score_feature_documents,
)


def _features() -> dict:
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "categorical_distributions": {
            "process_name": {"python": 0.75, "gunicorn": 0.25},
            "executable": {"/usr/bin/python": 0.75, "/usr/bin/gunicorn": 0.25},
            "parent_child": {"/bin/sh -> /usr/bin/python": 1.0},
            "user_uid": {"1000": 1.0},
            "runtime_action": {"container:start": 1.0},
            "process_sequence_bigram": {"/usr/bin/python -> /usr/bin/gunicorn": 1.0},
        },
        "observed_sets": {},
        "numeric_summaries": {
            "process_events_per_minute": {
                "min": 2.0,
                "max": 4.0,
                "mean": 3.0,
                "median": 3.0,
                "p95": 4.0,
                "stddev": 0.8,
            },
            "runtime_events_per_minute": {
                "min": 0.0,
                "max": 1.0,
                "mean": 0.5,
                "median": 0.5,
                "p95": 1.0,
                "stddev": 0.5,
            },
            "distinct_processes_per_window": {
                "min": 2.0,
                "max": 2.0,
                "mean": 2.0,
                "median": 2.0,
                "p95": 2.0,
                "stddev": 0.0,
            },
            "root_process_ratio": {
                "min": 0.0,
                "max": 0.0,
                "mean": 0.0,
                "median": 0.0,
                "p95": 0.0,
                "stddev": 0.0,
            },
            "shell_process_ratio": {
                "min": 0.0,
                "max": 0.0,
                "mean": 0.0,
                "median": 0.0,
                "p95": 0.0,
                "stddev": 0.0,
            },
        },
    }


def test_jensen_shannon_distance_is_bounded_symmetric_and_zero_for_identity() -> None:
    left = {"a": 0.75, "b": 0.25}
    right = {"a": 0.25, "b": 0.75}

    assert jensen_shannon_distance(left, left) == pytest.approx(0.0)
    assert jensen_shannon_distance(left, right) == pytest.approx(
        jensen_shannon_distance(right, left)
    )
    assert 0.0 < jensen_shannon_distance(left, right) < 1.0
    assert jensen_shannon_distance({"a": 1.0}, {"b": 1.0}) == pytest.approx(1.0)
    assert jensen_shannon_distance(left, {}) is None


def test_identical_feature_documents_have_zero_distance() -> None:
    features = _features()
    score, band, components, explanation = score_feature_documents(
        baseline_features=features,
        observation_features=copy.deepcopy(features),
    )

    assert score == pytest.approx(0.0)
    assert band == "baseline_like"
    assert components["categorical_distance"]["score"] == pytest.approx(0.0)
    assert components["novelty"]["score"] == pytest.approx(0.0)
    assert components["numeric_deviation"]["score"] == pytest.approx(0.0)
    assert explanation["interpretation"].startswith("The score measures behavioural distance")


def test_novel_shell_and_root_behaviour_produces_explainable_high_distance() -> None:
    baseline = _features()
    observed = copy.deepcopy(baseline)
    observed["categorical_distributions"] = {
        "process_name": {"bash": 0.5, "curl": 0.5},
        "executable": {"/bin/bash": 0.5, "/usr/bin/curl": 0.5},
        "parent_child": {"/usr/bin/gunicorn -> /bin/bash": 1.0},
        "user_uid": {"0": 1.0},
        "runtime_action": {"container:exec_start": 1.0},
        "process_sequence_bigram": {"/bin/bash -> /usr/bin/curl": 1.0},
    }
    for name, value in {
        "process_events_per_minute": 20.0,
        "runtime_events_per_minute": 5.0,
        "distinct_processes_per_window": 8.0,
        "root_process_ratio": 1.0,
        "shell_process_ratio": 0.5,
    }.items():
        observed["numeric_summaries"][name] = {
            "min": value,
            "max": value,
            "mean": value,
            "median": value,
            "p95": value,
            "stddev": 0.0,
        }

    score, band, components, explanation = score_feature_documents(
        baseline_features=baseline,
        observation_features=observed,
    )

    assert score >= 0.75
    assert band == "extreme"
    assert components["novelty"]["score"] == pytest.approx(1.0)
    assert any(item["token"] == "/bin/bash" for item in explanation["unseen_tokens"])
    assert explanation["top_contributors"][0]["weighted_contribution"] > 0


def test_algorithm_weights_are_normalised_and_versioned() -> None:
    assert sum(SCORING_CONFIG["top_level_weights"].values()) == pytest.approx(1.0)
    assert sum(SCORING_CONFIG["categorical_weights"].values()) == pytest.approx(1.0)
    assert sum(SCORING_CONFIG["numeric_weights"].values()) == pytest.approx(1.0)
    assert SCORING_CONFIG["algorithm_version"] == "porygon.distance.v1"


def test_observation_key_is_deterministic_and_event_set_sensitive() -> None:
    kwargs = {
        "profile_id": "00000000-0000-0000-0000-000000000001",
        "profile_model_hash": "a" * 64,
        "window_start": "2026-07-21T10:00:00+00:00",
        "window_end": "2026-07-21T10:01:00+00:00",
        "selected_event_ids_sha256": "b" * 64,
    }
    first = build_observation_key(**kwargs)
    second = build_observation_key(**kwargs)
    changed = build_observation_key(**{**kwargs, "selected_event_ids_sha256": "c" * 64})

    assert first == second
    assert first != changed
    assert len(first) == 64


def test_schema_mismatch_is_rejected() -> None:
    baseline = _features()
    observed = _features()
    observed["schema_version"] = "unsupported"

    with pytest.raises(ValueError, match="Unsupported observation feature schema"):
        score_feature_documents(
            baseline_features=baseline,
            observation_features=observed,
        )


def test_score_band_boundaries_are_explicit() -> None:
    assert score_band(0.0) == "baseline_like"
    assert score_band(0.249999) == "baseline_like"
    assert score_band(0.25) == "elevated"
    assert score_band(0.5) == "high"
    assert score_band(0.75) == "extreme"


def test_missing_feature_families_are_renormalised_not_zero_filled() -> None:
    baseline = _features()
    observed = _features()
    observed["categorical_distributions"] = {
        "process_name": {"python": 0.75, "gunicorn": 0.25},
    }
    observed["numeric_summaries"] = {}

    score, band, components, _ = score_feature_documents(
        baseline_features=baseline,
        observation_features=observed,
    )

    assert score == pytest.approx(0.0)
    assert band == "baseline_like"
    assert components["effective_group_weights"] == {
        "categorical_distance": pytest.approx(0.625),
        "novelty": pytest.approx(0.375),
    }
    assert components["categorical_distance"]["effective_family_weights"] == {
        "process_name": pytest.approx(1.0),
    }


def test_unscoreable_document_is_rejected_instead_of_assumed_normal() -> None:
    baseline = _features()
    observed = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "categorical_distributions": {},
        "numeric_summaries": {},
    }

    with pytest.raises(ValueError, match="No scoreable feature groups"):
        score_feature_documents(
            baseline_features=baseline,
            observation_features=observed,
        )
