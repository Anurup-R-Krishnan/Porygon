from __future__ import annotations

import pytest

from porygon_api.calibrated_rarity import (
    ALGORITHM_ID,
    COMPONENT_REGISTRY_ID,
    empirical_upper_tail_pvalue,
    fuse_component_ranks,
    hellinger_distance,
    markov_surprisal,
    novelty_mass,
    sha256_json,
)


def test_calibrated_identity_symmetry_and_bounds() -> None:
    left = {"a": 3, "b": 1}
    right = {"b": 1, "a": 3}
    assert hellinger_distance(left, left) == pytest.approx(0.0)
    assert hellinger_distance(left, right) == pytest.approx(hellinger_distance(right, left))
    assert 0.0 <= hellinger_distance(left, {"c": 1}) <= 1.0
    assert hellinger_distance(left, {}) is None


def test_calibrated_novelty_is_explicit_and_order_invariant() -> None:
    first = novelty_mass(["known"], {"new": 3, "known": 1})
    second = novelty_mass(["known"], {"known": 1, "new": 3})
    assert first == second
    assert first["score"] == pytest.approx(0.75)
    assert first["unseen"] == [{"token": "new", "proportion": 0.75}]


def test_markov_surprisal_reports_unseen_transitions_and_fixed_smoothing() -> None:
    result = markov_surprisal(
        {"sh": {"sleep": 3}},
        [("sh", "sleep"), ("sh", "curl")],
    )
    assert result["available"] is True
    assert result["smoothing_alpha"] == 1.0
    assert result["transition_count"] == 2
    assert result["unseen"] == [{"transition": "sh -> curl", "count": 1}]
    assert result["score"] > 0.0


def test_markov_empty_observation_is_missing_not_normal() -> None:
    result = markov_surprisal({"sh": {"sleep": 1}}, [])
    assert result["available"] is False
    assert result["score"] is None


def test_empirical_tail_uses_inclusive_ties_and_finite_sample_floor() -> None:
    result = empirical_upper_tail_pvalue([0.1, 0.2, 0.2], 0.2)
    assert result["inclusive_exceedances"] == 2
    assert result["p_value"] == pytest.approx(3 / 4)
    floor = empirical_upper_tail_pvalue([1.0, 2.0, 3.0], 4.0)
    assert floor["p_value"] == pytest.approx(1 / 4)
    assert empirical_upper_tail_pvalue([], 1.0)["status"] == "insufficient_data"


def test_unweighted_rank_fusion_is_order_invariant_and_tracks_missingness() -> None:
    first = fuse_component_ranks(
        {"numeric_tail": 0.9, "categorical_shift": 0.3, "sequence_surprisal": None, "novelty_mass": 0.6}
    )
    second = fuse_component_ranks(
        {"novelty_mass": 0.6, "sequence_surprisal": None, "categorical_shift": 0.3, "numeric_tail": 0.9}
    )
    assert first == second
    assert first["rarity"] == pytest.approx(0.6)
    assert first["missing_components"] == ["sequence_surprisal"]
    assert first["component_registry_id"] == COMPONENT_REGISTRY_ID


def test_fusion_rejects_out_of_range_and_empty_components() -> None:
    with pytest.raises(ValueError, match=r"in \[0, 1\]"):
        fuse_component_ranks({"categorical_shift": 1.1})
    result = fuse_component_ranks({name: None for name in ("categorical_shift", "sequence_surprisal")})
    assert result["status"] == "insufficient_data"
    assert result["rarity"] is None


def test_calibrated_hash_is_canonical_and_stable() -> None:
    assert ALGORITHM_ID == "porygon.rarity.calibrated"
    assert sha256_json({"b": 2, "a": 1}) == sha256_json({"a": 1, "b": 2})
    assert sha256_json({"a": 1}) != sha256_json({"a": 2})
