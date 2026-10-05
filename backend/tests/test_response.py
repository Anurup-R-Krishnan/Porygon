from porygon_api.response import (
    allowed_actions_for_incident,
    build_execution_idempotency_key,
    build_recommendation_document,
    build_recommendation_key,
    response_policy_hash,
)


def test_low_evidence_incident_is_observe_only() -> None:
    allowed = allowed_actions_for_incident(
        severity_score=0.4,
        confidence_score=0.4,
        findings=[],
        has_target=True,
    )
    assert allowed == ["observe_only"]


def test_high_incident_allows_pause_but_not_automatically_stop() -> None:
    allowed = allowed_actions_for_incident(
        severity_score=0.8,
        confidence_score=0.7,
        findings=[{"rule_id": "POR-DET-002"}],
        has_target=True,
    )
    assert allowed == ["observe_only", "pause_container"]


def test_stop_requires_critical_scores_and_strong_rule() -> None:
    allowed = allowed_actions_for_incident(
        severity_score=0.95,
        confidence_score=0.9,
        findings=[{"rule_id": "POR-DET-005"}],
        has_target=True,
    )
    assert allowed == ["observe_only", "pause_container", "stop_container"]


def test_recommendation_and_execution_keys_are_deterministic() -> None:
    policy_hash = response_policy_hash()
    first = build_recommendation_key(
        incident_id="incident-1", target_container_id="a" * 64, policy_hash=policy_hash
    )
    second = build_recommendation_key(
        incident_id="incident-1", target_container_id="a" * 64, policy_hash=policy_hash
    )
    assert first == second
    assert len(first) == 64
    assert build_execution_idempotency_key(
        recommendation_id="recommendation-1", action_type="pause_container"
    ) == build_execution_idempotency_key(
        recommendation_id="recommendation-1", action_type="pause_container"
    )


def test_document_exposes_risk_and_never_claims_attack_proof() -> None:
    document = build_recommendation_document(
        incident_id="incident-1",
        target_container_id="a" * 64,
        severity_score=0.95,
        confidence_score=0.9,
        findings=[{"rule_id": "POR-DET-007"}],
    )
    assert document["recommended_action"] == "stop_container"
    assert any("not proof" in note for note in document["risk_notes"])
    assert any("in-memory state" in note for note in document["risk_notes"])
