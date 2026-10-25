import pytest
from fastapi import HTTPException

from porygon_api.config import get_settings
from porygon_api.response import allowed_actions_for_incident
from porygon_api.security import require_operator_token


def test_disruptive_execution_is_disabled_by_default() -> None:
    assert get_settings().response_execution_mode == "disabled"


def test_internal_credential_cannot_authenticate_as_operator() -> None:
    internal = get_settings().internal_api_token.get_secret_value()
    with pytest.raises(HTTPException) as exc_info:
        require_operator_token(x_porygon_operator_token=internal)
    assert exc_info.value.status_code == 401


def test_missing_exact_target_restricts_policy_to_observe_only() -> None:
    allowed = allowed_actions_for_incident(
        severity_score=1.0,
        confidence_score=1.0,
        findings=[{"rule_id": "POR-DET-005"}],
        has_target=False,
    )
    assert allowed == ["observe_only"]
