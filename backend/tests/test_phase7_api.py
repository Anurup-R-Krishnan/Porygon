from porygon_api.main import app, get_response_policy


def test_phase7_routes_are_exposed_in_openapi() -> None:
    paths = app.openapi()["paths"]
    required = {
        "/api/v1/response-policy",
        "/operator/v1/incidents/{incident_id}/response-recommendations",
        "/api/v1/response-recommendations",
        "/api/v1/response-recommendations/{recommendation_id}",
        "/operator/v1/response-recommendations/{recommendation_id}/approve",
        "/operator/v1/response-recommendations/{recommendation_id}/reject",
        "/internal/v1/response-executions/claim",
        "/internal/v1/response-executions/{execution_id}/complete",
        "/operator/v1/response-executions/{execution_id}/rollback",
        "/operator/v1/response-executions/{execution_id}/retry",
        "/api/v1/response-executions",
        "/api/v1/response-executions/{execution_id}",
        "/api/v1/incidents/{incident_id}/response-audit",
    }
    assert required.issubset(paths)


def test_response_policy_requires_human_approval() -> None:
    response = get_response_policy()
    assert len(response["policy_hash"]) == 64
    assert "No Docker state is changed" in response["interpretation"]
    assert response["execution_mode"] == "disabled"
    assert response["approval_max_age_seconds"] >= 60
    assert response["policy"]["version"] == "porygon.response.v1"
