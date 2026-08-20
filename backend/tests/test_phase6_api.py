from porygon_api.main import app, get_detection_rules_config


def test_phase6_routes_are_exposed_in_openapi() -> None:
    paths = app.openapi()["paths"]
    required = {
        "/api/v1/detection-rules/config",
        "/api/v1/detection-allowlists",
        "/internal/v1/detection-allowlists",
        "/internal/v1/detection-allowlists/{allowlist_id}/deactivate",
        "/internal/v1/detections/run",
        "/api/v1/detection-runs",
        "/api/v1/detection-runs/{run_id}",
        "/api/v1/incidents",
        "/api/v1/incidents/{incident_id}",
        "/api/v1/incidents/{incident_id}/timeline",
        "/internal/v1/incidents/{incident_id}/status",
    }
    assert required.issubset(paths)


def test_detection_config_separates_severity_confidence_and_verdict() -> None:
    response = get_detection_rules_config()
    assert response["ruleset_version"] == "porygon.detection.v1"
    assert response["matcher_revision"] == "porygon.detection.matcher.v3"
    assert len(response["ruleset_hash"]) == 64
    assert response["rules"]
    assert "Neither is a probability of compromise" in response["interpretation"]
