from __future__ import annotations

from porygon_api.main import app, get_anomaly_scoring_config


def test_phase5_routes_are_exposed_in_openapi() -> None:
    paths = app.openapi()["paths"]

    assert "/internal/v1/anomaly-scores/compute" in paths
    assert "/api/v1/anomaly-scores" in paths
    assert "/api/v1/anomaly-scores/config" in paths
    assert "/api/v1/anomaly-scores/{score_id}" in paths


def test_scoring_config_endpoint_marks_bands_as_provisional() -> None:
    response = get_anomaly_scoring_config()

    assert response["algorithm_version"] == "porygon.distance.v1"
    assert response["feature_schema_version"] == "porygon.behaviour.v1"
    assert "not validated attack thresholds" in response["interpretation"]
