from porygon_api.main import health_live


def test_live_endpoint_does_not_require_database() -> None:
    response = health_live()
    assert response.status == "ok"
    assert response.database == "not_checked"
