from porygon_telemetry.config import Settings


def test_auto_docker_host_id_is_not_reported() -> None:
    settings = Settings(internal_api_token="x" * 32, docker_host_id="auto")
    assert settings.reported_docker_host_id is None
