from porygon_collector.config import Settings


def test_heartbeat_interval_has_safe_lower_bound() -> None:
    settings = Settings(internal_api_token="x" * 32, heartbeat_interval_seconds=2)
    assert settings.heartbeat_interval_seconds == 2
