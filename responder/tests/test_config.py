from porygon_responder.config import Settings


def test_defaults_are_safe() -> None:
    settings = Settings(internal_api_token="x" * 32)
    assert settings.protected_label == "com.porygon.protected"
    assert settings.lease_seconds >= 10
    assert settings.stop_timeout_seconds >= 1
