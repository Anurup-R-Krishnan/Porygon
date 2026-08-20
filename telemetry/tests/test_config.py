import pytest
from pydantic import ValidationError

from porygon_telemetry.config import Settings


def test_auto_docker_host_id_is_not_reported() -> None:
    settings = Settings(internal_api_token="x" * 32, docker_host_id="auto")
    assert settings.reported_docker_host_id is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("dead_letter_max_records", 0),
        ("dead_letter_max_total_bytes", 0),
        ("dead_letter_excerpt_bytes", 0),
        ("dead_letter_retention_seconds", 0),
    ],
)
def test_dead_letter_limits_must_be_positive(name: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(internal_api_token="x" * 32, **{name: value})
