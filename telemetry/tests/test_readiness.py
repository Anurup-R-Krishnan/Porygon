from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from porygon_telemetry.main import _heartbeat_is_fresh, health_ready
from porygon_telemetry.state import TelemetryState


def _request(state: TelemetryState):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(telemetry=state)))


def _healthy_state() -> TelemetryState:
    state = TelemetryState(started_at=datetime.now(timezone.utc))
    state.set(
        source_running=True,
        source_file_available=True,
        backend_last_success_at=datetime.now(timezone.utc),
    )
    return state


@pytest.mark.parametrize(
    ("changes", "condition"),
    [
        ({"source_running": False}, "falco_source_not_running"),
        ({"source_file_available": False}, "falco_file_unavailable"),
        ({"backend_last_success_at": None}, "backend_heartbeat_missing"),
        (
            {"backend_last_success_at": datetime.now(timezone.utc) - timedelta(hours=1)},
            "backend_heartbeat_stale",
        ),
    ],
)
def test_readiness_names_failed_condition(changes, condition) -> None:
    state = _healthy_state()
    state.set(**changes)

    with pytest.raises(HTTPException) as exc_info:
        health_ready(_request(state))

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail["condition"] == condition


def test_idle_source_is_ready_without_recent_event() -> None:
    result = health_ready(_request(_healthy_state()))
    assert result["status"] == "ok"
    assert result["last_read_at"] is None


def test_heartbeat_freshness_boundary_and_timezone_requirement() -> None:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    interval = 10
    assert _heartbeat_is_fresh(now - timedelta(seconds=29.999), interval, now=now)
    assert _heartbeat_is_fresh(now - timedelta(seconds=30), interval, now=now)
    assert not _heartbeat_is_fresh(now - timedelta(seconds=30.001), interval, now=now)
    assert not _heartbeat_is_fresh(datetime(2026, 8, 20, 12, 0), interval, now=now)
