from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from porygon_scanner.main import _heartbeat_is_fresh, health_ready


def _request(state: dict[str, object]):
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(scanner_state=state)))


def _healthy_state() -> dict[str, object]:
    return {
        "docker_connected": True,
        "backend_last_success_at": datetime.now(timezone.utc),
        "last_claim_at": None,
        "last_completion_at": None,
    }


def test_scanner_rejects_stale_backend_heartbeat() -> None:
    state = _healthy_state()
    state["backend_last_success_at"] = datetime.now(timezone.utc) - timedelta(hours=1)
    with pytest.raises(HTTPException) as exc_info:
        health_ready(_request(state))
    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Backend heartbeat is stale"


def test_scanner_heartbeat_freshness_boundary_and_timezone_requirement() -> None:
    now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    interval = 10
    assert _heartbeat_is_fresh(now - timedelta(seconds=29.999), interval, now=now)
    assert _heartbeat_is_fresh(now - timedelta(seconds=30), interval, now=now)
    assert not _heartbeat_is_fresh(now - timedelta(seconds=30.001), interval, now=now)
    assert not _heartbeat_is_fresh(datetime(2026, 8, 20, 12, 0), interval, now=now)
