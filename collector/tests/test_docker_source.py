from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from porygon_collector.docker_source import DockerEventSource
from porygon_collector.spool import OutboxStore
from porygon_collector.state import CollectorState


def _event(event_id: str, time_nano: int) -> dict[str, object]:
    return {"event_id": event_id, "time_nano": time_nano, "action": "start"}


class FakeDockerClient:
    def __init__(self, windows: list[list[dict[str, object]]]) -> None:
        self.windows = windows
        self.yield_counts: list[int] = []

    def events(self, **_kwargs):
        events = self.windows.pop(0)
        window_index = len(self.yield_counts)
        self.yield_counts.append(0)
        for event in events:
            self.yield_counts[window_index] += 1
            yield event


def test_saturation_preserves_cursor_and_replays_rejected_event(
    tmp_path,
    monkeypatch,
) -> None:
    first = _event("a" * 64, 1_000_000_001)
    rejected = _event("b" * 64, 2_000_000_002)
    later = _event("c" * 64, 3_000_000_003)
    client = FakeDockerClient([[first, rejected, later], [rejected, later], [later]])
    store = OutboxStore(str(tmp_path / "outbox.db"), max_events=1)
    state = CollectorState(started_at=datetime.now(timezone.utc))
    settings = SimpleNamespace(docker_event_overlap_seconds=2)
    source = DockerEventSource(settings, state, store)
    monkeypatch.setattr(
        "porygon_collector.docker_source.normalize_event",
        lambda _client, _store, _host_id, raw_event: raw_event,
    )
    monkeypatch.setattr(source.stop_event, "wait", lambda _seconds: False)

    assert source._capture_window(client, "host-1", since=0, until=10) is False
    assert store.fetch_due(10) == [first]
    assert store.get_cursor() == first["time_nano"]
    assert client.yield_counts == [2]

    store.acknowledge([str(first["event_id"])])
    assert source._capture_window(client, "host-1", since=0, until=10) is False
    assert store.fetch_due(10) == [rejected]
    assert store.get_cursor() == rejected["time_nano"]
    assert client.yield_counts == [2, 2]

    store.acknowledge([str(rejected["event_id"])])
    assert source._capture_window(client, "host-1", since=0, until=10) is True
    assert store.fetch_due(10) == [later]
    assert store.get_cursor() == later["time_nano"]
    assert state.snapshot()["spool_overflow_count"] == 2
