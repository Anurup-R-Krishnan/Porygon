from __future__ import annotations

from porygon_collector.spool import OutboxStore


def _event(event_id: str) -> dict[str, object]:
    return {"event_id": event_id, "action": "start"}


def test_outbox_deduplicates_and_acknowledges(tmp_path) -> None:
    store = OutboxStore(str(tmp_path / "outbox.db"), max_events=10)
    event_id = "a" * 64

    assert store.enqueue(_event(event_id)) is True
    assert store.enqueue(_event(event_id)) is False
    assert store.count() == 1
    assert store.fetch_due(10)[0]["event_id"] == event_id

    store.acknowledge([event_id])
    assert store.count() == 0


def test_container_cache_survives_store_reopen(tmp_path) -> None:
    path = str(tmp_path / "outbox.db")
    first = OutboxStore(path, max_events=10)
    first.cache_container("container-1", {"container": {"name": "probe"}})

    second = OutboxStore(path, max_events=10)
    assert second.get_cached_container("container-1") == {"container": {"name": "probe"}}
