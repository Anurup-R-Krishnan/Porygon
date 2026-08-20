from __future__ import annotations

import json
import sqlite3

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


def test_store_repairs_legacy_detailed_actions_without_dropping_events(tmp_path) -> None:
    path = str(tmp_path / "outbox.db")
    event_id = "b" * 64
    store = OutboxStore(path, max_events=10)
    assert store.enqueue(
        {
            "event_id": event_id,
            "action": "exec_create: sh -c " + "echo-safe " * 100,
            "command": "sleep 300",
            "raw_event": {"Action": "exec_create: sh -c echo-safe"},
        }
    )

    reopened = OutboxStore(path, max_events=10)
    repaired = reopened.fetch_due(10)

    assert reopened.count() == 1
    assert repaired[0]["event_id"] == event_id
    assert repaired[0]["action"] == "exec_create"
    assert repaired[0]["command"] == "sh -c echo-safe"
    assert repaired[0]["raw_event"]["Action"] == "exec_create: sh -c echo-safe"
    assert reopened.get_metadata("legacy_actions_repaired_total") == "1"
    assert reopened.get_metadata("legacy_exec_commands_repaired_total") == "1"

    OutboxStore(path, max_events=10)
    assert reopened.get_metadata("legacy_actions_repaired_total") == "1"
    assert reopened.get_metadata("legacy_exec_commands_repaired_total") == "1"

    with sqlite3.connect(path) as connection:
        raw = connection.execute(
            "SELECT payload FROM outbox WHERE event_id = ?", (event_id,)
        ).fetchone()[0]
    assert json.loads(raw)["action"] == "exec_create"
