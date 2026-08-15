from porygon_telemetry.spool import TelemetryStore


def test_outbox_and_file_cursor_are_durable(tmp_path) -> None:
    path = str(tmp_path / "telemetry.db")
    first = TelemetryStore(path, max_events=10)
    event = {"event_id": "a" * 64, "process_pid": 123}

    assert first.enqueue(event) is True
    assert first.enqueue(event) is False
    first.update_file_cursor(99, 4096)

    second = TelemetryStore(path, max_events=10)
    assert second.count() == 1
    assert second.get_file_cursor() == (99, 4096)
    second.acknowledge(["a" * 64])
    assert second.count() == 0


def test_dead_letter_count(tmp_path) -> None:
    store = TelemetryStore(str(tmp_path / "telemetry.db"), max_events=10)
    store.record_dead_letter(
        source_inode=1,
        source_offset=0,
        raw_line="not-json",
        error="JSONDecodeError",
    )
    assert store.dead_letter_count() == 1
