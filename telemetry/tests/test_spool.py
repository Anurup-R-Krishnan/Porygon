import hashlib
import sqlite3

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


def _dead_letter_rows(path) -> list[sqlite3.Row]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute("SELECT * FROM dead_letters ORDER BY id").fetchall()
    finally:
        connection.close()


def test_dead_letter_hashes_redacts_and_bounds_large_unicode_input(tmp_path) -> None:
    path = tmp_path / "telemetry.db"
    store = TelemetryStore(
        str(path),
        max_events=10,
        dead_letter_excerpt_bytes=128,
    )
    raw = (
        '"apiKey":"json-secret" token="super-secret" '
        "--password hunter2 Bearer abc123 π"
    ) + ("x" * 1_000_000)
    store.record_dead_letter(
        source_inode=7,
        source_offset=42,
        raw_line=raw,
        error="ValueError: password=also-secret",
    )

    row = _dead_letter_rows(path)[0]
    assert row["source_inode"] == 7
    assert row["source_offset"] == 42
    assert row["raw_line"] == ""
    assert row["raw_sha256"] == hashlib.sha256(raw.encode()).hexdigest()
    assert row["raw_byte_length"] == len(raw.encode())
    assert len(row["excerpt"].encode()) <= 128
    assert "super-secret" not in row["excerpt"]
    assert "json-secret" not in row["excerpt"]
    assert "hunter2" not in row["excerpt"]
    assert "abc123" not in row["excerpt"]
    assert "also-secret" not in row["error_message"]


def test_dead_letter_count_and_byte_limits_evict_oldest(tmp_path) -> None:
    path = tmp_path / "telemetry.db"
    store = TelemetryStore(
        str(path),
        max_events=10,
        dead_letter_max_records=2,
        dead_letter_max_total_bytes=10,
        dead_letter_excerpt_bytes=64,
    )
    for index, raw in enumerate(("aaaaaa", "bbbbbb", "cc")):
        store.record_dead_letter(
            source_inode=1,
            source_offset=index,
            raw_line=raw,
            error="ValueError",
        )

    rows = _dead_letter_rows(path)
    assert [row["source_offset"] for row in rows] == [1, 2]
    assert store.dead_letter_stats() == {
        "inserted": 3,
        "evicted": 1,
        "retained_count": 2,
        "retained_bytes": 8,
    }


def test_dead_letter_age_limit_is_enforced_transactionally(tmp_path, monkeypatch) -> None:
    now = [1_000.0]
    monkeypatch.setattr("porygon_telemetry.spool.time.time", lambda: now[0])
    store = TelemetryStore(
        str(tmp_path / "telemetry.db"),
        max_events=10,
        dead_letter_retention_seconds=60,
    )
    store.record_dead_letter(
        source_inode=1,
        source_offset=1,
        raw_line="old",
        error="ValueError",
    )
    now[0] = 1_061.0
    store.record_dead_letter(
        source_inode=1,
        source_offset=2,
        raw_line="new",
        error="ValueError",
    )

    rows = _dead_letter_rows(store.path)
    assert [row["source_offset"] for row in rows] == [2]
    assert store.dead_letter_stats()["evicted"] == 1


def test_old_dead_letter_schema_is_upgraded_without_retaining_raw_line(tmp_path) -> None:
    path = tmp_path / "telemetry.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE dead_letters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_inode INTEGER,
            source_offset INTEGER NOT NULL,
            raw_line TEXT NOT NULL,
            error TEXT NOT NULL,
            recorded_at REAL NOT NULL
        );
        INSERT INTO dead_letters(source_inode, source_offset, raw_line, error, recorded_at)
        VALUES (3, 9, 'api_key=legacy-secret', 'JSONDecodeError: invalid', 2000000000);
        """
    )
    connection.commit()
    connection.close()

    store = TelemetryStore(str(path), max_events=10)
    row = _dead_letter_rows(path)[0]
    assert row["raw_line"] == ""
    assert row["raw_sha256"] == hashlib.sha256(b"api_key=legacy-secret").hexdigest()
    assert row["raw_byte_length"] == len(b"api_key=legacy-secret")
    assert "legacy-secret" not in row["excerpt"]
    assert store.dead_letter_count() == 1
