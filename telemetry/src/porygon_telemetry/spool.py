from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class SpoolFullError(RuntimeError):
    pass


class TelemetryStore:
    def __init__(self, path: str, max_events: int) -> None:
        self.path = Path(path)
        self.max_events = max_events
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS outbox (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    enqueued_at REAL NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS ix_outbox_due
                    ON outbox(next_attempt_at, enqueued_at);

                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS dead_letters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_inode INTEGER,
                    source_offset INTEGER NOT NULL,
                    raw_line TEXT NOT NULL,
                    error TEXT NOT NULL,
                    recorded_at REAL NOT NULL
                );
                """
            )

    def enqueue(self, payload: dict[str, Any]) -> bool:
        event_id = str(payload["event_id"])
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT 1 FROM outbox WHERE event_id = ?",
                (event_id,),
            ).fetchone()
            if existing:
                return False

            count = connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            if count >= self.max_events:
                raise SpoolFullError(
                    f"Durable process outbox reached configured limit of {self.max_events} events"
                )

            connection.execute(
                """
                INSERT INTO outbox(event_id, payload, enqueued_at, attempts, next_attempt_at)
                VALUES (?, ?, ?, 0, 0)
                """,
                (event_id, serialized, time.time()),
            )
        return True

    def fetch_due(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload
                FROM outbox
                WHERE next_attempt_at <= ?
                ORDER BY enqueued_at, event_id
                LIMIT ?
                """,
                (time.time(), limit),
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def acknowledge(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as connection:
            connection.execute(
                f"DELETE FROM outbox WHERE event_id IN ({placeholders})",
                event_ids,
            )

    def mark_failed(self, event_ids: list[str], error: str, max_retry_seconds: int) -> None:
        if not event_ids:
            return
        now = time.time()
        with self._connect() as connection:
            for event_id in event_ids:
                row = connection.execute(
                    "SELECT attempts FROM outbox WHERE event_id = ?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    continue
                attempts = int(row["attempts"]) + 1
                delay = min(max_retry_seconds, 2 ** min(attempts, 10))
                connection.execute(
                    """
                    UPDATE outbox
                    SET attempts = ?, next_attempt_at = ?, last_error = ?
                    WHERE event_id = ?
                    """,
                    (attempts, now + delay, error[:1000], event_id),
                )

    def count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM outbox").fetchone()[0])

    def set_metadata(self, key: str, value: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_metadata(self, key: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = ?",
                (key,),
            ).fetchone()
        return str(row["value"]) if row else None

    def get_file_cursor(self) -> tuple[int | None, int]:
        inode = self.get_metadata("falco_file_inode")
        offset = self.get_metadata("falco_file_offset")
        return (int(inode) if inode is not None else None, int(offset or 0))

    def update_file_cursor(self, inode: int, offset: int) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES ('falco_file_inode', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(inode),),
            )
            connection.execute(
                """
                INSERT INTO metadata(key, value) VALUES ('falco_file_offset', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(offset),),
            )

    def record_dead_letter(
        self,
        *,
        source_inode: int | None,
        source_offset: int,
        raw_line: str,
        error: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO dead_letters(source_inode, source_offset, raw_line, error, recorded_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (source_inode, source_offset, raw_line[:1_000_000], error[:1000], time.time()),
            )

    def dead_letter_count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0])
