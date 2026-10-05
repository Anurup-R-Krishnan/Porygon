from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any


class SpoolFullError(RuntimeError):
    pass


_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(token|password|passwd|secret|api[_-]?key|authorization)"
    r"\s*=\s*(?:\"[^\"]*\"|'[^']*'|\S+)"
)
_SECRET_ARGUMENT = re.compile(
    r"(?i)(--(?:token|password|passwd|secret|api[_-]?key|authorization))"
    r"(?:=|\s+)\S+"
)
_SECRET_JSON = re.compile(
    r"(?i)([\"'](?:token|password|passwd|secret|api[_-]?key|authorization)[\"']"
    r"\s*:\s*)(?:\"[^\"]*\"|'[^']*'|[^,\s}]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+\S+")


def _redact(value: str) -> str:
    value = _SECRET_JSON.sub(lambda match: f'{match.group(1)}"<redacted>"', value)
    value = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", value)
    value = _SECRET_ARGUMENT.sub(lambda match: f"{match.group(1)}=<redacted>", value)
    return _BEARER_TOKEN.sub("Bearer <redacted>", value)


def _truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")[:max_bytes]
    return encoded.decode("utf-8", errors="ignore")


def _error_parts(error: str) -> tuple[str, str]:
    error_class, separator, message = error.partition(":")
    if not separator:
        return error[:128], ""
    return error_class[:128], _truncate_utf8(_redact(message.strip()), 512)


class TelemetryStore:
    def __init__(
        self,
        path: str,
        max_events: int,
        *,
        dead_letter_max_records: int = 1000,
        dead_letter_max_total_bytes: int = 1_048_576,
        dead_letter_excerpt_bytes: int = 512,
        dead_letter_retention_seconds: int = 604_800,
    ) -> None:
        self.path = Path(path)
        self.max_events = max_events
        self.dead_letter_max_records = dead_letter_max_records
        self.dead_letter_max_total_bytes = dead_letter_max_total_bytes
        self.dead_letter_excerpt_bytes = dead_letter_excerpt_bytes
        self.dead_letter_retention_seconds = dead_letter_retention_seconds
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
                CREATE INDEX IF NOT EXISTS ix_dead_letters_recorded_at
                    ON dead_letters(recorded_at, id);
                """
            )
            self._upgrade_dead_letters(connection)
            self._prune_dead_letters(connection, time.time())

    def _upgrade_dead_letters(self, connection: sqlite3.Connection) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(dead_letters)").fetchall()
        }
        additions = {
            "raw_sha256": "TEXT NOT NULL DEFAULT ''",
            "raw_byte_length": "INTEGER NOT NULL DEFAULT 0",
            "excerpt": "TEXT NOT NULL DEFAULT ''",
            "error_class": "TEXT NOT NULL DEFAULT ''",
            "error_message": "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(f"ALTER TABLE dead_letters ADD COLUMN {name} {definition}")

        rows = connection.execute(
            """
            SELECT id, raw_line, error, raw_sha256
            FROM dead_letters
            WHERE raw_line != '' OR raw_sha256 = ''
            """
        ).fetchall()
        for row in rows:
            raw_line = str(row["raw_line"])
            raw_bytes = raw_line.encode("utf-8")
            error_class, error_message = _error_parts(str(row["error"]))
            excerpt = _truncate_utf8(_redact(raw_line), self.dead_letter_excerpt_bytes)
            connection.execute(
                """
                UPDATE dead_letters
                SET raw_line = '', raw_sha256 = ?, raw_byte_length = ?, excerpt = ?,
                    error_class = ?, error_message = ?
                WHERE id = ?
                """,
                (
                    hashlib.sha256(raw_bytes).hexdigest(),
                    len(raw_bytes),
                    excerpt,
                    error_class,
                    error_message,
                    int(row["id"]),
                ),
            )

    @staticmethod
    def _increment_metadata(
        connection: sqlite3.Connection,
        key: str,
        amount: int,
    ) -> None:
        if amount <= 0:
            return
        connection.execute(
            """
            INSERT INTO metadata(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE
            SET value = CAST(metadata.value AS INTEGER) + CAST(excluded.value AS INTEGER)
            """,
            (key, str(amount)),
        )

    def _prune_dead_letters(self, connection: sqlite3.Connection, now: float) -> None:
        before = int(connection.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0])
        connection.execute(
            "DELETE FROM dead_letters WHERE recorded_at < ?",
            (now - self.dead_letter_retention_seconds,),
        )

        count = int(connection.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0])
        excess = max(0, count - self.dead_letter_max_records)
        if excess:
            connection.execute(
                """
                DELETE FROM dead_letters
                WHERE id IN (
                    SELECT id FROM dead_letters ORDER BY recorded_at, id LIMIT ?
                )
                """,
                (excess,),
            )

        rows = connection.execute(
            """
            SELECT id, length(CAST(excerpt AS BLOB)) AS excerpt_bytes
            FROM dead_letters ORDER BY recorded_at, id
            """
        ).fetchall()
        total_bytes = sum(int(row["excerpt_bytes"] or 0) for row in rows)
        delete_ids: list[int] = []
        for row in rows:
            if total_bytes <= self.dead_letter_max_total_bytes:
                break
            delete_ids.append(int(row["id"]))
            total_bytes -= int(row["excerpt_bytes"] or 0)
        if delete_ids:
            placeholders = ",".join("?" for _ in delete_ids)
            connection.execute(
                f"DELETE FROM dead_letters WHERE id IN ({placeholders})",
                delete_ids,
            )

        after = int(connection.execute("SELECT COUNT(*) FROM dead_letters").fetchone()[0])
        self._increment_metadata(connection, "dead_letters_evicted", before - after)

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
        raw_bytes = raw_line.encode("utf-8")
        excerpt = _truncate_utf8(_redact(raw_line), self.dead_letter_excerpt_bytes)
        error_class, error_message = _error_parts(error)
        now = time.time()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO dead_letters(
                    source_inode, source_offset, raw_line, error, recorded_at,
                    raw_sha256, raw_byte_length, excerpt, error_class, error_message
                )
                VALUES (?, ?, '', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source_inode,
                    source_offset,
                    error[:1000],
                    now,
                    hashlib.sha256(raw_bytes).hexdigest(),
                    len(raw_bytes),
                    excerpt,
                    error_class,
                    error_message,
                ),
            )
            self._increment_metadata(connection, "dead_letters_inserted", 1)
            self._prune_dead_letters(connection, now)

    def dead_letter_count(self) -> int:
        return int(self.dead_letter_stats()["retained_count"])

    def dead_letter_stats(self) -> dict[str, int]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS retained_count,
                       COALESCE(SUM(length(CAST(excerpt AS BLOB))), 0) AS retained_bytes
                FROM dead_letters
                """
            ).fetchone()
            inserted = connection.execute(
                "SELECT value FROM metadata WHERE key = 'dead_letters_inserted'"
            ).fetchone()
            evicted = connection.execute(
                "SELECT value FROM metadata WHERE key = 'dead_letters_evicted'"
            ).fetchone()
        return {
            "inserted": int(inserted["value"]) if inserted else 0,
            "evicted": int(evicted["value"]) if evicted else 0,
            "retained_count": int(row["retained_count"]),
            "retained_bytes": int(row["retained_bytes"]),
        }
