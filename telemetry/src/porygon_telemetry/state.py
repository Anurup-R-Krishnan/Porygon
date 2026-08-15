from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock


@dataclass
class TelemetryState:
    started_at: datetime
    backend_last_success_at: datetime | None = None
    backend_last_error: str | None = None
    backend_consecutive_failures: int = 0

    source_running: bool = False
    source_file_available: bool = False
    source_inode: int | None = None
    source_offset: int = 0
    source_last_read_at: datetime | None = None
    source_last_error: str | None = None

    delivery_last_success_at: datetime | None = None
    delivery_last_error: str | None = None
    queue_depth: int = 0
    events_enqueued: int = 0
    events_delivered: int = 0
    duplicates_ignored: int = 0
    ignored_non_porygon_events: int = 0
    malformed_lines: int = 0
    spool_overflow_count: int = 0

    _lock: Lock = field(default_factory=Lock, repr=False)

    def set(self, **values) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, key, value)

    def increment(self, **values: int) -> None:
        with self._lock:
            for key, value in values.items():
                setattr(self, key, getattr(self, key) + value)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "started_at": self.started_at,
                "backend_last_success_at": self.backend_last_success_at,
                "backend_last_error": self.backend_last_error,
                "backend_consecutive_failures": self.backend_consecutive_failures,
                "source_running": self.source_running,
                "source_file_available": self.source_file_available,
                "source_inode": self.source_inode,
                "source_offset": self.source_offset,
                "source_last_read_at": self.source_last_read_at,
                "source_last_error": self.source_last_error,
                "delivery_last_success_at": self.delivery_last_success_at,
                "delivery_last_error": self.delivery_last_error,
                "queue_depth": self.queue_depth,
                "events_enqueued": self.events_enqueued,
                "events_delivered": self.events_delivered,
                "duplicates_ignored": self.duplicates_ignored,
                "ignored_non_porygon_events": self.ignored_non_porygon_events,
                "malformed_lines": self.malformed_lines,
                "spool_overflow_count": self.spool_overflow_count,
            }
