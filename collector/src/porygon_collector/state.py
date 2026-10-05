from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock


@dataclass
class CollectorState:
    started_at: datetime
    backend_last_success_at: datetime | None = None
    backend_last_error: str | None = None
    backend_consecutive_failures: int = 0

    docker_connected: bool = False
    event_stream_connected: bool = False
    effective_docker_host_id: str | None = None
    docker_last_success_at: datetime | None = None
    docker_last_error: str | None = None
    last_event_at: datetime | None = None

    delivery_last_success_at: datetime | None = None
    delivery_last_error: str | None = None
    queue_depth: int = 0
    events_enqueued: int = 0
    events_delivered: int = 0
    duplicate_events_ignored: int = 0
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
                "docker_connected": self.docker_connected,
                "event_stream_connected": self.event_stream_connected,
                "effective_docker_host_id": self.effective_docker_host_id,
                "docker_last_success_at": self.docker_last_success_at,
                "docker_last_error": self.docker_last_error,
                "last_event_at": self.last_event_at,
                "delivery_last_success_at": self.delivery_last_success_at,
                "delivery_last_error": self.delivery_last_error,
                "queue_depth": self.queue_depth,
                "events_enqueued": self.events_enqueued,
                "events_delivered": self.events_delivered,
                "duplicate_events_ignored": self.duplicate_events_ignored,
                "spool_overflow_count": self.spool_overflow_count,
            }
