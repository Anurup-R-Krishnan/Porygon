from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

import docker
from docker.errors import APIError, DockerException

from porygon_collector.config import Settings
from porygon_collector.normalizer import build_container_snapshot, normalize_event
from porygon_collector.spool import OutboxStore, SpoolFullError
from porygon_collector.state import CollectorState

logger = logging.getLogger("porygon.collector.docker")


class DockerEventSource:
    def __init__(self, settings: Settings, state: CollectorState, store: OutboxStore) -> None:
        self.settings = settings
        self.state = state
        self.store = store
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="porygon-docker-events",
            daemon=True,
        )
        self.client: docker.APIClient | None = None

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.client is not None:
            try:
                self.client.close()
            except Exception:
                pass
        self.thread.join(timeout=5)

    def _connect(self) -> tuple[docker.APIClient, str]:
        client = docker.APIClient(
            base_url=self.settings.docker_base_url,
            version="auto",
            timeout=max(
                self.settings.docker_timeout_seconds,
                self.settings.docker_event_window_seconds + 5,
            ),
        )
        client.ping()
        info = client.info()
        daemon_id = str(info.get("ID") or "unknown-docker-daemon")
        host_id = daemon_id if self.settings.docker_host_id == "auto" else self.settings.docker_host_id
        self.state.set(
            docker_connected=True,
            effective_docker_host_id=host_id,
            docker_last_success_at=datetime.now(timezone.utc),
            docker_last_error=None,
        )
        return client, host_id

    def _warm_container_cache(self, client: docker.APIClient) -> None:
        for summary in client.containers(all=True):
            container_id = summary.get("Id")
            if not container_id:
                continue
            try:
                snapshot = build_container_snapshot(client, str(container_id))
                self.store.cache_container(str(container_id), snapshot)
            except (APIError, DockerException):
                logger.debug("Could not cache container %s", str(container_id)[:12])

    def _since_seconds(self) -> int:
        cursor = self.store.get_cursor()
        if cursor is None:
            return max(0, int(time.time()) - self.settings.docker_event_overlap_seconds)
        cursor_seconds = cursor // 1_000_000_000
        return max(0, cursor_seconds - self.settings.docker_event_overlap_seconds)

    def _run(self) -> None:
        reconnect_delay = 1
        while not self.stop_event.is_set():
            try:
                self.client, host_id = self._connect()
                self._warm_container_cache(self.client)
                reconnect_delay = 1

                while not self.stop_event.is_set():
                    since = self._since_seconds()
                    until = int(time.time()) + self.settings.docker_event_window_seconds
                    self.state.set(event_stream_connected=True)
                    stream = self.client.events(
                        since=since,
                        until=until,
                        decode=True,
                        filters={"type": ["container", "network"]},
                    )
                    for raw_event in stream:
                        if self.stop_event.is_set():
                            break
                        event = normalize_event(self.client, self.store, host_id, raw_event)
                        try:
                            inserted = self.store.enqueue(event)
                        except SpoolFullError as exc:
                            self.state.increment(spool_overflow_count=1)
                            self.state.set(docker_last_error=str(exc))
                            logger.error("%s", exc)
                            time.sleep(1)
                            continue

                        self.store.update_cursor(int(event["time_nano"]))
                        self.state.set(
                            docker_last_success_at=datetime.now(timezone.utc),
                            last_event_at=datetime.now(timezone.utc),
                            queue_depth=self.store.count(),
                            docker_last_error=None,
                        )
                        if inserted:
                            self.state.increment(events_enqueued=1)
                        else:
                            self.state.increment(duplicate_events_ignored=1)
                    # A normally completed bounded stream has delivered all matching events
                    # through `until`. Advance the durable cursor even when the window was quiet,
                    # while the overlap still protects second-level timestamp boundaries.
                    self.store.update_cursor(until * 1_000_000_000)
                    self.state.set(
                        docker_last_success_at=datetime.now(timezone.utc),
                        docker_last_error=None,
                    )

            except (DockerException, OSError, ValueError) as exc:
                self.state.set(
                    docker_connected=False,
                    event_stream_connected=False,
                    docker_last_error=f"{exc.__class__.__name__}: {exc}",
                )
                logger.warning(
                    "Docker event source unavailable; retrying in %ss: %s",
                    reconnect_delay,
                    exc.__class__.__name__,
                )
                self.stop_event.wait(reconnect_delay)
                reconnect_delay = min(
                    self.settings.docker_reconnect_max_seconds,
                    reconnect_delay * 2,
                )
            finally:
                self.state.set(event_stream_connected=False)
                if self.client is not None:
                    try:
                        self.client.close()
                    except Exception:
                        pass
                    self.client = None
