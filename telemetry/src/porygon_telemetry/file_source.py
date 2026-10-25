from __future__ import annotations

import json
import logging
import sqlite3
import time
import threading
from datetime import datetime, timezone
from pathlib import Path

from porygon_telemetry.config import Settings
from porygon_telemetry.normalizer import normalize_falco_event
from porygon_telemetry.spool import SpoolFullError, TelemetryStore
from porygon_telemetry.state import TelemetryState

logger = logging.getLogger("porygon.telemetry.falco-file")


class FalcoFileSource:
    def __init__(self, settings: Settings, state: TelemetryState, store: TelemetryStore) -> None:
        self.settings = settings
        self.state = state
        self.store = store
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run,
            name="porygon-falco-file-source",
            daemon=True,
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)

    def _run(self) -> None:
        active_path = Path(self.settings.falco_log_path)
        draining_path = active_path.with_name(active_path.name + ".draining")
        self.state.set(source_running=True)
        try:
            while not self.stop_event.is_set():
                # Drain a renamed file before following the active filename. The
                # inode/checkpoint survive restarts, including between rename and
                # final draining. Falco keep_alive=false reopens on every write.
                path = draining_path if draining_path.exists() else active_path
                try:
                    stat = path.stat()
                except FileNotFoundError:
                    self.state.set(source_file_available=False, source_last_error=None)
                    self.stop_event.wait(self.settings.falco_poll_seconds)
                    continue
                except OSError as exc:
                    self.state.set(
                        source_file_available=False,
                        source_last_error=f"{exc.__class__.__name__}: {exc}",
                    )
                    self.stop_event.wait(self.settings.falco_poll_seconds)
                    continue

                inode = int(stat.st_ino)
                stored_inode, stored_offset = self.store.get_file_cursor()
                offset = stored_offset if stored_inode == inode and stat.st_size >= stored_offset else 0
                self.state.set(
                    source_file_available=True,
                    source_inode=inode,
                    source_offset=offset,
                    source_last_error=None,
                )

                try:
                    with path.open("rb") as stream:
                        stream.seek(offset)
                        while not self.stop_event.is_set():
                            batch_start = stream.tell()
                            events = []
                            ignored = 0
                            consumed = 0
                            # One durable transaction per bounded group of source lines.
                            # Nothing advances the checkpoint until all valid events commit.
                            for _ in range(min(100, self.settings.spool_max_events)):
                                line_offset = stream.tell()
                                line = stream.readline(self.settings.falco_max_line_bytes + 1)
                                if not line:
                                    break
                                if not line.endswith(b"\n") and len(line) <= self.settings.falco_max_line_bytes:
                                    stream.seek(line_offset)
                                    break
                                consumed += 1
                                raw_text = line.decode("utf-8", errors="replace").strip()
                                try:
                                    if len(line) > self.settings.falco_max_line_bytes:
                                        # Discard the remainder as one oversized record rather
                                        # than treating its chunks as independent JSON events.
                                        while line and not line.endswith(b"\n"):
                                            line = stream.readline(self.settings.falco_max_line_bytes + 1)
                                        raise ValueError("Falco JSON line exceeded configured maximum")
                                    raw_event = json.loads(raw_text)
                                    if not isinstance(raw_event, dict):
                                        raise ValueError("Falco event must be a JSON object")
                                    event = normalize_falco_event(
                                        raw_event,
                                        sensor_instance_id=self.settings.telemetry_instance_id,
                                        expected_rule=self.settings.falco_expected_rule,
                                        reported_docker_host_id=self.settings.reported_docker_host_id,
                                    )
                                    if event is None:
                                        ignored += 1
                                    else:
                                        events.append(event)
                                except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                                    self.store.record_dead_letter(
                                        source_inode=inode, source_offset=line_offset,
                                        raw_line=raw_text, error=f"{exc.__class__.__name__}: {exc}",
                                    )
                                    self.state.increment(malformed_lines=1)
                            if not consumed:
                                break
                            new_offset = stream.tell()
                            try:
                                inserted, depth = self.store.enqueue_batch(events, inode=inode, offset=new_offset)
                            except SpoolFullError as exc:
                                self.state.increment(spool_overflow_count=1)
                                self.state.set(source_last_error=str(exc))
                                stream.seek(batch_start)
                                self.stop_event.wait(1.0)
                                break
                            self.state.increment(events_enqueued=inserted,
                                                 duplicates_ignored=len(events)-inserted,
                                                 ignored_non_porygon_events=ignored)
                            self.state.set(
                                source_offset=new_offset,
                                source_last_read_at=datetime.now(timezone.utc),
                                source_last_error=None, queue_depth=depth,
                            )
                    self._rotate_consumed_file(active_path, draining_path, path)
                except (OSError, sqlite3.Error) as exc:
                    self.state.set(source_last_error=f"{exc.__class__.__name__}: {exc}")
                    logger.warning("Falco file read failed: %s", exc.__class__.__name__)

                self.stop_event.wait(self.settings.falco_poll_seconds)
        finally:
            self.state.set(source_running=False)

    def _rotate_consumed_file(self, active: Path, draining: Path, consumed: Path) -> None:
        """Reclaim only bytes already committed to the durable outbox.

        An in-flight writer may still hold the renamed inode. Keep it until it
        has been quiet for two seconds and drain any late append first.
        """
        stat = consumed.stat()
        inode, offset = self.store.get_file_cursor()
        if inode != stat.st_ino or offset < stat.st_size:
            return
        if consumed == draining:
            if time.time() - stat.st_mtime >= 2.0:
                draining.unlink()
        elif stat.st_size >= self.settings.falco_rotate_bytes and not draining.exists():
            active.rename(draining)
            active.touch(mode=0o660, exist_ok=True)
