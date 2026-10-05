from __future__ import annotations

import json
import logging
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
        path = Path(self.settings.falco_log_path)
        self.state.set(source_running=True)
        try:
            while not self.stop_event.is_set():
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
                            line_offset = stream.tell()
                            line = stream.readline(self.settings.falco_max_line_bytes + 1)
                            if not line:
                                break
                            if len(line) > self.settings.falco_max_line_bytes:
                                error = (
                                    "Falco JSON line exceeded configured maximum of "
                                    f"{self.settings.falco_max_line_bytes} bytes"
                                )
                                self.store.record_dead_letter(
                                    source_inode=inode,
                                    source_offset=line_offset,
                                    raw_line=line.decode("utf-8", errors="replace"),
                                    error=error,
                                )
                                self.store.update_file_cursor(inode, stream.tell())
                                self.state.increment(malformed_lines=1)
                                continue
                            if not line.endswith(b"\n"):
                                stream.seek(line_offset)
                                break

                            raw_text = line.decode("utf-8", errors="replace").strip()
                            try:
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
                                    self.state.increment(ignored_non_porygon_events=1)
                                else:
                                    inserted = self.store.enqueue(event)
                                    if inserted:
                                        self.state.increment(events_enqueued=1)
                                    else:
                                        self.state.increment(duplicates_ignored=1)
                            except SpoolFullError as exc:
                                self.state.increment(spool_overflow_count=1)
                                self.state.set(source_last_error=str(exc))
                                stream.seek(line_offset)
                                self.stop_event.wait(1.0)
                                break
                            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                                self.store.record_dead_letter(
                                    source_inode=inode,
                                    source_offset=line_offset,
                                    raw_line=raw_text,
                                    error=f"{exc.__class__.__name__}: {exc}",
                                )
                                self.state.increment(malformed_lines=1)

                            new_offset = stream.tell()
                            self.store.update_file_cursor(inode, new_offset)
                            self.state.set(
                                source_offset=new_offset,
                                source_last_read_at=datetime.now(timezone.utc),
                                source_last_error=None,
                                queue_depth=self.store.count(),
                            )
                except OSError as exc:
                    self.state.set(source_last_error=f"{exc.__class__.__name__}: {exc}")
                    logger.warning("Falco file read failed: %s", exc.__class__.__name__)

                self.stop_event.wait(self.settings.falco_poll_seconds)
        finally:
            self.state.set(source_running=False)
