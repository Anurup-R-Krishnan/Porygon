from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

_NA_VALUES = {"", "<NA>", "N/A", "null", "None", None}
_ISO_PATTERN = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d+))?(?P<zone>Z|[+-]\d{2}:?\d{2})$"
)


def _clean(value: Any) -> Any | None:
    if value is None:
        return None
    if isinstance(value, str) and value in _NA_VALUES:
        return None
    return value


def _text(value: Any, max_length: int | None = None) -> str | None:
    value = _clean(value)
    if value is None:
        return None
    rendered = str(value)
    return rendered[:max_length] if max_length else rendered


def _nonnegative_int(value: Any) -> int | None:
    value = _clean(value)
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _event_time(raw_event: dict[str, Any], fields: dict[str, Any]) -> tuple[int, datetime]:
    raw_time = _nonnegative_int(fields.get("evt.rawtime"))
    if raw_time is not None:
        return raw_time, datetime.fromtimestamp(raw_time / 1_000_000_000, tz=timezone.utc)

    rendered = _text(raw_event.get("time"))
    if not rendered:
        raise ValueError("Falco event has neither evt.rawtime nor an ISO8601 time field")

    match = _ISO_PATTERN.match(rendered)
    if not match:
        raise ValueError(f"Unsupported Falco timestamp: {rendered}")

    zone = match.group("zone")
    if zone == "Z":
        zone = "+00:00"
    elif len(zone) == 5 and ":" not in zone:
        zone = zone[:3] + ":" + zone[3:]

    base = datetime.fromisoformat(match.group("base") + zone).astimezone(timezone.utc)
    fraction = (match.group("fraction") or "")[:9].ljust(9, "0")
    time_nano = int(base.timestamp()) * 1_000_000_000 + int(fraction or 0)
    return time_nano, datetime.fromtimestamp(time_nano / 1_000_000_000, tz=timezone.utc)


def _image_ref(fields: dict[str, Any]) -> str | None:
    repository = _text(fields.get("container.image.repository"))
    tag = _text(fields.get("container.image.tag"))
    if repository and tag:
        return f"{repository}:{tag}"
    return repository


def normalize_falco_event(
    raw_event: dict[str, Any],
    *,
    sensor_instance_id: str,
    expected_rule: str,
    reported_docker_host_id: str | None,
) -> dict[str, Any] | None:
    rule_name = _text(raw_event.get("rule"), 255)
    if rule_name != expected_rule:
        return None

    source = _text(raw_event.get("source"), 32) or "syscall"
    if source != "syscall":
        return None

    fields_value = raw_event.get("output_fields") or {}
    if not isinstance(fields_value, dict):
        raise ValueError("Falco output_fields must be a JSON object")
    fields = {str(key): value for key, value in fields_value.items()}

    time_nano, occurred_at = _event_time(raw_event, fields)
    process_pid = _nonnegative_int(fields.get("proc.pid"))
    if process_pid is None:
        raise ValueError("Falco process event is missing proc.pid")

    reported_container_id = _text(fields.get("container.id"), 128)
    if reported_container_id == "host":
        return None

    identity = {
        "sensor_instance_id": sensor_instance_id,
        "time_nano": time_nano,
        "event_number": _nonnegative_int(fields.get("evt.num")),
        "event_type": _text(fields.get("evt.type"), 64) or "execve",
        "container_id": reported_container_id,
        "process_pid": process_pid,
        "process_ppid": _nonnegative_int(fields.get("proc.ppid")),
        "command_line": _text(fields.get("proc.cmdline")),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    event_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    tags_value = raw_event.get("tags") or []
    tags = [str(item)[:128] for item in tags_value if _clean(item) is not None][:64]

    return {
        "event_id": event_id,
        "sensor_instance_id": sensor_instance_id,
        "sensor_hostname": _text(raw_event.get("hostname"), 255),
        "source": "falco",
        "rule_name": rule_name,
        "priority": _text(raw_event.get("priority"), 32) or "Notice",
        "occurred_at": occurred_at.isoformat(),
        "time_nano": time_nano,
        "event_number": _nonnegative_int(fields.get("evt.num")),
        "event_type": _text(fields.get("evt.type"), 64) or "execve",
        "reported_docker_host_id": reported_docker_host_id,
        "reported_container_id": reported_container_id,
        "reported_container_name": _text(fields.get("container.name"), 255),
        "reported_image_ref": _image_ref(fields),
        "process_pid": process_pid,
        "process_ppid": _nonnegative_int(fields.get("proc.ppid")),
        "process_vpid": _nonnegative_int(fields.get("thread.vpid")),
        "process_name": _text(fields.get("proc.name"), 255),
        "executable": _text(fields.get("proc.exepath")),
        "command_line": _text(fields.get("proc.cmdline")),
        "working_directory": _text(fields.get("proc.cwd")),
        "tty": _nonnegative_int(fields.get("proc.tty")),
        "parent_name": _text(fields.get("proc.pname"), 255),
        "parent_executable": _text(fields.get("proc.pexepath")),
        "parent_command_line": _text(fields.get("proc.pcmdline")),
        "user_uid": _nonnegative_int(fields.get("user.uid")),
        "user_name": _text(fields.get("user.name"), 255),
        "group_gid": _nonnegative_int(fields.get("group.gid")),
        "group_name": _text(fields.get("group.name"), 255),
        "tags": tags,
        "output": _text(raw_event.get("output")),
        "output_fields": fields,
        "raw_event": raw_event,
    }
