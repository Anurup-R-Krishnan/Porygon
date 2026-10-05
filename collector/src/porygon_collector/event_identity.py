from __future__ import annotations

import hashlib
import json
from typing import Any


def canonicalize_action(value: object) -> str:
    """Return the bounded Docker action category, excluding free-form detail."""
    action = str(value or "unknown").strip().lower()
    category = action.split(":", 1)[0].strip() or "unknown"
    return category[:64]


def action_detail(value: object) -> str | None:
    """Return Docker's optional action detail without changing the raw event."""
    action = str(value or "")
    _, separator, detail = action.partition(":")
    if not separator:
        return None
    clean = detail.strip()
    return clean or None


def deterministic_event_id(
    docker_host_id: str,
    event_type: str,
    action: str,
    scope: str | None,
    actor_id: str,
    time_nano: int,
    attributes: dict[str, Any],
) -> str:
    identity = {
        "docker_host_id": docker_host_id,
        "event_type": event_type,
        "action": action,
        "scope": scope,
        "actor_id": actor_id,
        "time_nano": time_nano,
        "attributes": attributes,
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
