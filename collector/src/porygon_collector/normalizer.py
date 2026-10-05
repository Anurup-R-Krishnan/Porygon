from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from docker.errors import APIError, ImageNotFound, NotFound

from porygon_collector.event_identity import (
    action_detail,
    canonicalize_action,
    deterministic_event_id,
)
from porygon_collector.spool import OutboxStore


def _canonical_repository(value: str | None) -> str | None:
    if not value:
        return None
    repository = value.split("@", 1)[0]
    final_component = repository.rsplit("/", 1)[-1]
    if ":" in final_component:
        repository = repository.rsplit(":", 1)[0]
    if repository.startswith("docker.io/"):
        repository = repository[len("docker.io/") :]
    if repository.startswith("library/"):
        repository = repository[len("library/") :]
    return repository


def select_primary_repo_digest(image_ref: str | None, repo_digests: list[str]) -> str | None:
    clean = sorted({digest for digest in repo_digests if "@sha256:" in digest})
    if not clean:
        return None

    wanted_repository = _canonical_repository(image_ref)
    if wanted_repository:
        for digest in clean:
            if _canonical_repository(digest) == wanted_repository:
                return digest
    return clean[0]


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _join_command(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        return " ".join(str(part) for part in value)
    return str(value)


def _reduce_networks(network_settings: dict[str, Any]) -> dict[str, Any]:
    reduced: dict[str, Any] = {}
    for name, details in (network_settings.get("Networks") or {}).items():
        reduced[name] = {
            "network_id": details.get("NetworkID"),
            "endpoint_id": details.get("EndpointID"),
            "gateway": details.get("Gateway"),
            "ip_address": details.get("IPAddress"),
            "global_ipv6_address": details.get("GlobalIPv6Address"),
            "aliases": details.get("Aliases") or [],
        }
    return reduced


def _reduce_mounts(mounts: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [
        {
            "type": mount.get("Type"),
            "source": mount.get("Source"),
            "destination": mount.get("Destination"),
            "mode": mount.get("Mode"),
            "rw": mount.get("RW"),
            "propagation": mount.get("Propagation"),
        }
        for mount in (mounts or [])
    ]


def build_container_snapshot(api_client, container_id: str) -> dict[str, Any]:
    container = api_client.inspect_container(container_id)
    config = container.get("Config") or {}
    host_config = container.get("HostConfig") or {}
    state = container.get("State") or {}
    image_id = container.get("Image")
    image_ref = config.get("Image")

    image_details: dict[str, Any]
    try:
        image = api_client.inspect_image(image_id)
        repo_digests = _string_list(image.get("RepoDigests"))
        primary_digest = select_primary_repo_digest(image_ref, repo_digests)
        image_details = {
            "id": image.get("Id") or image_id,
            "repo_digests": repo_digests,
            "repo_tags": _string_list(image.get("RepoTags")),
            "primary_repo_digest": primary_digest,
            "digest_status": "resolved" if primary_digest else "unavailable",
            "os": image.get("Os"),
            "architecture": image.get("Architecture"),
            "created": image.get("Created"),
        }
    except (APIError, ImageNotFound, NotFound):
        image_details = {
            "id": image_id,
            "repo_digests": [],
            "repo_tags": [],
            "primary_repo_digest": None,
            "digest_status": "inspection_failed",
            "os": None,
            "architecture": None,
            "created": None,
        }

    name = (container.get("Name") or "").lstrip("/") or None
    return {
        "container": {
            "id": container.get("Id") or container_id,
            "name": name,
            "created": container.get("Created"),
            "restart_count": container.get("RestartCount"),
            "platform": container.get("Platform"),
        },
        "state": {
            "status": state.get("Status"),
            "running": state.get("Running"),
            "paused": state.get("Paused"),
            "restarting": state.get("Restarting"),
            "oom_killed": state.get("OOMKilled"),
            "dead": state.get("Dead"),
            "pid": state.get("Pid"),
            "exit_code": state.get("ExitCode"),
            "started_at": state.get("StartedAt"),
            "finished_at": state.get("FinishedAt"),
        },
        "config": {
            "image": image_ref,
            "hostname": config.get("Hostname"),
            "user": config.get("User"),
            "working_dir": config.get("WorkingDir"),
            "entrypoint": config.get("Entrypoint"),
            "command": config.get("Cmd"),
            "labels": config.get("Labels") or {},
            # Environment variables are intentionally excluded because they often contain secrets.
        },
        "host_config": {
            "privileged": host_config.get("Privileged"),
            "readonly_rootfs": host_config.get("ReadonlyRootfs"),
            "network_mode": host_config.get("NetworkMode"),
            "pid_mode": host_config.get("PidMode"),
            "ipc_mode": host_config.get("IpcMode"),
            "uts_mode": host_config.get("UTSMode"),
            "userns_mode": host_config.get("UsernsMode"),
            "cap_add": host_config.get("CapAdd") or [],
            "cap_drop": host_config.get("CapDrop") or [],
            "security_opt": host_config.get("SecurityOpt") or [],
            "devices": host_config.get("Devices") or [],
        },
        "networks": _reduce_networks(container.get("NetworkSettings") or {}),
        "mounts": _reduce_mounts(container.get("Mounts")),
        "image": image_details,
    }


def _container_id_from_event(event_type: str, actor_id: str, attributes: dict[str, Any]) -> str | None:
    if event_type == "container":
        return actor_id or None
    if event_type == "network":
        for key in ("container", "containerID", "container_id"):
            value = attributes.get(key)
            if value:
                return str(value)
    return None


def _event_time(raw_event: dict[str, Any]) -> tuple[int, datetime]:
    time_nano = int(raw_event.get("timeNano") or raw_event.get("TimeNano") or 0)
    if time_nano <= 0:
        seconds = int(raw_event.get("time") or raw_event.get("Time") or 0)
        time_nano = seconds * 1_000_000_000
    occurred_at = datetime.fromtimestamp(time_nano / 1_000_000_000, tz=timezone.utc)
    return time_nano, occurred_at


def normalize_event(
    api_client,
    store: OutboxStore,
    docker_host_id: str,
    raw_event: dict[str, Any],
) -> dict[str, Any]:
    event_type = str(raw_event.get("Type") or raw_event.get("type") or "unknown").lower()
    raw_action = (
        raw_event.get("Action")
        or raw_event.get("action")
        or raw_event.get("status")
        or "unknown"
    )
    action = canonicalize_action(raw_action)
    scope_value = raw_event.get("scope") or raw_event.get("Scope")
    scope = str(scope_value) if scope_value is not None else None

    actor = raw_event.get("Actor") or raw_event.get("actor") or {}
    actor_id = str(actor.get("ID") or actor.get("Id") or raw_event.get("id") or "unknown")
    raw_attributes = actor.get("Attributes") or actor.get("attributes") or {}
    attributes = {str(key): str(value) for key, value in raw_attributes.items()}
    time_nano, occurred_at = _event_time(raw_event)

    container_id = _container_id_from_event(event_type, actor_id, attributes)
    snapshot: dict[str, Any] = {}
    if container_id:
        try:
            snapshot = build_container_snapshot(api_client, container_id)
            store.cache_container(container_id, snapshot)
        except (APIError, NotFound):
            snapshot = store.get_cached_container(container_id) or {}

    container_info = snapshot.get("container", {})
    config = snapshot.get("config", {})
    image = snapshot.get("image", {})

    container_name = container_info.get("name") or attributes.get("name")
    image_id = image.get("id")
    image_ref = config.get("image") or attributes.get("image") or attributes.get("from")
    image_digest = image.get("primary_repo_digest")
    if container_id:
        image_digest_status = image.get("digest_status") or "inspection_failed"
    else:
        image_digest_status = "not_applicable"

    command = attributes.get("execCommand") or attributes.get("command")
    if not command and action in {"exec_create", "exec_start"}:
        command = action_detail(raw_action)
    if not command:
        command = _join_command(config.get("command"))

    event_id = deterministic_event_id(
        docker_host_id=docker_host_id,
        event_type=event_type,
        action=action,
        scope=scope,
        actor_id=actor_id,
        time_nano=time_nano,
        attributes=attributes,
    )

    return {
        "event_id": event_id,
        "docker_host_id": docker_host_id,
        "event_type": event_type,
        "action": action,
        "scope": scope,
        "actor_id": actor_id,
        "occurred_at": occurred_at.isoformat(),
        "time_nano": time_nano,
        "container_id": container_id,
        "container_name": container_name,
        "image_id": image_id,
        "image_ref": image_ref,
        "image_digest": image_digest,
        "image_digest_status": image_digest_status,
        "command": command,
        "container_user": config.get("user"),
        "attributes": attributes,
        "container_snapshot": snapshot,
        "raw_event": raw_event,
    }
