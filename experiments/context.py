"""Runtime-context fingerprint defined by docs/PROFILE_SCOPE_EXPERIMENT_V1.md.

The fingerprint is the digest-plus-context arm's identity input. It is derived
only from configuration known before workload execution, never from runtime
counters, and never from environment values or literal argument values.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from experiments.artifacts import sha256_json

SCHEMA_VERSION = "porygon.runtime-context.v1"
MISSING = "missing"
_SECRET_MARKERS = ("password", "passwd", "token", "secret", "credential", "apikey", "api-key")
# "key" alone would swallow benign flags such as --keyspace; match it only as a whole word.
_SECRET_WORDS = ("key", "pass")


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _is_secret_flag(name: str) -> bool:
    lowered = name.lstrip("-").lower()
    return any(marker in lowered for marker in _SECRET_MARKERS) or lowered in _SECRET_WORDS


def _classify_value(token: str) -> str:
    if "://" in token:
        return "<url>"
    if token.startswith(("/", "./", "../")):
        return "<path>"
    try:
        int(token)
    except ValueError:
        return "<positional>"
    return "<integer>"


def argv_shape(argv: list[str] | None) -> list[str] | str:
    """Reduce an argv list to executable basename, flag names, and value classes."""
    if argv is None:
        return MISSING
    shape: list[str] = []
    pending_secret = False
    pending_flag = False
    for index, raw in enumerate(argv):
        token = _nfc(str(raw))
        if index == 0:
            shape.append("exe:" + token.rsplit("/", 1)[-1])
            continue
        if token.startswith("-"):
            name, _, inline = token.partition("=")
            if _is_secret_flag(name):
                shape.append("flag:<secret>")
                pending_secret, pending_flag = not inline, False
                if inline:
                    shape.append("<secret-value>")
            else:
                shape.append("flag:" + name.lower())
                pending_flag, pending_secret = not inline, False
                if inline:
                    shape.append("<flag-value>")
            continue
        if pending_secret:
            shape.append("<secret-value>")
        elif pending_flag:
            shape.append("<flag-value>")
        else:
            shape.append(_classify_value(token))
        pending_secret = pending_flag = False
    return shape


def _user_class(user: Any) -> str:
    if user is None or user == "":
        return MISSING
    text = str(user).split(":", 1)[0].strip().lower()
    return "root" if text in ("0", "root") else "nonroot"


def _tristate(value: Any) -> Any:
    return value if isinstance(value, bool) else MISSING


def normalise_network_mode(value: Any) -> str:
    """Reduce a network mode to its security-relevant class.

    A user-defined network's *name* is an ephemeral deployment detail — an experiment
    run creates a fresh one per run — while the spec excludes container IDs and names
    from the identity. Keeping the literal name would give two identical deployments
    two different context identities, so every stratum would stay below its minimum
    run count and return `insufficient_profile` forever. What is security-relevant is
    the class: host networking, no networking, a shared container namespace, the
    default bridge, or an isolated user-defined network.
    """
    if value is None or value == "":
        return MISSING
    text = _nfc(str(value)).strip().lower()
    if text in ("host", "none"):
        return text
    if text in ("bridge", "default"):
        return "bridge"
    if text.startswith("container:"):
        return "container"
    return "user-defined"


def _capabilities(host_config: dict[str, Any]) -> dict[str, Any]:
    # Docker reports capabilities with and without the CAP_ prefix depending on version and
    # on how the flag was written. Stripping it keeps one intent on one identity.
    result = {}
    for field, key in (("CapAdd", "add"), ("CapDrop", "drop")):
        raw = host_config.get(field)
        result[key] = (
            []
            if raw is None
            else sorted({_nfc(str(item)).upper().removeprefix("CAP_") for item in raw})
        )
    return result


def _devices(host_config: dict[str, Any]) -> list[dict[str, Any]] | str:
    raw = host_config.get("Devices")
    if raw is None:
        return []
    devices = [
        {
            "destination": _nfc(str(item.get("PathInContainer", MISSING))),
            "permissions": _nfc(str(item.get("CgroupPermissions", MISSING))).lower(),
        }
        for item in raw
    ]
    return sorted(devices, key=lambda item: (item["destination"], item["permissions"]))


def _ports(config: dict[str, Any], host_config: dict[str, Any]) -> list[dict[str, Any]]:
    exposed = config.get("ExposedPorts") or {}
    bindings = host_config.get("PortBindings") or {}
    ports = []
    for spec in sorted(set(exposed) | set(bindings)):
        port, _, protocol = _nfc(spec).partition("/")
        bound = bindings.get(spec) or []
        first = bound[0] if bound else None
        if first is None:
            binding_scope, host_port_mode = MISSING, "none"
        else:
            host_ip = str(first.get("HostIp", "") or "")
            host_port = str(first.get("HostPort", "") or "")
            if host_ip in ("", "0.0.0.0", "::"):
                binding_scope = "wildcard"
            elif host_ip in ("127.0.0.1", "::1"):
                binding_scope = "loopback"
            else:
                binding_scope = "specific"
            host_port_mode = "fixed" if host_port else "ephemeral"
        ports.append(
            {
                "container_port": int(port) if port.isdigit() else MISSING,
                "protocol": (protocol or "tcp").lower(),
                "binding_scope": binding_scope,
                "host_port_mode": host_port_mode,
            }
        )
    return sorted(ports, key=lambda item: (str(item["container_port"]), item["protocol"]))


def _mounts(inspection: dict[str, Any]) -> list[dict[str, Any]] | str:
    raw = inspection.get("Mounts")
    if raw is None:
        return MISSING
    mounts = [
        {
            "destination": _nfc(str(item.get("Destination", MISSING))),
            "type": _nfc(str(item.get("Type", MISSING))).lower(),
            "read_only": not item["RW"] if isinstance(item.get("RW"), bool) else MISSING,
        }
        for item in raw
    ]
    # `docker inspect` omits tmpfs from .Mounts, but a writable tmpfs at a given destination
    # is a security-relevant part of the runtime context, so it is folded in here.
    for destination in (inspection.get("HostConfig") or {}).get("Tmpfs") or {}:
        mounts.append(
            {"destination": _nfc(str(destination)), "type": "tmpfs", "read_only": False}
        )
    return sorted(mounts, key=lambda item: (item["destination"], item["type"]))


def runtime_context(inspection: dict[str, Any]) -> dict[str, Any]:
    """Build the canonical runtime-context document from `docker inspect` output."""
    config = inspection.get("Config") or {}
    host_config = inspection.get("HostConfig") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "entrypoint_shape": argv_shape(config.get("Entrypoint")),
        "command_shape": argv_shape(config.get("Cmd")),
        "configured_user": _user_class(config.get("User")),
        "privileged": _tristate(host_config.get("Privileged")),
        "read_only_rootfs": _tristate(host_config.get("ReadonlyRootfs")),
        "network_mode": normalise_network_mode(host_config.get("NetworkMode")),
        "capabilities": _capabilities(host_config),
        "devices": _devices(host_config),
        "ports": _ports(config, host_config),
        "mounts": _mounts(inspection),
    }


def canonicalize(document: dict[str, Any]) -> dict[str, Any]:
    """Sort every set-like collection so semantically equal documents converge.

    Entrypoint and command shape keep their order because argument position is part of
    the shape. Everything else is order-insensitive per the profile-scope specification.
    """
    from experiments.artifacts import canonical_json

    canonical = dict(document)
    capabilities = canonical.get("capabilities")
    if isinstance(capabilities, dict):
        canonical["capabilities"] = {
            key: sorted(value) if isinstance(value, list) else value
            for key, value in sorted(capabilities.items())
        }
    for field in ("devices", "ports", "mounts"):
        value = canonical.get(field)
        if isinstance(value, list):
            canonical[field] = sorted(value, key=canonical_json)
    return canonical


def context_hash(document: dict[str, Any]) -> str:
    if document.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("runtime-context document must declare " + SCHEMA_VERSION)
    return sha256_json(canonicalize(document))
