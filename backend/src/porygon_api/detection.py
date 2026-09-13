from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable

RULESET_VERSION = "porygon.detection.v1"
MATCHER_REVISION = "porygon.detection.matcher.v4"
CORRELATION_WINDOW_SECONDS = 120

SHELL_NAMES = {"sh", "bash", "dash", "ash", "zsh", "ksh", "fish"}
MULTICALL_BINARY_NAMES = {"busybox", "toybox"}

DETECTION_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "POR-DET-001",
        "name": "High Behavioral Distance",
        "category": "anomaly",
        "description": "The observation window's Jensen-Shannon behavioral distance score is at least 0.50 relative to the container's trained baseline profile.",
        "severity_weight": 0.65,
        "confidence_weight": 0.70,
        "incident_eligible": False,
    },
    {
        "rule_id": "POR-DET-002",
        "name": "Previously Unseen Shell Execution",
        "category": "execution",
        "description": "A shell executable not present in the selected digest baseline executed.",
        "severity_weight": 0.72,
        "confidence_weight": 0.90,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-003",
        "name": "Novel Root Process",
        "category": "privilege",
        "description": "A UID 0 process executed although UID 0 was absent from the baseline.",
        "severity_weight": 0.78,
        "confidence_weight": 0.90,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-004",
        "name": "Previously Unseen Non-Shell Executable",
        "category": "execution",
        "description": "A non-shell executable absent from the digest baseline executed, regardless of name.",
        "severity_weight": 0.64,
        "confidence_weight": 0.80,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-005",
        "name": "Shell-to-Tool Sequence",
        "category": "correlation",
        "description": "An unseen shell was followed by an unseen non-shell executable in the same container within the correlation window.",
        "severity_weight": 0.90,
        "confidence_weight": 0.95,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-006",
        "name": "Docker Exec Activity",
        "category": "container-control",
        "description": "Docker exec activity occurred during the observation window.",
        "severity_weight": 0.35,
        "confidence_weight": 0.95,
        "incident_eligible": False,
    },
    {
        "rule_id": "POR-DET-007",
        "name": "Privileged Container Configuration",
        "category": "container-configuration",
        "description": "A container lifecycle event reported privileged mode during the observation window.",
        "severity_weight": 0.92,
        "confidence_weight": 0.95,
        "incident_eligible": True,
    },
)
RULE_BY_ID = {item["rule_id"]: item for item in DETECTION_RULES}

CUSTOM_RULE_ID_PREFIX = "POR-CUS-"
CUSTOM_CONDITION_MAX_DEPTH = 6
CUSTOM_CONDITION_MAX_LEAVES = 40
CUSTOM_ANCESTOR_MAX_DEPTH = 25
NUMERIC_CONDITION_FIELDS = {"user_uid"}
POR_DET_004_MATCH_CAP = 10

_PROCESS_FIELDS = {
    "executable",
    "process_name",
    "parent_executable",
    "parent_name",
    "command_line",
    "user_uid",
    "container_id",
}
_RUNTIME_FIELDS = {"action", "privileged", "image_digest", "container_id"}
_CONTAINS_FIELDS = {"command_line", "executable"}
_CONDITION_OPS = {"equals", "not_equals", "in", "not_in", "contains"}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def ruleset_hash() -> str:
    document = {
        "rules": DETECTION_RULES,
        "matcher_revision": MATCHER_REVISION,
    }
    return hashlib.sha256(_canonical_json(document).encode("utf-8")).hexdigest()


def custom_ruleset_hash(custom_rules: Iterable[dict[str, Any]]) -> str:
    documents = sorted(
        (
            {
                "slug": rule["slug"],
                "name": rule["name"],
                "target": rule["target"],
                "condition": rule["condition"],
                "severity_weight": rule["severity_weight"],
                "confidence_weight": rule["confidence_weight"],
                "incident_eligible": rule["incident_eligible"],
            }
            for rule in custom_rules
        ),
        key=lambda item: item["slug"],
    )
    return hashlib.sha256(_canonical_json(documents).encode("utf-8")).hexdigest()


def validate_custom_condition(condition: Any, *, target: str, _depth: int = 0, _leaves: list[None] | None = None) -> None:
    """Validate a custom-rule condition tree against the fixed, safe vocabulary.

    Raises ValueError on any structural or vocabulary violation. No expression is ever
    evaluated as code: this only ever compares field allowlists/operator names.
    """
    if _leaves is None:
        _leaves = []
    if _depth > CUSTOM_CONDITION_MAX_DEPTH:
        raise ValueError("condition tree exceeds the maximum nesting depth")
    if not isinstance(condition, dict):
        raise ValueError("condition node must be an object")

    if "all" in condition or "any" in condition:
        key = "all" if "all" in condition else "any"
        children = condition[key]
        if not isinstance(children, list) or not children:
            raise ValueError(f"'{key}' must be a non-empty list of conditions")
        for child in children:
            validate_custom_condition(child, target=target, _depth=_depth + 1, _leaves=_leaves)
        return
    if "not" in condition:
        validate_custom_condition(condition["not"], target=target, _depth=_depth + 1, _leaves=_leaves)
        return

    _leaves.append(None)
    if len(_leaves) > CUSTOM_CONDITION_MAX_LEAVES:
        raise ValueError("condition tree exceeds the maximum number of leaf conditions")

    field = condition.get("field")
    op = condition.get("op")
    scope = condition.get("scope", "event")
    allowed_fields = _PROCESS_FIELDS if target == "process" else _RUNTIME_FIELDS
    if field not in allowed_fields:
        raise ValueError(f"unknown field {field!r} for target {target!r}")
    if op not in _CONDITION_OPS:
        raise ValueError(f"unknown operator {op!r}")
    if op == "contains" and field not in _CONTAINS_FIELDS:
        raise ValueError(f"operator 'contains' is not supported for field {field!r}")
    if scope not in {"event", "ancestor"}:
        raise ValueError(f"unknown scope {scope!r}")
    if scope == "ancestor" and target != "process":
        raise ValueError("scope 'ancestor' is only valid for target 'process'")
    if "value" not in condition:
        raise ValueError("condition leaf is missing 'value'")
    if op in {"in", "not_in"} and not isinstance(condition["value"], list):
        raise ValueError(f"operator {op!r} requires a list value")




def build_allowlist_matcher_hash(
    *,
    image_digest: str,
    rule_id: str,
    executable: str | None,
    parent_executable: str | None,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "image_digest": image_digest,
                "rule_id": rule_id,
                "executable": executable,
                "parent_executable": parent_executable,
            }
        ).encode("utf-8")
    ).hexdigest()


def allowlist_set_hash(allowlists: Iterable[Any]) -> str:
    documents = sorted(
        (
            {
                "allowlist_id": item.allowlist_id,
                "matcher_hash": item.matcher_hash,
                "expires_at": _iso(item.expires_at) if item.expires_at else None,
            }
            for item in allowlists
        ),
        key=lambda item: item["allowlist_id"],
    )
    return hashlib.sha256(_canonical_json(documents).encode("utf-8")).hexdigest()


def build_detection_run_key(
    score_id: str,
    selected_allowlist_hash: str,
    selected_custom_ruleset_hash: str = "",
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "score_id": score_id,
                "ruleset_version": RULESET_VERSION,
                "ruleset_hash": ruleset_hash(),
                "allowlist_set_hash": selected_allowlist_hash,
                "custom_ruleset_hash": selected_custom_ruleset_hash,
            }
        ).encode("utf-8")
    ).hexdigest()


def _round(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 12)


def _multicall_applet_from_cmdline(command_line: str | None) -> str | None:
    """Recover the dispatched applet name from a multicall invocation's argv.

    Falco's proc.name/proc.exepath never change for busybox/toybox applets: the
    binary dispatches internally on argv[0] without exec()-ing a new image, so
    identity has to come from the captured command line's second token instead.
    """
    text = (command_line or "").strip()
    if not text:
        return None
    parts = text.split()
    if len(parts) < 2:
        return None
    candidate = PurePosixPath(parts[1]).name.lower()
    if not candidate or candidate.startswith("-"):
        # argv[1] is a flag (e.g. `busybox --help`), not a dispatched applet name;
        # let the caller fall back to the real binary/base name instead.
        return None
    return candidate


def _resolve_multicall_name(name: str, command_line: str | None) -> str | None:
    if name and name.lower() not in MULTICALL_BINARY_NAMES:
        return name.lower()
    applet = _multicall_applet_from_cmdline(command_line)
    if applet:
        return applet
    return name.lower() if name else None


def _basename(event: Any) -> str:
    executable = (getattr(event, "executable", None) or "").strip()
    name = (getattr(event, "process_name", None) or "").strip()
    executable_name = PurePosixPath(executable).name.lower() if executable else ""
    if executable_name in MULTICALL_BINARY_NAMES:
        resolved = _resolve_multicall_name(name, getattr(event, "command_line", None))
        if resolved:
            return resolved
    token = executable_name or name
    return token.lower()


def _event_executable(event: Any) -> str:
    executable = (getattr(event, "executable", None) or "").strip()
    name = (getattr(event, "process_name", None) or "").strip()
    executable_name = PurePosixPath(executable).name.lower() if executable else ""
    if executable_name in MULTICALL_BINARY_NAMES:
        resolved = _resolve_multicall_name(name, getattr(event, "command_line", None))
        if resolved:
            return resolved
    return executable or name or "<unknown>"


def _parent_executable(event: Any) -> str | None:
    executable = (getattr(event, "parent_executable", None) or "").strip()
    name = (getattr(event, "parent_name", None) or "").strip()
    executable_name = PurePosixPath(executable).name.lower() if executable else ""
    if executable_name in MULTICALL_BINARY_NAMES:
        resolved = _resolve_multicall_name(name, getattr(event, "parent_command_line", None))
        if resolved:
            return resolved
    return executable or name or None


def _process_identity_seen(
    event: Any,
    *,
    baseline_executables: set[str],
    baseline_process_names: set[str],
) -> bool:
    executable = (getattr(event, "executable", None) or "").strip()
    name = (getattr(event, "process_name", None) or "").strip().lower()
    executable_name = PurePosixPath(executable).name.lower() if executable else ""
    if executable_name in MULTICALL_BINARY_NAMES:
        resolved = _resolve_multicall_name(name, getattr(event, "command_line", None))
        return bool(resolved) and resolved in baseline_process_names
    return executable in baseline_executables or name in baseline_process_names


def _ancestor_chain(event: Any, events_by_id: dict[str, Any], *, max_depth: int = CUSTOM_ANCESTOR_MAX_DEPTH) -> list[Any]:
    """Walk parent_event_id back through the in-window event set.

    Bounded to events already loaded for the scored window: an ancestor that executed
    before the window started is invisible here, matching the same window boundary the
    built-in shell-to-tool correlation (POR-DET-005) already reasons under.
    """
    chain: list[Any] = []
    current = event
    seen: set[str] = set()
    for _ in range(max_depth):
        parent_id = getattr(current, "parent_event_id", None)
        if not parent_id or parent_id in seen:
            break
        parent = events_by_id.get(parent_id)
        if parent is None:
            break
        chain.append(parent)
        seen.add(parent_id)
        current = parent
    return chain


def _process_chain_documents(event: Any, events_by_id: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = [event, *_ancestor_chain(event, events_by_id)]
    return [
        {
            "event_id": node.event_id,
            "executable": _event_executable(node),
            "parent_executable": _parent_executable(node),
            "occurred_at": _iso(node.occurred_at),
        }
        for node in nodes
    ]


def _field_value(event: Any, field: str) -> Any:
    if field == "executable":
        return _basename(event)
    if field == "parent_executable":
        parent = _parent_executable(event)
        return PurePosixPath(parent).name.lower() if parent else ""
    if field == "process_name":
        return (getattr(event, "process_name", None) or "").lower()
    if field == "parent_name":
        return (getattr(event, "parent_name", None) or "").lower()
    if field == "command_line":
        return getattr(event, "command_line", None) or ""
    if field == "user_uid":
        return getattr(event, "user_uid", None)
    if field == "container_id":
        return getattr(event, "container_id", None)
    if field == "action":
        return getattr(event, "action", None)
    if field == "image_digest":
        return getattr(event, "image_digest", None)
    if field == "privileged":
        snapshot = getattr(event, "container_snapshot", None) or {}
        return bool((snapshot.get("host_config") or {}).get("privileged"))
    return None


def _coerce_numeric(value: Any) -> Any:
    """Coerce a string-typed numeric value to int, leaving everything else untouched.

    The dashboard's rule-builder UI sends UID values as strings; the events themselves
    carry `user_uid` as an int. Without this, `leaf["value"] == event.user_uid` compares
    a string to an int and is always False in Python, so builder-authored rules on
    numeric fields silently never match.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return value
    return value


def _leaf_matches(leaf: dict[str, Any], event: Any) -> bool:
    field = leaf["field"]
    value = _field_value(event, field)
    expected = leaf["value"]
    op = leaf["op"]
    if field in NUMERIC_CONDITION_FIELDS:
        value = _coerce_numeric(value)
        if isinstance(expected, list):
            expected = [_coerce_numeric(item) for item in expected]
        else:
            expected = _coerce_numeric(expected)
    if op == "equals":
        return value == expected
    if op == "not_equals":
        return value != expected
    if op == "in":
        return value in expected
    if op == "not_in":
        return value not in expected
    if op == "contains":
        return isinstance(value, str) and isinstance(expected, str) and expected.lower() in value.lower()
    return False


def evaluate_custom_condition(condition: dict[str, Any], event: Any, events_by_id: dict[str, Any]) -> bool:
    if "all" in condition:
        return all(evaluate_custom_condition(child, event, events_by_id) for child in condition["all"])
    if "any" in condition:
        return any(evaluate_custom_condition(child, event, events_by_id) for child in condition["any"])
    if "not" in condition:
        return not evaluate_custom_condition(condition["not"], event, events_by_id)

    scope = condition.get("scope", "event")
    if scope == "ancestor":
        return any(_leaf_matches(condition, ancestor) for ancestor in _ancestor_chain(event, events_by_id))
    return _leaf_matches(condition, event)


def _iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _match(
    rule_id: str,
    *,
    occurred_at: datetime,
    source_type: str,
    source_id: str,
    container_id: str | None,
    summary: str,
    details: dict[str, Any],
    rule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_rule = rule if rule is not None else RULE_BY_ID[rule_id]
    return {
        **resolved_rule,
        "rule_id": rule_id,
        "occurred_at": _iso(occurred_at),
        "source_type": source_type,
        "source_id": source_id,
        "container_id": container_id,
        "summary": summary,
        "details": details,
    }


def _custom_rule_matches(
    custom_rules: Iterable[dict[str, Any]],
    *,
    process_events: list[Any],
    runtime_events: list[Any],
    events_by_id: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Evaluate every custom rule, isolating each rule's failures from the others.

    A single malformed rule row (bad migration, direct SQL edit, a future relaxed
    validator) must not raise out of this loop: that would crash detection for every
    container in the run, not just the one rule. Failures are recorded as `rule_error`
    entries instead of being swallowed silently.
    """
    matches: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for custom_rule in custom_rules:
        slug = custom_rule.get("slug") if isinstance(custom_rule, dict) else None
        try:
            if not custom_rule.get("enabled", True):
                continue
            rule_id = f"{CUSTOM_RULE_ID_PREFIX}{custom_rule['slug']}"
            rule_document = {
                "rule_id": rule_id,
                "name": custom_rule["name"],
                "category": custom_rule["category"],
                "description": custom_rule["description"],
                "severity_weight": custom_rule["severity_weight"],
                "confidence_weight": custom_rule["confidence_weight"],
                "incident_eligible": custom_rule["incident_eligible"],
            }
            target = custom_rule["target"]
            condition = custom_rule["condition"]
            source_events = process_events if target == "process" else runtime_events
            for event in source_events:
                if not evaluate_custom_condition(condition, event, events_by_id):
                    continue
                if target == "process":
                    details = {
                        "executable": _event_executable(event),
                        "parent_executable": _parent_executable(event),
                        "command_line": getattr(event, "command_line", None),
                        "process_chain": _process_chain_documents(event, events_by_id),
                    }
                else:
                    details = {
                        "action": getattr(event, "action", None),
                        "image_digest": getattr(event, "image_digest", None),
                    }
                matches.append(
                    _match(
                        rule_id,
                        occurred_at=event.occurred_at,
                        source_type="process_event" if target == "process" else "runtime_event",
                        source_id=event.event_id,
                        container_id=event.container_id,
                        summary=f"Custom rule '{custom_rule['name']}' matched.",
                        details=details,
                        rule=rule_document,
                    )
                )
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                {
                    "slug": slug,
                    "rule_id": f"{CUSTOM_RULE_ID_PREFIX}{slug}" if slug else None,
                    "error": str(exc),
                }
            )
    return matches, errors


def _deduplicate(matches: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in matches:
        key = (item["rule_id"], item["source_type"], item["source_id"])
        unique[key] = item
    return sorted(
        unique.values(),
        key=lambda item: (item["occurred_at"], item["rule_id"], item["source_id"]),
    )


def severity_level(value: float) -> str:
    if value < 0.25:
        return "low"
    if value < 0.50:
        return "medium"
    if value < 0.75:
        return "high"
    return "critical"


def confidence_level(value: float) -> str:
    if value < 0.35:
        return "low"
    if value < 0.70:
        return "medium"
    return "high"


def _allowlist_match(match: dict[str, Any], allowlist: Any) -> bool:
    if match["rule_id"] != allowlist.rule_id:
        return False
    details = match.get("details", {})
    if allowlist.executable is not None:
        executable = details.get("executable") or details.get("process_name")
        if executable != allowlist.executable:
            return False
    if allowlist.parent_executable is not None:
        parent = details.get("parent_executable")
        if parent != allowlist.parent_executable:
            return False
    return True


def _apply_allowlists(
    matches: list[dict[str, Any]],
    allowlists: list[Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    suppressed_source_events: dict[str, str] = {}

    for match in matches:
        if match["rule_id"] == "POR-DET-005":
            continue
        selected = next((item for item in allowlists if _allowlist_match(match, item)), None)
        if selected is None:
            active.append(match)
            continue
        document = {**match, "suppressed_by_allowlist_id": selected.allowlist_id}
        suppressed.append(document)
        if match["rule_id"] in {"POR-DET-002", "POR-DET-004"}:
            suppressed_source_events[match["source_id"]] = selected.allowlist_id

    for match in matches:
        if match["rule_id"] != "POR-DET-005":
            continue
        details = match.get("details", {})
        suppressor = suppressed_source_events.get(details.get("shell_event_id")) or suppressed_source_events.get(
            details.get("tool_event_id")
        )
        if suppressor is not None:
            suppressed.append({**match, "suppressed_by_allowlist_id": suppressor})
        else:
            active.append(match)

    return _deduplicate(active), _deduplicate(suppressed)


def evaluate_detection(
    *,
    anomaly_score: Any,
    profile: Any,
    process_events: list[Any],
    runtime_events: list[Any],
    allowlists: list[Any] | None = None,
    custom_rules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Evaluate deterministic evidence rules for one immutable score window.

    Severity estimates potential impact. Confidence estimates evidence support and
    correlation quality. Neither value is a probability of compromise. Custom rules are
    strictly additive: they never affect ruleset_hash()/RULESET_VERSION, which identify
    only the 7 built-in rules.
    """

    if getattr(anomaly_score, "status", None) != "scored" or getattr(anomaly_score, "total_score", None) is None:
        return {
            "ruleset_version": RULESET_VERSION,
            "ruleset_hash": ruleset_hash(),
            "custom_ruleset_hash": custom_ruleset_hash(custom_rules or []),
            "status": "insufficient_data",
            "matches": [],
            "suppressed_matches": [],
            "rule_errors": [],
            "incident_eligible": False,
            "anomaly_score": None,
            "severity_score": None,
            "severity_level": "unknown",
            "confidence_score": 0.0,
            "confidence_level": "low",
            "summary": "Detection was not run because the observation lacked sufficient scoreable evidence.",
            "metrics": {
                "process_events": len(process_events),
                "runtime_events": len(runtime_events),
                "source_types": [],
            },
        }

    baseline_sets = (getattr(profile, "features", {}) or {}).get("observed_sets", {})
    baseline_executables = set(baseline_sets.get("executables", []))
    baseline_process_names = {str(item).lower() for item in baseline_sets.get("process_names", [])}
    baseline_uids = set(baseline_sets.get("user_uids", []))
    events_by_id = {event.event_id: event for event in process_events}

    matches: list[dict[str, Any]] = []
    anomaly_value = float(anomaly_score.total_score)
    if anomaly_value >= 0.50:
        matches.append(
            _match(
                "POR-DET-001",
                occurred_at=anomaly_score.window_end,
                source_type="anomaly_score",
                source_id=anomaly_score.score_id,
                container_id=None,
                summary=f"Behavioural distance {anomaly_value:.3f} is in the {anomaly_score.score_band} band.",
                details={
                    "total_score": anomaly_value,
                    "score_band": anomaly_score.score_band,
                    "algorithm_version": anomaly_score.algorithm_version,
                },
            )
        )

    unseen_shells: list[Any] = []
    unseen_tools: list[Any] = []
    por_det_004_match_count = 0
    additional_unseen_executables = 0
    for event in process_events:
        name = _basename(event)
        executable = _event_executable(event)
        executable_seen = _process_identity_seen(
            event,
            baseline_executables=baseline_executables,
            baseline_process_names=baseline_process_names,
        )
        if name in SHELL_NAMES and not executable_seen:
            unseen_shells.append(event)
            matches.append(
                _match(
                    "POR-DET-002",
                    occurred_at=event.occurred_at,
                    source_type="process_event",
                    source_id=event.event_id,
                    container_id=event.container_id,
                    summary=f"Previously unseen shell {executable} executed.",
                    details={
                        "process_name": event.process_name,
                        "executable": executable,
                        "raw_executable": event.executable,
                        "parent_name": event.parent_name,
                        "parent_executable": _parent_executable(event),
                        "raw_parent_executable": event.parent_executable,
                        "user_uid": event.user_uid,
                        "command_line": event.command_line,
                        "process_chain": _process_chain_documents(event, events_by_id),
                    },
                )
            )
        if event.user_uid == 0 and "0" not in baseline_uids:
            matches.append(
                _match(
                    "POR-DET-003",
                    occurred_at=event.occurred_at,
                    source_type="process_event",
                    source_id=event.event_id,
                    container_id=event.container_id,
                    summary=f"UID 0 process {executable} was absent from the baseline user set.",
                    details={
                        "process_name": event.process_name,
                        "executable": executable,
                        "raw_executable": event.executable,
                        "user_uid": event.user_uid,
                        "parent_event_id": event.parent_event_id,
                        "process_chain": _process_chain_documents(event, events_by_id),
                    },
                )
            )
        if name and name not in SHELL_NAMES and not executable_seen:
            unseen_tools.append(event)
            if por_det_004_match_count < POR_DET_004_MATCH_CAP:
                por_det_004_match_count += 1
                matches.append(
                    _match(
                        "POR-DET-004",
                        occurred_at=event.occurred_at,
                        source_type="process_event",
                        source_id=event.event_id,
                        container_id=event.container_id,
                        summary=f"Previously unseen non-shell executable {executable} executed.",
                        details={
                            "process_name": event.process_name,
                            "executable": executable,
                            "raw_executable": event.executable,
                            "parent_name": event.parent_name,
                            "parent_executable": _parent_executable(event),
                            "raw_parent_executable": event.parent_executable,
                            "command_line": event.command_line,
                            "process_chain": _process_chain_documents(event, events_by_id),
                        },
                    )
                )
            else:
                additional_unseen_executables += 1

    correlation_window = timedelta(seconds=CORRELATION_WINDOW_SECONDS)
    for shell in unseen_shells:
        candidates = [
            tool
            for tool in unseen_tools
            if tool.container_id
            and tool.container_id == shell.container_id
            and shell.occurred_at <= tool.occurred_at <= shell.occurred_at + correlation_window
        ]
        for tool in candidates:
            matches.append(
                _match(
                    "POR-DET-005",
                    occurred_at=tool.occurred_at,
                    source_type="derived_correlation",
                    source_id=f"{shell.event_id}:{tool.event_id}",
                    container_id=tool.container_id,
                    summary=f"Unseen shell {_event_executable(shell)} was followed by {_event_executable(tool)} within {CORRELATION_WINDOW_SECONDS} seconds.",
                    details={
                        "shell_event_id": shell.event_id,
                        "tool_event_id": tool.event_id,
                        "elapsed_seconds": round((tool.occurred_at - shell.occurred_at).total_seconds(), 6),
                        "process_chain": _process_chain_documents(tool, events_by_id),
                    },
                )
            )

    for event in runtime_events:
        if event.event_type == "container" and event.action in {"exec_create", "exec_start", "exec_die"}:
            matches.append(
                _match(
                    "POR-DET-006",
                    occurred_at=event.occurred_at,
                    source_type="runtime_event",
                    source_id=event.event_id,
                    container_id=event.container_id,
                    summary=f"Docker container action {event.action} occurred.",
                    details={"action": event.action, "command": event.command},
                )
            )
        privileged = bool((event.container_snapshot or {}).get("host_config", {}).get("privileged"))
        if privileged and event.event_type == "container" and event.action in {"create", "start"}:
            matches.append(
                _match(
                    "POR-DET-007",
                    occurred_at=event.occurred_at,
                    source_type="runtime_event",
                    source_id=event.event_id,
                    container_id=event.container_id,
                    summary="Container lifecycle evidence reported privileged mode.",
                    details={
                        "action": event.action,
                        "privileged": True,
                        "image_digest": event.image_digest,
                    },
                )
            )

    custom_matches, rule_errors = _custom_rule_matches(
        custom_rules or [],
        process_events=process_events,
        runtime_events=runtime_events,
        events_by_id=events_by_id,
    )
    matches.extend(custom_matches)

    matches, suppressed_matches = _apply_allowlists(_deduplicate(matches), allowlists or [])
    eligible_matches = [item for item in matches if item["incident_eligible"]]
    source_types = sorted({item["source_type"] for item in matches})

    if matches:
        combined_rule_confidence = 1.0
        for item in matches:
            combined_rule_confidence *= 1.0 - float(item["confidence_weight"])
        combined_rule_confidence = 1.0 - combined_rule_confidence
    else:
        combined_rule_confidence = 0.0

    source_diversity = min(1.0, len(source_types) / 3.0)
    process_evidence = min(1.0, len(process_events) / 5.0)
    runtime_evidence = 1.0 if runtime_events else 0.0
    evidence_coverage = 0.75 * process_evidence + 0.25 * runtime_evidence
    confidence_score = _round(
        0.50 * combined_rule_confidence + 0.25 * source_diversity + 0.25 * evidence_coverage
    )

    if eligible_matches:
        max_rule_severity = max(float(item["severity_weight"]) for item in eligible_matches)
        corroboration_bonus = min(0.12, max(0, len(eligible_matches) - 1) * 0.03)
        severity_score = _round(0.65 * max_rule_severity + 0.35 * anomaly_value + corroboration_bonus)
    else:
        severity_score = _round(0.25 * anomaly_value)

    incident_eligible = bool(eligible_matches)
    if incident_eligible:
        summary = f"{len(eligible_matches)} incident-eligible rule match(es) correlated for {profile.image_digest}."
        status = "incident_created"
    elif matches:
        summary = "Only informational evidence matched; no incident was created."
        status = "findings_only"
    else:
        summary = "No deterministic Phase 6 rules matched this scored window."
        status = "no_findings"

    return {
        "ruleset_version": RULESET_VERSION,
        "ruleset_hash": ruleset_hash(),
        "custom_ruleset_hash": custom_ruleset_hash(custom_rules or []),
        "status": status,
        "matches": matches,
        "suppressed_matches": suppressed_matches,
        "rule_errors": rule_errors,
        "incident_eligible": incident_eligible,
        "anomaly_score": _round(anomaly_value),
        "severity_score": severity_score,
        "severity_level": severity_level(severity_score),
        "confidence_score": confidence_score,
        "confidence_level": confidence_level(confidence_score),
        "summary": summary,
        "metrics": {
            "process_events": len(process_events),
            "runtime_events": len(runtime_events),
            "source_types": source_types,
            "eligible_matches": len(eligible_matches),
            "informational_matches": len(matches) - len(eligible_matches),
            "suppressed_matches": len(suppressed_matches),
            "correlation_window_seconds": CORRELATION_WINDOW_SECONDS,
            "additional_unseen_executables": additional_unseen_executables,
        },
    }
