from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Iterable

RULESET_VERSION = "porygon.detection.v1"
CORRELATION_WINDOW_SECONDS = 120

SHELL_NAMES = {"sh", "bash", "dash", "ash", "zsh", "ksh", "fish"}
SUSPICIOUS_TOOL_NAMES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "scp",
    "base64",
    "openssl",
    "python",
    "python3",
    "perl",
    "ruby",
}

DETECTION_RULES: tuple[dict[str, Any], ...] = (
    {
        "rule_id": "POR-DET-001",
        "name": "High behavioural distance",
        "category": "anomaly",
        "description": "The completed window has a Phase 5 score of at least 0.50.",
        "severity_weight": 0.65,
        "confidence_weight": 0.70,
        "incident_eligible": False,
    },
    {
        "rule_id": "POR-DET-002",
        "name": "Previously unseen shell execution",
        "category": "execution",
        "description": "A shell executable not present in the selected digest baseline executed.",
        "severity_weight": 0.72,
        "confidence_weight": 0.90,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-003",
        "name": "Novel root process",
        "category": "privilege",
        "description": "A UID 0 process executed although UID 0 was absent from the baseline.",
        "severity_weight": 0.78,
        "confidence_weight": 0.90,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-004",
        "name": "Previously unseen dual-use tool",
        "category": "execution",
        "description": "A downloader, network utility, interpreter, or encoding tool absent from the baseline executed.",
        "severity_weight": 0.64,
        "confidence_weight": 0.80,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-005",
        "name": "Shell-to-tool sequence",
        "category": "correlation",
        "description": "An unseen shell was followed by an unseen dual-use tool in the same container within the correlation window.",
        "severity_weight": 0.90,
        "confidence_weight": 0.95,
        "incident_eligible": True,
    },
    {
        "rule_id": "POR-DET-006",
        "name": "Docker exec activity",
        "category": "container-control",
        "description": "Docker exec activity occurred during the observation window.",
        "severity_weight": 0.35,
        "confidence_weight": 0.95,
        "incident_eligible": False,
    },
    {
        "rule_id": "POR-DET-007",
        "name": "Privileged container configuration",
        "category": "container-configuration",
        "description": "A container lifecycle event reported privileged mode during the observation window.",
        "severity_weight": 0.92,
        "confidence_weight": 0.95,
        "incident_eligible": True,
    },
)
RULE_BY_ID = {item["rule_id"]: item for item in DETECTION_RULES}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def ruleset_hash() -> str:
    return hashlib.sha256(_canonical_json(DETECTION_RULES).encode("utf-8")).hexdigest()




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


def build_detection_run_key(score_id: str, selected_allowlist_hash: str) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "score_id": score_id,
                "ruleset_version": RULESET_VERSION,
                "ruleset_hash": ruleset_hash(),
                "allowlist_set_hash": selected_allowlist_hash,
            }
        ).encode("utf-8")
    ).hexdigest()


def _round(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 12)


def _basename(event: Any) -> str:
    executable = (getattr(event, "executable", None) or "").strip()
    name = (getattr(event, "process_name", None) or "").strip()
    token = PurePosixPath(executable).name if executable else name
    return token.lower()


def _event_executable(event: Any) -> str:
    return (getattr(event, "executable", None) or getattr(event, "process_name", None) or "<unknown>").strip()


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
) -> dict[str, Any]:
    rule = RULE_BY_ID[rule_id]
    return {
        **rule,
        "occurred_at": _iso(occurred_at),
        "source_type": source_type,
        "source_id": source_id,
        "container_id": container_id,
        "summary": summary,
        "details": details,
    }


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
) -> dict[str, Any]:
    """Evaluate deterministic evidence rules for one immutable score window.

    Severity estimates potential impact. Confidence estimates evidence support and
    correlation quality. Neither value is a probability of compromise.
    """

    if getattr(anomaly_score, "status", None) != "scored" or getattr(anomaly_score, "total_score", None) is None:
        return {
            "ruleset_version": RULESET_VERSION,
            "ruleset_hash": ruleset_hash(),
            "status": "insufficient_data",
            "matches": [],
            "suppressed_matches": [],
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
    for event in process_events:
        name = _basename(event)
        executable = _event_executable(event)
        executable_seen = executable in baseline_executables or name in baseline_process_names
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
                        "executable": event.executable,
                        "parent_name": event.parent_name,
                        "parent_executable": event.parent_executable,
                        "user_uid": event.user_uid,
                        "command_line": event.command_line,
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
                        "executable": event.executable,
                        "user_uid": event.user_uid,
                        "parent_event_id": event.parent_event_id,
                    },
                )
            )
        if name in SUSPICIOUS_TOOL_NAMES and not executable_seen:
            unseen_tools.append(event)
            matches.append(
                _match(
                    "POR-DET-004",
                    occurred_at=event.occurred_at,
                    source_type="process_event",
                    source_id=event.event_id,
                    container_id=event.container_id,
                    summary=f"Previously unseen dual-use tool {executable} executed.",
                    details={
                        "process_name": event.process_name,
                        "executable": event.executable,
                        "parent_name": event.parent_name,
                        "parent_executable": event.parent_executable,
                        "command_line": event.command_line,
                    },
                )
            )

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
        "status": status,
        "matches": matches,
        "suppressed_matches": suppressed_matches,
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
        },
    }
