from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

POLICY_VERSION = "porygon.response.v1"
ACTION_ORDER = {
    "observe_only": 0,
    "pause_container": 1,
    "stop_container": 2,
}

RESPONSE_POLICY: dict[str, Any] = {
    "version": POLICY_VERSION,
    "principles": [
        "No response action executes without an explicit human approval.",
        "The approved action must not exceed the policy's allowed action set.",
        "Targets must be exact container IDs already attached to the incident.",
        "Porygon-protected containers are never modified.",
        "Execution and rollback are idempotent and independently audited.",
    ],
    "actions": {
        "observe_only": {
            "disruption": "none",
            "effect": "Record the decision and continue monitoring without changing Docker state.",
            "rollback": "not_required",
        },
        "pause_container": {
            "disruption": "high",
            "effect": "Suspend all processes in the target container using the Docker pause API.",
            "rollback": "unpause_container",
        },
        "stop_container": {
            "disruption": "critical",
            "effect": "Request a graceful container stop, followed by Docker's configured kill fallback.",
            "rollback": "start_container",
            "warning": "Starting the container does not restore lost in-memory state or active connections.",
        },
    },
    "decision_thresholds": {
        "pause_min_severity": 0.70,
        "pause_min_confidence": 0.55,
        "stop_min_severity": 0.90,
        "stop_min_confidence": 0.75,
    },
}


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def response_policy_hash() -> str:
    return hashlib.sha256(canonical_json(RESPONSE_POLICY).encode("utf-8")).hexdigest()


def build_recommendation_key(
    *,
    incident_id: str,
    target_container_id: str | None,
    policy_hash: str | None = None,
) -> str:
    document = {
        "incident_id": incident_id,
        "target_container_id": target_container_id,
        "policy_version": POLICY_VERSION,
        "policy_hash": policy_hash or response_policy_hash(),
    }
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()


def _finding_rule_ids(findings: Iterable[dict[str, Any]]) -> set[str]:
    return {
        str(item.get("rule_id"))
        for item in findings
        if item.get("rule_id") is not None
    }


def allowed_actions_for_incident(
    *,
    severity_score: float,
    confidence_score: float,
    findings: Iterable[dict[str, Any]],
    has_target: bool,
) -> list[str]:
    allowed = ["observe_only"]
    if not has_target:
        return allowed

    thresholds = RESPONSE_POLICY["decision_thresholds"]
    if (
        severity_score >= float(thresholds["pause_min_severity"])
        and confidence_score >= float(thresholds["pause_min_confidence"])
    ):
        allowed.append("pause_container")

    rule_ids = _finding_rule_ids(findings)
    strong_rule = bool({"POR-DET-005", "POR-DET-007"} & rule_ids)
    if (
        severity_score >= float(thresholds["stop_min_severity"])
        and confidence_score >= float(thresholds["stop_min_confidence"])
        and strong_rule
    ):
        allowed.append("stop_container")
    return allowed


def recommended_action(allowed_actions: list[str]) -> str:
    return max(allowed_actions, key=lambda action: ACTION_ORDER[action])


def build_recommendation_document(
    *,
    incident_id: str,
    target_container_id: str | None,
    severity_score: float,
    confidence_score: float,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    allowed = allowed_actions_for_incident(
        severity_score=severity_score,
        confidence_score=confidence_score,
        findings=findings,
        has_target=target_container_id is not None,
    )
    recommended = recommended_action(allowed)
    risk_notes = [
        "An anomaly or deterministic rule match is evidence, not proof of compromise.",
        "A human must validate business impact and ownership before approval.",
    ]
    if "pause_container" in allowed:
        risk_notes.append("Pausing freezes every process and may interrupt availability.")
    if "stop_container" in allowed:
        risk_notes.append(
            "Stopping may lose in-memory state; a later start is not a full rollback."
        )

    rationale = (
        f"Policy {POLICY_VERSION} allows {', '.join(allowed)} for incident {incident_id} "
        f"at severity={severity_score:.3f} and confidence={confidence_score:.3f}."
    )
    return {
        "policy_version": POLICY_VERSION,
        "policy_hash": response_policy_hash(),
        "recommended_action": recommended,
        "allowed_actions": allowed,
        "rationale": rationale,
        "risk_notes": risk_notes,
    }


def build_execution_idempotency_key(
    *, recommendation_id: str, action_type: str
) -> str:
    document = {
        "recommendation_id": recommendation_id,
        "action_type": action_type,
        "operation": "execute",
    }
    return hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
