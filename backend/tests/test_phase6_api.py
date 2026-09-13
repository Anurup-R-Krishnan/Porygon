import pytest
from pydantic import ValidationError

from porygon_api.main import app, get_detection_rules_config
from porygon_api.schemas import CustomDetectionRuleCreateIn, DetectionAllowlistCreateIn


def test_phase6_routes_are_exposed_in_openapi() -> None:
    paths = app.openapi()["paths"]
    required = {
        "/api/v1/detection-rules/config",
        "/api/v1/detection-allowlists",
        "/internal/v1/detection-allowlists",
        "/internal/v1/detection-allowlists/{allowlist_id}/deactivate",
        "/internal/v1/detections/run",
        "/api/v1/detection-runs",
        "/api/v1/detection-runs/{run_id}",
        "/api/v1/incidents",
        "/api/v1/incidents/{incident_id}",
        "/api/v1/incidents/{incident_id}/timeline",
        "/internal/v1/incidents/{incident_id}/status",
        "/api/v1/custom-detection-rules",
        "/operator/v1/custom-detection-rules",
        "/operator/v1/custom-detection-rules/{custom_rule_id}/disable",
        "/operator/v1/custom-detection-rules/{custom_rule_id}/enable",
    }
    assert required.issubset(paths)


def test_detection_config_separates_severity_confidence_and_verdict() -> None:
    response = get_detection_rules_config()
    assert response["ruleset_version"] == "porygon.detection.v1"
    assert response["matcher_revision"] == "porygon.detection.matcher.v4"
    assert len(response["ruleset_hash"]) == 64
    assert response["rules"]
    assert "Neither is a probability of compromise" in response["interpretation"]


def test_custom_detection_rule_schema_accepts_a_valid_condition() -> None:
    payload = CustomDetectionRuleCreateIn(
        slug="nc-listener",
        name="Netcat listener spawned",
        description="Flags any execution of nc.",
        category="custom",
        target="process",
        condition={"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
        severity_weight=0.8,
        confidence_weight=0.9,
        incident_eligible=True,
        created_by="operator@example.com",
    )
    assert payload.slug == "nc-listener"


def _expression_payload(expression: str, **overrides: object) -> CustomDetectionRuleCreateIn:
    fields: dict[str, object] = {
        "slug": "expr-rule",
        "name": "Expression rule",
        "description": "Authored as text rather than through the builder.",
        "category": "custom",
        "target": "process",
        "expression": expression,
        "severity_weight": 0.8,
        "confidence_weight": 0.9,
        "incident_eligible": True,
        "created_by": "operator@example.com",
    }
    fields.update(overrides)
    return CustomDetectionRuleCreateIn(**fields)


def test_custom_detection_rule_schema_compiles_an_expression_into_a_condition() -> None:
    payload = _expression_payload('executable == "nc" and ancestor.parent_executable in ["sh", "bash"]')
    assert payload.condition == {
        "all": [
            {"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
            {"field": "parent_executable", "op": "in", "value": ["sh", "bash"], "scope": "ancestor"},
        ]
    }


def test_custom_detection_rule_schema_rejects_a_malformed_expression() -> None:
    with pytest.raises(ValidationError):
        _expression_payload('executable == ')


def test_custom_detection_rule_schema_rejects_an_expression_using_an_unknown_field() -> None:
    with pytest.raises(ValidationError):
        _expression_payload('__import__ == "os"')


def test_custom_detection_rule_schema_requires_exactly_one_condition_form() -> None:
    with pytest.raises(ValidationError):
        _expression_payload(
            'executable == "nc"',
            condition={"field": "executable", "op": "equals", "value": "nc", "scope": "event"},
        )
    with pytest.raises(ValidationError):
        CustomDetectionRuleCreateIn(
            slug="no-condition",
            name="No condition",
            description="Neither form supplied.",
            category="custom",
            target="process",
            severity_weight=0.5,
            confidence_weight=0.5,
            incident_eligible=True,
            created_by="operator@example.com",
        )


def test_custom_detection_rule_schema_rejects_an_unsafe_condition() -> None:
    with pytest.raises(ValidationError):
        CustomDetectionRuleCreateIn(
            slug="bad-rule",
            name="Bad rule",
            description="Uses an unknown field.",
            category="custom",
            target="process",
            condition={"field": "not_a_real_field", "op": "equals", "value": "x"},
            severity_weight=0.5,
            confidence_weight=0.5,
            incident_eligible=True,
            created_by="operator@example.com",
        )


def test_custom_detection_rule_schema_rejects_ancestor_scope_on_runtime_target() -> None:
    with pytest.raises(ValidationError):
        CustomDetectionRuleCreateIn(
            slug="bad-rule-2",
            name="Bad rule 2",
            description="Ancestor scope is process-only.",
            category="custom",
            target="runtime",
            condition={"field": "privileged", "op": "equals", "value": True, "scope": "ancestor"},
            severity_weight=0.5,
            confidence_weight=0.5,
            incident_eligible=True,
            created_by="operator@example.com",
        )


def _allowlist_payload(rule_id: str) -> DetectionAllowlistCreateIn:
    return DetectionAllowlistCreateIn(
        image_digest="example/app@sha256:" + "a" * 64,
        rule_id=rule_id,
        executable="nc",
        reason="Known-good tool used by the deploy sidecar.",
        approved_by="operator@example.com",
    )


@pytest.mark.parametrize("rule_id", ["POR-DET-002", "POR-DET-003", "POR-DET-004"])
def test_detection_allowlist_schema_still_accepts_the_fixed_builtin_rule_ids(rule_id: str) -> None:
    assert _allowlist_payload(rule_id).rule_id == rule_id


def test_detection_allowlist_schema_accepts_a_custom_rule_id() -> None:
    # Custom rule ids (POR-CUS-<slug>) used to be rejected by a fixed Literal, so a
    # custom rule's matches could never be allowlisted no matter what it detected.
    assert _allowlist_payload("POR-CUS-nc-listener").rule_id == "POR-CUS-nc-listener"


def test_detection_allowlist_schema_rejects_an_unknown_rule_id() -> None:
    with pytest.raises(ValidationError):
        _allowlist_payload("POR-DET-999")
    with pytest.raises(ValidationError):
        _allowlist_payload("POR-CUS-")
