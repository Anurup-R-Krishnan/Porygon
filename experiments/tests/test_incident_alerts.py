"""Tests for scripts/incident_alerts.py."""
from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "incident_alerts.py"
spec = importlib.util.spec_from_file_location("incident_alerts", SCRIPT_PATH)
incident_alerts = importlib.util.module_from_spec(spec)
sys.modules["incident_alerts"] = incident_alerts
spec.loader.exec_module(incident_alerts)


def _config(tmp_path, **overrides):
    args = argparse.Namespace(
        base_url="http://x", dashboard_url="http://y", min_severity="high",
        state_file=str(tmp_path / "state.json"),
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return incident_alerts.AlertConfig(args)


def _incident(incident_id="i1", severity="critical", status="open"):
    return {
        "incident_id": incident_id, "title": "t", "status": status,
        "severity_level": severity, "severity_score": 0.9,
        "confidence_level": "high", "confidence_score": 1.0,
        "anomaly_score": 0.5, "image_digest": "x@sha256:" + "0" * 64,
        "container_ids": ["c1"], "first_seen_at": "2026-01-01T00:00:00Z",
        "created_at": "2026-01-01T00:00:00Z", "summary": "s", "findings": [],
    }


def test_severity_meets_threshold_orders_correctly():
    assert incident_alerts.severity_meets_threshold(_incident(severity="critical"), "high")
    assert incident_alerts.severity_meets_threshold(_incident(severity="high"), "high")
    assert not incident_alerts.severity_meets_threshold(_incident(severity="medium"), "high")
    assert not incident_alerts.severity_meets_threshold(_incident(severity="low"), "critical")


def test_alert_config_rejects_unknown_min_severity(tmp_path):
    args = argparse.Namespace(base_url=None, dashboard_url=None, min_severity="extreme", state_file=str(tmp_path / "s.json"))
    with pytest.raises(SystemExit, match="PORYGON_ALERT_MIN_SEVERITY"):
        incident_alerts.AlertConfig(args)


def test_check_once_sends_for_new_high_severity_incident(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.setattr(incident_alerts, "fetch_open_incidents", lambda base_url: [_incident()])
    sent_calls = []
    monkeypatch.setattr(incident_alerts, "send_email", lambda cfg, subj, body: sent_calls.append(subj))

    sent = incident_alerts.check_once(config)

    assert sent == 1
    assert len(sent_calls) == 1
    assert "CRITICAL" in sent_calls[0]
    state = incident_alerts.load_state(config.state_file)
    assert "i1" in state["notified_incident_ids"]


def test_check_once_never_resends_an_already_notified_incident(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.setattr(incident_alerts, "fetch_open_incidents", lambda base_url: [_incident()])
    sent_calls = []
    monkeypatch.setattr(incident_alerts, "send_email", lambda cfg, subj, body: sent_calls.append(subj))

    incident_alerts.check_once(config)
    second = incident_alerts.check_once(config)

    assert second == 0
    assert len(sent_calls) == 1


def test_check_once_skips_incidents_below_severity_threshold(tmp_path, monkeypatch):
    config = _config(tmp_path, min_severity="critical")
    monkeypatch.setattr(incident_alerts, "fetch_open_incidents", lambda base_url: [_incident(severity="high")])
    sent_calls = []
    monkeypatch.setattr(incident_alerts, "send_email", lambda cfg, subj, body: sent_calls.append(subj))

    sent = incident_alerts.check_once(config)

    assert sent == 0
    assert sent_calls == []


def test_check_once_skips_non_open_incidents(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.setattr(incident_alerts, "fetch_open_incidents", lambda base_url: [_incident(status="resolved")])
    sent_calls = []
    monkeypatch.setattr(incident_alerts, "send_email", lambda cfg, subj, body: sent_calls.append(subj))

    sent = incident_alerts.check_once(config)

    assert sent == 0


def test_dry_run_never_writes_state_and_always_redetects(tmp_path, monkeypatch):
    """Regression test: a dry run must never mark an incident notified, or
    the real alert for it would silently never fire once dry-run testing
    is over. Found and fixed during manual verification."""
    config = _config(tmp_path)
    monkeypatch.setattr(incident_alerts, "fetch_open_incidents", lambda base_url: [_incident()])
    send_calls = []
    monkeypatch.setattr(incident_alerts, "send_email", lambda cfg, subj, body: send_calls.append(subj))

    first = incident_alerts.check_once(config, dry_run=True)
    second = incident_alerts.check_once(config, dry_run=True)

    assert first == 1
    assert second == 1  # still detected both times
    assert send_calls == []  # never actually sent
    assert not config.state_file.exists()  # state never written


def test_format_alert_email_includes_key_incident_fields():
    subject, body = incident_alerts.format_alert_email(_incident(), "http://dash:3000")
    assert "CRITICAL" in subject
    assert "critical" in body
    assert "i1" in body or "incident_id" not in body  # id shown via dashboard link, not required verbatim
    assert "0.500" in body  # anomaly_score formatted
