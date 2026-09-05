#!/usr/bin/env python3
"""Incident alerting: watch for new open incidents and email a human.

A detection nobody sees is not security. This script closes that gap: it
polls the real backend (the same GET /api/v1/incidents endpoint the
dashboard uses), finds incidents at or above a severity threshold that
have not been notified yet, and sends a real email describing exactly what
happened, with links back to the live incident and its evidence timeline.

State is kept on disk (--state-file) so a restart never re-sends an alert
for an incident already notified, and a crash never silently drops one
that has not been.

Configuration is entirely via environment variables (or CLI flags), so the
same script works with Gmail (an app password, not the account password:
https://myaccount.google.com/apppasswords), any other SMTP provider, or a
local mail relay:

    PORYGON_ALERT_SMTP_HOST=smtp.gmail.com
    PORYGON_ALERT_SMTP_PORT=587
    PORYGON_ALERT_SMTP_USER=you@gmail.com
    PORYGON_ALERT_SMTP_PASSWORD=<16-char app password>
    PORYGON_ALERT_FROM=you@gmail.com
    PORYGON_ALERT_TO=you@gmail.com
    PORYGON_ALERT_MIN_SEVERITY=high      # low|medium|high|critical
    PORYGON_ALERT_DASHBOARD_URL=http://127.0.0.1:3000

Usage:
    python3 scripts/incident_alerts.py watch --interval-seconds 30
    python3 scripts/incident_alerts.py check           # one-shot, for cron
    python3 scripts/incident_alerts.py test-email       # send one test email now
"""
from __future__ import annotations

import argparse
import json
import os
import smtplib
import sys
import time
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_STATE_FILE = ROOT / "artifacts" / "incident_alert_state.json"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(name, default)


class AlertConfig:
    def __init__(self, args: argparse.Namespace) -> None:
        self.base_url = args.base_url or _env("PORYGON_ALERT_BASE_URL", "http://127.0.0.1:8000")
        self.dashboard_url = args.dashboard_url or _env("PORYGON_ALERT_DASHBOARD_URL", "http://127.0.0.1:3000")
        self.min_severity = (args.min_severity or _env("PORYGON_ALERT_MIN_SEVERITY", "high")).lower()
        self.smtp_host = _env("PORYGON_ALERT_SMTP_HOST")
        self.smtp_port = int(_env("PORYGON_ALERT_SMTP_PORT", "587") or 587)
        self.smtp_user = _env("PORYGON_ALERT_SMTP_USER")
        self.smtp_password = _env("PORYGON_ALERT_SMTP_PASSWORD")
        self.mail_from = _env("PORYGON_ALERT_FROM") or self.smtp_user
        self.mail_to = _env("PORYGON_ALERT_TO") or self.smtp_user
        self.state_file = Path(args.state_file) if args.state_file else DEFAULT_STATE_FILE
        if self.min_severity not in SEVERITY_ORDER:
            raise SystemExit(f"PORYGON_ALERT_MIN_SEVERITY must be one of {sorted(SEVERITY_ORDER)}, got {self.min_severity!r}")

    def require_smtp(self) -> None:
        missing = [
            name for name, value in (
                ("PORYGON_ALERT_SMTP_HOST", self.smtp_host),
                ("PORYGON_ALERT_SMTP_USER", self.smtp_user),
                ("PORYGON_ALERT_SMTP_PASSWORD", self.smtp_password),
                ("PORYGON_ALERT_TO / PORYGON_ALERT_SMTP_USER", self.mail_to),
            ) if not value
        ]
        if missing:
            raise SystemExit(
                "Missing required email configuration: " + ", ".join(missing) +
                ". Set these environment variables (see scripts/incident_alerts.py docstring)."
            )


def fetch_open_incidents(base_url: str, limit: int = 50) -> list[dict[str, Any]]:
    url = f"{base_url}/api/v1/incidents?limit={limit}"
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.loads(response.read())


def load_state(state_file: Path) -> dict[str, Any]:
    if not state_file.exists():
        return {"notified_incident_ids": []}
    return json.loads(state_file.read_text(encoding="utf-8"))


def save_state(state_file: Path, state: dict[str, Any]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")


def severity_meets_threshold(incident: dict[str, Any], min_severity: str) -> bool:
    level = incident.get("severity_level", "low")
    return SEVERITY_ORDER.get(level, 0) >= SEVERITY_ORDER[min_severity]


def format_alert_email(incident: dict[str, Any], dashboard_url: str) -> tuple[str, str]:
    incident_id = incident["incident_id"]
    subject = f"[Porygon] {incident['severity_level'].upper()} incident: {incident['title']}"

    top_findings = incident.get("findings", [])[:5]
    findings_lines = "\n".join(
        f"  - {f.get('rule_id', '?')} ({f.get('name', '?')}): {f.get('summary', '')}"
        for f in top_findings
    )
    body = f"""Porygon detected a behavioral deviation and opened an incident.

Title:       {incident['title']}
Status:      {incident['status']}
Severity:    {incident['severity_level']} (score {incident['severity_score']:.3f})
Confidence:  {incident['confidence_level']} (score {incident['confidence_score']:.3f})
Anomaly:     {incident['anomaly_score']:.3f} (behavioural distance from the trained baseline)
Image:       {incident['image_digest']}
Containers:  {', '.join(incident.get('container_ids', []))}
First seen:  {incident['first_seen_at']}
Created:     {incident['created_at']}

Summary: {incident['summary']}

Top evidence:
{findings_lines}

This score is a behavioural-distance measurement, not proof of compromise.
Review the evidence before taking action.

View the full evidence trace and approve/dismiss:
  {dashboard_url}/#pipeline (select incident {incident_id})

Raw incident record:
  {dashboard_url.replace(':3000', ':8000')}/api/v1/incidents/{incident_id}
"""
    return subject, body


def send_email(config: AlertConfig, subject: str, body: str) -> None:
    config.require_smtp()
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = config.mail_from
    message["To"] = config.mail_to

    with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=30) as server:
        server.starttls()
        server.login(config.smtp_user, config.smtp_password)
        server.sendmail(config.mail_from, [config.mail_to], message.as_string())


def check_once(config: AlertConfig, *, dry_run: bool = False) -> int:
    """Fetch open incidents, send an email for each new one at/above
    threshold, and record it as notified. Returns the count of alerts sent."""
    state = load_state(config.state_file)
    notified: set[str] = set(state.get("notified_incident_ids", []))

    incidents = fetch_open_incidents(config.base_url)
    sent = 0
    for incident in incidents:
        if incident.get("status") != "open":
            continue
        if incident["incident_id"] in notified:
            continue
        if not severity_meets_threshold(incident, config.min_severity):
            continue

        subject, body = format_alert_email(incident, config.dashboard_url)
        if dry_run:
            print(f"[dry-run] would send: {subject}")
            sent += 1
            continue  # never mark an incident notified on a dry run; the
            # real alert must still fire once dry-run testing is done
        send_email(config, subject, body)
        print(f"[sent] {subject}")
        notified.add(incident["incident_id"])
        sent += 1

    if dry_run:
        return sent  # state is never written on a dry run
    state["notified_incident_ids"] = sorted(notified)
    state["last_checked_at_utc"] = datetime.now(timezone.utc).isoformat()
    save_state(config.state_file, state)
    return sent


def watch(config: AlertConfig, *, interval_seconds: int, dry_run: bool) -> None:
    print(f"Watching {config.base_url} for incidents >= {config.min_severity}, every {interval_seconds}s")
    while True:
        try:
            sent = check_once(config, dry_run=dry_run)
            if sent:
                print(f"[{datetime.now(timezone.utc).isoformat()}] sent {sent} alert(s)")
        except Exception as error:  # keep watching even if one poll fails
            print(f"[{datetime.now(timezone.utc).isoformat()}] check failed: {error}", file=sys.stderr)
        time.sleep(interval_seconds)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base-url")
    parser.add_argument("--dashboard-url")
    parser.add_argument("--min-severity", choices=sorted(SEVERITY_ORDER))
    parser.add_argument("--state-file")
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="Check once and exit (for cron)")
    check_parser.add_argument("--dry-run", action="store_true", help="Print what would be sent, do not send email")

    watch_parser = subparsers.add_parser("watch", help="Poll continuously")
    watch_parser.add_argument("--interval-seconds", type=int, default=30)
    watch_parser.add_argument("--dry-run", action="store_true")

    subparsers.add_parser("test-email", help="Send one test email immediately using a synthetic incident")

    args = parser.parse_args(argv)
    config = AlertConfig(args)

    if args.command == "check":
        sent = check_once(config, dry_run=args.dry_run)
        print(f"{sent} alert(s) sent" if not args.dry_run else f"{sent} alert(s) would be sent")
        return 0
    if args.command == "watch":
        watch(config, interval_seconds=args.interval_seconds, dry_run=args.dry_run)
        return 0
    if args.command == "test-email":
        synthetic = {
            "incident_id": "test-0000-0000-0000-000000000000",
            "title": "Test alert from scripts/incident_alerts.py",
            "status": "open",
            "severity_level": "critical",
            "severity_score": 0.9,
            "confidence_level": "high",
            "confidence_score": 1.0,
            "anomaly_score": 0.5,
            "image_digest": "test@sha256:" + "0" * 64,
            "container_ids": ["test-container"],
            "first_seen_at": datetime.now(timezone.utc).isoformat(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "summary": "This is a test email to confirm alert delivery works.",
            "findings": [],
        }
        subject, body = format_alert_email(synthetic, config.dashboard_url)
        send_email(config, subject, body)
        print(f"test email sent to {config.mail_to}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
