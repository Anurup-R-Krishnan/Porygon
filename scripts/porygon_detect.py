#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def _request(method: str, url: str, token: str | None = None, payload: dict | None = None) -> object:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Porygon-Internal-Token"] = token
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Porygon API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach Porygon API: {exc.reason}") from exc


def _token() -> str:
    token = os.getenv("PORYGON_INTERNAL_API_TOKEN", "")
    if len(token) < 32:
        raise SystemExit("Set PORYGON_INTERNAL_API_TOKEN to the same token used by the stack")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Porygon Phase 6 detection and inspect incidents")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("config", help="Show the immutable deterministic ruleset")

    run = commands.add_parser("run", help="Run detection for one stored anomaly score")
    run.add_argument("score_id")

    list_runs = commands.add_parser("runs", help="List detection runs")
    list_runs.add_argument("--image-digest")
    list_runs.add_argument(
        "--status",
        choices=["insufficient_data", "no_findings", "findings_only", "incident_created"],
    )
    list_runs.add_argument("--limit", type=int, default=100)

    get_run = commands.add_parser("get-run", help="Read one detection run with its incident")
    get_run.add_argument("run_id")

    incidents = commands.add_parser("incidents", help="List incidents")
    incidents.add_argument("--image-digest")
    incidents.add_argument("--status", choices=["open", "acknowledged", "resolved", "dismissed"])
    incidents.add_argument("--minimum-severity", type=float)
    incidents.add_argument("--limit", type=int, default=100)

    incident = commands.add_parser("incident", help="Read one incident")
    incident.add_argument("incident_id")

    timeline = commands.add_parser("timeline", help="Read one incident evidence timeline")
    timeline.add_argument("incident_id")

    update = commands.add_parser("status", help="Acknowledge, resolve, or dismiss an incident")
    update.add_argument("incident_id")
    update.add_argument("new_status", choices=["acknowledged", "resolved", "dismissed"])
    update.add_argument("--actor", required=True)
    update.add_argument("--note")

    allowlists = commands.add_parser("allowlists", help="List digest-scoped detection allowlists")
    allowlists.add_argument("--image-digest")
    allowlists.add_argument("--active", choices=["true", "false"])

    create_allowlist = commands.add_parser(
        "allowlist-create",
        help="Approve an exact executable exception for one image digest and rule",
    )
    create_allowlist.add_argument("--image-digest", required=True)
    create_allowlist.add_argument(
        "--rule-id",
        required=True,
        choices=["POR-DET-002", "POR-DET-003", "POR-DET-004"],
    )
    create_allowlist.add_argument("--executable", required=True)
    create_allowlist.add_argument("--parent-executable")
    create_allowlist.add_argument("--reason", required=True)
    create_allowlist.add_argument("--approved-by", required=True)
    create_allowlist.add_argument("--approval-reference")
    create_allowlist.add_argument("--expires-at")

    deactivate_allowlist = commands.add_parser(
        "allowlist-deactivate",
        help="Deactivate one approved detection exception",
    )
    deactivate_allowlist.add_argument("allowlist_id")
    deactivate_allowlist.add_argument("--actor", required=True)

    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    if args.command == "config":
        result = _request("GET", f"{base_url}/api/v1/detection-rules/config")
    elif args.command == "run":
        result = _request(
            "POST",
            f"{base_url}/internal/v1/detections/run",
            token=_token(),
            payload={"anomaly_score_id": args.score_id},
        )
    elif args.command == "runs":
        query = {
            key: value
            for key, value in {
                "image_digest": args.image_digest,
                "status": args.status,
                "limit": args.limit,
            }.items()
            if value is not None
        }
        result = _request("GET", f"{base_url}/api/v1/detection-runs?{urllib.parse.urlencode(query)}")
    elif args.command == "get-run":
        result = _request("GET", f"{base_url}/api/v1/detection-runs/{args.run_id}")
    elif args.command == "incidents":
        query = {
            key: value
            for key, value in {
                "image_digest": args.image_digest,
                "status": args.status,
                "minimum_severity": args.minimum_severity,
                "limit": args.limit,
            }.items()
            if value is not None
        }
        result = _request("GET", f"{base_url}/api/v1/incidents?{urllib.parse.urlencode(query)}")
    elif args.command == "incident":
        result = _request("GET", f"{base_url}/api/v1/incidents/{args.incident_id}")
    elif args.command == "timeline":
        result = _request("GET", f"{base_url}/api/v1/incidents/{args.incident_id}/timeline")
    elif args.command == "status":
        result = _request(
            "POST",
            f"{base_url}/internal/v1/incidents/{args.incident_id}/status",
            token=_token(),
            payload={"status": args.new_status, "actor": args.actor, "note": args.note},
        )
    elif args.command == "allowlists":
        query = {
            key: value
            for key, value in {
                "image_digest": args.image_digest,
                "active": args.active,
            }.items()
            if value is not None
        }
        result = _request(
            "GET",
            f"{base_url}/api/v1/detection-allowlists?{urllib.parse.urlencode(query)}",
        )
    elif args.command == "allowlist-create":
        result = _request(
            "POST",
            f"{base_url}/internal/v1/detection-allowlists",
            token=_token(),
            payload={
                "image_digest": args.image_digest,
                "rule_id": args.rule_id,
                "executable": args.executable,
                "parent_executable": args.parent_executable,
                "reason": args.reason,
                "approved_by": args.approved_by,
                "approval_reference": args.approval_reference,
                "expires_at": args.expires_at,
            },
        )
    else:
        result = _request(
            "POST",
            f"{base_url}/internal/v1/detection-allowlists/{args.allowlist_id}/deactivate",
            token=_token(),
            payload={"actor": args.actor},
        )

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
