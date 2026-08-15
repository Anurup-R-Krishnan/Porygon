#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def request(method: str, url: str, *, token: str | None = None, payload: dict | None = None) -> object:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Porygon-Operator-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Porygon API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach Porygon API: {exc.reason}") from exc


def operator_token() -> str:
    value = os.getenv("PORYGON_OPERATOR_API_TOKEN", "")
    if len(value) < 32:
        raise SystemExit("Set PORYGON_OPERATOR_API_TOKEN to the operator token used by the stack")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Porygon Phase 7 response decisions")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("policy")
    generate = commands.add_parser("generate")
    generate.add_argument("incident_id")

    recommendations = commands.add_parser("recommendations")
    recommendations.add_argument("--incident-id")
    recommendations.add_argument("--status", choices=["proposed", "approved", "rejected"])

    approve = commands.add_parser("approve")
    approve.add_argument("recommendation_id")
    approve.add_argument("action", choices=["observe_only", "pause_container", "stop_container"])
    approve.add_argument("--actor", required=True)
    approve.add_argument("--note", required=True)
    approve.add_argument("--acknowledge-disruption", action="store_true")

    reject = commands.add_parser("reject")
    reject.add_argument("recommendation_id")
    reject.add_argument("--actor", required=True)
    reject.add_argument("--note", required=True)

    executions = commands.add_parser("executions")
    executions.add_argument("--incident-id")
    executions.add_argument("--status")

    get_execution = commands.add_parser("execution")
    get_execution.add_argument("execution_id")

    rollback = commands.add_parser("rollback")
    rollback.add_argument("execution_id")
    rollback.add_argument("--actor", required=True)
    rollback.add_argument("--note", required=True)
    rollback.add_argument("--acknowledge-limitations", action="store_true")

    retry = commands.add_parser("retry")
    retry.add_argument("execution_id")
    retry.add_argument("--actor", required=True)
    retry.add_argument("--note", required=True)
    retry.add_argument("--acknowledge-retry", action="store_true")

    audit = commands.add_parser("audit")
    audit.add_argument("incident_id")

    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    if args.command == "policy":
        result = request("GET", f"{base}/api/v1/response-policy")
    elif args.command == "generate":
        result = request(
            "POST",
            f"{base}/operator/v1/incidents/{args.incident_id}/response-recommendations",
            token=operator_token(),
        )
    elif args.command == "recommendations":
        query = urllib.parse.urlencode(
            {k: v for k, v in {"incident_id": args.incident_id, "status": args.status}.items() if v}
        )
        result = request("GET", f"{base}/api/v1/response-recommendations?{query}")
    elif args.command == "approve":
        result = request(
            "POST",
            f"{base}/operator/v1/response-recommendations/{args.recommendation_id}/approve",
            token=operator_token(),
            payload={
                "action_type": args.action,
                "actor": args.actor,
                "note": args.note,
                "acknowledge_disruption": args.acknowledge_disruption,
            },
        )
    elif args.command == "reject":
        result = request(
            "POST",
            f"{base}/operator/v1/response-recommendations/{args.recommendation_id}/reject",
            token=operator_token(),
            payload={"actor": args.actor, "note": args.note},
        )
    elif args.command == "executions":
        query = urllib.parse.urlencode(
            {k: v for k, v in {"incident_id": args.incident_id, "status": args.status}.items() if v}
        )
        result = request("GET", f"{base}/api/v1/response-executions?{query}")
    elif args.command == "execution":
        result = request("GET", f"{base}/api/v1/response-executions/{args.execution_id}")
    elif args.command == "rollback":
        result = request(
            "POST",
            f"{base}/operator/v1/response-executions/{args.execution_id}/rollback",
            token=operator_token(),
            payload={
                "actor": args.actor,
                "note": args.note,
                "acknowledge_limitations": args.acknowledge_limitations,
            },
        )
    elif args.command == "retry":
        result = request(
            "POST",
            f"{base}/operator/v1/response-executions/{args.execution_id}/retry",
            token=operator_token(),
            payload={
                "actor": args.actor,
                "note": args.note,
                "acknowledge_retry": args.acknowledge_retry,
            },
        )
    else:
        result = request("GET", f"{base}/api/v1/incidents/{args.incident_id}/response-audit")

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
