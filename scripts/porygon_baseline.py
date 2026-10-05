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
    parser = argparse.ArgumentParser(description="Build and manage Porygon behaviour profiles")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="Build a draft profile from an approved interval")
    build.add_argument("--image-digest", required=True)
    build.add_argument("--start", required=True, help="ISO-8601 timestamp with timezone")
    build.add_argument("--end", required=True, help="ISO-8601 timestamp with timezone")
    build.add_argument("--approved-by", required=True)
    build.add_argument("--approval-reference")
    build.add_argument("--notes")
    build.add_argument("--window-seconds", type=int, default=60)
    build.add_argument("--minimum-process-events", type=int, default=20)
    build.add_argument("--minimum-nonempty-windows", type=int, default=3)

    activate = commands.add_parser("activate", help="Activate a quality-passing draft")
    activate.add_argument("profile_id")

    list_command = commands.add_parser("list", help="List stored profiles")
    list_command.add_argument("--image-digest")
    list_command.add_argument("--status", choices=["draft", "active", "retired"])

    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    if args.command == "build":
        result = _request(
            "POST",
            f"{base_url}/internal/v1/baselines/build",
            token=_token(),
            payload={
                "image_digest": args.image_digest,
                "training_start": args.start,
                "training_end": args.end,
                "window_seconds": args.window_seconds,
                "minimum_process_events": args.minimum_process_events,
                "minimum_nonempty_windows": args.minimum_nonempty_windows,
                "approved_by": args.approved_by,
                "approval_reference": args.approval_reference,
                "notes": args.notes,
            },
        )
    elif args.command == "activate":
        result = _request(
            "POST",
            f"{base_url}/internal/v1/baselines/{args.profile_id}/activate",
            token=_token(),
        )
    else:
        query = {
            key: value
            for key, value in {
                "image_digest": args.image_digest,
                "status": args.status,
            }.items()
            if value
        }
        suffix = "?" + urllib.parse.urlencode(query) if query else ""
        result = _request("GET", f"{base_url}/api/v1/baselines{suffix}")

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
