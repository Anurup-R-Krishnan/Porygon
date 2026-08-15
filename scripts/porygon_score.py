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
    parser = argparse.ArgumentParser(description="Compute and inspect Porygon behavioural-distance scores")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    commands = parser.add_subparsers(dest="command", required=True)

    compute = commands.add_parser("compute", help="Score one completed fixed observation window")
    compute.add_argument("--image-digest", required=True)
    compute.add_argument("--window-start", required=True, help="ISO-8601 timestamp with timezone")
    compute.add_argument("--profile-id", help="Use a specific active or retired profile version")

    list_command = commands.add_parser("list", help="List stored scores")
    list_command.add_argument("--image-digest")
    list_command.add_argument("--profile-id")
    list_command.add_argument("--status", choices=["scored", "insufficient_data"])
    list_command.add_argument("--minimum-score", type=float)
    list_command.add_argument("--limit", type=int, default=100)

    get_command = commands.add_parser("get", help="Read one stored score")
    get_command.add_argument("score_id")

    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    if args.command == "compute":
        result = _request(
            "POST",
            f"{base_url}/internal/v1/anomaly-scores/compute",
            token=_token(),
            payload={
                "image_digest": args.image_digest,
                "window_start": args.window_start,
                "profile_id": args.profile_id,
            },
        )
    elif args.command == "get":
        result = _request("GET", f"{base_url}/api/v1/anomaly-scores/{args.score_id}")
    else:
        query = {
            key: value
            for key, value in {
                "image_digest": args.image_digest,
                "profile_id": args.profile_id,
                "status": args.status,
                "minimum_score": args.minimum_score,
                "limit": args.limit,
            }.items()
            if value is not None
        }
        result = _request(
            "GET",
            f"{base_url}/api/v1/anomaly-scores?{urllib.parse.urlencode(query)}",
        )

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
