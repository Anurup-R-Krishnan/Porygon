#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def request(
    method: str,
    url: str,
    *,
    operator: bool = False,
    payload: dict[str, Any] | None = None,
) -> object:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    if operator:
        token = os.getenv("PORYGON_OPERATOR_API_TOKEN", "")
        if len(token) < 32:
            raise SystemExit("Set PORYGON_OPERATOR_API_TOKEN to the operator token used by the stack")
        headers["X-Porygon-Operator-Token"] = token
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"Porygon API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach Porygon API: {exc.reason}") from exc


def query_string(values: dict[str, object | None]) -> str:
    return urllib.parse.urlencode({key: value for key, value in values.items() if value is not None})


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Porygon Phase 8 image scans and vulnerability evidence")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("policy", help="Show evidence stages and the exploitation claim boundary")

    create = commands.add_parser("create", help="Queue a digest-bound image scan")
    create.add_argument("--image-digest", required=True)
    create.add_argument("--requested-by", required=True)
    create.add_argument("--docker-host-id")
    create.add_argument("--scan-reference", default="initial")
    create.add_argument("--note")

    scans = commands.add_parser("scans", help="List image scans")
    scans.add_argument("--image-digest")
    scans.add_argument("--status", choices=["queued", "claimed", "completed", "failed"])
    scans.add_argument("--limit", type=int, default=100)

    get_scan = commands.add_parser("scan", help="Read one scan summary and immutable findings")
    get_scan.add_argument("scan_id")

    get_sbom = commands.add_parser("sbom", help="Read the full CycloneDX document for one scan")
    get_sbom.add_argument("scan_id")

    get_report = commands.add_parser("report", help="Read the preserved raw Trivy JSON report")
    get_report.add_argument("scan_id")

    findings = commands.add_parser("findings", help="List vulnerability findings")
    findings.add_argument("--image-digest")
    findings.add_argument("--cve-id")
    findings.add_argument("--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    findings.add_argument("--limit", type=int, default=100)

    intel = commands.add_parser("intel", help="Read the latest known EPSS/KEV record for one CVE")
    intel.add_argument("cve_id")

    args = parser.parse_args()
    base = args.base_url.rstrip("/")

    if args.command == "policy":
        result = request("GET", f"{base}/api/v1/vulnerability-policy")
    elif args.command == "create":
        result = request(
            "POST",
            f"{base}/operator/v1/image-scans",
            operator=True,
            payload={
                "image_digest": args.image_digest,
                "requested_by": args.requested_by,
                "docker_host_id": args.docker_host_id,
                "scan_reference": args.scan_reference,
                "note": args.note,
                "scanner_name": "trivy",
                "scanner_version": "0.72.0",
            },
        )
    elif args.command == "scans":
        query = query_string(
            {"image_digest": args.image_digest, "status": args.status, "limit": args.limit}
        )
        result = request("GET", f"{base}/api/v1/image-scans?{query}")
    elif args.command == "scan":
        result = request("GET", f"{base}/api/v1/image-scans/{args.scan_id}")
    elif args.command == "sbom":
        result = request("GET", f"{base}/api/v1/image-scans/{args.scan_id}/sbom")
    elif args.command == "report":
        result = request("GET", f"{base}/api/v1/image-scans/{args.scan_id}/report")
    elif args.command == "findings":
        query = query_string(
            {
                "image_digest": args.image_digest,
                "cve_id": args.cve_id,
                "severity": args.severity,
                "limit": args.limit,
            }
        )
        result = request("GET", f"{base}/api/v1/vulnerabilities?{query}")
    else:
        result = request("GET", f"{base}/api/v1/vulnerability-intel/{args.cve_id.upper()}")

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
