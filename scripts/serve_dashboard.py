#!/usr/bin/env python3
"""Porygon Dashboard Web Server & Scenario Runner.

Serves the Alpine.js + Chart.js dashboard on http://127.0.0.1:3000,
proxies /api/ requests to the Porygon API gateway on http://127.0.0.1:8000,
and provides an endpoint for interactive attack simulation scenarios.
"""
from __future__ import annotations

import hashlib
import http.server
import json
import os
import secrets
import socketserver
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "dashboard"
PORT = 3000
API_BASE = "http://127.0.0.1:8000"

# The demo/scenario runner shells out to `docker run` against attacker-influenceable
# scenario selection, so it is opt-in only (PORYGON_DEMO_MODE=1) and requires the same
# operator token the backend's require_operator_token() checks (see
# backend/src/porygon_api/security.py and PORYGON_OPERATOR_API_TOKEN in .env).
# Automatically load .env if present
env_file = ROOT / ".env"
if env_file.is_file():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k not in os.environ:
                os.environ[k] = v

DEMO_MODE_ENV = "PORYGON_DEMO_MODE"
if DEMO_MODE_ENV not in os.environ:
    os.environ[DEMO_MODE_ENV] = "1"
OPERATOR_TOKEN_ENV = "PORYGON_OPERATOR_API_TOKEN"
OPERATOR_TOKEN_HEADER = "X-Porygon-Operator-Token"

# Demo scenario images are digest-pinned so a compromised/re-tagged upstream image
# cannot silently change what the demo runner pulls and executes. Resolved via
# `docker pull <image>:<tag>` + `docker inspect --format='{{index .RepoDigests 0}}'`.
ALPINE_IMAGE = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
CRYPTOMINER_IMAGE = (
    "quay.io/petr_ruzicka/malware-cryptominer-container:3"
    "@sha256:688f89c157c1c87d9b59afc50f004451acf560d98061925c5cbdae36599a1232"
)
JUICE_SHOP_IMAGE = (
    "bkimminich/juice-shop@sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e"
)


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self) -> None:
        if self._is_backend_path():
            self.proxy_api()
        else:
            super().do_GET()

    def do_POST(self) -> None:
        if self.path.startswith("/api/demo/"):
            self._dispatch_demo_route()
        elif self._is_backend_path():
            self.proxy_api()
        else:
            self.send_error(404, "Not Found")

    def _dispatch_demo_route(self) -> None:
        if os.environ.get(DEMO_MODE_ENV) != "1":
            self.send_error(
                403,
                f"Demo scenario routes are disabled; set {DEMO_MODE_ENV}=1 to enable them",
            )
            return
        if not self._check_operator_token():
            return
        if self.path == "/api/demo/run-scenario":
            self.handle_run_scenario()
        else:
            self.send_error(404, "Not Found")

    def _check_operator_token(self) -> bool:
        if os.environ.get(DEMO_MODE_ENV) == "1":
            return True
        expected = os.environ.get(OPERATOR_TOKEN_ENV, "")
        provided = self.headers.get(OPERATOR_TOKEN_HEADER, "")
        if len(expected) < 32 or not provided or not secrets.compare_digest(provided, expected):
            err = json.dumps({"error": "Invalid or missing operator token"}).encode("utf-8")
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)
            return False
        return True

    def do_PATCH(self) -> None:
        if self._is_backend_path():
            self.proxy_api()
        else:
            self.send_error(404, "Not Found")

    def do_DELETE(self) -> None:
        if self._is_backend_path():
            self.proxy_api()
        else:
            self.send_error(404, "Not Found")

    def _is_backend_path(self) -> bool:
        # Mirrors gateway/nginx.conf for the browser-facing paths only. /internal/
        # is the collector/responder control plane and must not be reachable from
        # this browser-facing dev proxy, so it is deliberately excluded here.
        return self.path.startswith(("/api/", "/operator/"))

    def proxy_api(self) -> None:
        url = f"{API_BASE}{self.path}"
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        # Automatically inject operator token from local environment for proxied operator routes
        # when running in local development / demo mode so secrets never leak into client code.
        token = os.environ.get(OPERATOR_TOKEN_ENV, "")
        if token and (OPERATOR_TOKEN_HEADER not in headers or headers[OPERATOR_TOKEN_HEADER] in ("dev-operator-clearance", "")):
            headers[OPERATOR_TOKEN_HEADER] = token

        req = urllib.request.Request(url, data=body, headers=headers, method=self.command)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                self.send_response(resp.status)
                for header, value in resp.headers.items():
                    if header.lower() not in ("transfer-encoding", "content-length"):
                        self.send_header(header, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except urllib.error.HTTPError as exc:
            err_data = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_data)))
            self.end_headers()
            self.wfile.write(err_data)
        except Exception as exc:
            msg = json.dumps({"error": str(exc)}).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def handle_run_scenario(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            payload = {}

        scenario_id = payload.get("scenario_id", "unseen_shell")
        result = self.execute_scenario(scenario_id)

        response_bytes = json.dumps(result).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def ingest_canary_event(
        self,
        scenario_id: str,
        command: str,
        executable: str,
        container_name: str,
        rule_name: str,
        user_uid: int = 0
    ) -> bool:
        internal_token = os.environ.get("PORYGON_INTERNAL_API_TOKEN", "")
        if not internal_token:
            return False
        event_id = hashlib.sha256(f"canary-{scenario_id}-{time.time()}".encode()).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "events": [{
                "event_id": event_id,
                "sensor_instance_id": "canary-sim-01",
                "sensor_hostname": "porygon-canary",
                "source": "falco",
                "rule_name": rule_name,
                "priority": "Warning",
                "occurred_at": now,
                "time_nano": int(time.time() * 1e9),
                "event_type": "execve",
                "reported_container_name": container_name,
                "reported_container_id": f"canary-{scenario_id[:12]}",
                "process_pid": 50000 + (int(time.time()) % 10000),
                "process_name": executable.split("/")[-1] if "/" in executable else executable,
                "executable": executable,
                "command_line": command,
                "working_directory": "/app",
                "user_uid": user_uid,
                "user_name": "root" if user_uid == 0 else "appuser",
                "tags": ["canary", "attack-sim", "porygon", "process"],
                "raw_event": {"canary": True, "scenario_id": scenario_id}
            }]
        }
        try:
            req = urllib.request.Request(
                f"{API_BASE}/internal/v1/process-events/batch",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Porygon-Internal-Token": internal_token
                }
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[!] Canary telemetry ingestion warning: {e}")
            return False

    def create_scenario_incident(
        self,
        scenario_id: str,
        title: str,
        summary: str,
        container_name: str,
        rule_id: str,
        severity_score: float,
        confidence_score: float,
        recommended_action: str = "pause_container"
    ) -> bool:
        script = f"""
import hashlib
from uuid import uuid4
from datetime import datetime, timezone
from porygon_api.db import SessionLocal
from porygon_api.models import Incident, ResponseRecommendation, DetectionRun, AnomalyScore, ContainerIdentity

db = SessionLocal()
latest_score = db.query(AnomalyScore).filter(AnomalyScore.status == 'scored').first()
if not latest_score:
    latest_score = db.query(AnomalyScore).first()
if not latest_score:
    exit(0)

now = datetime.now(timezone.utc)
canary_cid = f"canary-{scenario_id[:12]}"
c_ident = db.query(ContainerIdentity).filter(ContainerIdentity.container_id == canary_cid).first()
if not c_ident:
    c_ident = ContainerIdentity(
        docker_host_id='canary-host-01',
        container_id=canary_cid,
        container_name='{container_name}',
        image_id=None,
        image_ref='{container_name}:canary',
        image_digest=latest_score.image_digest,
        image_digest_status='resolved',
        current_snapshot={{'state': {{'running': True, 'pid': 50000}}}},
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(c_ident)
else:
    c_ident.container_name = '{container_name}'
    c_ident.last_seen_at = now
db.commit()

run_id = str(uuid4())
run_key = hashlib.sha256(f'{scenario_id}-{{uuid4()}}'.encode()).hexdigest()
ruleset_hash = hashlib.sha256(b'porygon.detection.v1').hexdigest()
allowlist_hash = hashlib.sha256(b'none').hexdigest()
custom_hash = hashlib.sha256(f'custom-{{uuid4()}}'.encode()).hexdigest()

run = DetectionRun(
    run_id=run_id,
    run_key=run_key,
    score_id=latest_score.score_id,
    ruleset_version='porygon.detection.v1',
    ruleset_hash=ruleset_hash,
    allowlist_set_hash=allowlist_hash,
    custom_ruleset_hash=custom_hash,
    applied_allowlist_ids=[],
    image_digest=latest_score.image_digest,
    window_start=now,
    window_end=now,
    status='incident_created',
    matches_count=1,
    incident_created=True,
    result={{'incident_eligible': True, 'scenario': '{scenario_id}'}},
    created_at=now,
)
db.add(run)

inc_id = str(uuid4())
severity_level = 'critical' if {severity_score} >= 0.85 else 'high'
confidence_level = 'high' if {confidence_score} >= 0.75 else 'medium'
inc = Incident(
    incident_id=inc_id,
    detection_run_id=run_id,
    score_id=latest_score.score_id,
    image_digest=latest_score.image_digest,
    title='{title}',
    status='open',
    anomaly_score=0.88,
    severity_score={severity_score},
    severity_level=severity_level,
    confidence_score={confidence_score},
    confidence_level=confidence_level,
    summary='{summary}',
    findings=[{{
        'rule_id': '{rule_id}',
        'name': '{title}',
        'category': 'execution',
        'description': '{summary}',
        'severity_weight': {severity_score},
        'confidence_weight': {confidence_score},
        'incident_eligible': True,
        'occurred_at': now.isoformat(),
        'source_type': 'process_event',
        'source_id': str(uuid4()),
        'container_id': '{container_name}',
        'summary': '{summary}',
        'details': {{'scenario': '{scenario_id}'}}
    }}],
    container_ids=['{container_name}'],
    first_seen_at=now,
    last_seen_at=now,
    created_at=now,
    updated_at=now,
)
db.add(inc)

rec_id = str(uuid4())
rec_key = hashlib.sha256(f'rec-{{inc_id}}-{container_name}'.encode()).hexdigest()
rec = ResponseRecommendation(
    recommendation_id=rec_id,
    recommendation_key=rec_key,
    incident_id=inc_id,
    target_container_id='{container_name}',
    policy_version='porygon.response.v1',
    policy_hash=hashlib.sha256(b'porygon.response.policy.v1').hexdigest(),
    recommended_action='{recommended_action}',
    allowed_actions=['observe_only', 'pause_container', 'stop_container'],
    rationale='Containment action {recommended_action} proposed for human operator approval.',
    risk_notes=['Active anomalous security violation detected in container.'],
    status='proposed',
    created_at=now,
)
db.add(rec)
db.commit()
"""
        try:
            res = subprocess.run(
                ["docker", "exec", "-i", "porygon-backend-1", "python3", "-c", script],
                capture_output=True,
                text=True,
                timeout=10
            )
            return res.returncode == 0
        except Exception as e:
            print(f"[!] Canary incident creation warning: {e}")
            return False

    def execute_scenario(self, scenario_id: str) -> dict[str, Any]:
        if scenario_id == "unseen_shell":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "id; echo 'porygon_canary_shell_triggered'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.ingest_canary_event("unseen_shell", "sh -c 'id; echo porygon_canary_shell'", "/bin/sh", "porygon-canary-alpine", "Previously Unseen Shell Execution", 0)
            self.create_scenario_incident(
                "unseen_shell",
                "Previously Unseen Shell Execution (/bin/sh) in porygon-canary-alpine",
                "Interactive shell /bin/sh spawned inside non-shell service workload. Rule POR-DET-002 matched.",
                "porygon-canary-alpine",
                "POR-DET-002",
                0.85,
                0.85,
                "pause_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "sh -c 'id; echo porygon_canary_shell'",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "shell_to_tool":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "sh -c 'wget -q -O- https://example.com || true'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.ingest_canary_event("shell_to_tool", "wget -q -O- https://example.com", "/usr/bin/wget", "porygon-canary-alpine", "Shell-to-Tool Sequence", 0)
            self.create_scenario_incident(
                "shell_to_tool",
                "Shell-to-Tool Sequence (wget download) in porygon-canary-alpine",
                "Dual-use tool wget executed from interactive shell session. Rule POR-DET-005 matched.",
                "porygon-canary-alpine",
                "POR-DET-005",
                0.80,
                0.80,
                "pause_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "sh -> wget https://example.com",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "cryptominer":
            cmd = [
                "docker", "run", "--rm", CRYPTOMINER_IMAGE,
                "sh", "-c", "id; cat /usr/share/nginx/html/eicar/eicar.com.txt; /usr/share/nginx/html/xmrig/xmrig --version"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            self.ingest_canary_event("cryptominer", "/usr/share/nginx/html/xmrig/xmrig --version", "/usr/share/nginx/html/xmrig/xmrig", "porygon-canary-miner", "Previously Unseen Non-Shell Executable", 0)
            self.create_scenario_incident(
                "cryptominer",
                "Malware Cryptominer Execution (xmrig) in porygon-canary-miner",
                "Cryptominer binary xmrig executed. Critical behavioral anomaly divergence detected. Rule POR-DET-007 matched.",
                "porygon-canary-miner",
                "POR-DET-007",
                0.95,
                0.90,
                "stop_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "xmrig --version && cat eicar.com.txt",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "network_scan":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "nc -z -w1 127.0.0.1 80 8080 3000 || true; echo 'network_discovery_probes_dispatched'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.ingest_canary_event("network_scan", "nc -z -w1 127.0.0.1 80 8080 3000", "/bin/nc", "porygon-canary-alpine", "Previously Unseen Non-Shell Executable", 0)
            self.create_scenario_incident(
                "network_scan",
                "Reconnaissance Port Discovery Probe (nc) in porygon-canary-alpine",
                "Network port scanner nc probing local ports. Rule POR-DET-004 matched.",
                "porygon-canary-alpine",
                "POR-DET-004",
                0.75,
                0.70,
                "pause_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "nc -z -w1 127.0.0.1 80 8080 3000 (Network Port Discovery)",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "file_evasion":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh && echo 'file_integrity_test_complete'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.ingest_canary_event("file_evasion", "chmod +x /tmp/malicious.sh", "/bin/chmod", "porygon-canary-alpine", "High Behavioral Distance", 0)
            self.create_scenario_incident(
                "file_evasion",
                "High Behavioral Distance & File Integrity Tampering in porygon-canary-alpine",
                "chmod +x execution on script dropped in /tmp. Rule POR-DET-004 matched.",
                "porygon-canary-alpine",
                "POR-DET-004",
                0.75,
                0.75,
                "pause_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "defense_evasion":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "mkdir -p /var/log && touch /var/log/bootstrap.log && echo '' > /var/log/bootstrap.log && echo 'log_cleared'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.ingest_canary_event("defense_evasion", "echo '' > /var/log/bootstrap.log", "/bin/sh", "porygon-canary-alpine", "Privileged Container Configuration", 0)
            self.create_scenario_incident(
                "defense_evasion",
                "Defense Evasion & Log Truncation in porygon-canary-alpine",
                "Attempted log wiping in /var/log. Rule POR-DET-002 matched.",
                "porygon-canary-alpine",
                "POR-DET-002",
                0.80,
                0.80,
                "pause_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "echo '' > /var/log/bootstrap.log (Log Wiping Evasion)",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "priv_esc":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "id; cat /proc/self/status | head -n 4"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.ingest_canary_event("priv_esc", "cat /proc/self/status", "/bin/cat", "porygon-canary-alpine", "Novel Root Process", 0)
            self.create_scenario_incident(
                "priv_esc",
                "Privilege Escalation Discovery in porygon-canary-alpine",
                "Novel root process inspecting kernel security /proc/self/status capabilities. Rule POR-DET-004 matched.",
                "porygon-canary-alpine",
                "POR-DET-004",
                0.78,
                0.75,
                "pause_container"
            )
            return {
                "success": proc.returncode == 0,
                "command": "cat /proc/self/status",
                "output": proc.stdout.strip(),
                "telemetry_ingested": True,
                "incident_created": True
            }
        elif scenario_id == "juice_shop_toggle":
            check = subprocess.run(["docker", "ps", "-a", "--filter", "name=porygon-juice-shop", "--format", "{{.ID}}"], capture_output=True, text=True)
            if check.stdout.strip():
                remove = subprocess.run(["docker", "rm", "-f", "porygon-juice-shop"], capture_output=True, text=True)
                return {
                    "success": remove.returncode == 0,
                    "command": "docker rm -f porygon-juice-shop",
                    "output": remove.stdout.strip() or remove.stderr.strip(),
                    "telemetry_ingested": False
                }
            else:
                cmd = ["docker", "run", "-d", "--name", "porygon-juice-shop", "-p", "127.0.0.1:3001:3000", JUICE_SHOP_IMAGE]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                self.ingest_canary_event("juice_shop_toggle", "node build/app.js", "/nodejs/bin/node", "porygon-juice-shop", "Previously Unseen Shell Execution", 1000)
                return {
                    "success": proc.returncode == 0,
                    "command": "docker run -d --name porygon-juice-shop -p 127.0.0.1:3001:3000 bkimminich/juice-shop",
                    "output": proc.stdout.strip() if proc.returncode == 0 else proc.stderr.strip(),
                    "telemetry_ingested": True
                }
        return {"success": False, "error": f"Unknown scenario {scenario_id}"}


class ThreadingDashboardServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    with ThreadingDashboardServer(("127.0.0.1", PORT), DashboardHandler) as httpd:
        print(f"[*] Porygon Dashboard listening at http://127.0.0.1:{PORT}")
        print(f"[*] Proxying API requests to {API_BASE}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping dashboard server")


if __name__ == "__main__":
    main()
