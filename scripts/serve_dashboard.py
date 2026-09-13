#!/usr/bin/env python3
"""Porygon Dashboard Web Server & Scenario Runner.

Serves the Alpine.js + Chart.js dashboard on http://127.0.0.1:3000,
proxies /api/ requests to the Porygon API gateway on http://127.0.0.1:8000,
and provides an endpoint for interactive attack simulation scenarios.
"""
from __future__ import annotations

import http.server
import json
import os
import secrets
import socketserver
import subprocess
import urllib.error
import urllib.request
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
DEMO_MODE_ENV = "PORYGON_DEMO_MODE"
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
        expected = os.environ.get(OPERATOR_TOKEN_ENV, "")
        provided = self.headers.get(OPERATOR_TOKEN_HEADER, "")
        if len(expected) < 32 or not provided or not secrets.compare_digest(provided, expected):
            self.send_error(401, "Invalid or missing operator token")
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

    def execute_scenario(self, scenario_id: str) -> dict[str, Any]:
        if scenario_id == "unseen_shell":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "id; echo 'porygon_canary_shell_triggered'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "sh -c 'id; echo porygon_canary_shell'",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "shell_to_tool":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "sh -c 'wget -q -O- https://example.com || true'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "sh -> wget https://example.com",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "cryptominer":
            cmd = [
                "docker", "run", "--rm", CRYPTOMINER_IMAGE,
                "sh", "-c", "id; cat /usr/share/nginx/html/eicar/eicar.com.txt; /usr/share/nginx/html/xmrig/xmrig --version"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            return {
                "success": proc.returncode == 0,
                "command": "xmrig --version && cat eicar.com.txt",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "network_scan":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "nc -z -w1 127.0.0.1 80 8080 3000 || true; echo 'network_discovery_probes_dispatched'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "nc -z -w1 127.0.0.1 80 8080 3000 (Network Port Discovery)",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "file_evasion":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh && echo 'file_integrity_test_complete'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "defense_evasion":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "mkdir -p /var/log && touch /var/log/bootstrap.log && echo '' > /var/log/bootstrap.log && echo 'log_cleared'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "echo '' > /var/log/bootstrap.log (Log Wiping Evasion)",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "priv_esc":
            cmd = ["docker", "run", "--rm", ALPINE_IMAGE, "sh", "-c", "id; cat /proc/self/status | head -n 4"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "cat /proc/self/status",
                "output": proc.stdout.strip(),
            }
        elif scenario_id == "juice_shop_toggle":
            # Check if juice shop container exists
            check = subprocess.run(["docker", "ps", "-a", "--filter", "name=porygon-juice-shop", "--format", "{{.ID}}"], capture_output=True, text=True)
            if check.stdout.strip():
                # Stop & remove
                remove = subprocess.run(["docker", "rm", "-f", "porygon-juice-shop"], capture_output=True, text=True)
                return {
                    "success": remove.returncode == 0,
                    "command": "docker rm -f porygon-juice-shop",
                    "output": remove.stdout.strip() or remove.stderr.strip(),
                }
            else:
                # Run on 127.0.0.1:3001 to avoid port 3000 collision
                cmd = ["docker", "run", "-d", "--name", "porygon-juice-shop", "-p", "127.0.0.1:3001:3000", JUICE_SHOP_IMAGE]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                return {
                    "success": proc.returncode == 0,
                    "command": "docker run -d --name porygon-juice-shop -p 127.0.0.1:3001:3000 bkimminich/juice-shop",
                    "output": proc.stdout.strip() if proc.returncode == 0 else proc.stderr.strip(),
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
