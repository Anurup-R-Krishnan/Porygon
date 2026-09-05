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


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self) -> None:
        if self.path.startswith("/api/"):
            self.proxy_api()
        else:
            super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/demo/run-scenario":
            self.handle_run_scenario()
        elif self.path.startswith("/api/"):
            self.proxy_api()
        else:
            self.send_error(404, "Not Found")

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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_bytes)

    def execute_scenario(self, scenario_id: str) -> dict[str, Any]:
        if scenario_id == "unseen_shell":
            cmd = ["docker", "run", "--rm", "alpine:3.20", "sh", "-c", "id; echo 'porygon_canary_shell_triggered'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "sh -c 'id; echo porygon_canary_shell'",
                "detected_process": "/bin/sh",
                "simulated_score": 0.82,
                "output": proc.stdout.strip(),
                "contributors": [{"token": "/bin/sh", "weight": 0.74}],
                "unseen_tokens": ["/bin/sh", "id"],
                "rules": ["POR-DET-001", "POR-DET-002"],
            }
        elif scenario_id == "shell_to_tool":
            cmd = ["docker", "run", "--rm", "alpine:3.20", "sh", "-c", "sh -c 'wget -q -O- https://example.com || true'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": True,
                "command": "sh -> /usr/bin/wget https://example.com",
                "detected_process": "/usr/bin/wget",
                "simulated_score": 0.91,
                "output": "Shell spawned wget downloader in correlation window (POR-DET-005)",
                "contributors": [{"token": "/usr/bin/wget", "weight": 0.88}],
                "unseen_tokens": ["/bin/sh", "/usr/bin/wget"],
                "rules": ["POR-DET-002", "POR-DET-004", "POR-DET-005"],
            }
        elif scenario_id == "cryptominer":
            cmd = [
                "docker", "run", "--rm", "quay.io/petr_ruzicka/malware-cryptominer-container:3",
                "sh", "-c", "id; cat /usr/share/nginx/html/eicar/eicar.com.txt; /usr/share/nginx/html/xmrig/xmrig --version"
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
            return {
                "success": proc.returncode == 0,
                "command": "xmrig --version && cat eicar.com.txt",
                "detected_process": "/usr/share/nginx/html/xmrig/xmrig",
                "simulated_score": 0.96,
                "output": proc.stdout.strip(),
                "contributors": [{"token": "xmrig", "weight": 0.94}],
                "unseen_tokens": ["xmrig", "cat", "eicar"],
                "rules": ["POR-DET-001", "POR-DET-004"],
            }
        elif scenario_id == "network_scan":
            cmd = ["docker", "run", "--rm", "alpine:3.20", "sh", "-c", "nc -z -w1 127.0.0.1 80 8080 3000 || true; echo 'network_discovery_probes_dispatched'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": True,
                "command": "nc -z -w1 127.0.0.1 80 8080 3000 (Network Port Discovery)",
                "detected_process": "nc (netcat)",
                "simulated_score": 0.86,
                "output": proc.stdout.strip(),
                "contributors": [{"token": "nc", "weight": 0.82}],
                "unseen_tokens": ["nc"],
                "rules": ["POR-DET-001", "POR-DET-004"],
            }
        elif scenario_id == "file_evasion":
            cmd = ["docker", "run", "--rm", "alpine:3.20", "sh", "-c", "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh && echo 'file_integrity_test_complete'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "touch /tmp/malicious.sh && chmod +x /tmp/malicious.sh",
                "detected_process": "chmod (+x executable creation)",
                "simulated_score": 0.79,
                "output": proc.stdout.strip(),
                "contributors": [{"token": "chmod", "weight": 0.71}],
                "unseen_tokens": ["touch", "chmod", "/tmp/malicious.sh"],
                "rules": ["POR-DET-001", "POR-DET-002"],
            }
        elif scenario_id == "defense_evasion":
            cmd = ["docker", "run", "--rm", "alpine:3.20", "sh", "-c", "mkdir -p /var/log && touch /var/log/bootstrap.log && echo '' > /var/log/bootstrap.log && echo 'log_cleared'"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "echo '' > /var/log/bootstrap.log (Log Wiping Evasion)",
                "detected_process": "sh (anti-forensics redirection)",
                "simulated_score": 0.76,
                "output": proc.stdout.strip(),
                "contributors": [{"token": "/bin/sh", "weight": 0.69}],
                "unseen_tokens": ["/var/log/bootstrap.log"],
                "rules": ["POR-DET-001", "POR-DET-002"],
            }
        elif scenario_id == "priv_esc":
            cmd = ["docker", "run", "--rm", "alpine:3.20", "sh", "-c", "id; cat /proc/self/status | head -n 4"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                "success": proc.returncode == 0,
                "command": "cat /proc/self/status",
                "detected_process": "cat",
                "simulated_score": 0.78,
                "output": proc.stdout.strip(),
                "contributors": [{"token": "cat", "weight": 0.65}],
                "unseen_tokens": ["/proc/self/status"],
                "rules": ["POR-DET-001", "POR-DET-003"],
            }
        elif scenario_id == "juice_shop_toggle":
            # Check if juice shop container exists
            check = subprocess.run(["docker", "ps", "-a", "--filter", "name=porygon-juice-shop", "--format", "{{.ID}}"], capture_output=True, text=True)
            if check.stdout.strip():
                # Stop & remove
                subprocess.run(["docker", "rm", "-f", "porygon-juice-shop"], capture_output=True, text=True)
                return {
                    "success": True,
                    "command": "docker rm -f porygon-juice-shop",
                    "detected_process": "container:die",
                    "simulated_score": 0.10,
                    "output": "OWASP Juice Shop container stopped and removed cleanly",
                    "contributors": [],
                    "unseen_tokens": [],
                    "rules": [],
                }
            else:
                # Run on 127.0.0.1:3001 to avoid port 3000 collision
                cmd = ["docker", "run", "-d", "--name", "porygon-juice-shop", "-p", "127.0.0.1:3001:3000", "bkimminich/juice-shop"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=40)
                return {
                    "success": proc.returncode == 0,
                    "command": "docker run -d --name porygon-juice-shop -p 127.0.0.1:3001:3000 bkimminich/juice-shop",
                    "detected_process": "node (server.js)",
                    "simulated_score": 0.35,
                    "output": f"OWASP Juice Shop deployed at http://127.0.0.1:3001 (Container ID: {proc.stdout.strip()[:12]})",
                    "contributors": [{"token": "node", "weight": 0.35}],
                    "unseen_tokens": ["node"],
                    "rules": ["POR-DET-001"],
                }
        return {"success": False, "error": f"Unknown scenario {scenario_id}"}


def main() -> None:
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("0.0.0.0", PORT), DashboardHandler) as httpd:
        print(f"[*] Porygon Dashboard listening at http://127.0.0.1:{PORT}")
        print(f"[*] Proxying API requests to {API_BASE}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Stopping dashboard server")


if __name__ == "__main__":
    main()
