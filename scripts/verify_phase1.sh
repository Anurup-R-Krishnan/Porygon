#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f .env ]] || fail ".env is missing. Run: cp .env.example .env, then replace the placeholder secrets."

if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets. Replace them before verification."
fi

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is not available"
command -v curl >/dev/null 2>&1 || fail "curl is not installed"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed"

docker compose config --quiet
pass "Compose configuration is valid"

docker compose up --detach --build --wait
pass "All Phase 1 services reached healthy state"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"

curl --fail --silent --show-error "${base_url}/health/live" >/dev/null
curl --fail --silent --show-error "${base_url}/health/ready" >/dev/null
pass "Backend liveness and database readiness checks passed"

sleep 2
services_before="$(curl --fail --silent --show-error "${base_url}/api/v1/services")"
first_seen_before="$(SERVICES_JSON="$services_before" python3 - <<'PY'
import json, os
items = json.loads(os.environ["SERVICES_JSON"])
collector = next((item for item in items if item["service_name"] == "collector"), None)
if collector is None:
    raise SystemExit("collector heartbeat not found")
print(collector["first_seen_at"])
PY
)"
pass "Collector authenticated to the backend and persisted a heartbeat"

docker compose down
docker compose up --detach --wait
sleep 2

services_after="$(curl --fail --silent --show-error "${base_url}/api/v1/services")"
first_seen_after="$(SERVICES_JSON="$services_after" python3 - <<'PY'
import json, os
items = json.loads(os.environ["SERVICES_JSON"])
collector = next((item for item in items if item["service_name"] == "collector"), None)
if collector is None:
    raise SystemExit("collector heartbeat not found after restart")
print(collector["first_seen_at"])
PY
)"

[[ "$first_seen_before" == "$first_seen_after" ]] || fail "PostgreSQL heartbeat record did not persist across Compose restart"
pass "PostgreSQL data persisted across Compose restart"

docker compose ps
printf '\nPhase 1 verification complete.\n'
