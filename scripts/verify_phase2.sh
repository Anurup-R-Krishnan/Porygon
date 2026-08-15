#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PROBE_NAME="porygon-phase2-probe"
PROBE_NETWORK="porygon-phase2-test-net"
PROBE_IMAGE="alpine:3.20"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_probe() {
  docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
  docker network rm "$PROBE_NETWORK" >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT

[[ -f .env ]] || fail ".env is missing. Run: cp .env.example .env, then replace the placeholder secrets."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets. Replace them before verification."
fi

for command in docker curl python3 stat; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is not available"

socket_path="$(grep -E '^DOCKER_SOCKET_PATH=' .env | tail -1 | cut -d= -f2- || true)"
socket_path="${socket_path:-/var/run/docker.sock}"
[[ -S "$socket_path" ]] || fail "Docker socket not found at $socket_path"

configured_gid="$(grep -E '^DOCKER_GID=' .env | tail -1 | cut -d= -f2- || true)"
actual_gid="$(stat -c '%g' "$socket_path")"
[[ -n "$configured_gid" ]] || fail "DOCKER_GID is missing from .env. Set it to: $actual_gid"
[[ "$configured_gid" == "$actual_gid" ]] || fail "DOCKER_GID=$configured_gid does not match socket GID $actual_gid"

cleanup_probe

docker compose config --quiet
pass "Compose configuration is valid"

docker compose up --detach --build --wait
pass "PostgreSQL, backend, and Docker collector reached healthy state"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"

curl --fail --silent --show-error "${base_url}/health/live" >/dev/null
curl --fail --silent --show-error "${base_url}/health/ready" >/dev/null
pass "Backend liveness and database readiness checks passed"

collector_uid="$(docker compose exec -T collector id -u | tr -d '\r')"
[[ "$collector_uid" != "0" ]] || fail "Collector is running as root"

backend_mounts="$(docker inspect "$(docker compose ps -q backend)" --format '{{json .Mounts}}')"
if [[ "$backend_mounts" == *"docker.sock"* ]]; then
  fail "Backend must not have Docker socket access"
fi
collector_mounts="$(docker inspect "$(docker compose ps -q collector)" --format '{{json .Mounts}}')"
[[ "$collector_mounts" == *"docker.sock"* ]] || fail "Collector Docker socket mount is missing"
pass "Docker access is isolated to the non-root collector service"

docker pull "$PROBE_IMAGE" >/dev/null
expected_repo_digest="$(docker image inspect "$PROBE_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$expected_repo_digest" == *@sha256:* ]] || fail "Could not resolve a repository digest for $PROBE_IMAGE"
pass "Pulled probe image has immutable repository digest $expected_repo_digest"

docker network create "$PROBE_NETWORK" >/dev/null

# Force an ingestion outage. Events generated below must survive in the collector's SQLite outbox.
docker compose stop backend >/dev/null

docker create \
  --name "$PROBE_NAME" \
  --label io.porygon.phase2.probe=true \
  "$PROBE_IMAGE" sleep 300 >/dev/null
docker start "$PROBE_NAME" >/dev/null
docker exec "$PROBE_NAME" sh -c 'echo porygon-phase2' >/dev/null
docker network connect "$PROBE_NETWORK" "$PROBE_NAME"
docker network disconnect "$PROBE_NETWORK" "$PROBE_NAME"
docker stop --time 2 "$PROBE_NAME" >/dev/null
docker rm "$PROBE_NAME" >/dev/null

sleep 3
spooled_count="$(docker compose exec -T collector python - <<'PY'
import sqlite3
connection = sqlite3.connect('/var/lib/porygon/outbox.db')
print(connection.execute('SELECT COUNT(*) FROM outbox').fetchone()[0])
PY
)"
spooled_count="$(echo "$spooled_count" | tr -d '\r' | tail -1)"
[[ "$spooled_count" =~ ^[0-9]+$ ]] || fail "Could not read collector outbox count"
(( spooled_count > 0 )) || fail "Events were not retained while the backend was unavailable"
pass "Collector durably spooled $spooled_count events while the backend was stopped"

docker compose up --detach --wait backend >/dev/null

probe_events=""
for _ in $(seq 1 90); do
  probe_events="$(curl --fail --silent --show-error --get \
    --data-urlencode "container_name=${PROBE_NAME}" \
    --data-urlencode "limit=500" \
    "${base_url}/api/v1/events" || true)"
  if PROBE_EVENTS="$probe_events" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY'
import json, os, sys
try:
    events = json.loads(os.environ['PROBE_EVENTS'])
except Exception:
    sys.exit(1)
actions = {event.get('action') for event in events}
required = {'create', 'start', 'exec_create', 'exec_start', 'die', 'destroy', 'connect', 'disconnect'}
if not required.issubset(actions):
    sys.exit(1)
expected = os.environ['EXPECTED_DIGEST']
container_events = [e for e in events if e.get('container_id')]
if not container_events or any(e.get('image_digest') != expected for e in container_events):
    sys.exit(1)
if len({e['event_id'] for e in events}) != len(events):
    sys.exit(1)
if not all(isinstance(e.get('raw_event'), dict) for e in events):
    sys.exit(1)
if not any('porygon-phase2' in (e.get('command') or '') for e in events):
    sys.exit(1)
PY
  then
    break
  fi
  sleep 2
done

PROBE_EVENTS="$probe_events" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY' || fail "Required probe events or digest enrichment were not stored"
import json, os

events = json.loads(os.environ['PROBE_EVENTS'])
actions = {event.get('action') for event in events}
required = {'create', 'start', 'exec_create', 'exec_start', 'die', 'destroy', 'connect', 'disconnect'}
missing = sorted(required - actions)
assert not missing, f"missing actions: {missing}"
expected = os.environ['EXPECTED_DIGEST']
container_events = [e for e in events if e.get('container_id')]
assert container_events
assert all(e.get('image_digest') == expected for e in container_events)
assert len({e['event_id'] for e in events}) == len(events)
assert all(isinstance(e.get('raw_event'), dict) for e in events)
assert any('porygon-phase2' in (e.get('command') or '') for e in events)
print(len(events))
PY
pass "Lifecycle, exec, and network actions were normalized with the correct image digest"

count_before="$(PROBE_EVENTS="$probe_events" python3 - <<'PY'
import json, os
print(len(json.loads(os.environ['PROBE_EVENTS'])))
PY
)"

docker compose restart collector >/dev/null
docker compose up --detach --wait collector >/dev/null
sleep 5

probe_events_after="$(curl --fail --silent --show-error --get \
  --data-urlencode "container_name=${PROBE_NAME}" \
  --data-urlencode "limit=500" \
  "${base_url}/api/v1/events")"
count_after="$(PROBE_EVENTS="$probe_events_after" python3 - <<'PY'
import json, os
items=json.loads(os.environ['PROBE_EVENTS'])
assert len({item['event_id'] for item in items}) == len(items)
print(len(items))
PY
)"
[[ "$count_before" == "$count_after" ]] || fail "Event replay changed probe count from $count_before to $count_after"
pass "Collector replay did not duplicate stored events"

for _ in $(seq 1 45); do
  services_json="$(curl --fail --silent --show-error "${base_url}/api/v1/services")"
  queue_depth="$(SERVICES_JSON="$services_json" python3 - <<'PY'
import json, os
items=json.loads(os.environ['SERVICES_JSON'])
collector=next((x for x in items if x['service_name']=='collector'), None)
if collector is None:
    print(-1)
else:
    print(collector.get('service_metadata', {}).get('queue_depth', -1))
PY
)"
  [[ "$queue_depth" == "0" ]] && break
  sleep 2
done
[[ "$queue_depth" == "0" ]] || fail "Collector outbox did not drain; last reported depth was $queue_depth"
pass "Durable outbox drained after backend recovery"

curl --fail --silent --show-error "${base_url}/api/v1/events/summary?container_name=${PROBE_NAME}" \
  > artifacts/phase2-probe-summary.json
printf '%s' "$probe_events_after" > artifacts/phase2-probe-events.json
curl --fail --silent --show-error "${base_url}/api/v1/images" > artifacts/phase2-images.json
curl --fail --silent --show-error "${base_url}/api/v1/containers" > artifacts/phase2-containers.json
docker compose ps > artifacts/phase2-services.txt
docker compose images > artifacts/phase2-images.txt

printf '\nPhase 2 verification complete.\n'
