#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PROBE_NAME="porygon-phase3-probe"
PROBE_IMAGE="alpine:3.20"

fail() {
  echo "[FAIL] $*" >&2
  docker compose logs --tail=120 falco telemetry backend collector 2>/dev/null || true
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_probe() {
  docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT

[[ -f .env ]] || fail ".env is missing. Run: cp .env.example .env, then replace the placeholder secrets."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets. Replace them before verification."
fi

for command in docker curl python3 stat uname; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is not available"
[[ "$(uname -s)" == "Linux" ]] || fail "Falco modern eBPF requires a Linux host"
[[ -r /sys/kernel/btf/vmlinux ]] || fail "Kernel BTF is unavailable at /sys/kernel/btf/vmlinux"

socket_path="$(grep -E '^DOCKER_SOCKET_PATH=' .env | tail -1 | cut -d= -f2- || true)"
socket_path="${socket_path:-/var/run/docker.sock}"
[[ -S "$socket_path" ]] || fail "Docker socket not found at $socket_path"
configured_gid="$(grep -E '^DOCKER_GID=' .env | tail -1 | cut -d= -f2- || true)"
actual_gid="$(stat -c '%g' "$socket_path")"
[[ -n "$configured_gid" ]] || fail "DOCKER_GID is missing from .env. Set it to: $actual_gid"
[[ "$configured_gid" == "$actual_gid" ]] || fail "DOCKER_GID=$configured_gid does not match socket GID $actual_gid"

cleanup_probe
mkdir -p artifacts

docker compose config --quiet
pass "Compose configuration is valid"

docker compose up --detach --build --wait
pass "PostgreSQL, backend, Docker collector, telemetry adapter, and Falco started"

falco_id="$(docker compose ps -q falco)"
[[ -n "$falco_id" ]] || fail "Falco container was not created"
sleep 8
[[ "$(docker inspect -f '{{.State.Running}}' "$falco_id")" == "true" ]] || fail "Falco is not running"
pass "Falco remained running with the modern eBPF configuration"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"
curl --fail --silent --show-error "${base_url}/health/ready" >/dev/null

collector_uid="$(docker compose exec -T collector id -u | tr -d '\r')"
telemetry_uid="$(docker compose exec -T telemetry id -u | tr -d '\r')"
[[ "$collector_uid" != "0" ]] || fail "Docker collector is running as root"
[[ "$telemetry_uid" != "0" ]] || fail "Telemetry adapter is running as root"
backend_mounts="$(docker inspect "$(docker compose ps -q backend)" --format '{{json .Mounts}}')"
telemetry_mounts="$(docker inspect "$(docker compose ps -q telemetry)" --format '{{json .Mounts}}')"
[[ "$backend_mounts" != *"docker.sock"* ]] || fail "Backend must not have Docker socket access"
[[ "$telemetry_mounts" != *"docker.sock"* ]] || fail "Telemetry adapter must not have Docker socket access"
pass "Docker and kernel privileges are isolated from the backend and telemetry adapter"

docker pull "$PROBE_IMAGE" >/dev/null
expected_repo_digest="$(docker image inspect "$PROBE_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$expected_repo_digest" == *@sha256:* ]] || fail "Could not resolve a repository digest for $PROBE_IMAGE"

docker run --detach \
  --name "$PROBE_NAME" \
  --label io.porygon.phase3.probe=true \
  "$PROBE_IMAGE" sh -c 'sleep 300' >/dev/null
full_container_id="$(docker inspect "$PROBE_NAME" --format '{{.Id}}')"

container_json=""
for _ in $(seq 1 60); do
  container_json="$(curl --fail --silent --show-error "${base_url}/api/v1/containers?limit=500" || true)"
  if CONTAINERS_JSON="$container_json" PROBE_NAME="$PROBE_NAME" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY'
import json, os, sys
try:
    items=json.loads(os.environ['CONTAINERS_JSON'])
except Exception:
    sys.exit(1)
match=next((x for x in items if x.get('container_name') == os.environ['PROBE_NAME']), None)
if not match:
    sys.exit(1)
if match.get('container_id') != os.environ['EXPECTED_ID']:
    sys.exit(1)
if match.get('image_digest') != os.environ['EXPECTED_DIGEST']:
    sys.exit(1)
PY
  then
    break
  fi
  sleep 2
done
CONTAINERS_JSON="$container_json" PROBE_NAME="$PROBE_NAME" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY' || fail "Docker identity was not ready before process testing"
import json, os
items=json.loads(os.environ['CONTAINERS_JSON'])
match=next(x for x in items if x.get('container_name') == os.environ['PROBE_NAME'])
assert match['container_id'] == os.environ['EXPECTED_ID']
assert match['image_digest'] == os.environ['EXPECTED_DIGEST']
PY
pass "Probe container identity is bound to the immutable image digest"

# Force a visible process tree: outer sh -> inner sh -> sleep.
docker exec "$PROBE_NAME" sh -c 'sh -c "sleep 4 & child=$!; wait $child" porygon-phase3-inner' porygon-phase3-outer

process_events=""
for _ in $(seq 1 90); do
  process_events="$(curl --fail --silent --show-error --get \
    --data-urlencode "container_id=${full_container_id}" \
    --data-urlencode "limit=500" \
    "${base_url}/api/v1/process-events" || true)"
  if PROCESS_EVENTS="$process_events" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY'
import json, os, sys
try:
    events=json.loads(os.environ['PROCESS_EVENTS'])
except Exception:
    sys.exit(1)
if not events:
    sys.exit(1)
by_id={e['event_id']: e for e in events}
sleeps=[e for e in events if e.get('process_name') == 'sleep']
if not sleeps:
    sys.exit(1)
linked=[]
for event in sleeps:
    parent_id=event.get('parent_event_id')
    parent=by_id.get(parent_id)
    if event.get('parent_name') == 'sh' and parent and parent.get('process_name') == 'sh' and parent.get('process_pid') == event.get('process_ppid'):
        linked.append((event,parent))
if not linked:
    sys.exit(1)
if any(e.get('correlation_status') != 'resolved' for e in events):
    sys.exit(1)
if any(e.get('container_id') != os.environ['EXPECTED_ID'] for e in events):
    sys.exit(1)
if any(e.get('image_digest') != os.environ['EXPECTED_DIGEST'] for e in events):
    sys.exit(1)
PY
  then
    break
  fi
  sleep 2
done
PROCESS_EVENTS="$process_events" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY' || fail "Falco process tree was not normalized and correlated correctly"
import json, os
events=json.loads(os.environ['PROCESS_EVENTS'])
by_id={e['event_id']: e for e in events}
sleeps=[e for e in events if e.get('process_name') == 'sleep']
assert sleeps
assert any(
    e.get('parent_name') == 'sh'
    and e.get('parent_event_id') in by_id
    and by_id[e['parent_event_id']].get('process_name') == 'sh'
    and by_id[e['parent_event_id']].get('process_pid') == e.get('process_ppid')
    for e in sleeps
)
assert all(e.get('correlation_status') == 'resolved' for e in events)
assert all(e.get('container_id') == os.environ['EXPECTED_ID'] for e in events)
assert all(e.get('image_digest') == os.environ['EXPECTED_DIGEST'] for e in events)
print(len(events))
PY
pass "Process executions include PID/PPID ancestry and resolve to the full container ID and image digest"

# Prove that the Falco JSON file survives a telemetry-adapter outage.
uname_before="$(PROCESS_EVENTS="$process_events" python3 - <<'PY'
import json, os
print(sum(1 for e in json.loads(os.environ['PROCESS_EVENTS']) if e.get('process_name') == 'uname'))
PY
)"
docker compose stop telemetry >/dev/null
docker exec "$PROBE_NAME" sh -c 'uname -a >/tmp/porygon-phase3-replay'
sleep 2
docker compose up --detach --wait telemetry >/dev/null

uname_events=""
for _ in $(seq 1 60); do
  uname_events="$(curl --fail --silent --show-error --get \
    --data-urlencode "container_id=${full_container_id}" \
    --data-urlencode "process_name=uname" \
    --data-urlencode "limit=500" \
    "${base_url}/api/v1/process-events" || true)"
  uname_after="$(PROCESS_EVENTS="$uname_events" python3 - <<'PY'
import json, os
try:
    print(len(json.loads(os.environ['PROCESS_EVENTS'])))
except Exception:
    print(-1)
PY
)"
  (( uname_after > uname_before )) && break
  sleep 2
done
(( uname_after > uname_before )) || fail "Telemetry adapter did not replay the Falco event file after restart"
pass "Persistent Falco JSON output was replayed after a telemetry-adapter outage"

# Prove that normalized process events survive a backend outage in the SQLite outbox.
id_before_json="$(curl --fail --silent --show-error --get \
  --data-urlencode "container_id=${full_container_id}" \
  --data-urlencode "process_name=id" \
  --data-urlencode "limit=500" \
  "${base_url}/api/v1/process-events")"
id_before="$(PROCESS_EVENTS="$id_before_json" python3 - <<'PY'
import json, os
print(len(json.loads(os.environ['PROCESS_EVENTS'])))
PY
)"

docker compose stop backend >/dev/null
docker exec "$PROBE_NAME" id >/dev/null
sleep 3
spooled_count="$(docker compose exec -T telemetry python - <<'PY'
import sqlite3
connection=sqlite3.connect('/var/lib/porygon/process-outbox.db')
print(connection.execute('SELECT COUNT(*) FROM outbox').fetchone()[0])
PY
)"
spooled_count="$(echo "$spooled_count" | tr -d '\r' | tail -1)"
[[ "$spooled_count" =~ ^[0-9]+$ ]] || fail "Could not read process telemetry outbox count"
(( spooled_count > 0 )) || fail "Process events were not retained while the backend was unavailable"
pass "Telemetry adapter durably spooled $spooled_count process events during backend outage"

docker compose up --detach --wait backend >/dev/null
id_events=""
for _ in $(seq 1 90); do
  id_events="$(curl --fail --silent --show-error --get \
    --data-urlencode "container_id=${full_container_id}" \
    --data-urlencode "process_name=id" \
    --data-urlencode "limit=500" \
    "${base_url}/api/v1/process-events" || true)"
  id_after="$(PROCESS_EVENTS="$id_events" python3 - <<'PY'
import json, os
try:
    print(len(json.loads(os.environ['PROCESS_EVENTS'])))
except Exception:
    print(-1)
PY
)"
  (( id_after > id_before )) && break
  sleep 2
done
(( id_after > id_before )) || fail "Spool did not drain after backend recovery"
pass "Process telemetry outbox drained after backend recovery"

all_before="$(curl --fail --silent --show-error --get \
  --data-urlencode "container_id=${full_container_id}" \
  --data-urlencode "limit=500" \
  "${base_url}/api/v1/process-events")"
count_before="$(PROCESS_EVENTS="$all_before" python3 - <<'PY'
import json, os
items=json.loads(os.environ['PROCESS_EVENTS'])
assert len({x['event_id'] for x in items}) == len(items)
print(len(items))
PY
)"
docker compose restart telemetry >/dev/null
docker compose up --detach --wait telemetry >/dev/null
sleep 5
all_after="$(curl --fail --silent --show-error --get \
  --data-urlencode "container_id=${full_container_id}" \
  --data-urlencode "limit=500" \
  "${base_url}/api/v1/process-events")"
count_after="$(PROCESS_EVENTS="$all_after" python3 - <<'PY'
import json, os
items=json.loads(os.environ['PROCESS_EVENTS'])
assert len({x['event_id'] for x in items}) == len(items)
print(len(items))
PY
)"
[[ "$count_before" == "$count_after" ]] || fail "Telemetry replay changed event count from $count_before to $count_after"
pass "Durable file replay and backend ingestion are idempotent"

dead_letters="$(docker compose exec -T telemetry python - <<'PY'
import sqlite3
connection=sqlite3.connect('/var/lib/porygon/process-outbox.db')
print(connection.execute('SELECT COUNT(*) FROM dead_letters').fetchone()[0])
PY
)"
dead_letters="$(echo "$dead_letters" | tr -d '\r' | tail -1)"
[[ "$dead_letters" == "0" ]] || fail "Telemetry adapter recorded $dead_letters malformed Falco lines"
pass "Falco JSON stream contained no malformed records"

printf '%s' "$all_after" > artifacts/phase3-process-events.json
curl --fail --silent --show-error "${base_url}/api/v1/process-events/summary?container_name=${PROBE_NAME}" \
  > artifacts/phase3-process-summary.json
curl --fail --silent --show-error "${base_url}/api/v1/system/info" \
  > artifacts/phase3-system-info.json
docker compose logs --no-color falco > artifacts/phase3-falco.log
docker compose ps > artifacts/phase3-services.txt

printf '\nPhase 3 verification complete.\n'
