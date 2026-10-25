#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

RUN_ID="${PORYGON_VERIFY_RUN_ID:-$(date -u +%Y%m%dt%H%M%Sz)-$$}"
PROBE_NAME="porygon-phase2-${RUN_ID}"
PROBE_NETWORK="porygon-phase2-net-${RUN_ID}"
PROBE_IMAGE="alpine:3.20"
PROBE_EXECUTIONS="${PORYGON_PHASE2_EXECUTIONS:-40}"
COLLECTOR_CONSTRAINED=false
LOCAL_ARTIFACT_DIR="artifacts/local"
PROBE_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/phase2-${RUN_ID}-events.json"
PROBE_EVENTS_AFTER_PATH="${LOCAL_ARTIFACT_DIR}/phase2-${RUN_ID}-events-after.json"
DAEMON_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/phase2-${RUN_ID}-docker-events.jsonl"
EVIDENCE_DIR="${LOCAL_ARTIFACT_DIR}/phase2-${RUN_ID}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_all() {
  docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
  docker network rm "$PROBE_NETWORK" >/dev/null 2>&1 || true
  rm -f "$PROBE_EVENTS_PATH" "$PROBE_EVENTS_AFTER_PATH" "$DAEMON_EVENTS_PATH"
  if [[ "$COLLECTOR_CONSTRAINED" == true ]]; then
    docker compose up --detach backend >/dev/null 2>&1 || true
    docker compose up --detach --no-deps --force-recreate collector >/dev/null 2>&1 || true
  fi
}
trap cleanup_all EXIT

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

cleanup_all
mkdir -p artifacts
mkdir -p "$LOCAL_ARTIFACT_DIR"
mkdir -p "$EVIDENCE_DIR"

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

PORYGON_SPOOL_MAX_EVENTS=100 docker compose up \
  --detach --no-deps --force-recreate --wait collector >/dev/null
COLLECTOR_CONSTRAINED=true
configured_spool_limit="$(docker compose exec -T collector python - <<'PY'
from porygon_collector.config import get_settings
print(get_settings().spool_max_events)
PY
)"
configured_spool_limit="$(echo "$configured_spool_limit" | tr -d '\r' | tail -1)"
[[ "$configured_spool_limit" == "100" ]] || fail "Collector spool limit was not constrained to 100"
pass "Collector spool was temporarily constrained to 100 events"

docker pull "$PROBE_IMAGE" >/dev/null
expected_repo_digest="$(docker image inspect "$PROBE_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$expected_repo_digest" == *@sha256:* ]] || fail "Could not resolve a repository digest for $PROBE_IMAGE"
pass "Pulled probe image has immutable repository digest $expected_repo_digest"

docker network create "$PROBE_NETWORK" >/dev/null

# Force an ingestion outage. Events generated below must survive in the collector's SQLite outbox.
overflow_before="$(docker compose exec -T collector python - <<'PY'
import json, urllib.request
print(json.load(urllib.request.urlopen('http://127.0.0.1:8001/status'))['spool_overflow_count'])
PY
)"
overflow_before="$(echo "$overflow_before" | tr -d '\r' | tail -1)"
[[ "$overflow_before" =~ ^[0-9]+$ ]] || fail "Could not read pre-run overflow count"
run_started_epoch="$(date +%s)"
docker compose stop backend >/dev/null

docker create \
  --name "$PROBE_NAME" \
  --label io.porygon.phase2.probe=true \
  --label "io.porygon.phase2.run=${RUN_ID}" \
  "$PROBE_IMAGE" sleep 300 >/dev/null
full_container_id="$(docker inspect "$PROBE_NAME" --format '{{.Id}}')"
docker start "$PROBE_NAME" >/dev/null
for execution in $(seq 1 "$PROBE_EXECUTIONS"); do
  docker exec "$PROBE_NAME" sh -c "echo porygon-phase2-${RUN_ID}-${execution}" >/dev/null
done
docker network connect "$PROBE_NETWORK" "$PROBE_NAME"
docker network disconnect "$PROBE_NETWORK" "$PROBE_NAME"
docker stop --time 2 "$PROBE_NAME" >/dev/null
docker rm "$PROBE_NAME" >/dev/null
run_finished_epoch="$(date +%s)"

docker events \
  --since "$run_started_epoch" \
  --until "$((run_finished_epoch + 1))" \
  --format '{{json .}}' > "$DAEMON_EVENTS_PATH"
daemon_metrics="$(DAEMON_EVENTS_PATH="$DAEMON_EVENTS_PATH" PROBE_NAME="$PROBE_NAME" FULL_CONTAINER_ID="$full_container_id" python3 - <<'PY'
import json, os
with open(os.environ['DAEMON_EVENTS_PATH'], encoding='utf-8') as handle:
    observed=[json.loads(line) for line in handle if line.strip()]
events=[]
for event in observed:
    actor=event.get('Actor') or {}
    attributes=actor.get('Attributes') or {}
    is_container=(
        event.get('Type') == 'container'
        and attributes.get('name') == os.environ['PROBE_NAME']
    )
    is_network=(
        event.get('Type') == 'network'
        and attributes.get('container') == os.environ['FULL_CONTAINER_ID']
    )
    if is_container or is_network:
        events.append(event)
actions=[str(event.get('Action') or '').split(':', 1)[0] for event in events]
print(json.dumps({'count': len(events), 'actions': sorted(set(actions))}, separators=(',', ':')))
PY
)"
daemon_event_count="$(DAEMON_METRICS="$daemon_metrics" python3 - <<'PY'
import json, os
print(json.loads(os.environ['DAEMON_METRICS'])['count'])
PY
)"
(( daemon_event_count > 100 )) || fail "Canary produced only $daemon_event_count Docker events; saturation was not exercised"

spool_metrics=""
for _ in $(seq 1 45); do
  spool_metrics="$(docker compose exec -T -e PROBE_NAME="$PROBE_NAME" collector python - <<'PY'
import json, os, sqlite3
connection=sqlite3.connect('/var/lib/porygon/outbox.db')
rows=connection.execute('SELECT payload FROM outbox').fetchall()
payloads=[json.loads(row[0]) for row in rows]
probe=[item for item in payloads if item.get('container_name') == os.environ['PROBE_NAME']]
print(json.dumps({
    'outbox_count': len(payloads),
    'canary_count': len(probe),
    'canary_event_ids': sorted(item['event_id'] for item in probe),
}, separators=(',', ':')))
PY
)"
  spooled_count="$(SPOOL_METRICS="$spool_metrics" python3 - <<'PY'
import json, os
print(json.loads(os.environ['SPOOL_METRICS'])['outbox_count'])
PY
)"
  [[ "$spooled_count" == "100" ]] && break
  sleep 1
done
[[ "$spooled_count" == "100" ]] || fail "Constrained collector outbox did not reach its 100-event limit"

overflow_after="$(docker compose exec -T collector python - <<'PY'
import json, urllib.request
print(json.load(urllib.request.urlopen('http://127.0.0.1:8001/status'))['spool_overflow_count'])
PY
)"
overflow_after="$(echo "$overflow_after" | tr -d '\r' | tail -1)"
[[ "$overflow_after" =~ ^[0-9]+$ ]] || fail "Could not read post-run overflow count"
overflow_delta="$((overflow_after - overflow_before))"
(( overflow_delta > 0 )) || fail "Collector reached its limit without recording saturation"
pass "Collector recorded saturation and retained exactly 100 queued events without advancing past failures"

docker compose up --detach --wait backend >/dev/null

for _ in $(seq 1 90); do
  curl --fail --silent --show-error --get \
    --data-urlencode "container_name=${PROBE_NAME}" \
    --data-urlencode "limit=500" \
    --output "$PROBE_EVENTS_PATH" \
    "${base_url}/api/v1/events" || true
  if PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" EXPECTED_DIGEST="$expected_repo_digest" RUN_ID="$RUN_ID" python3 - <<'PY'
import json, os, sys
try:
    with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
        events = json.load(handle)
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
if not any(os.environ['RUN_ID'] in (e.get('command') or '') for e in events):
    sys.exit(1)
PY
  then
    break
  fi
  sleep 2
done

PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" EXPECTED_DIGEST="$expected_repo_digest" RUN_ID="$RUN_ID" python3 - <<'PY' || fail "Required probe events or digest enrichment were not stored"
import json, os

with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    events = json.load(handle)
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
assert any(os.environ['RUN_ID'] in (e.get('command') or '') for e in events)
print(len(events))
PY
pass "Lifecycle, exec, and network actions were normalized with the correct image digest"

inserted_count="$(PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    print(len(json.load(handle)))
PY
)"
[[ "$inserted_count" == "$daemon_event_count" ]] || fail \
  "Docker exposed $daemon_event_count canary events but PostgreSQL stored $inserted_count"
pass "Every canary event observed at the Docker API boundary reached PostgreSQL exactly once"

count_before="$(PROBE_EVENTS_PATH="$PROBE_EVENTS_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    print(len(json.load(handle)))
PY
)"

docker compose restart collector >/dev/null
for _ in $(seq 1 60); do
  collector_health="$(docker inspect \
    --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' \
    "$(docker compose ps -q collector)")"
  [[ "$collector_health" == "healthy" ]] && break
  sleep 1
done
[[ "$collector_health" == "healthy" ]] || fail "Collector did not become healthy after replay restart"
sleep 5

curl --fail --silent --show-error --get \
  --data-urlencode "container_name=${PROBE_NAME}" \
  --data-urlencode "limit=500" \
  --output "$PROBE_EVENTS_AFTER_PATH" \
  "${base_url}/api/v1/events"
count_after="$(PROBE_EVENTS_PATH="$PROBE_EVENTS_AFTER_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROBE_EVENTS_PATH'], encoding='utf-8') as handle:
    items=json.load(handle)
assert len({item['event_id'] for item in items}) == len(items)
print(len(items))
PY
)"
[[ "$count_before" == "$count_after" ]] || fail "Event replay changed probe count from $count_before to $count_after"
pass "Collector replay did not duplicate stored events"
replay_row_growth="$((count_after - count_before))"

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

docker compose up --detach --no-deps --force-recreate --wait collector >/dev/null
COLLECTOR_CONSTRAINED=false
pass "Collector spool limit was restored after the saturation drill"

RUN_ID="$RUN_ID" \
PROBE_NAME="$PROBE_NAME" \
PROBE_EXECUTIONS="$PROBE_EXECUTIONS" \
DAEMON_METRICS="$daemon_metrics" \
SPOOL_METRICS="$spool_metrics" \
SPOOL_LIMIT="$configured_spool_limit" \
OVERFLOW_DELTA="$overflow_delta" \
INSERTED_COUNT="$inserted_count" \
REPLAY_ROW_GROWTH="$replay_row_growth" \
python3 - <<'PY' > artifacts/phase2-capture-integrity.json
import json, os

daemon=json.loads(os.environ['DAEMON_METRICS'])
spool=json.loads(os.environ['SPOOL_METRICS'])
document={
    'schema_version': 'porygon.capture-integrity.v1',
    'run_id': os.environ['RUN_ID'],
    'canary': {
        'container_name': os.environ['PROBE_NAME'],
        'exec_operations_issued': int(os.environ['PROBE_EXECUTIONS']),
    },
    'boundaries': {
        'docker_api_events_observed': daemon['count'],
        'docker_api_actions_observed': daemon['actions'],
        'collector_spool_limit': int(os.environ['SPOOL_LIMIT']),
        'collector_events_retained_at_saturation': spool['outbox_count'],
        'canary_events_retained_at_saturation': spool['canary_count'],
        'collector_overflow_attempts_observed': int(os.environ['OVERFLOW_DELTA']),
        'postgres_canary_rows_after_recovery': int(os.environ['INSERTED_COUNT']),
        'postgres_row_growth_after_replay': int(os.environ['REPLAY_ROW_GROWTH']),
    },
    'dead_letter': {
        'status': 'not_applicable',
        'count': None,
        'reason': 'The Docker collector has no dead-letter path; schema acceptance is proven by database equality.',
    },
    'unmeasured_boundaries': [
        'Docker daemon loss before publication on the events API',
        'Host failure and Docker history rollover outside this bounded run',
        'Kernel and Falco drops; those belong to the Phase 3/5 measurement path',
    ],
}
print(json.dumps(document, indent=2, sort_keys=True))
PY

curl --fail --silent --show-error "${base_url}/api/v1/events/summary?container_name=${PROBE_NAME}" \
  > "${EVIDENCE_DIR}/probe-summary.json"
cp "$PROBE_EVENTS_AFTER_PATH" "${EVIDENCE_DIR}/probe-events.json"
curl --fail --silent --show-error "${base_url}/api/v1/images" > "${EVIDENCE_DIR}/images.json"
curl --fail --silent --show-error "${base_url}/api/v1/containers" > "${EVIDENCE_DIR}/containers.json"
docker compose ps > "${EVIDENCE_DIR}/services.txt"
docker compose images > "${EVIDENCE_DIR}/images.txt"

printf '\nPhase 2 verification complete.\n'
