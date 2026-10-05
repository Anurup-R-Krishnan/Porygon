#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

RUN_ID="${PORYGON_VERIFY_RUN_ID:-$(date -u +%Y%m%dt%H%M%Sz)-$$}"
PROBE_NAME="porygon-phase3-${RUN_ID}"
PROBE_IMAGE="alpine:3.20"
LOCAL_ARTIFACT_DIR="artifacts/local"
CONTAINERS_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-containers.json"
PROCESS_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-process.json"
UNAME_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-uname.json"
ID_BEFORE_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-id-before.json"
ID_EVENTS_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-id.json"
ALL_BEFORE_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-all-before.json"
ALL_AFTER_PATH="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}-all-after.json"
EVIDENCE_DIR="${LOCAL_ARTIFACT_DIR}/phase3-${RUN_ID}"
TELEMETRY_STATUS_PATH="${EVIDENCE_DIR}/telemetry-status.json"

fail() {
  echo "[FAIL] $*" >&2
  docker compose ps 2>/dev/null || true
  docker compose logs --tail=40 telemetry backend collector 2>/dev/null || true
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_probe() {
  docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
  rm -f "$CONTAINERS_PATH" "$PROCESS_EVENTS_PATH" "$UNAME_EVENTS_PATH" \
    "$ID_BEFORE_PATH" "$ID_EVENTS_PATH" "$ALL_BEFORE_PATH" "$ALL_AFTER_PATH"
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
mkdir -p "$LOCAL_ARTIFACT_DIR"
mkdir -p "$EVIDENCE_DIR"

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
  --label "io.porygon.phase3.run=${RUN_ID}" \
  "$PROBE_IMAGE" sh -c 'sleep 300' >/dev/null
full_container_id="$(docker inspect "$PROBE_NAME" --format '{{.Id}}')"
reported_container_id="${full_container_id:0:12}"

for _ in $(seq 1 60); do
  curl --fail --silent --show-error \
    --output "$CONTAINERS_PATH" \
    "${base_url}/api/v1/containers?limit=500" || true
  if CONTAINERS_PATH="$CONTAINERS_PATH" PROBE_NAME="$PROBE_NAME" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY'
import json, os, sys
try:
    with open(os.environ['CONTAINERS_PATH'], encoding='utf-8') as handle:
        items=json.load(handle)
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
CONTAINERS_PATH="$CONTAINERS_PATH" PROBE_NAME="$PROBE_NAME" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY' || fail "Docker identity was not ready before process testing"
import json, os
with open(os.environ['CONTAINERS_PATH'], encoding='utf-8') as handle:
    items=json.load(handle)
match=next(x for x in items if x.get('container_name') == os.environ['PROBE_NAME'])
assert match['container_id'] == os.environ['EXPECTED_ID']
assert match['image_digest'] == os.environ['EXPECTED_DIGEST']
PY
pass "Probe container identity is bound to the immutable image digest"

# Force a visible process tree: outer sh -> inner sh -> sleep.
docker exec "$PROBE_NAME" sh -c 'sh -c "sleep 4 & child=$!; wait $child" porygon-phase3-inner' porygon-phase3-outer

for _ in $(seq 1 90); do
  curl --fail --silent --show-error --get \
    --data-urlencode "container_id=${full_container_id}" \
    --data-urlencode "limit=500" \
    --output "$PROCESS_EVENTS_PATH" \
    "${base_url}/api/v1/process-events" || true
  if PROCESS_EVENTS_PATH="$PROCESS_EVENTS_PATH" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY'
import json, os, sys
try:
    with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
        events=json.load(handle)
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
PROCESS_EVENTS_PATH="$PROCESS_EVENTS_PATH" EXPECTED_ID="$full_container_id" EXPECTED_DIGEST="$expected_repo_digest" python3 - <<'PY' || fail "Falco process tree was not normalized and correlated correctly"
import json, os
with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
    events=json.load(handle)
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
uname_before="$(PROCESS_EVENTS_PATH="$PROCESS_EVENTS_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
    print(sum(1 for e in json.load(handle) if e.get('process_name') == 'uname'))
PY
)"
docker compose stop telemetry >/dev/null
docker exec "$PROBE_NAME" sh -c 'uname -a >/tmp/porygon-phase3-replay'
sleep 2
docker compose up --detach --wait telemetry >/dev/null

for _ in $(seq 1 60); do
  curl --fail --silent --show-error --get \
    --data-urlencode "container_id=${full_container_id}" \
    --data-urlencode "process_name=uname" \
    --data-urlencode "limit=500" \
    --output "$UNAME_EVENTS_PATH" \
    "${base_url}/api/v1/process-events" || true
  uname_after="$(PROCESS_EVENTS_PATH="$UNAME_EVENTS_PATH" python3 - <<'PY'
import json, os
try:
    with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
        print(len(json.load(handle)))
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
curl --fail --silent --show-error --get \
  --data-urlencode "container_id=${full_container_id}" \
  --data-urlencode "process_name=id" \
  --data-urlencode "limit=500" \
  --output "$ID_BEFORE_PATH" \
  "${base_url}/api/v1/process-events"
id_before="$(PROCESS_EVENTS_PATH="$ID_BEFORE_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
    print(len(json.load(handle)))
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
for _ in $(seq 1 90); do
  curl --fail --silent --show-error --get \
    --data-urlencode "container_id=${full_container_id}" \
    --data-urlencode "process_name=id" \
    --data-urlencode "limit=500" \
    --output "$ID_EVENTS_PATH" \
    "${base_url}/api/v1/process-events" || true
  id_after="$(PROCESS_EVENTS_PATH="$ID_EVENTS_PATH" python3 - <<'PY'
import json, os
try:
    with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
        print(len(json.load(handle)))
except Exception:
    print(-1)
PY
)"
  (( id_after > id_before )) && break
  sleep 2
done
(( id_after > id_before )) || fail "Spool did not drain after backend recovery"
pass "Process telemetry outbox drained after backend recovery"

curl --fail --silent --show-error --get \
  --data-urlencode "container_id=${reported_container_id}" \
  --data-urlencode "limit=500" \
  --output "$ALL_BEFORE_PATH" \
  "${base_url}/api/v1/process-events"
count_before="$(PROCESS_EVENTS_PATH="$ALL_BEFORE_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
    items=json.load(handle)
assert len({x['event_id'] for x in items}) == len(items)
print(len(items))
PY
)"
docker compose restart telemetry >/dev/null
docker compose up --detach --wait telemetry >/dev/null
sleep 5
curl --fail --silent --show-error --get \
  --data-urlencode "container_id=${reported_container_id}" \
  --data-urlencode "limit=500" \
  --output "$ALL_AFTER_PATH" \
  "${base_url}/api/v1/process-events"
count_after="$(PROCESS_EVENTS_PATH="$ALL_AFTER_PATH" python3 - <<'PY'
import json, os
with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
    items=json.load(handle)
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

docker compose exec -T telemetry python - <<'PY' > "$TELEMETRY_STATUS_PATH"
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8002/status') as response:
    print(json.dumps(json.load(response), indent=2, sort_keys=True))
PY

falco_source_count="$(docker compose exec -T -e FULL_CONTAINER_ID="$full_container_id" telemetry python - <<'PY'
import json, os
count=0
with open('/var/log/porygon/falco-events.jsonl', encoding='utf-8') as handle:
    for line in handle:
        try:
            event=json.loads(line)
        except json.JSONDecodeError:
            continue
        fields=event.get('output_fields') or {}
        reported=str(fields.get('container.id') or '')
        if reported and reported != 'host' and os.environ['FULL_CONTAINER_ID'].startswith(reported):
            count += 1
print(count)
PY
)"
falco_source_count="$(echo "$falco_source_count" | tr -d '\r' | tail -1)"
[[ "$falco_source_count" =~ ^[0-9]+$ ]] || fail "Could not count probe records in Falco output"
[[ "$falco_source_count" == "$count_after" ]] || fail \
  "Falco recorded $falco_source_count probe events but PostgreSQL stored $count_after"
pass "Every probe record observed in the Falco file reached PostgreSQL exactly once"

correlation_metrics="$(PROCESS_EVENTS_PATH="$ALL_AFTER_PATH" python3 - <<'PY'
import json, os
from collections import Counter
with open(os.environ['PROCESS_EVENTS_PATH'], encoding='utf-8') as handle:
    counts=Counter(item['correlation_status'] for item in json.load(handle))
print(json.dumps(dict(sorted(counts.items())), separators=(',', ':')))
PY
)"

RUN_ID="$RUN_ID" \
PROBE_NAME="$PROBE_NAME" \
FALCO_SOURCE_COUNT="$falco_source_count" \
TELEMETRY_OUTBOX_DURING_OUTAGE="$spooled_count" \
POSTGRES_COUNT="$count_after" \
REPLAY_ROW_GROWTH="$((count_after - count_before))" \
DEAD_LETTERS="$dead_letters" \
CORRELATION_METRICS="$correlation_metrics" \
TELEMETRY_STATUS_PATH="$TELEMETRY_STATUS_PATH" \
python3 - <<'PY' > artifacts/phase3-capture-integrity.json
import json, os
from pathlib import Path

status=json.loads(Path(os.environ['TELEMETRY_STATUS_PATH']).read_text(encoding='utf-8'))
correlation=json.loads(os.environ['CORRELATION_METRICS'])
document={
    'schema_version': 'porygon.capture-integrity.v1',
    'run_id': os.environ['RUN_ID'],
    'canary': {'container_name': os.environ['PROBE_NAME']},
    'boundaries': {
        'falco_file_probe_records_observed': int(os.environ['FALCO_SOURCE_COUNT']),
        'telemetry_outbox_events_during_backend_outage': int(os.environ['TELEMETRY_OUTBOX_DURING_OUTAGE']),
        'postgres_probe_rows_after_recovery': int(os.environ['POSTGRES_COUNT']),
        'postgres_probe_rows_by_correlation_status': correlation,
        'postgres_row_growth_after_replay': int(os.environ['REPLAY_ROW_GROWTH']),
        'telemetry_dead_letters_retained': int(os.environ['DEAD_LETTERS']),
        'telemetry_spool_overflow_attempts_observed': status['spool_overflow_count'],
    },
    'unmeasured_boundaries': [
        'Kernel-to-eBPF events not emitted to Falco',
        'Falco userspace drops because Falco metrics are not sampled by this gate',
        'Host failure outside this bounded run',
    ],
}
print(json.dumps(document, indent=2, sort_keys=True))
PY

cp "$ALL_AFTER_PATH" "${EVIDENCE_DIR}/process-events.json"
curl --fail --silent --show-error "${base_url}/api/v1/process-events/summary?container_name=${PROBE_NAME}" \
  > "${EVIDENCE_DIR}/process-summary.json"
curl --fail --silent --show-error "${base_url}/api/v1/system/info" \
  > "${EVIDENCE_DIR}/system-info.json"
docker compose logs --no-color falco > "${EVIDENCE_DIR}/falco.log"
docker compose ps > "${EVIDENCE_DIR}/services.txt"

printf '\nPhase 3 verification complete.\n'
