#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

RUN_ID="${PORYGON_VERIFY_RUN_ID:-$(date -u +%Y%m%dt%H%M%Sz)-$$}"
PROBE_NAME="porygon-phase5-${RUN_ID}"
PROBE_IMAGE="alpine:3.20"
CONTAINERS_PATH="artifacts/local/phase5-${RUN_ID}-containers.json"

fail() {
  echo "[FAIL] $*" >&2
  docker compose logs --tail=160 backend telemetry collector 2>/dev/null || true
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_probe() {
  docker rm -f "$PROBE_NAME" >/dev/null 2>&1 || true
  rm -f "$CONTAINERS_PATH"
}
trap cleanup_probe EXIT

[[ -f .env ]] || fail ".env is missing. Copy .env.example and replace its placeholders."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets"
fi
for command in docker curl python3; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done

mkdir -p artifacts
mkdir -p artifacts/local

./scripts/verify_phase4.sh
pass "Phases 1-4 remain valid and an active immutable-digest profile exists"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"
token="$(grep -E '^PORYGON_INTERNAL_API_TOKEN=' .env | tail -1 | cut -d= -f2- || true)"
[[ ${#token} -ge 32 ]] || fail "PORYGON_INTERNAL_API_TOKEN is missing or too short"

digest="$(cat artifacts/phase4-selected-digest.txt)"
[[ "$digest" == *@sha256:* ]] || fail "Phase 4 did not provide an immutable repository digest"

curl --fail --silent --show-error \
  "${base_url}/api/v1/anomaly-scores/config" > artifacts/phase5-scoring-config.json
python3 - <<'PY' || fail "Scoring configuration is missing reproducibility metadata"
import json
cfg=json.load(open('artifacts/phase5-scoring-config.json'))
assert cfg['algorithm_version']=='porygon.distance.v1'
assert cfg['feature_schema_version']=='porygon.behaviour.v1'
assert abs(sum(cfg['scoring_config']['top_level_weights'].values())-1.0) < 1e-12
assert 'not validated attack thresholds' in cfg['interpretation']
PY
pass "Public API exposes the immutable scoring definition and provisional-band warning"

curl --fail --silent --show-error --get \
  --data-urlencode "image_digest=${digest}" \
  "${base_url}/api/v1/baselines/active" > artifacts/phase5-active-profile.json

readarray -t profile_values < <(python3 - <<'PY'
import json
p=json.load(open('artifacts/phase5-active-profile.json'))
print(p['profile_id'])
print(p['window_seconds'])
print(p['training_start'])
PY
)
profile_id="${profile_values[0]}"
window_seconds="${profile_values[1]}"
training_start="${profile_values[2]}"
[[ "$window_seconds" =~ ^[0-9]+$ ]] || fail "Active profile window_seconds is invalid"

cleanup_probe
docker pull "$PROBE_IMAGE" >/dev/null
expected_repo_digest="$(docker image inspect "$PROBE_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$expected_repo_digest" == "$digest" ]] || fail "Probe image digest changed between Phase 4 and Phase 5"
docker run --detach \
  --name "$PROBE_NAME" \
  --label io.porygon.phase5.probe=true \
  --label "io.porygon.phase5.run=${RUN_ID}" \
  "$PROBE_IMAGE" sh -c 'sleep 600' >/dev/null
full_container_id="$(docker inspect "$PROBE_NAME" --format '{{.Id}}')"

container_ready=false
for _ in $(seq 1 60); do
  curl --fail --silent --show-error \
    --output "$CONTAINERS_PATH" \
    "${base_url}/api/v1/containers?limit=500" || true
  if CONTAINERS_PATH="$CONTAINERS_PATH" PROBE_NAME="$PROBE_NAME" EXPECTED_DIGEST="$digest" python3 - <<'PY'
import json, os, sys
try:
    with open(os.environ['CONTAINERS_PATH'], encoding='utf-8') as handle:
        items=json.load(handle)
except Exception:
    sys.exit(1)
match=next((item for item in items if item.get('container_name')==os.environ['PROBE_NAME']), None)
if not match or match.get('image_digest') != os.environ['EXPECTED_DIGEST']:
    sys.exit(1)
PY
  then
    container_ready=true
    break
  fi
  sleep 2
done
[[ "$container_ready" == true ]] || fail "Phase 5 probe was not correlated to the expected digest"
pass "Phase 5 probe resolves to the same immutable digest as the active profile"

utc_now() {
  python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
}

sleep_until_window_complete() {
  local started="$1"
  local seconds="$2"
  STARTED="$started" WINDOW_SECONDS="$seconds" python3 - <<'PY'
import os, time
from datetime import datetime, timedelta, timezone
start=datetime.fromisoformat(os.environ['STARTED'].replace('Z','+00:00')).astimezone(timezone.utc)
target=start+timedelta(seconds=int(os.environ['WINDOW_SECONDS'])+2)
delay=(target-datetime.now(timezone.utc)).total_seconds()
if delay > 0:
    time.sleep(delay)
PY
}

write_payload() {
  local start="$1"
  local output="$2"
  IMAGE_DIGEST="$digest" WINDOW_START="$start" PROFILE_ID="$profile_id" OUTPUT="$output" python3 - <<'PY'
import json, os
payload={
    'image_digest': os.environ['IMAGE_DIGEST'],
    'window_start': os.environ['WINDOW_START'],
    'profile_id': os.environ['PROFILE_ID'],
}
open(os.environ['OUTPUT'],'w').write(json.dumps(payload, indent=2, sort_keys=True))
PY
}

compute_score() {
  local payload="$1"
  local output="$2"
  curl --fail --silent --show-error \
    -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Porygon-Internal-Token: ${token}" \
    --data-binary "@${payload}" \
    "${base_url}/internal/v1/anomaly-scores/compute" > "$output"
}

# Completed window with no new process execution. This must not be called normal.
empty_start="$(utc_now)"
sleep_until_window_complete "$empty_start" "$window_seconds"
write_payload "$empty_start" artifacts/phase5-empty-payload.json
compute_score artifacts/phase5-empty-payload.json artifacts/phase5-empty-score.json
python3 - <<'PY' || fail "An empty telemetry window was not marked insufficient_data"
import json
s=json.load(open('artifacts/phase5-empty-score.json'))
assert s['status']=='insufficient_data'
assert s['score_band']=='insufficient_data'
assert s['total_score'] is None
assert 'not evidence of normal behaviour' in s['explanation']['interpretation']
PY
pass "Missing process evidence is persisted as insufficient_data, never assumed normal"

# Baseline-like process tree: sh -> sh -> sleep, matching the controlled training pattern.
normal_start="$(utc_now)"
docker exec "$PROBE_NAME" sh -c 'sh -c "sleep 1 & child=$!; wait $child" phase5-normal-inner' phase5-normal-outer
sleep_until_window_complete "$normal_start" "$window_seconds"
write_payload "$normal_start" artifacts/phase5-normal-payload.json
compute_score artifacts/phase5-normal-payload.json artifacts/phase5-normal-score.json
python3 - <<'PY' || fail "Baseline-like window did not produce a bounded explainable score"
import json
s=json.load(open('artifacts/phase5-normal-score.json'))
assert s['status']=='scored'
assert 0.0 <= s['total_score'] <= 1.0
assert s['score_band'] in {'baseline_like','elevated','high','extreme'}
assert s['algorithm_version']=='porygon.distance.v1'
assert s['explanation']['top_contributors']
assert len(s['observation_manifest']['selected_event_ids_sha256'])==64
PY
pass "A completed baseline-like window produced a bounded, persisted, explainable distance score"

# Deliberately novel process mix. These commands are evidence generators, not an exploit.
anomaly_start="$(utc_now)"
docker exec "$PROBE_NAME" sh -c '
  base64 /etc/passwd >/dev/null
  find /etc -maxdepth 1 >/dev/null
  wc -c /etc/passwd >/dev/null
  sha256sum /etc/passwd >/dev/null
  head -c 8 /dev/zero >/dev/null
  tail -n 1 /etc/passwd >/dev/null
  cut -d: -f1 /etc/passwd >/dev/null
  printf test | tr a-z A-Z >/dev/null
  od -An -tx1 /etc/hostname >/dev/null
  cksum /etc/passwd >/dev/null
'
sleep_until_window_complete "$anomaly_start" "$window_seconds"
write_payload "$anomaly_start" artifacts/phase5-novel-payload.json
compute_score artifacts/phase5-novel-payload.json artifacts/phase5-novel-score.json

NORMAL_SCORE="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/phase5-normal-score.json'))['total_score'])
PY
)" NOVEL_SCORE="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/phase5-novel-score.json'))['total_score'])
PY
)" python3 - <<'PY' || fail "Novel workload did not produce stronger explainable deviation"
import json, os
normal=float(os.environ['NORMAL_SCORE'])
novel=float(os.environ['NOVEL_SCORE'])
s=json.load(open('artifacts/phase5-novel-score.json'))
assert s['status']=='scored'
assert 0.0 <= novel <= 1.0
assert novel > normal
assert s['components']['novelty']['score'] > 0.0
assert s['explanation']['unseen_tokens']
assert any(item['weighted_contribution'] > 0 for item in s['explanation']['top_contributors'])
PY
pass "A deliberately novel workload scored farther from the profile than the baseline-like workload"

# Exact retry must return the same persisted record.
compute_score artifacts/phase5-novel-payload.json artifacts/phase5-novel-score-retry.json
python3 - <<'PY' || fail "Exact rescoring was not idempotent"
import json
first=json.load(open('artifacts/phase5-novel-score.json'))
retry=json.load(open('artifacts/phase5-novel-score-retry.json'))
assert retry['score_id']==first['score_id']
assert retry['observation_key']==first['observation_key']
assert retry['total_score']==first['total_score']
PY
pass "Exact rescoring returned the original record instead of creating a duplicate"

# Training data must not be scored as independent evaluation evidence.
TRAINING_START="$training_start" IMAGE_DIGEST="$digest" PROFILE_ID="$profile_id" python3 - <<'PY'
import json, os
payload={
    'image_digest': os.environ['IMAGE_DIGEST'],
    'window_start': os.environ['TRAINING_START'],
    'profile_id': os.environ['PROFILE_ID'],
}
open('artifacts/phase5-overlap-payload.json','w').write(json.dumps(payload, indent=2, sort_keys=True))
PY
http_code="$(curl --silent --output artifacts/phase5-overlap-response.json --write-out '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Internal-Token: ${token}" \
  --data-binary @artifacts/phase5-overlap-payload.json \
  "${base_url}/internal/v1/anomaly-scores/compute")"
[[ "$http_code" == "409" ]] || fail "Training-overlap score returned HTTP $http_code instead of 409"
pass "Training and evaluation windows are kept separate"

curl --fail --silent --show-error --get \
  --data-urlencode "image_digest=${digest}" \
  "${base_url}/api/v1/anomaly-scores" > artifacts/phase5-scores.json
curl --fail --silent --show-error "${base_url}/api/v1/system/info" \
  > artifacts/phase5-system-info.json

python3 - <<'PY' || fail "Stored score and system invariants failed"
import json
scores=json.load(open('artifacts/phase5-scores.json'))
info=json.load(open('artifacts/phase5-system-info.json'))
assert len(scores) >= 3
assert sum(item['status']=='insufficient_data' for item in scores) >= 1
assert sum(item['status']=='scored' for item in scores) >= 2
assert len({item['observation_key'] for item in scores}) == len(scores)
assert int(info['phase'].split()[1].rstrip(':')) >= 5
assert info['anomaly_scores'] >= 3
assert info['scored_observations'] >= 2
assert info['insufficient_observations'] >= 1
PY
pass "System API reports unique scored and insufficient observations"

docker compose ps > artifacts/phase5-services.txt
printf '\nPhase 5 verification complete. Scores are behavioural distances, not attack verdicts.\n'
