#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

TARGET_NAME="porygon-phase7-target"
TARGET_IMAGE="alpine:3.20"

fail() {
  echo "[FAIL] $*" >&2
  docker compose logs --tail=180 backend responder collector telemetry 2>/dev/null || true
  exit 1
}

pass() {
  echo "[PASS] $*"
}

cleanup_target() {
  docker rm -f "$TARGET_NAME" >/dev/null 2>&1 || true
}
trap cleanup_target EXIT

[[ -f .env ]] || fail ".env is missing. Copy .env.example and replace its placeholders."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets"
fi
for command in docker curl python3; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done

mkdir -p artifacts

internal_token="$(grep -E '^PORYGON_INTERNAL_API_TOKEN=' .env | tail -1 | cut -d= -f2- || true)"
operator_token="$(grep -E '^PORYGON_OPERATOR_API_TOKEN=' .env | tail -1 | cut -d= -f2- || true)"
execution_mode="$(grep -E '^PORYGON_RESPONSE_EXECUTION_MODE=' .env | tail -1 | cut -d= -f2- || true)"
[[ ${#internal_token} -ge 32 ]] || fail "PORYGON_INTERNAL_API_TOKEN is missing or too short"
[[ ${#operator_token} -ge 32 ]] || fail "PORYGON_OPERATOR_API_TOKEN is missing or too short"
[[ "$internal_token" != "$operator_token" ]] || fail "Internal and operator tokens must be different"
[[ "$execution_mode" == "live" ]] || fail "Set PORYGON_RESPONSE_EXECUTION_MODE=live only for this controlled Phase 7 acceptance test"

./scripts/verify_phase6.sh
pass "Cumulative Phase 1-6 live verification completed"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"

curl --fail --silent --show-error "${base_url}/api/v1/response-policy" \
  > artifacts/phase7-response-policy.json
python3 - <<'PY' || fail "Response policy or runtime safety controls are invalid"
import json
p=json.load(open('artifacts/phase7-response-policy.json'))
assert p['policy']['version']=='porygon.response.v1'
assert len(p['policy_hash'])==64
assert p['execution_mode']=='live'
assert p['approval_max_age_seconds'] >= 60
assert 'separate operator credential' in p['interpretation']
assert set(p['policy']['actions']) == {'observe_only','pause_container','stop_container'}
PY
pass "Response policy is versioned, hashed, operator-gated, and explicitly live for this test"

# An automated-service credential must not authorize a human/operator decision.
http_code="$(curl --silent --output artifacts/phase7-token-separation.json --write-out '%{http_code}' \
  -X POST \
  -H "X-Porygon-Operator-Token: ${internal_token}" \
  "${base_url}/operator/v1/incidents/not-a-real-incident/response-recommendations")"
[[ "$http_code" == "401" ]] || fail "Internal token was not rejected by the operator boundary (HTTP $http_code)"
pass "Automated-service and human/operator credentials are separated"

digest="$(cat artifacts/phase4-selected-digest.txt)"
[[ "$digest" == *@sha256:* ]] || fail "Phase 4 did not provide an immutable repository digest"

curl --fail --silent --show-error --get \
  --data-urlencode "image_digest=${digest}" \
  "${base_url}/api/v1/baselines/active" > artifacts/phase7-active-profile.json
readarray -t profile_values < <(python3 - <<'PY'
import json
p=json.load(open('artifacts/phase7-active-profile.json'))
print(p['profile_id'])
print(p['window_seconds'])
PY
)
profile_id="${profile_values[0]}"
window_seconds="${profile_values[1]}"
[[ "$window_seconds" =~ ^[0-9]+$ ]] || fail "Active profile window_seconds is invalid"

cleanup_target
docker pull "$TARGET_IMAGE" >/dev/null
expected_repo_digest="$(docker image inspect "$TARGET_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$expected_repo_digest" == "$digest" ]] || fail "Target image digest changed since the baseline was built"
docker run --detach \
  --name "$TARGET_NAME" \
  --label io.porygon.phase7.target=true \
  "$TARGET_IMAGE" sh -c 'sleep 900' >/dev/null
full_container_id="$(docker inspect "$TARGET_NAME" --format '{{.Id}}')"
[[ ${#full_container_id} -eq 64 ]] || fail "Docker did not return a full container ID"

container_ready=false
for _ in $(seq 1 60); do
  containers="$(curl --fail --silent --show-error "${base_url}/api/v1/containers?limit=500" || true)"
  if CONTAINERS_JSON="$containers" TARGET_NAME="$TARGET_NAME" EXPECTED_DIGEST="$digest" EXPECTED_ID="$full_container_id" python3 - <<'PY'
import json, os, sys
try:
    items=json.loads(os.environ['CONTAINERS_JSON'])
except Exception:
    sys.exit(1)
match=next((item for item in items if item.get('container_name')==os.environ['TARGET_NAME']), None)
if not match:
    sys.exit(1)
if match.get('image_digest') != os.environ['EXPECTED_DIGEST']:
    sys.exit(1)
if match.get('container_id') != os.environ['EXPECTED_ID']:
    sys.exit(1)
PY
  then
    container_ready=true
    break
  fi
  sleep 2
done
[[ "$container_ready" == true ]] || fail "Phase 7 target was not correlated to the immutable image digest"
pass "Disposable response target is bound to the active immutable-digest profile"

window_start="$(python3 - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).isoformat())
PY
)"
# Controlled evidence only: shell plus encoding tool. This is not an exploit.
docker exec "$TARGET_NAME" sh -c 'ln -sf /bin/busybox /tmp/ash; /tmp/ash -c "base64 /etc/hostname >/dev/null"'
STARTED="$window_start" WINDOW_SECONDS="$window_seconds" python3 - <<'PY'
import os, time
from datetime import datetime, timedelta, timezone
start=datetime.fromisoformat(os.environ['STARTED'].replace('Z','+00:00')).astimezone(timezone.utc)
target=start+timedelta(seconds=int(os.environ['WINDOW_SECONDS'])+2)
delay=(target-datetime.now(timezone.utc)).total_seconds()
if delay > 0:
    time.sleep(delay)
PY

IMAGE_DIGEST="$digest" WINDOW_START="$window_start" PROFILE_ID="$profile_id" python3 - <<'PY' > artifacts/phase7-score-request.json
import json, os
print(json.dumps({
  'image_digest': os.environ['IMAGE_DIGEST'],
  'window_start': os.environ['WINDOW_START'],
  'profile_id': os.environ['PROFILE_ID'],
}))
PY
curl --fail --silent --show-error \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Internal-Token: ${internal_token}" \
  --data-binary @artifacts/phase7-score-request.json \
  "${base_url}/internal/v1/anomaly-scores/compute" > artifacts/phase7-score.json
score_id="$(python3 - <<'PY'
import json
s=json.load(open('artifacts/phase7-score.json'))
assert s['status']=='scored'
print(s['score_id'])
PY
)"

SCORE_ID="$score_id" python3 - <<'PY' > artifacts/phase7-detection-request.json
import json, os
print(json.dumps({'anomaly_score_id': os.environ['SCORE_ID']}))
PY
curl --fail --silent --show-error \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Internal-Token: ${internal_token}" \
  --data-binary @artifacts/phase7-detection-request.json \
  "${base_url}/internal/v1/detections/run" > artifacts/phase7-detection.json
readarray -t detection_values < <(EXPECTED_CONTAINER="$full_container_id" python3 - <<'PY'
import json, os
r=json.load(open('artifacts/phase7-detection.json'))
assert r['run']['status']=='incident_created'
i=r['incident']
assert i is not None and i['status']=='open'
assert os.environ['EXPECTED_CONTAINER'] in i['container_ids']
assert any(f['rule_id'] in {'POR-DET-002','POR-DET-004','POR-DET-005'} for f in i['findings'])
print(i['incident_id'])
print(i['severity_score'])
print(i['confidence_score'])
PY
)
incident_id="${detection_values[0]}"
pass "Controlled novel behaviour created an open incident for the exact live container"

curl --fail --silent --show-error \
  -X POST -H "X-Porygon-Operator-Token: ${operator_token}" \
  "${base_url}/operator/v1/incidents/${incident_id}/response-recommendations" \
  > artifacts/phase7-recommendations.json
readarray -t recommendation_values < <(EXPECTED_CONTAINER="$full_container_id" python3 - <<'PY'
import json, os
r=json.load(open('artifacts/phase7-recommendations.json'))
item=next(x for x in r['recommendations'] if x['target_container_id']==os.environ['EXPECTED_CONTAINER'])
assert item['status']=='proposed'
assert 'observe_only' in item['allowed_actions']
assert 'pause_container' in item['allowed_actions']
assert item['approved_action'] is None
print(item['recommendation_id'])
print(item['recommended_action'])
PY
)
recommendation_id="${recommendation_values[0]}"
pass "Policy produced a typed recommendation without changing Docker state"

[[ "$(docker inspect "$TARGET_NAME" --format '{{.State.Paused}}')" == "false" ]] || fail "Target changed before approval"

RECOMMENDATION_ID="$recommendation_id" python3 - <<'PY' > artifacts/phase7-approval-request.json
import json, os
print(json.dumps({
  'action_type':'pause_container',
  'actor':'phase7-verifier',
  'note':'Controlled acceptance-test containment',
  'acknowledge_disruption':True,
}))
PY
curl --fail --silent --show-error \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Operator-Token: ${operator_token}" \
  --data-binary @artifacts/phase7-approval-request.json \
  "${base_url}/operator/v1/response-recommendations/${recommendation_id}/approve" \
  > artifacts/phase7-approved-execution.json
execution_id="$(python3 - <<'PY'
import json
r=json.load(open('artifacts/phase7-approved-execution.json'))
assert r['action_type']=='pause_container'
assert r['status'] in {'pending','claimed','succeeded'}
print(r['execution_id'])
PY
)"

execution_complete=false
for _ in $(seq 1 60); do
  curl --fail --silent --show-error \
    "${base_url}/api/v1/response-executions/${execution_id}" \
    > artifacts/phase7-execution.json
  state="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/phase7-execution.json'))['status'])
PY
)"
  if [[ "$state" == "succeeded" ]]; then
    execution_complete=true
    break
  fi
  [[ "$state" != "failed" ]] || fail "Pause execution failed; inspect artifacts/phase7-execution.json"
  sleep 1
done
[[ "$execution_complete" == true ]] || fail "Responder did not complete the approved action"
[[ "$(docker inspect "$TARGET_NAME" --format '{{.State.Paused}}')" == "true" ]] || fail "Docker did not report the target as paused"
python3 - <<'PY' || fail "Execution result lacks state verification evidence"
import json
r=json.load(open('artifacts/phase7-execution.json'))
assert r['pre_state']['paused'] is False
assert r['post_state']['paused'] is True
assert r['result']['verification']=='passed'
assert r['result']['verification_scope']=='immediate Docker inspect state'
PY
pass "Responder paused only the explicitly approved exact target and verified Docker state"

# Exact repeated approval must not create another execution.
curl --fail --silent --show-error \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Operator-Token: ${operator_token}" \
  --data-binary @artifacts/phase7-approval-request.json \
  "${base_url}/operator/v1/response-recommendations/${recommendation_id}/approve" \
  > artifacts/phase7-approval-retry.json
FIRST_EXECUTION="$execution_id" python3 - <<'PY' || fail "Repeated approval was not idempotent"
import json, os
r=json.load(open('artifacts/phase7-approval-retry.json'))
assert r['execution_id']==os.environ['FIRST_EXECUTION']
PY
pass "Repeated identical approval returned the original execution"

cat > artifacts/phase7-rollback-request.json <<'JSON'
{
  "actor": "phase7-verifier",
  "note": "Restore the controlled workload after evidence capture",
  "acknowledge_limitations": true
}
JSON
curl --fail --silent --show-error \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Operator-Token: ${operator_token}" \
  --data-binary @artifacts/phase7-rollback-request.json \
  "${base_url}/operator/v1/response-executions/${execution_id}/rollback" \
  > artifacts/phase7-rollback-queued.json

rollback_complete=false
for _ in $(seq 1 60); do
  curl --fail --silent --show-error \
    "${base_url}/api/v1/response-executions/${execution_id}" \
    > artifacts/phase7-rolled-back-execution.json
  state="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/phase7-rolled-back-execution.json'))['status'])
PY
)"
  if [[ "$state" == "rolled_back" ]]; then
    rollback_complete=true
    break
  fi
  [[ "$state" != "rollback_failed" ]] || fail "Rollback failed; inspect artifacts/phase7-rolled-back-execution.json"
  sleep 1
done
[[ "$rollback_complete" == true ]] || fail "Responder did not complete the rollback"
[[ "$(docker inspect "$TARGET_NAME" --format '{{.State.Paused}}')" == "false" ]] || fail "Target remains paused after rollback"
[[ "$(docker inspect "$TARGET_NAME" --format '{{.State.Running}}')" == "true" ]] || fail "Target is not running after rollback"
pass "Pause rollback unpaused the target and verified its running state"

curl --fail --silent --show-error \
  "${base_url}/api/v1/incidents/${incident_id}/response-audit" \
  > artifacts/phase7-response-audit.json
python3 - <<'PY' || fail "Response audit trail is incomplete or out of order"
import json
events=json.load(open('artifacts/phase7-response-audit.json'))
types=[x['event_type'] for x in events]
required=[
  'recommendation_created',
  'recommendation_approved',
  'execute_claimed',
  'execute_succeeded',
  'rollback_requested',
  'rollback_claimed',
  'rollback_succeeded',
]
pos=-1
for item in required:
    pos=types.index(item, pos+1)
assert all(events[i]['created_at'] <= events[i+1]['created_at'] for i in range(len(events)-1))
assert events[-1]['details']['post_state']['paused'] is False
PY
pass "Recommendation, approval, execution, verification, and rollback are chronologically audited"

curl --fail --silent --show-error "${base_url}/api/v1/system/info" \
  > artifacts/phase7-system-info.json
python3 - <<'PY' || fail "Phase 7 system counters are inconsistent"
import json
info=json.load(open('artifacts/phase7-system-info.json'))
assert int(info['phase'].split()[1].rstrip(':')) >= 7
assert info['response_recommendations'] >= 1
assert info['approved_response_recommendations'] >= 1
assert info['response_executions'] >= 1
assert info['successful_response_executions'] >= 1
PY
pass "System API reports cumulative Phase 7 response state"

docker compose ps > artifacts/phase7-services.txt
printf '\nPhase 7 verification complete. Reset PORYGON_RESPONSE_EXECUTION_MODE=disabled after this controlled test.\n'
