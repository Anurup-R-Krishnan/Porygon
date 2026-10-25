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

./scripts/verify_anomaly_scoring.sh
pass "Anomaly scoring verification completed"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"
token="$(grep -E '^PORYGON_INTERNAL_API_TOKEN=' .env | tail -1 | cut -d= -f2- || true)"
[[ ${#token} -ge 32 ]] || fail "PORYGON_INTERNAL_API_TOKEN is missing or too short"

curl --fail --silent --show-error "${base_url}/api/v1/detection-rules/config" \
  > artifacts/detection-ruleset.json
python3 - <<'PY' || fail "Detection ruleset metadata is invalid"
import json
cfg=json.load(open('artifacts/detection-ruleset.json'))
assert cfg['ruleset_version']=='porygon.detection.v1'
assert cfg['matcher_revision']=='porygon.detection.matcher.v4'
assert len(cfg['ruleset_hash'])==64
assert len(cfg['rules']) >= 7
assert 'Neither is a probability of compromise' in cfg['interpretation']
PY
pass "Public API exposes a hashed, versioned deterministic ruleset"

read_score_id() {
  local file="$1"
  FILE="$file" python3 - <<'PY'
import json, os
print(json.load(open(os.environ['FILE']))['score_id'])
PY
}

run_detection() {
  local score_id="$1"
  local output="$2"
  SCORE_ID="$score_id" python3 - <<'PY' > artifacts/detection-request.json
import json, os
print(json.dumps({'anomaly_score_id': os.environ['SCORE_ID']}))
PY
  curl --fail --silent --show-error \
    -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Porygon-Internal-Token: ${token}" \
    --data-binary @artifacts/detection-request.json \
    "${base_url}/internal/v1/detections/run" > "$output"
}

[[ -f artifacts/scoring-empty-score.json ]] || fail "artifacts/scoring-empty-score.json is missing"
empty_score_id="$(read_score_id artifacts/scoring-empty-score.json)"
normal_score_id="$(read_score_id artifacts/scoring-normal-score.json)"
novel_score_id="$(read_score_id artifacts/scoring-novel-score.json)"

run_detection "$empty_score_id" artifacts/detection-empty-detection.json
python3 - <<'PY' || fail "Insufficient score created an invalid detection outcome"
import json
r=json.load(open('artifacts/detection-empty-detection.json'))
assert r['run']['status']=='insufficient_data'
assert r['run']['incident_created'] is False
assert r['incident'] is None
assert r['timeline']==[]
PY
pass "Insufficient telemetry cannot produce an incident"

run_detection "$normal_score_id" artifacts/detection-normal-detection.json
python3 - <<'PY' || fail "Baseline-like window produced an incident"
import json
r=json.load(open('artifacts/detection-normal-detection.json'))
assert r['run']['status'] in {'no_findings','findings_only'}
assert r['run']['incident_created'] is False
assert r['incident'] is None
PY
pass "Baseline-like evidence produced no incident"

run_detection "$novel_score_id" artifacts/detection-novel-detection.json
python3 - <<'PY' || fail "Novel workload did not create a deterministic incident"
import json
r=json.load(open('artifacts/detection-novel-detection.json'))
assert r['run']['status']=='incident_created'
assert r['run']['incident_created'] is True
incident=r['incident']
assert incident is not None
assert incident['status']=='open'
assert 0.0 <= incident['anomaly_score'] <= 1.0
assert 0.0 <= incident['severity_score'] <= 1.0
assert 0.0 <= incident['confidence_score'] <= 1.0
assert incident['severity_score'] != incident['confidence_score']
assert r['timeline']
assert [x['sequence_no'] for x in r['timeline']] == list(range(1, len(r['timeline'])+1))
assert any(x['source_type']=='anomaly_score' for x in r['timeline'])
assert any(x['rule_id'] for x in r['timeline'])
print(incident['incident_id'])
PY
pass "Novel runtime evidence created an explainable incident with a chronological timeline"

incident_id="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/detection-novel-detection.json'))['incident']['incident_id'])
PY
)"
run_id="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/detection-novel-detection.json'))['run']['run_id'])
PY
)"

run_detection "$novel_score_id" artifacts/detection-novel-detection-retry.json
FIRST_RUN="$run_id" python3 - <<'PY' || fail "Detection rerun was not idempotent"
import json, os
r=json.load(open('artifacts/detection-novel-detection-retry.json'))
assert r['run']['run_id']==os.environ['FIRST_RUN']
PY
pass "Exact detection rerun returned the original run and incident"

# Build exact, digest-scoped exceptions only for the process findings observed in this
# controlled maintenance window. High anomaly distance remains visible but is not
# independently incident-eligible.
python3 - <<'PY' > artifacts/detection-allowlist-candidates.json
import json
r=json.load(open('artifacts/detection-novel-detection.json'))
incident=r['incident']
items=[]
seen=set()
for finding in incident['findings']:
    if finding['rule_id'] not in {'POR-DET-002','POR-DET-003','POR-DET-004'}:
        continue
    executable=finding.get('details',{}).get('executable')
    if not executable:
        continue
    key=(finding['rule_id'], executable)
    if key in seen:
        continue
    seen.add(key)
    items.append({
        'image_digest': incident['image_digest'],
        'rule_id': finding['rule_id'],
        'executable': executable,
        'parent_executable': None,
        'reason': 'Controlled detection engine verification',
        'approved_by': 'detection-engine-verifier',
        'approval_reference': 'detection-engine-acceptance',
        'expires_at': None,
    })
assert items, 'novel workload did not produce an allowlistable exact process finding'
print(json.dumps(items))
PY

BASE_URL="$base_url" TOKEN="$token" python3 - <<'PY'
import json, os, urllib.request
base=os.environ['BASE_URL']
token=os.environ['TOKEN']
items=json.load(open('artifacts/detection-allowlist-candidates.json'))
created=[]
for item in items:
    req=urllib.request.Request(
        base+'/internal/v1/detection-allowlists',
        data=json.dumps(item).encode(),
        headers={'Content-Type':'application/json','X-Porygon-Internal-Token':token},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        created.append(json.load(response))
open('artifacts/detection-created-allowlists.json','w').write(json.dumps(created, indent=2, sort_keys=True))
PY

run_detection "$novel_score_id" artifacts/detection-allowlisted-detection.json
python3 - <<'PY' || fail "Digest-scoped maintenance allowlists did not suppress exact findings"
import json
r=json.load(open('artifacts/detection-allowlisted-detection.json'))
assert r['run']['status'] in {'no_findings','findings_only'}
assert r['run']['incident_created'] is False
assert r['incident'] is None
assert r['run']['result']['suppressed_matches']
assert all(item['suppressed_by_allowlist_id'] for item in r['run']['result']['suppressed_matches'])
assert r['run']['allowlist_set_hash'] != json.load(open('artifacts/detection-novel-detection.json'))['run']['allowlist_set_hash']
PY
pass "Exact digest-scoped maintenance allowlists suppressed matching findings without hiding behavioural distance"

BASE_URL="$base_url" TOKEN="$token" python3 - <<'PY'
import json, os, urllib.request
base=os.environ['BASE_URL']
token=os.environ['TOKEN']
items=json.load(open('artifacts/detection-created-allowlists.json'))
for item in items:
    req=urllib.request.Request(
        base+f"/internal/v1/detection-allowlists/{item['allowlist_id']}/deactivate",
        data=json.dumps({'actor':'detection-verifier'}).encode(),
        headers={'Content-Type':'application/json','X-Porygon-Internal-Token':token},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        result=json.load(response)
        assert result['active'] is False
PY
pass "Approved exceptions can be explicitly deactivated and remain auditable"

status_update() {
  local new_status="$1"
  local actor="$2"
  local note="$3"
  local output="$4"
  NEW_STATUS="$new_status" ACTOR="$actor" NOTE="$note" python3 - <<'PY' > artifacts/detection-status-request.json
import json, os
print(json.dumps({'status':os.environ['NEW_STATUS'],'actor':os.environ['ACTOR'],'note':os.environ['NOTE']}))
PY
  curl --fail --silent --show-error \
    -X POST -H 'Content-Type: application/json' \
    -H "X-Porygon-Internal-Token: ${token}" \
    --data-binary @artifacts/detection-status-request.json \
    "${base_url}/internal/v1/incidents/${incident_id}/status" > "$output"
}

status_update acknowledged detection-verifier "Evidence reviewed" artifacts/detection-acknowledged.json
status_update resolved detection-verifier "Controlled experiment completed" artifacts/detection-resolved.json
python3 - <<'PY' || fail "Incident lifecycle fields were not persisted"
import json
ack=json.load(open('artifacts/detection-acknowledged.json'))
resolved=json.load(open('artifacts/detection-resolved.json'))
assert ack['status']=='acknowledged'
assert ack['acknowledged_by']=='detection-verifier'
assert resolved['status']=='resolved'
assert resolved['closed_by']=='detection-verifier'
assert resolved['closure_note']=='Controlled experiment completed'
PY
pass "Human incident acknowledgement and resolution were persisted"

http_code="$(curl --silent --output artifacts/detection-invalid-transition.json --write-out '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Internal-Token: ${token}" \
  --data '{"status":"acknowledged","actor":"detection-verifier","note":"invalid reopen"}' \
  "${base_url}/internal/v1/incidents/${incident_id}/status")"
[[ "$http_code" == "409" ]] || fail "Terminal incident transition returned HTTP $http_code instead of 409"
pass "Terminal incidents cannot be reopened through an invalid state transition"

curl --fail --silent --show-error "${base_url}/api/v1/incidents/${incident_id}/timeline" \
  > artifacts/detection-final-timeline.json
curl --fail --silent --show-error "${base_url}/api/v1/system/info" \
  > artifacts/detection-system-info.json
python3 - <<'PY' || fail "Detection engine system counters or status evidence are inconsistent"
import json
timeline=json.load(open('artifacts/detection-final-timeline.json'))
info=json.load(open('artifacts/detection-system-info.json'))
assert timeline[-2]['details']['status']=='acknowledged'
assert timeline[-1]['details']['status']=='resolved'
assert info['capability']
assert info['detection_allowlists'] >= 1
assert info['active_detection_allowlists'] == 0
assert info['detection_runs'] >= 4
assert info['incidents'] >= 1
assert info['open_incidents'] == 0
PY
pass "System counters and complete evidence timeline remain consistent"

docker compose ps > artifacts/detection-services.txt
printf '\nDetection engine verification complete. Incident severity and confidence are evidence-oriented research signals, not compromise probabilities.\n'
