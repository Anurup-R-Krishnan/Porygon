#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
  echo "[FAIL] $*" >&2
  docker compose logs --tail=120 backend telemetry collector 2>/dev/null || true
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f .env ]] || fail ".env is missing. Copy .env.example and replace its placeholders."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder secrets"
fi
for command in docker curl python3; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done

mkdir -p artifacts

./scripts/verify_phase3.sh
pass "Phase 3 telemetry and correlation remain valid"

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"
token="$(grep -E '^PORYGON_INTERNAL_API_TOKEN=' .env | tail -1 | cut -d= -f2- || true)"
[[ ${#token} -ge 32 ]] || fail "PORYGON_INTERNAL_API_TOKEN is missing or too short"

python3 - <<'PY'
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

integrity=json.loads(Path('artifacts/phase3-capture-integrity.json').read_text())
events_path=Path('artifacts/local') / f"phase3-{integrity['run_id']}" / 'process-events.json'
events=json.loads(events_path.read_text())
if not events:
    raise SystemExit('Phase 3 produced no process events')
digests={event.get('image_digest') for event in events if event.get('image_digest')}
if len(digests) != 1:
    raise SystemExit(f'Expected one immutable digest, found {sorted(digests)}')
digest=next(iter(digests))
times=[datetime.fromisoformat(event['occurred_at'].replace('Z','+00:00')).astimezone(timezone.utc) for event in events]
start=min(times)-timedelta(seconds=1)
end=max(times)+timedelta(seconds=1)
base={
    'image_digest': digest,
    'training_start': start.isoformat(),
    'training_end': end.isoformat(),
    'minimum_process_events': 1,
    'minimum_nonempty_windows': 1,
    'approved_by': 'phase4-verifier',
    'approval_reference': 'scripts/verify_phase4.sh',
}
for name, window, minimum in [('v1',60,1), ('bad',45,999999), ('v2',30,1)]:
    payload=dict(base)
    payload['window_seconds']=window
    payload['minimum_process_events']=minimum
    payload['notes']=f'Controlled Phase 4 acceptance profile {name}'
    Path(f'artifacts/phase4-{name}-payload.json').write_text(json.dumps(payload, indent=2, sort_keys=True))
Path('artifacts/phase4-selected-digest.txt').write_text(digest+'\n')
PY

post_json() {
  local path="$1"
  local input="$2"
  local output="$3"
  curl --fail --silent --show-error \
    -X POST \
    -H 'Content-Type: application/json' \
    -H "X-Porygon-Internal-Token: ${token}" \
    --data-binary "@${input}" \
    "${base_url}${path}" > "${output}"
}

post_json "/internal/v1/baselines/build" \
  artifacts/phase4-v1-payload.json artifacts/phase4-profile-v1.json
v1_id="$(python3 - <<'PY'
import json
print(json.load(open('artifacts/phase4-profile-v1.json'))['profile_id'])
PY
)"
python3 - <<'PY' || fail "First profile was not a quality-passing draft"
import json
p=json.load(open('artifacts/phase4-profile-v1.json'))
assert p['status']=='draft'
assert p['quality']['passed'] is True
assert p['feature_schema_version']=='porygon.behaviour.v1'
assert len(p['model_hash'])==64
assert len(p['training_manifest']['selected_event_ids_sha256'])==64
for distribution in p['features']['categorical_distributions'].values():
    if distribution:
        assert abs(sum(distribution.values())-1.0) < 1e-8
PY
pass "Created a deterministic quality-passing draft for one immutable digest"

post_json "/internal/v1/baselines/${v1_id}/activate" /dev/null artifacts/phase4-profile-v1-active.json
python3 - <<'PY' || fail "First profile did not activate"
import json
assert json.load(open('artifacts/phase4-profile-v1-active.json'))['status']=='active'
PY
pass "Explicit activation promoted the first profile"

http_code="$(curl --silent --output artifacts/phase4-duplicate-response.json --write-out '%{http_code}' \
  -X POST -H 'Content-Type: application/json' \
  -H "X-Porygon-Internal-Token: ${token}" \
  --data-binary @artifacts/phase4-v1-payload.json \
  "${base_url}/internal/v1/baselines/build")"
[[ "$http_code" == "409" ]] || fail "Identical profile rebuild returned HTTP $http_code instead of 409"
pass "Identical training selection and vectorizer output were rejected"

post_json "/internal/v1/baselines/build" \
  artifacts/phase4-bad-payload.json artifacts/phase4-profile-quality-failed.json
bad_id="$(python3 - <<'PY'
import json
p=json.load(open('artifacts/phase4-profile-quality-failed.json'))
assert p['quality']['passed'] is False
print(p['profile_id'])
PY
)"
http_code="$(curl --silent --output artifacts/phase4-quality-activation-response.json --write-out '%{http_code}' \
  -X POST -H "X-Porygon-Internal-Token: ${token}" \
  "${base_url}/internal/v1/baselines/${bad_id}/activate")"
[[ "$http_code" == "409" ]] || fail "Quality-failing activation returned HTTP $http_code instead of 409"
pass "A quality-failing profile remained an inactive draft"

post_json "/internal/v1/baselines/build" \
  artifacts/phase4-v2-payload.json artifacts/phase4-profile-v2.json
v2_id="$(python3 - <<'PY'
import json
p=json.load(open('artifacts/phase4-profile-v2.json'))
assert p['quality']['passed'] is True
print(p['profile_id'])
PY
)"
post_json "/internal/v1/baselines/${v2_id}/activate" /dev/null artifacts/phase4-profile-v2-active.json
pass "Built and activated a changed profile version"

digest="$(cat artifacts/phase4-selected-digest.txt)"
curl --fail --silent --show-error --get \
  --data-urlencode "image_digest=${digest}" \
  "${base_url}/api/v1/baselines" > artifacts/phase4-profiles.json
curl --fail --silent --show-error --get \
  --data-urlencode "image_digest=${digest}" \
  "${base_url}/api/v1/baselines/active" > artifacts/phase4-active-profile.json

V1_ID="$v1_id" V2_ID="$v2_id" python3 - <<'PY' || fail "Profile lifecycle invariants failed"
import json, os
profiles=json.load(open('artifacts/phase4-profiles.json'))
by_id={p['profile_id']:p for p in profiles}
assert by_id[os.environ['V1_ID']]['status']=='retired'
assert by_id[os.environ['V2_ID']]['status']=='active'
assert sum(p['status']=='active' for p in profiles)==1
active=json.load(open('artifacts/phase4-active-profile.json'))
assert active['profile_id']==os.environ['V2_ID']
assert by_id[os.environ['V2_ID']]['profile_version'] > by_id[os.environ['V1_ID']]['profile_version']
PY
pass "New activation retired the previous active version and preserved one active digest profile"

http_code="$(curl --silent --output artifacts/phase4-retired-reactivation-response.json --write-out '%{http_code}' \
  -X POST -H "X-Porygon-Internal-Token: ${token}" \
  "${base_url}/internal/v1/baselines/${v1_id}/activate")"
[[ "$http_code" == "409" ]] || fail "Retired profile reactivation returned HTTP $http_code instead of 409"
pass "Retired profiles cannot be reactivated"

curl --fail --silent --show-error "${base_url}/api/v1/system/info" \
  > artifacts/phase4-system-info.json
python3 - <<'PY' || fail "System information did not report Phase 4 profile state"
import json
info=json.load(open('artifacts/phase4-system-info.json'))
assert info['behavior_profiles'] >= 3
assert info['active_behavior_profiles'] >= 1
assert int(info['phase'].split()[1].rstrip(':')) >= 4
PY
pass "System API reports stored and active behaviour profiles"

printf '\nPhase 4 verification complete. No anomaly verdicts were generated.\n'
