#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() { printf '[Phase 8] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; exit 1; }
pass() { printf '[PASS] %s\n' "$*"; }

for command in docker curl python3; do
  command -v "$command" >/dev/null 2>&1 || fail "Required command is missing: $command"
done
[[ -f .env ]] || fail ".env is missing. Copy .env.example and replace every placeholder."
if grep -q 'replace-with-' .env; then
  fail ".env still contains placeholder values"
fi

set -a
# shellcheck disable=SC1091
source .env
set +a
[[ ${#PORYGON_OPERATOR_API_TOKEN} -ge 32 ]] || fail "PORYGON_OPERATOR_API_TOKEN is not configured"
[[ ${#PORYGON_INTERNAL_API_TOKEN} -ge 32 ]] || fail "PORYGON_INTERNAL_API_TOKEN is not configured"
[[ "$PORYGON_INTERNAL_API_TOKEN" != "$PORYGON_OPERATOR_API_TOKEN" ]] || fail "Internal and operator tokens must be different"
[[ "${PORYGON_RESPONSE_EXECUTION_MODE:-disabled}" == "disabled" ]] || fail "Phase 8 verification requires response execution mode disabled"

API="http://127.0.0.1:${BACKEND_PORT:-8000}"
TARGET_NAME="porygon-phase8-target-$RANDOM"
TARGET_IMAGE="alpine:3.19"
SCAN_REFERENCE="phase8-acceptance-$(date -u +%Y%m%dT%H%M%SZ)"
SCAN_ID=""
WORK_DIR="$(mktemp -d)"
DETAIL_FILE="$WORK_DIR/detail.json"
SBOM_FILE="$WORK_DIR/sbom.json"
REPORT_FILE="$WORK_DIR/report.json"

cleanup() {
  docker rm -f "$TARGET_NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

log "Validating Compose and starting the cumulative stack"
docker compose config --quiet
docker compose up --detach --build --wait
pass "Compose configuration is valid and services are healthy"

curl -fsS "$API/health/ready" >/dev/null
curl -fsS "$API/api/v1/vulnerability-policy" | python3 -c '
import json, sys
p=json.load(sys.stdin)
assert p["scanner"]["pinned_version"] == "0.72.0"
assert "No stage proves exploitation" in p["claim_boundary"]
'
pass "Phase 8 policy and claim boundary are exposed"

log "Creating a disposable exact-digest target"
docker pull "$TARGET_IMAGE" >/dev/null
docker run -d --name "$TARGET_NAME" --label com.porygon.test=phase8 "$TARGET_IMAGE" sh -c 'while :; do sleep 30; done' >/dev/null
IMAGE_ID="$(docker image inspect "$TARGET_IMAGE" --format '{{.Id}}')"
IMAGE_DIGEST="$(docker image inspect "$TARGET_IMAGE" --format '{{index .RepoDigests 0}}')"
[[ "$IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "Could not resolve exact image ID"
[[ "$IMAGE_DIGEST" =~ @sha256:[0-9a-f]{64}$ ]] || fail "Could not resolve repository digest"

log "Waiting for the Phase 2 identity layer to register the digest"
for _ in $(seq 1 60); do
  if curl -fsS "$API/api/v1/images" | IMAGE_DIGEST="$IMAGE_DIGEST" python3 -c '
import json, os, sys
rows=json.load(sys.stdin)
wanted=os.environ["IMAGE_DIGEST"]
raise SystemExit(0 if any(r.get("primary_repo_digest") == wanted for r in rows) else 1)
' 2>/dev/null; then
    break
  fi
  sleep 1
done
curl -fsS "$API/api/v1/images" | IMAGE_DIGEST="$IMAGE_DIGEST" python3 -c '
import json, os, sys
rows=json.load(sys.stdin)
assert any(r.get("primary_repo_digest") == os.environ["IMAGE_DIGEST"] for r in rows)
'
pass "Immutable image identity is available to Phase 8"

PAYLOAD="$(python3 - <<PY
import json
print(json.dumps({
  "image_digest": "$IMAGE_DIGEST",
  "requested_by": "phase8-verifier",
  "scan_reference": "$SCAN_REFERENCE",
  "note": "Controlled non-exploit acceptance scan",
  "scanner_name": "trivy",
  "scanner_version": "0.72.0"
}))
PY
)"

log "Queueing the digest-bound scan"
SCAN_JSON="$(curl -fsS -X POST "$API/operator/v1/image-scans" \
  -H "X-Porygon-Operator-Token: $PORYGON_OPERATOR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$PAYLOAD")"
SCAN_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])' <<<"$SCAN_JSON")"
[[ -n "$SCAN_ID" ]] || fail "Scan was not queued"

DUPLICATE_ID="$(curl -fsS -X POST "$API/operator/v1/image-scans" \
  -H "X-Porygon-Operator-Token: $PORYGON_OPERATOR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$PAYLOAD" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')"
[[ "$DUPLICATE_ID" == "$SCAN_ID" ]] || fail "Identical scan request was not idempotent"
pass "Identical digest/version/reference scan requests are idempotent"

log "Waiting for the isolated scanner to complete"
STATUS=""
for _ in $(seq 1 180); do
  curl -fsS "$API/api/v1/image-scans/$SCAN_ID" -o "$DETAIL_FILE"
  STATUS="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["scan"]["status"])' "$DETAIL_FILE")"
  [[ "$STATUS" == "completed" || "$STATUS" == "failed" ]] && break
  sleep 2
done
[[ "$STATUS" == "completed" ]] || {
  cat "$DETAIL_FILE" >&2
  fail "Scan did not complete successfully; status=$STATUS"
}

curl -fsS "$API/api/v1/image-scans/$SCAN_ID/sbom" -o "$SBOM_FILE"
curl -fsS "$API/api/v1/image-scans/$SCAN_ID/report" -o "$REPORT_FILE"
IMAGE_ID="$IMAGE_ID" IMAGE_DIGEST="$IMAGE_DIGEST" python3 -   "$DETAIL_FILE" "$SBOM_FILE" "$REPORT_FILE" <<'PY'
import hashlib, json, os, re, sys

def canonical_sha(value):
    encoded=json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()

detail=json.load(open(sys.argv[1]))
sbom_artifact=json.load(open(sys.argv[2]))
report_artifact=json.load(open(sys.argv[3]))
scan=detail["scan"]
sbom=detail["sbom"]
report=detail["report"]
findings=detail["vulnerabilities"]
assert scan["image_id"] == os.environ["IMAGE_ID"]
assert scan["image_digest"] == os.environ["IMAGE_DIGEST"]
assert scan["scanner_name"] == "trivy"
assert scan["scanner_version"] == "0.72.0"
assert sbom["format"] == "cyclonedx-json"
assert sbom["component_count"] > 0
assert re.fullmatch(r"[0-9a-f]{64}", sbom["document_sha256"])
assert sbom_artifact["document_sha256"] == canonical_sha(sbom_artifact["document"])
assert report_artifact["document_sha256"] == canonical_sha(report_artifact["document"])
assert report["document_sha256"] == report_artifact["document_sha256"]
assert report["finding_count"] == len(findings)
allowed={"package_present", "deployed", "runtime_observed", "runtime_observed_and_port_published"}
for finding in findings:
    assert finding["exploit_status"] == "not_established"
    assert finding["evidence_stage"] in allowed
    assert finding["intel_snapshot"]["cve_id"] == finding["cve_id"]
    assert "A package/version match does not prove" in " ".join(finding["limitations"])
assert "do not establish exploitation" in scan["summary"]["claim_boundary"].lower()
assert scan["scanner_metadata"]["database_cache_files"]
PY
pass "Raw report, SBOM, database hashes, intel snapshots and evidence boundaries are valid"

NEW_REFERENCE="${SCAN_REFERENCE}-repeat"
NEW_ID="$(curl -fsS -X POST "$API/operator/v1/image-scans" \
  -H "X-Porygon-Operator-Token: $PORYGON_OPERATOR_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data "$(python3 - <<PY
import json
print(json.dumps({
  "image_digest": "$IMAGE_DIGEST",
  "requested_by": "phase8-verifier",
  "scan_reference": "$NEW_REFERENCE",
  "note": "Distinct reproducibility reference",
  "scanner_name": "trivy",
  "scanner_version": "0.72.0"
}))
PY
)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])')"
[[ "$NEW_ID" != "$SCAN_ID" ]] || fail "A distinct scan reference did not create a distinct scan record"
pass "Changed experiment reference creates a new immutable scan record"

printf '\nPhase 8 verification complete.\n'
