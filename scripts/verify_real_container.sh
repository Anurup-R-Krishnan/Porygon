#!/usr/bin/env bash
# Real-container acceptance.
#
# Proves the experiment harness works against actual Docker containers pulled by
# immutable digest, not against a synthetic fixture. It is non-disruptive: every
# container it creates is disposable, labelled, loopback-only, and removed by
# exact name plus label match. It never collects confirmatory data.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

fail() {
  echo "[FAIL] $*" >&2
  docker compose logs --tail=80 backend telemetry collector 2>/dev/null || true
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f .env ]] || fail ".env is missing. Copy .env.example and replace its placeholders."
for command in docker curl python3; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is not installed"
done
mkdir -p artifacts

backend_port="$(grep -E '^BACKEND_PORT=' .env | tail -1 | cut -d= -f2 || true)"
backend_port="${backend_port:-8000}"
base_url="http://127.0.0.1:${backend_port}"
curl --fail --silent --show-error "${base_url}/health/live" >/dev/null \
  || fail "the stack is not reachable on ${base_url}; run make up first"
pass "Live stack is reachable for real-container acceptance"

# The harness must refuse a mutable tag before any container is created.
python3 - <<'PY' || fail "A mutable image reference was not refused"
from experiments.real import PilotError, pull_pinned_image
try:
    pull_pinned_image("nginx:latest")
except PilotError as error:
    assert "mutable" in str(error), error
else:
    raise SystemExit("a mutable tag was accepted")
PY
pass "Mutable image references are refused before any container is created"

# The runtime-context fingerprint must agree with its own frozen specification.
python3 - <<'PY' || fail "The runtime-context fingerprint disagrees with its specification"
import json, re
from pathlib import Path
from experiments.context import context_hash

text = Path("docs/PROFILE_SCOPE_EXPERIMENT_V1.md").read_text(encoding="utf-8")
def example(name):
    match = re.search(rf"```json {name}\n(.*?)```", text, re.DOTALL)
    assert match, f"missing canonical example {name}"
    return json.loads(match.group(1))

a = context_hash(example("context-example-equivalent-a"))
b = context_hash(example("context-example-equivalent-b"))
c = context_hash(example("context-example-security-change"))
assert a == b, "reordered equivalent documents must share one identity"
assert a != c, "a security-relevant change must change the identity"
PY
pass "Runtime-context identity matches the frozen canonical examples"

run_id="realcontainer-$(date -u +%Y%m%dt%H%M%SZ)"
run_dir="artifacts/experiments/local/${run_id}"

python3 -m experiments.run pilot \
  --run-id "$run_id" \
  --run-dir "$run_dir" \
  --workloads WL-NGX-V1 \
  --scenarios SCN-EXEC \
  --variants baseline \
  --replicas 1 \
  --operations 10 \
  --base-url "$base_url" \
  || fail "the real-container pilot did not complete"
pass "A real container was pulled by digest, exercised, and torn down"

RUN_DIR="$run_dir" python3 - <<'PY' || fail "Real-container trial evidence is not acceptable"
import glob, json, os

run_dir = os.environ["RUN_DIR"]
trials = [json.load(open(path)) for path in sorted(glob.glob(f"{run_dir}/trials/*.json"))]
assert trials, "no trial record was written"
for trial in trials:
    assert trial["status"] == "completed", f"{trial['trial_id']}: {trial.get('failure_reason')}"
    assert trial["research_eligible"] is False, "a pilot trial must never claim research eligibility"
    assert "@sha256:" in trial["image"]["reference"], "the image was not pinned by digest"
    assert len(trial["runtime_context_hash"]) == 64, "no runtime-context identity was recorded"
    assert trial["cleanup"]["removed"] is True, "the trial container was not removed"

    ground_truth = trial["ground_truth"]
    executed = ground_truth["canary_sequences_executed"]
    assert executed == ground_truth["canary_sequences_planned"], "a ground-truth action did not run"
    assert ground_truth["action_started_at_utc"] < ground_truth["action_finished_at_utc"]
    assert len(ground_truth["command_template_sha256"]) == 64

    boundaries = trial["reconciliation"]["boundaries"]
    measured = [name for name, item in boundaries.items() if item["status"] == "measured"]
    assert "source" in measured, "Falco capture was not observed for the canaries"
    assert "database" in measured, "PostgreSQL persistence was not observed for the canaries"
    for name in ("source", "database"):
        entry = boundaries[name]
        assert entry["observed"] == len(executed), (
            f"{name}: observed {entry['observed']} of {len(executed)} canaries; "
            f"missing {entry['missing_sequences']}"
        )
        assert entry["loss_fraction"] == 0.0
    for name, entry in boundaries.items():
        if entry["status"] == "unmeasured":
            assert entry.get("reason"), f"{name} is unmeasured without a stated reason"
print(f"trials={len(trials)} canaries={sum(len(t['ground_truth']['canary_sequences_executed']) for t in trials)}")
PY
pass "Canaries reconciled from the generator through Falco to PostgreSQL with zero measured loss"

python3 -m experiments.run replay "$run_dir" >/dev/null \
  || fail "analysis replay did not reproduce the recorded summary"
python3 experiments/validate_artifacts.py "$run_dir" >/dev/null \
  || fail "the run artifacts did not validate"
pass "Real-container artifacts validate and replay deterministically"

leftover_containers="$(docker ps --all --filter "label=porygon.experiment.run=${run_id}" --format '{{.Names}}' | wc -l)"
leftover_networks="$(docker network ls --filter "label=porygon.experiment.run=${run_id}" --format '{{.Name}}' | wc -l)"
[[ "$leftover_containers" -eq 0 ]] || fail "${leftover_containers} experiment containers were left behind"
[[ "$leftover_networks" -eq 0 ]] || fail "${leftover_networks} experiment networks were left behind"
pass "Cleanup left no experiment container or network behind"

if python3 -m experiments.run confirmatory --protocol docs/RESEARCH_PROTOCOL_V1.md >/dev/null 2>&1; then
  fail "confirmatory collection was permitted while the protocol is review-pending"
fi
pass "Confirmatory collection remains refused while the protocol is review-pending"

RUN_DIR="$run_dir" RUN_ID="$run_id" python3 - <<'PY' > artifacts/real-container-acceptance.json
import glob, json, os
from datetime import datetime, timezone

run_dir = os.environ["RUN_DIR"]
trials = [json.load(open(path)) for path in sorted(glob.glob(f"{run_dir}/trials/*.json"))]
json.dump(
    {
        "schema_version": "porygon.real-container-acceptance.v1",
        "run_id": os.environ["RUN_ID"],
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "research_eligible": False,
        "evidence_class": "pilot",
        "trials": [
            {
                "trial_id": trial["trial_id"],
                "image_reference": trial["image"]["reference"],
                "runtime_context_hash": trial["runtime_context_hash"],
                "canaries": len(trial["ground_truth"]["canary_sequences_executed"]),
                "boundaries": {
                    name: item["status"] for name, item in trial["reconciliation"]["boundaries"].items()
                },
                "measured_loss_fraction": {
                    name: item["loss_fraction"]
                    for name, item in trial["reconciliation"]["boundaries"].items()
                    if item["status"] == "measured"
                },
            }
            for trial in trials
        ],
        "note": (
            "Real-container acceptance evidence. Pilot class: it proves the capture and "
            "identity pipeline, never detection quality or a research claim."
        ),
    },
    open(os.environ.get("OUT", "/dev/stdout"), "w"),
    indent=2,
    sort_keys=True,
)
PY
pass "Retained real-container acceptance evidence at artifacts/real-container-acceptance.json"

echo
echo "Real-container verification complete. Real containers were exercised; this is pilot evidence, not a research result."
