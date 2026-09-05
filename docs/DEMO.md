# Porygon demonstration path

A reproducible, ~10 minute walkthrough that shows the whole pipeline working on
real containers. Every command below was executed against this repository on
2026-09-05; the outputs quoted are real, not illustrative.

Nothing here needs internet access beyond the initial image pulls, and nothing
here runs a disruptive response action.

---

## 0. Prerequisites

```bash
make init        # once: creates .env with locally generated credentials
make up          # starts the 8-container stack and waits for health
docker compose ps
```

Expected: `backend`, `postgres`, `collector`, `telemetry`, `falco`, `responder`,
`scanner`, `gateway` all healthy. The API is reachable only on loopback:

```bash
curl -s http://127.0.0.1:8000/health/live
```

Several commands below call the internal API. Load the token from the
git-ignored `.env` without printing it:

```bash
export PORYGON_INTERNAL_API_TOKEN="$(grep -E '^PORYGON_INTERNAL_API_TOKEN=' .env | cut -d= -f2-)"
```

---

## 1. Start a controlled workload from an immutable digest

```bash
make experiment-pilot PILOT_ARGS="--workloads WL-PG-V1 --scenarios SCN-EXEC --replicas 1 --operations 20"
```

The runner pulls `postgres@sha256:1d04b9ba…` — the exact coordinate frozen in
`docs/PROFILE_SCOPE_EXPERIMENT_V1.md` — starts one labelled, loopback-only,
memory-capped container, drives a deterministic seeded query load, executes the
safe scenario, reconciles the telemetry, and removes the container.

**Talking point**: a mutable tag is refused outright. Ask the runner for
`nginx:latest` and it stops with *"refusing a mutable image reference"*.

---

## 2. Show the digest and context identity

```bash
python3 -c "
import json,glob
for f in sorted(glob.glob('artifacts/experiments/local/pilot-*/trials/*.json')):
    d=json.load(open(f))
    print(d['trial_id'], d['image']['reference'][:28], d.get('runtime_context_hash','')[:16])
"
```

Real output from the 9-trial pilot — three image digests, nine distinct context
hashes:

```text
wl-ngx-v1-…-baseline-r01                nginx@sha256:1eadbb0782   52e5e48b7368…
wl-ngx-v1-…-dropped_capabilities-r01    nginx@sha256:1eadbb0782   dcc8cf787707…
wl-ngx-v1-…-tmpfs_scratch-r01           nginx@sha256:1eadbb0782   cdde6f3c4d4b…
```

**This is the core of the project.** Same image digest, three deployments,
three different behavioural identities. A digest-only profile would treat all
three as one population; a digest-plus-context profile would not. Which is
better is the experiment's question, not its assumption.

Show the fingerprint itself and note what it deliberately omits — no
environment values, no literal arguments, no host paths, no container IDs:

```bash
python3 -c "
import json,glob
d=json.load(open(sorted(glob.glob('artifacts/experiments/local/pilot-*/trials/*.json'))[0]))
print(json.dumps(d['runtime_context'], indent=1))
"
```

---

## 3. Show telemetry arriving, and prove none was lost

```bash
cat artifacts/experiments/local/<run-id>/summary.csv | column -s, -t
```

Measured across the 9-trial pilot:

| Boundary | Result |
|---|---|
| generated canaries | 54 |
| observed at Falco (`source`) | 54 |
| persisted in PostgreSQL (`database`) | 54 |
| duplicates | 0 |
| workload operations | 360 / 360 succeeded |

**Talking point — honesty**: `spool` and `api` are recorded as `unmeasured`
with an explicit reason, not as zero. Kernel-to-eBPF loss is likewise never
claimed to be zero.

---

## 4. Build a digest-bound behavioural profile

```bash
python3 scripts/porygon_baseline.py build \
  --image-digest 'postgres@sha256:1d04b9ba1d4996401f2552b51beda8187f175c0645c091e4781134fc9c9a3eef' \
  --start '<pilot start>' --end '<pilot end>' \
  --window-seconds 10 \
  --approved-by 'demo' --approval-reference 'docs/DEMO.md'
```

Real result: `window_count: 7`, `process_event_count: 479`, `quality.passed: true`.

**Show the guardrail.** An earlier attempt with a 30-second window produced only
2 non-empty windows and the quality gate refused it:

```json
"minimum_nonempty_windows": {"required": 3, "actual": 2, "passed": false}
```

A profile that has not earned activation cannot be activated.

```bash
python3 scripts/porygon_baseline.py activate <profile_id>
```

Real result: `status: active`, `profile_version: 2`.

---

## 5. Score a *later* window — and show leakage being blocked

```bash
python3 scripts/porygon_score.py compute \
  --image-digest 'postgres@sha256:1d04b9ba…' \
  --window-start '<a window inside the training interval>'
```

Real result:

```text
HTTP 409: Scoring windows must not overlap the profile training interval
```

**Talking point**: split leakage is refused by the API, not merely discouraged
in a document. Now score a genuinely held-out window from a second run:

```bash
python3 scripts/porygon_score.py compute \
  --image-digest 'postgres@sha256:1d04b9ba…' --window-start '<later window>'
```

Real result: `score_band: baseline_like`, `process_event_count: 106`, with an
`explanation` block containing `top_contributors`, `unseen_tokens`,
`highest_numeric_deviations`, and `interpretation`.

A second run of the same digest under the same context scores as baseline-like.
That is the expected — and reassuring — outcome.

---

## 6. Run deterministic detection and read the evidence

```bash
python3 scripts/porygon_detect.py run <score_id>
```

Real result: `matches_count: 72`, `incident_created: false`,
`incident_eligible: false`, `anomaly_score: 0.082`.

Every match carries `rule_id`, `category`, `description`, the exact
`occurred_at`, a `source_id` hash, and the evidence `details` — for example
`POR-DET-006 "Docker exec activity"` with the literal command observed.

**Two talking points here, both worth making explicitly:**

1. **Anomaly evidence and rule evidence are separate.** 72 deterministic rule
   matches did **not** create an incident, because rule matches are evidence,
   not proof, and rarity alone does not escalate.
2. **The harness detected itself.** Most of those 72 matches are the demo's own
   `docker exec` calls (`pg_isready`, `psql`, the canary commands). That is
   correct behaviour and a good illustration of why *anomalous ≠ malicious*:
   this activity is unusual for the profile and entirely benign.

---

## 7. Show the incident and review surface

```bash
python3 scripts/porygon_detect.py incidents
python3 scripts/porygon_detect.py timeline <incident_id>   # when one exists
python3 scripts/porygon_detect.py config                   # immutable ruleset
```

Containment is never automatic. `PORYGON_RESPONSE_EXECUTION_MODE` stays
`disabled`, the default recommendation is `observe_only`, and a disruptive
action needs an allowlisted rule, adequate evidence quality, an exact target,
and human approval.

---

## 8. Show reproducibility

```bash
make experiment-replay  RUN_DIR=artifacts/experiments/local/<run-id>
make experiment-validate RUN_DIR=artifacts/experiments/local/<run-id>
```

Real results: `replay matched recorded summary` and
`[PASS] validated experiment artifacts`. Replay recomputes every derived table
from raw trial records and fails on a single differing byte.

Then show the refusal that protects the science:

```bash
make experiment-confirmatory
```

Real result:

```text
[blocked] confirmatory collection is refused until the protocol is frozen by human review
```

---

## 9. Closing frame

What was demonstrated: an immutable-digest workload, a deterministic runtime
context identity, kernel-level capture with a fully reconciled loss budget, a
quality-gated digest-bound profile, leakage-refusing scoring, deterministic rule
evidence kept separate from anomaly evidence, human-gated response, and
hash-verified reproducibility.

What was **not** demonstrated, and must not be claimed: detection accuracy,
false-positive rates, calibration coverage, profile-scope superiority, or
overhead budgets. Those need the frozen protocol and the confirmatory run
counts in `docs/RESEARCH_PROTOCOL_V1.md`. See
[`execution-status.md`](execution-status.md) for exactly what is and is not
implemented.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Set PORYGON_INTERNAL_API_TOKEN…` | token not exported | run the `export` in §0 |
| `HTTP 409 … overlap the profile training interval` | scoring a training window | score a later window (this is intended) |
| `quality.passed: false` | too few non-empty windows | lower `--window-seconds` or collect a longer run |
| pilot trial `status: failed` | readiness timeout or a context variant the image rejects | read `failure_reason` in the trial record; failures are retained on purpose |
| first pilot run is slow | pulling three pinned images | subsequent runs reuse the local images |
