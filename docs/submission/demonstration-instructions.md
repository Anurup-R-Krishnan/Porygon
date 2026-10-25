# Porygon working demonstration

Open `demo.mp4` for the 2 minute 4 second demonstration. It replays the successful terminal verification with idle time condensed and ends with measured results. `demo.cast` retains the complete timestamped output; `run.log` contains the command log.

## Recorded workflow

1. Capture a controlled container process sequence through Falco and the durable telemetry adapter.
2. Check delivery and replay: 11 observed records, 11 persisted records, zero additional rows after replay.
3. Build and activate a digest-bound behavior profile; score baseline and novel sequences over 30-second windows.
4. Create an incident with 13 matched findings.
5. Approve containment of the disposable target, verify its paused state, then roll back and verify it is running.
6. Verify the released dataset independently.

Recorded baseline score: 0.182950145543. Novel sequence score: 0.3213391093. Containment status: succeeded. Rollback status: rolled_back.

## Reproduce the recorded numbers offline

From this demonstration folder, using Python 3.11 or later:

```sh
python3 reproduce_metrics.py --input sample-outputs --expected metrics.json
```

This command reads the original JSON outputs and checks exact agreement with every recorded metric. It needs no Docker service, credentials or network. `versions.json` contains the recorded algorithm, profile, model hash, ruleset hash, image digest and configuration hash. `run-metadata.json` records the original source commit, working-tree state, command, timestamp and successful exit code. These identify the recorded run independently of later repository changes.

## Run a new end-to-end demonstration

Follow the installation guide, then run from the repository root:

```sh
python3 scripts/submission/record_demo.py --out artifacts/local/new-demonstration -- bash scripts/submission/run_demo.sh
python3 scripts/submission/reproduce_metrics.py --input artifacts > artifacts/local/new-demonstration/metrics.json
```

The runner starts with response execution disabled, temporarily enables it for the verifier's disposable target, and restores disabled mode on exit. The nested verification scripts exercise telemetry, profiling, scoring, detection, authorization, containment and rollback. A new run produces its own identifiers, timestamps, profile versions and scores.

## Dataset validation

From the submission root:

```sh
python3 02-dataset-release/porygon-pilot-v1.0.0/verify.py
```
