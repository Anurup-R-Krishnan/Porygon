# Live Demonstration Record: Real Malware Execution Against Porygon

Status: a real, single, manually-executed demonstration run against the live
stack on this machine, for presentation/discussion purposes. This is not a
controlled experiment trial, not part of the frozen protocol's confirmatory
dataset, and has n=1. It exists to answer, with real evidence rather than
assertion, "did anomaly detection catch anything it was never told about."

## Setup

Image: `quay.io/petr_ruzicka/malware-cryptominer-container:3`
Digest: `quay.io/petr_ruzicka/malware-cryptominer-container@sha256:688f89c157c1c87d9b59afc50f004451acf560d98061925c5cbdae36599a1232`

A real, publicly published container image (`ruzickap/malware-cryptominer-container`
on Artifact Hub / Quay.io) that stages genuine malware samples on disk
(Mirai variants, WannaCry, Kaiji, real trojan ELF binaries) and a real,
functional XMRig cryptominer binary. Per the image's own documentation,
starting the container does not activate any payload -- files sit dormant
until manually executed, which is exactly what was done here.

## Step 1: real baseline built from real Falco telemetry

The container was started and driven through 40+ rounds of benign shell
activity (`id`, `cat /etc/hostname`, `ls`, `whoami`) over roughly 3 minutes.
Falco (real eBPF sensor, unmodified `porygon_rules.yaml`) captured every
`execve` event; the telemetry adapter and collector pushed them through the
real SQLite outbox spool into PostgreSQL via the backend API. Verified via
`GET /api/v1/process-events?container_id=...`: 243 real events captured.

A behavior profile was built via `POST /internal/v1/baselines/build`
(`profile_id: c618071c-dbdc-468d-a1bb-1c16b40cbc52`) over that exact window,
then activated via `POST /internal/v1/baselines/{id}/activate`. The learned
baseline's `process_name` distribution: `{6, cat, id, ls, sh, whoami}` --
ordinary nginx-image shell maintenance activity. Nothing about malware,
cryptominers, or the string "xmrig" was given to the system at any point.

## Step 2: the real attack

```
docker exec --user root <container> sh -c "/usr/share/nginx/html/xmrig/xmrig --help > /tmp/xmrig_out.txt 2>&1 &"
```

This executes the real, statically-linked XMRig binary shipped in the image
(confirmed via `file`: `ELF 64-bit LSB executable, x86-64, statically
linked`). It printed its real usage banner, confirming it is a functional
mining binary, not a stub. Falco captured the exact event:

```
2026-09-06T11:56:36.697302Z  process=xmrig  executable=/usr/share/nginx/html/xmrig/xmrig
  command=xmrig --help  parent=nginx (via containerd-shim)
```

## Step 3: what each subsystem did, both reported honestly

### Anomaly scorer -- detected it

`POST /internal/v1/anomaly-scores/compute` for the window containing the
xmrig execution (`score_id: 4ef370a9-dca6-4d3f-8b78-14c399ee9a61`):

- **`total_score: 0.2696`, `score_band: "elevated"`** (threshold for
  `elevated` is `>= 0.25`, `backend/src/porygon_api/scoring.py:
  SCORING_CONFIG["score_bands"]["baseline_like_max"]`).
- `xmrig` explicitly listed under `explanation.unseen_tokens` with
  `feature: "process_name"`.
- The unseen executable `/usr/share/nginx/html/xmrig/xmrig` and the unseen
  parent-child edge `nginx -> xmrig` both contributed to the score.
- The `process_name` categorical distance alone was `0.6296` -- the single
  largest contributor.

This is genuine novelty detection: the token `xmrig` had zero probability
mass in the learned baseline, so it was flagged purely by deviating from
this container's own prior behavior, not by matching any known-bad name.

### Deterministic rule engine -- did not create an incident

`POST /internal/v1/detections/run` against that same anomaly score
(`run_id: f257dcd2-2ccd-404b-8d2c-f0df188995ec`):

- `status: "findings_only"`, `incident_created: false`,
  `incident_eligible: false`, `severity_level: "low"`.
- 6 matches, all `POR-DET-006` (generic "Docker exec activity occurred"),
  which is `incident_eligible: false` by design -- informational only.
- `POR-DET-004` ("previously unseen dual-use tool") did **not** fire,
  because its fixed name list
  (`SUSPICIOUS_TOOL_NAMES` in `backend/src/porygon_api/detection.py`) is
  `{curl, wget, nc, ncat, netcat, socat, telnet, ssh, scp, base64, openssl,
  python, python3, perl, ruby}` -- `xmrig` is not a member and never
  matches this rule regardless of how anomalous the anomaly scorer judges
  it, by construction.

## Honest interpretation

Two independent mechanisms produced two different, individually correct
results for the same event:

- The **anomaly scorer** generalizes: it flagged an executable it had never
  seen, with no prior knowledge that "xmrig" or "cryptominer" exists. This
  is the intended behavior of a statistical deviation measure.
- **`POR-DET-004`** is a fixed name list and, by construction, cannot ever
  flag a binary whose name is not already in that Python set. It correctly
  did not fire, and no other `incident_eligible` rule matched either, so no
  incident was created for this single test run.

Neither result is a "failure." They demonstrate, with real evidence rather
than assertion, the exact trade-off documented in
`docs/ADVERSARIAL_SCENARIOS_V1.md`: novelty-based scoring can catch
previously-unseen threats that name-list rules structurally cannot, and
name-list rules provide zero coverage outside their fixed list regardless of
how anomalous the underlying behavior is. A production deployment would need
either an expanded `POR-DET-004` list, a lower incident-creation threshold on
elevated anomaly scores, or both -- neither was tuned or retroactively
adjusted after seeing this result.

## Limits of this demonstration

- n=1, single manual run, not part of any statistically powered comparison.
- The score (0.2696) is close to the `elevated` threshold (0.25); a
  different, more subtly-named or more behaviorally-similar tool might not
  cross it.
- `POR-DET-004`'s list was not modified before or after this test; the gap
  it reveals was known in advance
  (`docs/ADVERSARIAL_SCENARIOS_V1.md`, scenario 7) and is reported here as
  observed, live evidence of that same, previously-identified gap.
- This is one real malware sample (XMRig) executed one way (`--help`, which
  does not actually begin mining). A full mining run, or a different
  malware family entirely, was not tested.
