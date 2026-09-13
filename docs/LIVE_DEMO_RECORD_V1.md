# Live Demonstration Record: Real Malware Execution Against Porygon

Status: two real, manually-executed demonstration runs against the live
stack on this machine, for presentation/discussion purposes, dated and
recorded separately below. Neither is a controlled experiment trial, neither
is part of the frozen protocol's pilot/confirmatory dataset, and each has
n=1. Run 1 exists to answer, with real evidence rather than assertion, "did
anomaly detection catch anything it was never told about." Run 2 re-executes
the identical attack after `POR-DET-004` was generalised from a fixed
dual-use-tool name list to *any* previously unseen non-shell executable, to
answer the follow-on question honestly rather than leave it as a documented
gap forever: does the broadened rule now catch what the first run's list
could not. **Run 2 supersedes Run 1 as the current system's behaviour; Run 1
is kept in full because it is the accurate historical record of what the
pre-broadening rule actually did, and both README.md and the presentation
decks cite one or the other explicitly rather than treating them as
interchangeable.**

## Run 1 -- 2026-09-06: fixed name-list rule, no incident created

### Setup

Image: `quay.io/petr_ruzicka/malware-cryptominer-container:3`
Digest: `quay.io/petr_ruzicka/malware-cryptominer-container@sha256:688f89c157c1c87d9b59afc50f004451acf560d98061925c5cbdae36599a1232`

A real, publicly published container image (`ruzickap/malware-cryptominer-container`
on Artifact Hub / Quay.io) that stages genuine malware samples on disk
(Mirai variants, WannaCry, Kaiji, real trojan ELF binaries) and a real,
functional XMRig cryptominer binary. Per the image's own documentation,
starting the container does not activate any payload -- files sit dormant
until manually executed, which is exactly what was done here.

### Step 1: real baseline built from real Falco telemetry

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

### Step 2: the real attack

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

### Step 3: what each subsystem did, both reported honestly

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

### Honest interpretation (Run 1)

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
adjusted after seeing this result. (`POR-DET-004` was later generalised --
see Run 2 below -- but that change was made as part of the project's regular
rule-hardening work, not as a reaction to this specific test.)

### Limits of Run 1

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

## Run 2 -- after the `POR-DET-004` rule was broadened: incident created

Exact date/time not independently captured in a timestamped artifact in this
repository -- unlike Run 1, this run was not logged with a dedicated
score/detection record at the time. It is documented here from the numbers
already carried in `docs/presentation/porygon_review_v3.tex` (Slide 25,
"Case Study: Cryptominer Binary"), which the audit verified are arithmetically
consistent with the current scoring formula in
`backend/src/porygon_api/detection.py` and `scoring.py`. Reported here so the
project's own documentation is internally consistent rather than presenting
only the earlier, superseded outcome as current.

### What changed between Run 1 and Run 2

`POR-DET-004` was generalised from a fixed dual-use-tool name list
(`SUSPICIOUS_TOOL_NAMES = {curl, wget, nc, ncat, netcat, socat, telnet, ssh,
scp, base64, openssl, python, python3, perl, ruby}`) to its current form:
*any* non-shell executable absent from the digest baseline, regardless of
name (`backend/src/porygon_api/detection.py`, rule `POR-DET-004`,
`"Previously Unseen Non-Shell Executable"`). No name was added to any list;
the list itself was removed. This is the same generalisation documented on
Slide 28 of `porygon_review_v3.tex` ("Detection Coverage") and was made as
part of the project's regular rule-hardening work, independent of and prior
to this specific re-run.

### The same real attack, re-executed

The same real, functional XMRig binary from the same published image was
executed the same way (`xmrig --help`) against a freshly built baseline with
the same "no prior knowledge of xmrig" property as Run 1.

- **`total_score: 0.567002499903`, `score_band: "high"`** -- flagged across
  four feature families (executable, process name, parent-child edge,
  sequence bigram), a stronger and more broadly corroborated signal than
  Run 1's 0.2696.
- **`POR-DET-004` fired**: `xmrig` is caught by baseline novelty alone, with
  no name ever added to any list. **`POR-DET-001`** (distance $\geq 0.50$)
  also fired, since the total score crossed the `high`-band boundary.
- Detection: `status: "incident_created"`, `incident_created: true`,
  severity **0.614**, confidence **0.887**.

### Honest interpretation (Run 2)

The rule change that produced this outcome was a generalisation, not a
name added for this specific malware sample: `xmrig` still appears nowhere
in `detection.py`. The same structural gap documented in Run 1 and in
`docs/ADVERSARIAL_SCENARIOS_V1.md` (scenario 7) — a rule that only recognises
names on a fixed list provides zero coverage outside that list — has been
closed for this rule by removing the list entirely, not by chasing this one
sample. Run 1 remains the accurate record of what the system did before that
change; Run 2 is the current, superseding behaviour.

### Limits of Run 2

- n=1, single manual re-run, not part of any statistically powered
  comparison, and not independently logged with a dedicated score/detection
  artifact at the time it was run (see the note above).
- The broadened `POR-DET-004` has been verified against four live re-run
  deviations total (this one plus three others catalogued in
  `porygon_review_v3.tex`, Slides 24, 26, 27), not yet re-run against the
  full 216-trial pilot protocol.
- This remains one real malware sample (XMRig) executed one way (`--help`).
  A full mining run, or a different malware family, was not tested in either
  run.
