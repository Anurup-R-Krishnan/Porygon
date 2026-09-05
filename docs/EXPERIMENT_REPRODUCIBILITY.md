# Experiment reproducibility

Every experiment run is a directory of immutable artifacts. Raw evidence is the
source of truth; every derived file references it and carries a hash in
`artifact-manifest.json`.

## Artifact layout

```text
artifacts/experiments/local/<run-id>/
  run.json                  provenance, written once before the first trial
  images.json               per-workload pinned image identity
  trials/<trial-id>.json    raw evidence for one trial (source of truth)
  summary.csv               derived; regenerated and byte-compared on replay
  artifact-manifest.json    SHA-256 of every other file in the run
```

`run.json` records the protocol ID and its status at creation time, run ID, Git
SHA and dirty flag, Python and platform strings, Docker server version, whether
kernel BTF was readable, the seed, the declared boundary list, and the full
planned matrix. It is written **before** the first trial so a resumed run keeps
its original provenance instead of re-stamping its creation time.

Each trial record carries the workload ID and family, human tag, complete image
identity, mode, scenario, context variant, replica index, seed, container name
and ID, the runtime-context document with its hash, a hash of the raw
inspection snapshot, the full timeline, readiness timing, raw load samples,
the ground-truth record, and the boundary reconciliation.

## Guarantees

- **Canonical JSON hashing** — sorted keys, no insignificant whitespace.
- **Atomic writes** — write to a temporary file, fsync, then rename.
- **Immutable completed artifacts** — rewriting a file with different bytes is
  refused. Only the derived `summary.csv` and manifest are regenerated.
- **Resumable** — an existing trial file is never re-run or overwritten.
- **Failure records** — a failed or interrupted trial is written with a reason.
  It is retained, never silently dropped.
- **Secret rejection** — an artifact containing a secret-like value is refused
  before it is written, and the error names the JSON path, never the value.
  The specification's own redaction placeholders (`flag:<secret>`,
  `<secret-value>`) are allowed because they prove redaction happened.
- **Manifest completeness** — validation fails if a file exists in the run
  directory but is absent from the manifest.
- **Deterministic replay** — `experiment-replay` regenerates the summary from
  raw trials and fails on any byte difference.

## Identity rules

- Images are referenced by immutable digest. A mutable tag is refused.
- The runtime-context fingerprint is derived only from configuration known
  before execution. It excludes environment values and names, literal argument
  values, host mount sources, container IDs and names, image tags, timestamps,
  labels, restart counts, PIDs, and every mutable runtime counter.
- Reordered but semantically equal context documents produce one hash;
  changing one security-relevant field produces a different hash. Both
  properties are tested directly against the canonical examples in
  `PROFILE_SCOPE_EXPERIMENT_V1.md`.
- Capability names are normalised across Docker versions (`CAP_NET_RAW` and
  `net_raw` are one identity).
- Network mode is reduced to its **security class** — `host`, `none`, `bridge`,
  `container`, or `user-defined` — never the literal network name. Each
  experiment run creates its own network, so keeping the name would give the
  same deployment a different identity in every run, and no context stratum
  could ever reach its minimum fit-run count. A class change (`bridge` → `host`)
  still changes the identity.
- Splits are assigned from the run ID alone, by complete run, before execution.
  `check_split_isolation` fails if any run appears in more than one split; a
  test asserts that this leakage is detected.

## Measurement rules

- Durations use a monotonic clock; cross-service traceability uses UTC.
- Latency percentiles are nearest-rank over raw samples. Percentiles are never
  computed from averages of service summaries.
- A boundary that cannot be observed is recorded as `unmeasured` with an
  explicit reason. Missing telemetry is never recorded as zero loss.
- Duplicates are counted separately and never reduce the loss fraction.
- Load driven through `docker exec` (PostgreSQL only, because the standard
  library has no PostgreSQL client) is counted as harness-induced process
  events so profiling can account for it.

## Commands

```bash
python3 -m pytest experiments/tests -q
make experiment-smoke                                   # synthetic integrity fixture
make experiment-pilot PILOT_ARGS="--workloads WL-NGX-V1"  # real containers, pilot only
make experiment-replay RUN_DIR=artifacts/experiments/local/<run-id>
make experiment-validate RUN_DIR=artifacts/experiments/local/<run-id>
make experiment-confirmatory                            # refused until the protocol is frozen
```

Useful `PILOT_ARGS`: `--workloads`, `--modes`, `--scenarios`, `--variants`,
`--replicas`, `--operations`, `--warmup-seconds`, `--settle-seconds`, `--seed`,
`--run-id`, `--base-url`.

## Evidence classes

The smoke fixture is synthetic. The pilot uses real containers but is collected
while the protocol is review-pending. Neither is confirmatory evidence, and
both record `research_eligible: false` in every artifact. Confirmatory
collection stays prohibited until independent security and methodology review
freezes the protocol.

## Still required before a paper claim

Pinned-image pilots prove the pipeline. They do not produce results. Detector
comparisons, ablations, the four profile-scope arms, load regimes, outage and
recovery timing, resource sampling, and generated tables and figures are not
implemented, and none of them may be reported before the protocol is frozen.
