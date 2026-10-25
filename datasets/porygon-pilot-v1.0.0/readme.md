# Porygon controlled container pilot dataset

Version: **1.0.0** · Release: **CC BY 4.0**

216 completed Docker-container trial metadata records collected on 6 September
2026: nginx, Redis and PostgreSQL; three controlled scenarios; two runtime-context
variants; twelve replicas per cell. Includes 72 non-attack-like and 144 attack-like
simulation trials. No real exploit was executed. These are pilot observations,
not confirmatory evidence or a validated malware/attack classification benchmark.

## Contents

- `trial-index.csv`: one derived row per trial, with conservative release labels.
- `trials/*.json`: 216 byte-preserved original trial records with ground truth,
  image identity, context, workload measurements, canary reconciliation and timeline.
- `provenance/`: original run manifest, study manifest and image inventory.
- `metadata.json`: authoritative release scope, counts and known provenance conflicts.
- `source-checksums.json`: original input SHA-256 hashes.
- `checksums.json`: hashes for all package files except itself.
- `data-dictionary.md`, `annotation.md`, `license.md`: interpretation and reuse status.
- `verify.py`: offline integrity and label checks using Python's standard library.

**Not included:** raw Falco/Docker process-event streams, process distributions,
per-arm predictions, a trained ML model or validated performance measurements.
The dataset supports metadata/context analysis and audit of collection artifacts;
it cannot independently reproduce the published detector FPR/recall tables.

## Verify and rebuild

From this directory, with Python 3.11 or newer:

```sh
python3 verify.py
```

From the Porygon repository root, rebuild from locally retained source artifacts:

```sh
python3 scripts/package_pilot_dataset.py
```

The builder checks inputs before writing, rejects secret-like fields using the
repository artifact validator, and refuses to overwrite changed payloads.
No Docker, network, credentials or database access is required for packaging.
Rebuilding requires the ignored local source folder; the delivered package itself
contains its source trial/manifests and can be verified independently.

## Method and interpretation

Each row represents one complete disposable container trial. The collection
matrix is 3 workloads × 3 scenarios × 2 context variants × 12 replicas = 216.
Context variants are `baseline` and `dropped_capabilities` (NET_RAW dropped).
Ground truth comes from the collection harness, not independent attack analysis.
Refer to `annotation.md` before interpreting any positive label.

All source trial splits and all release splits are **pilot**. Do not randomly
split event windows from these trials and claim an independent evaluation. A new
study must define its split unit and protocol before collecting evaluation data.

The original run name contains `confirmatory`, and nested historical study stages
retain confirmatory flags and fit/calibration/test counts. Those do not override
the trial-level pilot flags or this release's `research_eligible: false`.
Source bytes are preserved rather than edited to conceal these inconsistencies.

The repository's primary analysis uses 53 benign and 96 scenario observations;
those denominators do not equal this package's 72/144 collection label counts.
The exact analysis membership is not exported here. Do not infer per-trial
predictions, analysis splits or published metrics from the collection labels.

The existing scope comparison found no advantage of context-plus-digest over
digest-only for the tested process-name feature. A capability-only context change
need not change process behavior. Context-delta detection is a separate exploratory
analysis and detecting a configuration difference does not establish maliciousness.
No inference about real exploit detection, production generalization, full-pipeline
latency, ML accuracy or system overhead is supported by this package.

## Public release

Repository: https://github.com/Anurup-R-Krishnan/Porygon/tree/codex/technical-enrichment/datasets/porygon-pilot-v1.0.0

Release 1.0.0 contains 216 original trials, annotation guidelines, metadata,
an offline verifier and full CC BY 4.0 terms. Attribute the dataset as specified
in `license.md`. The release checksum manifest identifies its exact contents.
