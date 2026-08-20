# Porygon implementation plans

These plans are the first execution wave for moving Porygon from a strong prototype to a defensible research system. Execute them in order unless the dependency column says otherwise. Read a plan completely before changing code, run every gate, honor every STOP condition, and update its row here.

The repository had no commit when these plans were written. The source snapshot was therefore identified as `UNBORN` with workspace manifest SHA-256 `632c19fc254d1da0425e03af222b4a4309dfd05409bef2bad1d24526566fa9a3` on 2026-08-16. Plan 001 establishes the first commit; later plans include file-level pre-plan hashes for drift detection.

## Execution order and status

| Plan | Title | Priority | Effort | Depends on | Status |
|---|---|---:|---:|---|---|
| 001 | Establish a reproducible and honest repository baseline | P1 | M | — | DONE |
| 002 | Make capture saturation, readiness, and dead letters trustworthy | P1 | M | 001 | DONE |
| 003 | Freeze the research protocol and profile-identity experiment | P1 | M | 001, 002 | IN PROGRESS — HUMAN REVIEW PENDING |
| 004 | Replace weighted pseudo-scores with calibrated rarity and explicit evidence semantics | P1 | L | 003 | TODO |
| 005 | Build the Phase 9 experiment and performance-evidence harness | P1 | L | 002, 003, 004 | TODO |

Status values: `TODO`, `IN PROGRESS`, `DONE`, `BLOCKED: <reason>`, `REJECTED: <reason>`.

## Why this order

- 001 is mandatory because there is no commit, the documented configuration template is absent, and the current top-level verification command is not cumulative.
- 002 must precede data collection because the Docker collector can advance past an event it failed to persist; experiments cannot repair missing ground truth after the fact.
- 003 freezes hypotheses, independent units, splits, claims, and profile scopes before model choices or confirmatory observations can be influenced by results.
- 004 depends on the frozen protocol because its calibration units and outputs must match the experiment design.
- 005 is measurement-first. It records the functional, accuracy, latency, loss, and overhead baseline before any performance optimization is authorized.

## Product evaluation gate

Anti-inflated current score: **41/60** — Novelty 6, Feasibility 7, Scalability 5, Impact 7, Demo-ability 6, Domain fit 10. This is a credible “build with focus” project, not a novelty breakthrough yet. Its differentiator is the controlled comparison of global, tag, digest-only, and digest-plus-context profiles across same-image replicas—not behavioural profiling by itself.

Promotion gate: do not call the project top-tier until the confirmatory run from Plan 005 produces versioned evidence and the score is re-evaluated at **48/60 or higher**. A plausible target is 7/8/6/8/9/10, but those points must be earned by results, not prose.

## Next planning wave after 005

These are vetted findings, not rejected work. Plan them after the first measured Phase 9 run so scope and priorities reflect evidence:

- Repair the Phase 8 runtime-exposure contract: collector snapshots omit the published-port shape consumed by `vulnerability.py`, running state is inferred incorrectly, and process evidence is not time-bounded.
- Fence response and scanner completion with a unique claim token/generation and lease-expiry predicate; add responder lease renewal.
- Minimize and protect command-line/raw telemetry, require operator authorization for detailed reads, and add retention controls.
- Optimize only measured bottlenecks: SQLite spool batching, set-based process ingestion, Phase 8 evidence precomputation, artifact transport limits, analytical projections/indexes, temporal correlation, and dashboard summary queries.
- Produce hash-locked runtime-only images, pin base images by digest, and add Alembic ORM-drift checks.
- Decompose the 3,200-line backend composition module only after characterization and API-contract tests exist.
- Build the Phase 10 dashboard as a thin evidence viewer after experiment artifacts are stable.

## Findings considered and rejected

- Rewrite the control plane in Java: rejected. It adds migration risk and does not improve the research question, data quality, calibration, or experimental evidence.
- Redis in v1: rejected. PostgreSQL plus the existing durable local outboxes cover the current single-host research scope.
- Custom eBPF, Kubernetes, LLM summaries, and automatic response in v1: rejected. They expand attack surface and scope without strengthening the core experiment.
- Treat image digest as complete behavioural identity: rejected as a claim. Digest remains artifact identity; whether it is a sufficient profile scope is an empirical question in Plans 003 and 005.
- Report anomaly outputs as attack probabilities: rejected. Plan 004 produces calibrated rarity/p-values under stated assumptions and keeps deterministic security evidence separate.
