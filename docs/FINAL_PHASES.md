# Porygon Development Roadmap

This roadmap replaces the conflicting earlier versions. Porygon is a Docker-first runtime-behaviour research system. Kubernetes and vulnerability-to-runtime correlation are extensions, not prerequisites for the core paper.

## Research Protocol and Scope Freeze — Frozen

**Goal:** define exactly what is being claimed and measured.

The version 1 protocol package is frozen. Both required human approvals are
recorded (`docs/review/security-review.json`, `docs/review/methodology-review.json`,
both `decision: approved`), and `scripts/review_gate.py apply` has set
`RESEARCH_PROTOCOL_V1.md`'s status from `review_pending` to `FROZEN`.
Protocol freeze and review sign-off are necessary but not sufficient for
confirmatory collection: every run executed so far, including both studies
below, recorded `evidence_class: pilot`, `research_eligible: false` after a
mislabeling bug in the study-summary step (now fixed) was found and
corrected. Confirmatory-grade collection additionally requires
protocol-conformance machinery that has not been built yet; see
`docs/CONFIRMATORY_RESULT_V1.md` for the current evidence-class status.

- [`RESEARCH_PROTOCOL_V1.md`](RESEARCH_PROTOCOL_V1.md)
- [`THREAT_MODEL_V1.md`](THREAT_MODEL_V1.md)
- [`CLAIMS_V1.md`](CLAIMS_V1.md)
- [`PROFILE_SCOPE_EXPERIMENT_V1.md`](PROFILE_SCOPE_EXPERIMENT_V1.md)

Deliverables:

- Problem statement and non-goals
- Threat model and trust boundaries
- Event schema draft
- Research questions and hypotheses
- Benign and malicious experiment catalogue
- Metrics: precision, recall, false-positive rate, detection latency, ingestion loss, CPU, memory, and application overhead

Exit condition (met): every research question maps to a repeatable experiment
and a measurable output, the structural validator passes, and one human
security reviewer plus one human methodology reviewer approved the freeze.
This was a single-reviewer self-review for both roles, not independent peer
review — stated plainly rather than implied otherwise.

## Reproducible Platform Foundation — Implemented

**Goal:** establish a secure, containerized control plane before granting any service Docker-daemon access.

Components:

- PostgreSQL
- FastAPI backend
- Collector service in connectivity-only mode
- Alembic migrations
- Health checks, persistent volume, service authentication, and verification script

Exit condition: `./scripts/verify_phase1.sh` passes.

## Docker Identity and Runtime Event Ingestion — Implemented

**Goal:** collect trustworthy Docker lifecycle and exec events and bind them to immutable image identity.

Work:

- Read Docker Engine event stream
- Inspect containers for name, labels, image ID, repository digest, command, user, networks, mounts, and privileges
- Normalize raw events and preserve the original payload
- Deduplicate with deterministic event IDs
- Add bounded retries and a local spool for backend outages
- Treat Docker socket access as privileged and isolate it to the collector

Exit condition: `./scripts/verify_phase2.sh` — controlled create/start/exec/stop/network actions produce exactly-once stored normalized events with the correct image digest.

## eBPF Process-Execution Telemetry — Implemented

**Goal:** observe container process executions that Docker lifecycle events cannot reveal.

Implemented:

- Falco modern-eBPF sensor for container `execve` and `execveat` events
- Process PID, PPID, virtual PID, executable, command line, working directory, terminal, user, and group context
- Falco-reported parent context and evidence-backed `parent_event_id` linkage
- Short-container-ID resolution against Docker-identity records
- Full container ID, image ID, image reference, and repository-digest enrichment
- Persistent Falco JSON event file, durable telemetry cursor, SQLite outbox, retries, dead letters, and idempotent PostgreSQL ingestion

Not included here: file-access telemetry, network-connection telemetry, anomaly scoring, or attack classification.

Exit condition: `./scripts/verify_phase3.sh` captures a controlled process tree with correct PID/PPID linkage, full container identity, immutable digest, outage replay, and no duplicates.

## Digest-Bound Behavioural Profiles — Implemented

**Goal:** generate versioned normal-behaviour profiles separately for each immutable repository digest.

Implemented:

- Explicitly approved UTC training intervals; no automatic or continuous learning
- Exact `repository@sha256:...` identity
- Process name, executable, parent-child, user-ID, Docker-action, and within-container process-bigram distributions
- Observed-value sets for later novelty calculation
- Fixed-window event rates, distinct-process counts, root ratios, and shell ratios
- Deterministic event-selection and model hashes
- Draft, active, and retired profile versions
- Quality-gated activation and one active profile per digest
- Rejection of identical rebuilds and retired-profile reactivation

File, DNS, socket, and privilege-transition features are not claimed because the current sensor path only ingests process execution. The feature schema can be versioned when those evidence sources are implemented.

Exit condition: `./scripts/verify_phase4.sh` proves deterministic profile generation, quality gating, duplicate rejection, version activation, retirement, and one-active-profile enforcement.

## Behavioural Distance and Anomaly Scoring — Implemented

**Goal:** calculate an explainable deviation score instead of presenting a black-box verdict.

Implemented:

- Fixed observation windows inherited from each profile's `window_seconds`
- Active-profile selection and explicit historical scoring against retired versions
- Rejection of incomplete windows and profile-training overlap
- Evidence-count limits and explicit `insufficient_data` results
- Base-2 Jensen-Shannon distance for categorical distributions
- Probability-mass novelty for unseen processes, executables, edges, UIDs, actions, and sequence bigrams
- Scaled numeric deviation for rates, process diversity, root ratio, and shell ratio
- Versioned weighted score fusion with missing-family renormalization
- Persisted top contributors, unseen tokens, numeric deviations, profile identity, evidence manifest, and scoring configuration
- Deterministic observation keys and idempotent exact rescoring
- Provisional score bands that are explicitly not validated attack thresholds

Optional algorithms such as Isolation Forest, One-Class SVM, and Local Outlier Factor are reserved for detector-comparison evaluation. They are not part of the primary v1 scoring path.

Exit condition: `./scripts/verify_phase5.sh` proves insufficient-data handling, bounded explainable scoring, stronger deviation for a controlled novel workload, exact-retry idempotency, and training/evaluation separation.

## Detection, Correlation, and Explainable Incidents — Implemented

**Goal:** turn one scored observation window and deterministic evidence rules into a reproducible detection run and, where justified, one auditable incident.

Implemented:

- Versioned, hashed deterministic rule set (`POR-DET-001`..`007`)
- High behavioural distance retained as informational context rather than standalone incident proof
- Unseen shell, novel UID 0 process, unseen non-shell executable (any name), Docker exec, and privileged-container rules
- Same-container shell-to-tool correlation within a fixed 120-second window
- Digest-scoped exact executable allowlists with named human approval, expiry, and deactivation audit fields
- Allowlist-set hashing as part of detection-run identity
- Separate anomaly, severity, and confidence values
- One incident per detection run
- Chronological evidence timelines
- Open, acknowledged, resolved, and dismissed incident states
- Terminal-state transition protection
- Idempotent detection reruns

Current sensor evidence is process execution plus Docker lifecycle events. File, DNS, and outbound socket correlation are not claimed — this is the concrete blind spot behind, e.g., an attacker using an already-known tool (`curl`) against a new destination.

Exit condition: `./scripts/verify_phase6.sh` proves insufficient-data handling, baseline-like non-incidents, controlled process-based incident creation, exact digest-scoped suppression, idempotency, evidence ordering, and incident lifecycle enforcement.

## Human-Approved Response Recommendations — Implemented

**Goal:** recommend and execute proportionate actions without granting an automated detector unrestricted Docker control.

Implemented:

- Deterministic, versioned response policy
- Separate operator and internal-service credentials
- Safe-disabled disruptive execution mode by default
- Exact full-container-ID targeting
- `observe_only`, `pause_container`, and `stop_container` actions
- Human acknowledgement for disruptive actions
- Recommendation freshness limit
- One idempotent execution per approved recommendation
- Isolated non-root responder service with Docker socket access
- Porygon-protected container refusal
- Leased execution queue and abandoned-claim recovery
- Immediate Docker state verification
- Unpause rollback and explicitly limited stop/start compensation
- Manual retry only for transient executor failures
- Chronological response audit events
- No automatic deletion, command execution, or arbitrary Docker operation

Network disconnection is not implemented because the current evidence pipeline does not yet collect enough network telemetry to recommend it defensibly. Auto-execution without human approval remains deliberately out of scope; see [`CLAIMS_V1.md`](CLAIMS_V1.md) for the reasoning.

Exit condition: `./scripts/verify_phase7.sh` proves credential separation, no action before approval, exact-target pause, idempotent approval, verified rollback, and complete audit evidence.

## Digest-Bound SBOM and Vulnerability Enrichment — Implemented

**Goal:** add current static-image and prioritization context without claiming that package presence proves exploitation.

Implemented:

- Operator-requested scans for an exact known repository digest
- Exact local image-ID and Docker-host binding
- Isolated scanner service with a leased work queue
- Trivy `0.72.0` pinned by release version and architecture-specific SHA-256
- One Trivy JSON scan converted to CycloneDX, preserving both raw report and SBOM with canonical hashes
- Normalized vulnerability package matches with fix and CVSS data
- Trivy database-file hashes plus FIRST EPSS and CISA KEV enrichment
- External feed metadata and response/document hashes
- Immutable scan-time intelligence snapshot per finding
- Latest mutable intelligence lookup per CVE
- Runtime/deployment context using container snapshots, process evidence, and port publication
- Four explicit stages: `package_present`, `deployed`, `runtime_observed`, and `runtime_observed_and_port_published`
- `exploit_status = not_established` for every finding
- Idempotent scan identity, active queue-lease renewal, and explicit experiment references
- Finding/SBOM size limits and partial-intelligence handling

Not implemented or claimed:

- vulnerable function reachability
- exploit confirmation
- attack-compatible or suspected-exploitation stages
- static findings automatically creating incidents or response actions
- VEX generation

Exit condition: `./scripts/verify_phase8.sh` proves exact digest/image binding, scan idempotency, CycloneDX persistence, immutable enrichment snapshots, and the exploitation claim boundary on a real Docker host.

## Experimental Evaluation and Paper — In progress

**Goal:** produce defensible results.

Real progress: `docs/CONFIRMATORY_RESULT_V1.md` records the first real pilot
result (`study-20260905t181654Z`, 144 real trials,
`evidence_class: pilot`, `research_eligible: false`): `ARM-CONTEXT` vs `ARM-GLOBAL` shows a 100%
relative FPR reduction (35/35 → 0/35 false positives), exact McNemar
p = 5.8×10⁻¹¹ (Holm-adjusted), recall non-inferior at 100% under both arms.
`experiments/analysis.py` (exact McNemar, Holm correction, Clopper-Pearson
intervals, stratified bootstrap, `decide_primary_contrast`) and
`experiments/scope.py` (the GLOBAL/TAG/DIGEST/CONTEXT comparison itself,
reusing the production Jensen-Shannon scorer) did not exist before this was
built; neither did a working attack-scenario path (`SCN-LOG4SHELL-SIM`,
`SCN-RUNC-ESCAPE-SIM` were dead code until fixed).

Still open:

- Sample size (n=35 benign / n=62 scenario) is well below the frozen
  full-matrix target (200 trials). `experiments/sample_size.py` implements
  `ART-DES-001`'s exact-binomial power lock for the *next* confirmatory round,
  and found the protocol's own frozen recall-margin target (5 percentage
  points at 95% reference recall, 80% power, ≤120 runs/cell) is infeasible as
  written — needs a protocol revision before it can be used.
- `ARM-TAG` vs `ARM-DIGEST` remain indistinguishable: a real mutable-tag-drift
  test (`experiments/tag_drift.py`) found nginx 1.26.3→1.28.0 produces
  identical process-name shape (JS-distance 0.0); a drift scenario that
  changes deeper behaviour has not yet been tested.
- Detector comparison arms (`DET-RULES`/`DET-NOVELTY`/`DET-FREQUENCY`/
  `DET-SEQUENCE`/`DET-CALIBRATED`/`DET-HYBRID`), the six ablations, load
  regimes, outage/recovery timing, and resource sampling are still
  unimplemented.
- Two files this section previously linked
  (`EXPERIMENT_ACCEPTANCE.md`, `EXPERIMENT_REPRODUCIBILITY.md`) do not exist
  in this repository; the links have been removed rather than left broken.
  Reproduction steps live in `docs/CONFIRMATORY_RESULT_V1.md` and
  `experiments/study.py`'s own docstrings until a dedicated document is
  written.

Evaluation:

- Multiple benign workloads and versions
- Controlled attack scenarios only in an isolated lab
- Repeated trials with ground-truth timestamps
- Rules-only vs anomaly-only vs hybrid comparison
- Detection quality, latency, dropped-event rate, and overhead
- Ablation of feature groups and score components
- Honest failure and limitation analysis

Exit condition: all paper tables and graphs are generated from versioned experiment artifacts; no fabricated results or claims.

## Dashboard, Packaging, and Optional Extensions

**Goal:** make the system demonstrable and reproducible.

Mandatory:

- Incident list and evidence details
- Image-digest profile view
- Response approval queue
- Experiment metrics view
- Reproducible Compose deployment and documentation

Optional only after the core research works:

- Kubernetes deployment with Tetragon and Cilium
- NetworkPolicy quarantine
- LLM-generated incident summaries
- CVE-to-runtime evidence graph
- VEX output
- Multi-host collection
