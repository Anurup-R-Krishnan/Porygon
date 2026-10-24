# Porygon

> **Provenance-Bound Container Runtime Security, Kernel-Level eBPF Telemetry, and Explainable Machine-Learning Threat Classification**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![eBPF](https://img.shields.io/badge/Observability-Modern_eBPF-orange)](https://falco.org/)
[![Docker](https://img.shields.io/badge/Runtime-Docker_24+-2496ED)](https://www.docker.com/)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-brightgreen)](#prerequisites--system-requirements)
[![Status](https://img.shields.io/badge/Verification-Passed_Gates_1--8-success)](#verification--quality-assurance-gates)

Porygon is a production-grade, research-validated container runtime security platform for Linux/Docker environments. It bridges the gap between low-overhead kernel observability and high-confidence threat detection by binding statistical behavioral baselines and vulnerability metadata strictly to immutable image content digests (`sha256:...`) rather than mutable repository tags.

Porygon pairs deterministic eBPF process execution capture with a supervised **Tree Ensemble (Random Forest)** threat classifier and **TreeSHAP additive feature attribution**, delivering mathematically explainable security verdicts categorized across MITRE ATT&CK tactics alongside human-in-the-loop cryptographic containment.

---

## Table of Contents

- [Core Innovations & Validated Claims](#core-innovations--validated-claims)
- [System Architecture & Network Topology](#system-architecture--network-topology)
- [Subsystems Deep Dive](#subsystems-deep-dive)
  - [1. Kernel eBPF Telemetry & Ingestion](#1-kernel-ebpf-telemetry--ingestion)
  - [2. Digest-Bound Behavioral Baselines & Anomaly Scoring](#2-digest-bound-behavioral-baselines--anomaly-scoring)
  - [3. Explainable ML Threat Classifier (Random Forest + TreeSHAP)](#3-explainable-ml-threat-classifier-random-forest--treeshap)
  - [4. Dynamic SBOM & Runtime Vulnerability Reachability](#4-dynamic-sbom--runtime-vulnerability-reachability)
  - [5. Cryptographic Human-in-the-Loop Containment](#5-cryptographic-human-in-the-loop-containment)
  - [6. Interactive Newsprint Dashboard](#6-interactive-newsprint-dashboard)
- [Services & Port Mappings](#services--port-mappings)
- [Prerequisites & System Requirements](#prerequisites--system-requirements)
- [Quick Start](#quick-start)
- [Operator CLI Workflows](#operator-cli-workflows)
- [REST API Reference](#rest-api-reference)
- [Verification & Quality Assurance Gates](#verification--quality-assurance-gates)
- [Documentation Index](#documentation-index)

---

## Core Innovations & Validated Claims

```
+-------------------------------------------------------------------------------------------------+
|                                     THE PORYGON DEFENSE PARADIGM                                |
+-------------------------------------------------------------------------------------------------+
| Traditional Container Security          | Porygon Runtime Security Platform                     |
+-----------------------------------------+-------------------------------------------------------+
| Mutable tag scoping (redis:latest)      | Cryptographic content digest (sha256:4b83445e998a...)   |
| Black-box anomaly score (e.g. 0.94)     | Explainable TreeSHAP feature attributions per tactic  |
| Silent event dropping under burst       | Verified zero-loss saturation pipeline (100% loss-free)|
| Alert fatigue: 300+ dormant CVE alerts  | Runtime Reachability: alerts only when vuln executes  |
| Autonomous, destructive termination     | Non-destructive cgroup freezing + cryptographic lease |
+-------------------------------------------------------------------------------------------------+
```

### Validated Scientific & Engineering Claims
1. **Digest-Bound Baseline Scoping:** Baselines keyed to immutable cryptographic digests eliminate tag-poisoning drift and achieve statistically significant reductions in false-positive anomaly alerts compared to mutable tags.
2. **Lossless Telemetry Under Saturation:** Validated through automated saturation gates executing 5,000 rapid process executions with $0.00\%$ drop across kernel ring-buffers and PostgreSQL ingestion.
3. **No Unexplained Alarms:** Every security incident is accompanied by exact TreeSHAP feature attributions and parent-child process execution lineage.
4. **Non-Destructive Blast Radius Containment:** Container `PAUSE` halts malicious instruction execution via cgroup freezers in $<1\text{s}$ while preserving RAM, sockets, and open files for live forensic inspection.

---

## System Architecture & Network Topology

```
 +-----------------------------------------------------------------------------------------+
 |                                  LINUX HOST KERNEL                                      |
 |                                                                                         |
 |   +------------------------------------+       +------------------------------------+   |
 |   |        Monitored Container A       |       |        Monitored Container B       |   |
 |   |   execve()  execveat() clone()     |       |   execve()  execveat() clone()     |   |
 |   +-----------------+------------------+       +-----------------+------------------+   |
 |                     |                                            |                      |
 |                     +---------------------+----------------------+                      |
 |                                           | (raw tracepoints)                           |
 |                                           v                                             |
 |                       +---------------------------------------+                         |
 |                       |      Modern eBPF Driver (Falco)       |                         |
 |                       |   Ring Buffer / Tracepoint Capture    |                         |
 |                       +-------------------+-------------------+                         |
 +-------------------------------------------|---------------------------------------------+
                                             | Unix Socket / Stream
                                             v
               +-----------------------------------------------------------+
               |              porygon-collector (Go / Python)              |
               |   - Normalizes raw tracepoint telemetry                   |
               |   - Resolves cgroup ID -> Docker Container ID -> Digest   |
               |   - Enforces zero-drop queue with backpressure accounting |
               +-----------------------------+-----------------------------+
                                             | HTTP / Batch Ingestion
                                             v
               +-----------------------------------------------------------+
               |                  porygon-telemetry (API)                  |
               |   - Event deduplication & validation                      |
               |   - PostgreSQL persistence (Timescale/Indexed tables)     |
               +-----------------------------+-----------------------------+
                                             |
                                             v
               +-----------------------------------------------------------+
               |                    PostgreSQL Storage                     |
               |   - process_events (execve telemetry with parent lineage) |
               |   - container_baselines (SHA-256 digest-bound profiles)   |
               |   - anomaly_scores & security_incidents                   |
               |   - sbom_artifacts & image_vulnerabilities                |
               +-----------------------------+-----------------------------+
                                             ^
                                             | Queries & Enrichments
                                             v
 +-----------------------------------------------------------------------------------------+
 |                              INTELLIGENCE & DETECTION PLANE                             |
 |                                                                                         |
 |  +--------------------------------+          +---------------------------------------+  |
 |  |    Statistical Baseline Profiler|          |   Explainable ML Threat Classifier    |  |
 |  | - Digest-bound training windows |          | - 12-feature runtime window extractor |  |
 |  | - Frequency rarity scoring      |          | - Tree Ensemble (Random Forest)       |  |
 |  | - Parent-child lineage tracking |          | - TreeSHAP local feature attribution  |  |
 |  +----------------+---------------+          +-------------------+-------------------+  |
 |                   |                                              |                      |
 |                   +----------------------+-----------------------+                      |
 |                                          |                                              |
 |                                          v                                              |
 |                        +------------------------------------+                           |
 |                        |    Incident Correlation Engine     |                           |
 |                        |  - MITRE ATT&CK tactic tagging     |                           |
 |                        |  - Vulnerability reachability join |                           |
 |                        |  - Containment recommendation      |                           |
 |                        +-----------------+------------------+                           |
 +------------------------------------------|----------------------------------------------+
                                            |
                                            v
 +-----------------------------------------------------------------------------------------+
 |                                CONTROL & RESPONSE PLANE                                 |
 |                                                                                         |
 |   +------------------------------------+       +------------------------------------+   |
 |   |        porygon-dashboard           |       |         porygon-responder          |   |
 |   |  - Real-time Newsprint UI          |       |  - Cryptographic token validation  |   |
 |   |  - Visual TreeSHAP explanations    | <---> |  - Docker socket interface         |   |
 |   |  - Containment authorization queue |       |  - Pause / Stop / Network Isolate  |   |
 |   +------------------------------------+       +------------------------------------+   |
 +-----------------------------------------------------------------------------------------+
```

---

## Subsystems Deep Dive

### 1. Kernel eBPF Telemetry & Ingestion
- **Tracepoints Hooked:** `sys_enter_execve`, `sys_exit_execve`, `sys_enter_execveat`, `sys_exit_execveat`.
- **Zero Workload Mutation:** No application modification, no sidecar proxies, and no `LD_PRELOAD` wrappers.
- **Identity Resolution:** Maps kernel cgroup IDs to Docker container UUIDs and extracts immutable image content digests in real time.
- See [`docs/architecture/EBPF_TELEMETRY.md`](docs/architecture/EBPF_TELEMETRY.md).

### 2. Digest-Bound Behavioral Baselines & Anomaly Scoring
- **Deterministic Baseline Creation:** Records complete process trees, binary paths, arguments, and execution frequency histograms during approved training intervals.
- **Rarity Scoring ($S_{freq}$):** Laplace-smoothed logarithmic frequency evaluation flags executions that are mathematically rare.
- **Lineage Tree Validation:** Flags valid binaries executed by unauthorized parents (e.g. `nginx -> sh` vs `sshd -> sh`).
- **Drift Detection:** Computes Jensen-Shannon Divergence ($D_{JS}$) across rolling process distributions to detect slow-burn attacks.
- See [`docs/architecture/BEHAVIORAL_PROFILING.md`](docs/architecture/BEHAVIORAL_PROFILING.md).

### 3. Explainable ML Threat Classifier (Random Forest + TreeSHAP)
- **12-Dimensional Extracted Feature Vector:**
  1. `shell_ratio` - Interactive shell executions (`sh`, `bash`, `dash`).
  2. `root_ratio` - Executions running with UID 0.
  3. `recon_ratio` - Network and host enumeration utilities (`whoami`, `id`, `ip`, `nmap`).
  4. `tooling_ratio` - Ingress transfer utilities (`curl`, `wget`, `nc`, `socat`).
  5. `priv_escalation_ratio` - Escalation tooling (`sudo`, `su`, `nsenter`, `capsh`).
  6. `compiler_miner_ratio` - Compilers and miners (`gcc`, `make`, `xmrig`).
  7. `distinct_proc_count` - Unique binaries executed within window.
  8. `event_count` - Total process event burst volume.
  9. `unseen_executable_ratio` - Executions absent from baseline profile.
  10. `parent_shim_ratio` - Executions spawned by `runc` or `containerd-shim`.
  11. `suspicious_sequence_ratio` - Executions matching recon-to-exploit chaining.
  12. `jensen_shannon_drift` - Continuous statistical baseline drift.
- **MITRE ATT&CK Classification:** Categorizes activity into `benign`, `reconnaissance`, `privilege_escalation`, `shell_escape`, and `suspicious_tooling`.
- **Pure-Python Architecture:** Implemented in pure Python (`ml_classifier.py`) without native C-dependencies or bulky ML frameworks.
- See [`docs/architecture/ML_THREAT_CLASSIFIER.md`](docs/architecture/ML_THREAT_CLASSIFIER.md).

### 4. Dynamic SBOM & Runtime Vulnerability Reachability
- **Static Ingestion:** Generates SPDX/CycloneDX SBOMs with Anchore Syft and extracts known CVEs with Anchore Grype.
- **Runtime Reachability:** Dynamically joins intercepted runtime `execve` events against the container's known package manifest.
- **Dynamic Severity Elevation:** If an anomalous process execution matches an unpatched High/Critical CVE in the container filesystem, incident severity is immediately escalated to **Critical**.
- See [`docs/architecture/SBOM_VULNERABILITY.md`](docs/architecture/SBOM_VULNERABILITY.md).

### 5. Cryptographic Human-in-the-Loop Containment
- **Non-Destructive Freezing:** Pauses container cgroups (`docker pause`), stopping execution instantaneously without terminating RAM, network sockets, or open file descriptors.
- **Operator Leases:** All containment actions require HMAC-SHA256 signed operator tokens with 30-second TTLs to prevent unauthorized automated destruction.
- **Protected Service Whitelist:** Hardcoded protection prevents containment from targeting Porygon infrastructure containers (`backend`, `postgres`, `collector`).
- See [`docs/architecture/CONTAINMENT_ENGINE.md`](docs/architecture/CONTAINMENT_ENGINE.md).

### 6. Interactive Newsprint Dashboard
- Real-time incident triage and TreeSHAP attribution visualizations.
- Visual container baseline comparison and image digest drift metrics.
- Built-in **Attack Simulator**: Dispatch controlled test workloads (Shell Escape, Crypto-Miner, Port Scanner) to demonstrate real eBPF kernel detection.

---

## Services & Port Mappings

| Service | Internal Role | Tech Stack | Port | Access |
|---|---|---|---|---|
| **`porygon-backend`** | Core API, profiler, ML classifier, incidents | Python 3.14, FastAPI | `8000` | `http://localhost:8000` |
| **`porygon-dashboard`** | Newsprint UI, simulator, telemetry stream | Alpine.js, Chart.js, Tailwind | `8080` / `3000` | `http://localhost:8080` |
| **`porygon-telemetry`** | Kernel event ingestion & spooling | FastAPI, PostgreSQL | `8001` | Internal bridge |
| **`porygon-responder`** | Containment execution & lease verification | Python 3.14, Docker SDK | `8002` | Docker socket (gated) |
| **`porygon-collector`** | eBPF event normalizer & metadata resolver | Go / Python, Unix socket | `N/A` | Docker socket (read-only) |
| **`porygon-scanner`** | SBOM generation & Grype vulnerability scans | Syft, Grype, Python | `N/A` | Internal bridge |
| **`porygon-postgres`** | Relational event and profile storage | PostgreSQL 17.10 Bookworm | `5432` | Internal isolated |

---

## Prerequisites & System Requirements

- **Operating System:** Linux with kernel version $\ge 5.8$ (eBPF ring-buffer support).
- **Container Engine:** Docker Engine 24.0+ with Docker Compose v2.
- **Python:** Python 3.11, 3.12, 3.13, or 3.14.
- **Permissions:** Root / `sudo` access or membership in the `docker` group to interact with `/var/run/docker.sock` and eBPF tracepoints.

---

## Quick Start

### 1. Initialize Configuration
Generate cryptographically random passwords, API tokens, and resolve Docker socket GIDs:
```bash
make init
```

### 2. Launch the Platform
Build and start all services in detached mode:
```bash
make up
```

### 3. Check System Health
```bash
make ps
```

### 4. Launch the Dashboard
Serve the newsprint dashboard:
```bash
python3 scripts/serve_dashboard.py
```
Open **`http://localhost:8080`** (or **`http://localhost:3000`**) in your web browser.

---

## Operator CLI Workflows

Porygon provides specialized operator CLI scripts under `scripts/`:

```bash
# Build baseline for an image digest from an approved container run
python3 scripts/porygon_baseline.py build --container <container_id>

# Inspect drift and anomaly score for an active container
python3 scripts/porygon_score.py evaluate --container <container_id>

# Run vulnerability scan and generate SBOM for an image
python3 scripts/porygon_scan.py scan --image nginx@sha256:...

# Review active security incidents
python3 scripts/incident_alerts.py list

# Authorize container containment (PAUSE or STOP)
python3 scripts/porygon_respond.py execute --incident <incident_id> --action pause
```

---

## REST API Reference

### Core Backend & Intelligence Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `GET /health/live` | `GET` | Service liveness and dependency status |
| `GET /api/v1/incidents` | `GET` | Query security incidents with pagination and filtering |
| `POST /api/v1/incidents/{id}/authorize` | `POST` | Authorize container containment action using operator clearance token |
| `GET /api/v1/baselines/{digest}` | `GET` | Retrieve cryptographic baseline profile and execution histogram |
| `POST /api/v1/scoring/evaluate` | `POST` | Evaluate behavioral divergence and rarity for observation window |
| `GET /api/v1/vulnerabilities/{digest}` | `GET` | Retrieve SBOM packages and CVE reachability map |

### Machine Learning Classifier Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `POST /api/v1/ml/classify-container/{container_id}` | `POST` | Ingests rolling 60s telemetry for a live container, outputs MITRE tactic and TreeSHAP attributions |
| `POST /api/v1/ml/classify` | `POST` | Classifies raw list of eBPF process execution events on-the-fly |
| `POST /api/v1/ml/classify-features` | `POST` | Classifies a pre-computed 12-dimensional feature vector |
| `GET /api/v1/ml/model-info` | `GET` | Returns decision forest metadata, version (`porygon.ml.rf.v1`), and classes |

---

## Verification & Quality Assurance Gates

Porygon enforces an automated 8-phase verification harness (`scripts/verify_all.sh`):

```bash
# Run all static checks (syntax, types, linters, schemas)
make verify-static

# Run full unit test suite across backend and services
make verify-unit

# Run live non-disruptive acceptance on isolated test container
make verify-live-safe

# Run complete end-to-end verification gate
make verify
```

Verification status is dynamically generated into [`artifacts/verification-manifest.json`](artifacts/verification-manifest.json).

---

## Documentation Index

Explore the complete documentation in [`docs/`](docs/):

- **Architecture:**
  - [System Overview](docs/architecture/OVERVIEW.md)
  - [eBPF Kernel Telemetry](docs/architecture/EBPF_TELEMETRY.md)
  - [Digest-Bound Behavioral Profiling](docs/architecture/BEHAVIORAL_PROFILING.md)
  - [Explainable ML Threat Classifier](docs/architecture/ML_THREAT_CLASSIFIER.md)
  - [Containment Engine & Safety Leases](docs/architecture/CONTAINMENT_ENGINE.md)
  - [SBOM & Vulnerability Reachability](docs/architecture/SBOM_VULNERABILITY.md)
- **Academic Research & Protocol:**
  - [Research Protocol Archive](docs/research/README.md)
  - [Frozen Research Protocol v1](docs/research/RESEARCH_PROTOCOL_V1.md)
  - [Threat Model v1](docs/research/THREAT_MODEL_V1.md)
  - [Claims Boundaries v1](docs/research/CLAIMS_V1.md)
  - [Adversarial Scenarios Stress Tests](docs/research/ADVERSARIAL_SCENARIOS_V1.md)
  - [Development Roadmap (Phases 1–8)](docs/research/FINAL_PHASES.md)
- **Defense Presentations:**
  - [Presentation Guide & Slides](docs/presentation/README.md)
  - [Presentation Spoken Script](docs/presentation/PRESENTATION_SCRIPT.md)
- **Reviews:**
  - [Review Package](docs/review/REVIEW_PACKAGE.md)
