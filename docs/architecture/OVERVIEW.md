# Porygon Architecture Overview

> **Porygon** is a provenance-bound container runtime security platform combining kernel-level eBPF observability, deterministic statistical baseline profiling, explainable machine-learning threat classification, and cryptographic human-in-the-loop containment.

---

## 1. High-Level System Architecture

Porygon operates across three interconnected layers: the **Kernel & Ingestion Plane**, the **Intelligence & Correlation Plane**, and the **Control & Response Plane**.

```
 +-----------------------------------------------------------------------------------------+
 |                                  LINUX HOST KERNEL                                      |
 |                                                                                         |
 |   +------------------------------------+       +------------------------------------+   |
 |   |         App Container A            |       |         App Container B            |   |
 |   |    (cgroup, pid & mnt ns)          |       |    (cgroup, pid & mnt ns)          |   |
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
                                             | Unix Domain Socket / FIFO stream
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

## 2. Core Service Boundaries

| Service Name | Primary Role | Tech Stack | Internal Ports | External Access |
|---|---|---|---|---|
| `porygon-telemetry` | Ingestion, event validation, schema enforcement, time-series storage | Python 3.14, FastAPI, SQLAlchemy | `8001` | Internal network |
| `porygon-backend` | Core API, statistical profiler, ML threat classifier, vulnerability join | Python 3.14, FastAPI, Uvicorn | `8000` | `http://localhost:8000` |
| `porygon-collector` | Ring-buffer reader, Falco event parser, container metadata resolver | Python / Go, Unix Sockets | `N/A` | Docker host socket (read-only) |
| `porygon-responder` | Containment executor, cryptographic clearance validator | Python 3.14, Docker SDK | `8002` | Docker host socket (write-gated) |
| `porygon-scanner` | Image SBOM extraction (Syft) & vulnerability scanner (Grype) | Syft, Grype, Python worker | `N/A` | Image registry / local daemon |
| `porygon-dashboard` | Newsprint operational frontend, attack simulator, analytics | Vanilla JS, Alpine.js, Tailwind CSS, Chart.js | `8080` | `http://localhost:8080` |
| `postgres` | Central relational storage with indexed telemetry & profiles | PostgreSQL 17.10 (Bookworm) | `5432` | Internal isolated bridge |

---

## 3. Data Flow Lifecycles

### 1. Ingestion Pipeline
1. A container process issues an `execve` or `execveat` syscall.
2. The modern eBPF driver hooks kernel tracepoints without kernel modification or binary instrumentation.
3. The event is pushed into a shared kernel ring-buffer.
4. `porygon-collector` drains the ring buffer, associates the host cgroup with the Docker container ID, extracts the immutable image SHA-256 digest, and formats the event into the `porygon.behaviour.v1` schema.
5. Events are batched and posted into `porygon-telemetry`, which verifies schemas and writes them to PostgreSQL.

### 2. Behavioral Baseline & ML Threat Scoring
1. **Statistical Profiler (Phase 4):** Evaluates whether the executed binary, command arguments, and parent-child process relationship were observed during the container's approved baseline training window.
2. **Explainable ML Classifier:** Extracts 12 continuous metrics over rolling 60-second observation windows (e.g., shell command ratios, privilege escalation indicators, compiler executions, Jensen-Shannon distribution drift).
3. The Tree Ensemble classifies activity into one of 5 MITRE tactics (`benign`, `reconnaissance`, `privilege_escalation`, `shell_escape`, `suspicious_tooling`) and calculates TreeSHAP feature attributions explaining *why* the prediction was made.

### 3. Vulnerability Reachability Correlation (Phase 8)
1. Concurrently, `porygon-scanner` runs static SBOM analysis via Syft and CVE vulnerability assessment via Grype on the container's immutable image digest.
2. When runtime anomaly events occur, Porygon correlates executed binaries against known CVE vulnerabilities in the package manifest.
3. If an anomalous binary corresponds to a vulnerable library (e.g., vulnerable OpenSSL or curl binary), the incident severity is dynamically elevated to Critical.

### 4. Human-Approved Containment (Phase 7)
1. If an incident exceeds threat thresholds, the Incident Correlation Engine issues a **Containment Recommendation** (`PAUSE`, `STOP`, or `ISOLATE`).
2. The recommendation is queued in `porygon-dashboard`.
3. An authorized human operator reviews the behavioral evidence, TreeSHAP attributions, and CVE reachability graph.
4. The operator approves the action using a cryptographically validated lease token.
5. `porygon-responder` receives the signed action, verifies the clearance, and executes the containment action via the Docker daemon socket.
