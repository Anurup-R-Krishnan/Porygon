# Digest-Bound Behavioral Profiling & Rarity Scoring

> **Component:** `porygon-backend` (Behavioral Profiling, Anomaly Scoring, Detection Engine)  
> **Schema:** `porygon.behaviour.v1`, `porygon.rarity.provenance.calibrated`  
> **Core Concept:** Provenance-bound statistical baselines vs naive heuristic alerts

---

## 1. The Scoping Granularity Problem

Traditional runtime detection systems profile workloads using mutable metadata like container names or image tags (e.g., `redis:latest`, `node:alpine`). This approach suffers from two severe vulnerabilities:

1. **Tag Poisoning / Registry Drift:** A malicious actor or upstream rebuild modifies the image behind `myapp:latest`. The security system applies an outdated profile or fails to flag unexpected binaries.
2. **Context Blindness:** A container running with `--privileged` exhibits vastly different attack surfaces than the identical image running with a read-only root filesystem and dropped capabilities.

Porygon solves this through the **Profile Scope Experiment**, evaluating four experimental arms:

| Profile Arm | Scope Key | Description | Granularity |
|---|---|---|:---:|
| `ARM-GLOBAL` | `*` | Single global baseline across all containers on the host. | Lowest |
| `ARM-TAG` | `repo:tag` | Baseline keyed by mutable Docker tag (e.g. `nginx:latest`). | Low |
| `ARM-DIGEST` | `sha256:...` | Baseline strictly bound to the immutable image SHA-256 content digest. | **High (Porygon Core)** |
| `ARM-CONTEXT` | `sha256:... + perms` | Bound to digest PLUS host security context (privileged, caps, mounts). | **Optimal (Porygon Context)** |

---

## 2. Baseline Profile Construction

A Porygon baseline profile is generated during an explicitly approved observation or training interval for a specific image digest.

```
       +--------------------------------------------------------------+
       |          Training Window Ingestion (Baseline Profiling)       |
       |  - 500+ benign transactions exercised across container      |
       |  - Extract every distinct process execution (exe, cmd, user) |
       |  - Record parent-child lineage (ppid_comm -> child_comm)     |
       +------------------------------+-------------------------------+
                                      |
                                      v
       +--------------------------------------------------------------+
       |             Deterministic Baseline Construction              |
       |                                                              |
       | 1. Executable Set:                                           |
       |    {"/usr/sbin/nginx", "/usr/bin/find", "/bin/sh"}           |
       |                                                              |
       | 2. Execution Frequency Histogram:                            |
       |    nginx: 94.2%, find: 4.8%, sh: 1.0%                        |
       |                                                              |
       | 3. Lineage Tree Allowlist:                                   |
       |    init -> nginx                                             |
       |    nginx -> worker_process                                   |
       |    worker_process -> (no further forks permitted)            |
       +------------------------------+-------------------------------+
                                      |
                                      v
               Stored in PostgreSQL: container_baselines table
```

---

## 3. Rarity Scoring & Anomaly Formulas

When an event occurs in production, Porygon calculates an objective, calibrated rarity score rather than an arbitrary heuristic number.

### 1. Unseen Executable Penalty ($S_{exe}$)
If the executable path $e$ was never observed during baseline training for digest $D$:
$$S_{exe}(e, D) = 1.0$$
If $e$ was observed during training:
$$S_{exe}(e, D) = 0.0$$

### 2. Frequency Rarity Score ($S_{freq}$)
For binaries that appeared during training but with very low frequency:
$$S_{freq}(e, D) = -\log_{10}\left(\frac{\text{count}(e) + 1}{\sum_{i} \text{count}(e_i) + |E|}\right)$$
Where $|E|$ is Laplace smoothing over the vocabulary of observed executables.

### 3. Parent Lineage Rarity ($S_{lineage}$)
An executable may be benign in isolation (e.g., `/bin/bash`), but anomalous when spawned by an unauthorized parent (e.g., `apache2 -> bash` vs `sshd -> bash`):
$$S_{lineage}(e_{child}, e_{parent}) = \begin{cases} 1.0 & \text{if } (e_{parent}, e_{child}) \notin \text{AllowedEdges}(D) \\ 0.0 & \text{otherwise} \end{cases}$$

### 4. Jensen-Shannon Divergence ($D_{JS}$)
To detect slow-burn attacks and operational drift, Porygon computes the Jensen-Shannon Divergence between the baseline distribution $P$ and the recent observation window $Q$:
$$M = \frac{1}{2}(P + Q)$$
$$D_{JS}(P \parallel Q) = \frac{1}{2} D_{KL}(P \parallel M) + \frac{1}{2} D_{KL}(Q \parallel M)$$
Where $D_{KL}$ is the Kullback-Leibler divergence. When $D_{JS} > 0.45$, a statistical distribution drift alert is fired.

---

## 4. Calibrated Decision Thresholds

Rather than guessing alert thresholds, Porygon provides `scripts/check_research_protocol.py` and `scripts/probe_context_variants.py` to calibrate anomaly thresholds:

| Rarity Score Range | Classification | Action |
|---|---|---|
| $S < 0.15$ | **Benign / Normal** | Permitted without alert |
| $0.15 \le S < 0.65$ | **Low-Confidence Drift** | Telemetry recorded; logged for operator review |
| $0.65 \le S < 0.85$ | **Elevated Anomaly** | Incident generated; dashboard alert; MITRE tagging |
| $S \ge 0.85$ | **Critical Anomaly** | Immediate containment recommendation issued |
