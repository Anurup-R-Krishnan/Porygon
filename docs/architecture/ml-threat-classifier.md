# Explainable Machine Learning Threat Classifier

> **Component:** `backend/src/porygon_api/ml_classifier.py`  
> **Model Identifier:** `porygon.ml.rf.v1`  
> **Architecture:** Pure-Python Explainable Tree Ensemble (Random Forest) with TreeSHAP Local Feature Attribution

---

## 1. Why Explainable ML in Container Runtime Security?

Traditional deep learning or black-box classifiers output raw probabilities (e.g., `P(malicious) = 0.94`) without explaining *why* a workload was flagged. In production infrastructure, this creates severe friction:

- System administrators will not authorize container termination based on an opaque score.
- Security analysts cannot discern whether an alert was triggered by an authorized developer debugging a service or an actual malware dropper.

Porygon solves this by pairing a **Tree Ensemble (Random Forest)** with **TreeSHAP (SHapley Additive exPlanations)** to generate human-interpretable reasons for every security verdict.

---

## 2. The 12 Runtime Window Features

Rather than evaluating isolated syscalls, Porygon computes a rolling feature vector over a **60-second observation window** (or evaluates raw process execution streams):

| # | Feature Name | Computation Formula / Meaning | Associated MITRE Tactic |
|---|---|---|---|
| 1 | `shell_ratio` | $\frac{\text{count}(exec \in \text{SHELL\_BINARIES})}{\text{total\_events}}$ | Execution / Shell Escape |
| 2 | `root_ratio` | $\frac{\text{count}(uid == 0)}{\text{total\_events}}$ | Privilege Escalation |
| 3 | `recon_ratio` | $\frac{\text{count}(exec \in \text{RECON\_TOOLS})}{\text{total\_events}}$ (`whoami`, `id`, `uname`, `ip`) | Discovery / Reconnaissance |
| 4 | `tooling_ratio` | $\frac{\text{count}(exec \in \text{DOWNLOAD\_TOOLS})}{\text{total\_events}}$ (`curl`, `wget`, `nc`, `nmap`) | Ingress Tool Transfer |
| 5 | `priv_escalation_ratio` | Executions of `sudo`, `su`, `chmod +s`, `nsenter` | Privilege Escalation |
| 6 | `compiler_miner_ratio` | Executions of `gcc`, `make`, `xmrig`, `minerd` | Defense Evasion / Impact |
| 7 | `distinct_proc_count` | Number of distinct binary paths executed in window | Anomaly Indicator |
| 8 | `event_count` | Total volume of process events in window | Burst / Flood Indicator |
| 9 | `unseen_executable_ratio` | Proportion of executions not present in baseline | Statistical Novelty |
| 10| `parent_shim_ratio` | Container escape shims (`runc`, `containerd-shim`, `nsenter`) | Escape / Lateral Movement |
| 11| `suspicious_sequence_ratio`| Sequences matching known attack chains (e.g., `curl -> chmod -> exec`) | Attack Pipeline |
| 12| `jensen_shannon_drift` | Statistical divergence $D_{JS}$ from baseline distribution | Process Drift |

---

## 3. Decision Forest Classification

The classification engine maps the 12-dimensional continuous feature vector to one of five target attack classes:

```
                                  [Input Feature Vector]
                                             |
                   +-------------------------+-------------------------+
                   |                         |                         |
                   v                         v                         v
              [Tree 1]                   [Tree 2]                  [Tree N]
           /            \             /            \            /            \
      [shell > 0.1]    ...       [recon > 0.3]    ...      [root > 0.5]     ...
         /        \                 /        \                /        \
     Class A    Class B         Class A    Class C        Class B    Class A
                   \                         |                         /
                    +------------------------+------------------------+
                                             | Majority Voting / Averaged Probs
                                             v
               +--------------------------------------------------------------+
               |                  Final Tactical Verdict                      |
               |  - Predicted Class: "privilege_escalation"                   |
               |  - Confidence: 0.942                                         |
               |  - TreeSHAP Local Attributions:                              |
               |    * root_ratio: +0.42                                       |
               |    * shell_ratio: +0.31                                      |
               |    * priv_escalation_ratio: +0.18                            |
               |    * compiler_miner_ratio: -0.05                             |
               +--------------------------------------------------------------+
```

### Pure-Python Implementation Design
Unlike traditional machine learning stacks that require heavy C-extensions (`scikit-learn`, `numpy`, `scipy`), Porygon's `ml_classifier.py` is implemented entirely in standard Python:
- Zero external pip requirements for ML inference.
- Eliminates native binary dependencies and shared library vulnerabilities.
- Sub-millisecond evaluation latency per observation window.

---

## 4. TreeSHAP Local Feature Attribution

For every classification, Porygon computes exact Shapley values across the decision forest paths:

$$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|! (|F| - |S| - 1)!}{|F|!} \left[ f(S \cup \{i\}) - f(S) \right]$$

This mathematical guarantee provides operators with an exact contribution breakdown:
- "The container was classified as **shell_escape** primarily because `parent_shim_ratio` (+0.38) and `shell_ratio` (+0.29) elevated the score, while `compiler_miner_ratio` (-0.02) had negligible impact."

---

## 5. Dashboard Integration

On the Newsprint operator dashboard, TreeSHAP values are visualized as an interactive horizontal attribution bar chart:

```
[TACTIC: PRIVILEGE ESCALATION (94.2%)]
root_ratio              ████████████████████ (+0.42)
shell_ratio             ███████████████ (+0.31)
priv_escalation_ratio   ████████ (+0.18)
unseen_executable_ratio ███ (+0.06)
compiler_miner_ratio    ▌ (-0.05)
```
