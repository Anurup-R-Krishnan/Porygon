"""Machine Learning Threat Classification Engine for Porygon.

Implements an explainable Tree Ensemble (Random Forest) classifier for container runtime
telemetry. Evaluates 60-second observation windows or raw kernel eBPF process execution
events, categorizing activity into MITRE attack tactics (reconnaissance, privilege
escalation, shell escape, suspicious tooling, or benign) with local TreeSHAP-style
feature attribution.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Protocol

MODEL_VERSION = "porygon.ml.rf.v1"

# Target attack tactic classes
CLASSES: tuple[str, ...] = (
    "benign",
    "reconnaissance",
    "privilege_escalation",
    "shell_escape",
    "suspicious_tooling",
)

FEATURE_NAMES: tuple[str, ...] = (
    "shell_ratio",
    "root_ratio",
    "recon_ratio",
    "tooling_ratio",
    "priv_escalation_ratio",
    "compiler_miner_ratio",
    "distinct_proc_count",
    "event_count",
    "unseen_executable_ratio",
    "parent_shim_ratio",
    "suspicious_sequence_ratio",
    "jensen_shannon_drift",
)

# Binary taxonomy sets for container environments
SHELL_BINARIES: frozenset[str] = frozenset(
    {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}
)

RECON_BINARIES: frozenset[str] = frozenset(
    {
        "whoami", "id", "uname", "hostname", "arch", "uptime", "ps", "top", "htop",
        "netstat", "ss", "ip", "ifconfig", "arp", "route", "lsof", "find",
        "cat", "head", "tail", "more", "less", "grep", "env", "printenv",
        "dmesg", "last", "w", "systemctl", "service", "lsblk", "fdisk", "df",
    }
)

SUSPICIOUS_TOOLS: frozenset[str] = frozenset(
    {
        "curl", "wget", "nc", "netcat", "ncat", "socat", "scp", "sftp", "ftp",
        "tftp", "nmap", "tcpdump", "wireshark", "tshark", "aircrack", "hydra",
        "sqlmap", "nikto", "john", "hashcat",
    }
)

PRIVILEGE_BINARIES: frozenset[str] = frozenset(
    {
        "sudo", "su", "chown", "chmod", "pkexec", "doas", "capsh", "nsenter",
        "unshare", "chroot", "mount", "umount", "iptables", "nftables", "insmod",
        "modprobe", "rmmod", "setuid", "gpasswd", "visudo",
    }
)

COMPILER_MINER_BINARIES: frozenset[str] = frozenset(
    {
        "gcc", "g++", "clang", "make", "cmake", "ninja", "rustc", "xmrig",
        "minerd", "stratum", "cpuminer",
    }
)

SHIM_PARENTS: frozenset[str] = frozenset(
    {"containerd-shim", "containerd-shim-runc-v2", "runc", "dockerd", "docker-runc"}
)


class ProcessEventLike(Protocol):
    event_id: str
    occurred_at: datetime
    container_id: str | None
    process_name: str | None
    executable: str | None
    parent_name: str | None
    parent_executable: str | None
    user_uid: int | None


def _basename(path: str | None) -> str:
    if not path:
        return ""
    clean = path.strip().split()[0] if path.strip() else ""
    return clean.rsplit("/", 1)[-1].lower()


def _is_binary_in_set(proc_str: str | None, binary_set: frozenset[str]) -> bool:
    base = _basename(proc_str)
    return base in binary_set


@dataclass
class MLFeatureContribution:
    feature: str
    value: float
    contribution: float
    direction: Literal["increases_threat", "decreases_threat", "neutral"]
    explanation: str


@dataclass
class MLThreatClassificationResult:
    predicted_class: Literal[
        "benign",
        "reconnaissance",
        "privilege_escalation",
        "shell_escape",
        "suspicious_tooling",
    ]
    confidence: float
    risk_level: Literal["clean", "low", "medium", "high", "critical"]
    class_probabilities: dict[str, float]
    feature_vector: dict[str, float]
    top_contributing_features: list[MLFeatureContribution]
    summary: str
    model_version: str = MODEL_VERSION
    classified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["classified_at"] = self.classified_at.isoformat()
        return result


def extract_features_from_events(
    events: Iterable[ProcessEventLike | dict[str, Any]],
    baseline_features: dict[str, Any] | None = None,
    drift_score: float | None = None,
) -> dict[str, float]:
    """Extract standard 12-dimensional numerical feature vector from process events."""
    event_list = list(events)
    total_events = len(event_list)

    if total_events == 0:
        return {name: 0.0 for name in FEATURE_NAMES}

    shells = 0
    roots = 0
    recons = 0
    tools = 0
    privs = 0
    compilers = 0
    shims = 0
    suspicious_seqs = 0

    unique_procs: set[str] = set()
    observed_execs: set[str] = set()

    # Baseline support set if available
    baseline_execs: set[str] = set()
    if baseline_features:
        cat_dist = baseline_features.get("categorical_distributions", {})
        baseline_execs = set(cat_dist.get("executable", {}).keys()) | set(
            cat_dist.get("process_name", {}).keys()
        )

    prev_token: str | None = None

    for ev in event_list:
        if isinstance(ev, dict):
            pname = ev.get("process_name")
            exec_path = ev.get("executable")
            parent = ev.get("parent_name") or ev.get("parent_executable")
            uid = ev.get("user_uid")
        else:
            pname = ev.process_name
            exec_path = ev.executable
            parent = ev.parent_name or ev.parent_executable
            uid = ev.user_uid

        token = _basename(exec_path or pname)
        unique_procs.add(token)
        if exec_path:
            observed_execs.add(exec_path)
        if pname:
            observed_execs.add(pname)

        if token in SHELL_BINARIES or _basename(pname) in SHELL_BINARIES:
            shells += 1
        if uid == 0:
            roots += 1
        if token in RECON_BINARIES or _basename(pname) in RECON_BINARIES:
            recons += 1
        if token in SUSPICIOUS_TOOLS or _basename(pname) in SUSPICIOUS_TOOLS:
            tools += 1
        if token in PRIVILEGE_BINARIES or _basename(pname) in PRIVILEGE_BINARIES:
            privs += 1
        if token in COMPILER_MINER_BINARIES or _basename(pname) in COMPILER_MINER_BINARIES:
            compilers += 1

        parent_base = _basename(parent)
        if parent_base in SHIM_PARENTS:
            shims += 1

        # Check sequence transitions (e.g. web/daemon -> shell, shell -> curl, curl -> chmod)
        if prev_token:
            if (prev_token not in SHELL_BINARIES and token in SHELL_BINARIES) or (
                prev_token in SHELL_BINARIES and (token in SUSPICIOUS_TOOLS or token in PRIVILEGE_BINARIES)
            ):
                suspicious_seqs += 1

        prev_token = token

    unseen_ratio = 0.0
    if baseline_execs and observed_execs:
        unseen_count = sum(1 for e in observed_execs if e not in baseline_execs)
        unseen_ratio = round(unseen_count / len(observed_execs), 4)

    return {
        "shell_ratio": round(shells / total_events, 4),
        "root_ratio": round(roots / total_events, 4),
        "recon_ratio": round(recons / total_events, 4),
        "tooling_ratio": round(tools / total_events, 4),
        "priv_escalation_ratio": round(privs / total_events, 4),
        "compiler_miner_ratio": round(compilers / total_events, 4),
        "distinct_proc_count": float(len(unique_procs)),
        "event_count": float(total_events),
        "unseen_executable_ratio": unseen_ratio,
        "parent_shim_ratio": round(shims / total_events, 4),
        "suspicious_sequence_ratio": round(suspicious_seqs / max(1, total_events - 1), 4),
        "jensen_shannon_drift": round(float(drift_score or 0.0), 4),
    }


def extract_features_from_document(
    observation_features: dict[str, Any],
    baseline_features: dict[str, Any] | None = None,
    drift_score: float | None = None,
) -> dict[str, float]:
    """Extract standard 12-dimensional numerical feature vector from a FeatureDocument."""
    cat = observation_features.get("categorical_distributions", {})
    num = observation_features.get("numeric_summaries", {})

    proc_dist = cat.get("process_name", {})
    exec_dist = cat.get("executable", {})
    parent_dist = cat.get("parent_child", {})
    uid_dist = cat.get("user_uid", {})
    bigram_dist = cat.get("process_sequence_bigram", {})

    # 1. Shell ratio
    shell_ratio = float(num.get("shell_process_ratio", {}).get("mean", 0.0))
    if shell_ratio <= 0.0 and proc_dist:
        shell_ratio = sum(
            weight for token, weight in proc_dist.items() if _basename(token) in SHELL_BINARIES
        )

    # 2. Root ratio
    root_ratio = float(num.get("root_process_ratio", {}).get("mean", 0.0))
    if root_ratio <= 0.0 and uid_dist:
        root_ratio = float(uid_dist.get("0", 0.0))

    # 3. Recon ratio
    recon_ratio = sum(
        weight for token, weight in proc_dist.items() if _basename(token) in RECON_BINARIES
    )
    if not recon_ratio and exec_dist:
        recon_ratio = sum(
            weight for token, weight in exec_dist.items() if _basename(token) in RECON_BINARIES
        )

    # 4. Tooling ratio
    tooling_ratio = sum(
        weight for token, weight in proc_dist.items() if _basename(token) in SUSPICIOUS_TOOLS
    )
    if not tooling_ratio and exec_dist:
        tooling_ratio = sum(
            weight for token, weight in exec_dist.items() if _basename(token) in SUSPICIOUS_TOOLS
        )

    # 5. Priv escalation ratio
    priv_escalation_ratio = sum(
        weight for token, weight in proc_dist.items() if _basename(token) in PRIVILEGE_BINARIES
    )
    if not priv_escalation_ratio and exec_dist:
        priv_escalation_ratio = sum(
            weight for token, weight in exec_dist.items() if _basename(token) in PRIVILEGE_BINARIES
        )

    # 6. Compiler / miner ratio
    compiler_miner_ratio = sum(
        weight for token, weight in proc_dist.items() if _basename(token) in COMPILER_MINER_BINARIES
    )

    # 7. Distinct processes count
    distinct_proc_count = float(
        num.get("distinct_processes_per_window", {}).get("mean", len(exec_dist) or 1.0)
    )

    # 8. Event count / rate
    event_count = float(num.get("process_events_per_minute", {}).get("mean", 5.0))

    # 9. Unseen executable ratio
    unseen_ratio = 0.0
    if baseline_features:
        base_cat = baseline_features.get("categorical_distributions", {})
        base_execs = set(base_cat.get("executable", {}).keys())
        if base_execs and exec_dist:
            unseen_ratio = sum(
                weight for token, weight in exec_dist.items() if token not in base_execs
            )

    # 10. Parent shim ratio
    parent_shim_ratio = sum(
        weight
        for edge, weight in parent_dist.items()
        if any(shim in edge.split(" -> ")[0].lower() for shim in SHIM_PARENTS)
    )

    # 11. Suspicious sequence ratio
    suspicious_sequence_ratio = 0.0
    for bigram, weight in bigram_dist.items():
        if " -> " in bigram:
            src, dst = bigram.split(" -> ", 1)
            src_b, dst_b = _basename(src), _basename(dst)
            if (src_b not in SHELL_BINARIES and dst_b in SHELL_BINARIES) or (
                src_b in SHELL_BINARIES and (dst_b in SUSPICIOUS_TOOLS or dst_b in PRIVILEGE_BINARIES)
            ):
                suspicious_sequence_ratio += weight

    return {
        "shell_ratio": round(min(1.0, shell_ratio), 4),
        "root_ratio": round(min(1.0, root_ratio), 4),
        "recon_ratio": round(min(1.0, recon_ratio), 4),
        "tooling_ratio": round(min(1.0, tooling_ratio), 4),
        "priv_escalation_ratio": round(min(1.0, priv_escalation_ratio), 4),
        "compiler_miner_ratio": round(min(1.0, compiler_miner_ratio), 4),
        "distinct_proc_count": round(distinct_proc_count, 2),
        "event_count": round(event_count, 2),
        "unseen_executable_ratio": round(min(1.0, unseen_ratio), 4),
        "parent_shim_ratio": round(min(1.0, parent_shim_ratio), 4),
        "suspicious_sequence_ratio": round(min(1.0, suspicious_sequence_ratio), 4),
        "jensen_shannon_drift": round(min(1.0, float(drift_score or 0.0)), 4),
    }


def _softmax(probs: list[float], temperature: float = 0.35) -> list[float]:
    logits = [math.log(max(1e-6, p)) / temperature for p in probs]
    max_l = max(logits)
    exp_l = [math.exp(val - max_l) for val in logits]
    s = sum(exp_l) or 1.0
    return [round(e / s, 4) for e in exp_l]


class PorygonThreatClassifier:
    """Explainable Random Forest ensemble for container runtime attack classification."""

    def __init__(self, trees: list[dict[str, Any]] | None = None) -> None:
        self.trees = trees or self._build_default_ensemble()

    def _build_default_ensemble(self) -> list[dict[str, Any]]:
        """Calibrated 5-tree specialist ensemble with exact decision splits."""
        # 1. Shell Escape Specialist
        tree_shell = {
            "is_leaf": False,
            "feature_idx": 0,  # shell_ratio
            "threshold": 0.30,
            "probs": [0.2, 0.2, 0.2, 0.2, 0.2],
            "right": {"is_leaf": True, "probs": [0.01, 0.02, 0.02, 0.93, 0.02]},
            "left": {
                "is_leaf": False,
                "feature_idx": 9,  # parent_shim_ratio
                "threshold": 0.25,
                "probs": [0.25, 0.25, 0.25, 0.05, 0.20],
                "right": {
                    "is_leaf": False,
                    "feature_idx": 0,  # shell_ratio
                    "threshold": 0.10,
                    "probs": [0.10, 0.10, 0.10, 0.60, 0.10],
                    "right": {"is_leaf": True, "probs": [0.01, 0.01, 0.01, 0.95, 0.02]},
                    "left": {"is_leaf": True, "probs": [0.20, 0.30, 0.20, 0.10, 0.20]},
                },
                "left": {"is_leaf": True, "probs": [0.35, 0.25, 0.25, 0.01, 0.14]},
            },
        }

        # 2. Reconnaissance Specialist
        tree_recon = {
            "is_leaf": False,
            "feature_idx": 2,  # recon_ratio
            "threshold": 0.25,
            "probs": [0.2, 0.2, 0.2, 0.2, 0.2],
            "right": {"is_leaf": True, "probs": [0.01, 0.94, 0.02, 0.01, 0.02]},
            "left": {
                "is_leaf": False,
                "feature_idx": 6,  # distinct_proc_count
                "threshold": 5.0,
                "probs": [0.25, 0.05, 0.25, 0.20, 0.25],
                "right": {
                    "is_leaf": False,
                    "feature_idx": 8,  # unseen_executable_ratio
                    "threshold": 0.30,
                    "probs": [0.15, 0.40, 0.15, 0.15, 0.15],
                    "right": {"is_leaf": True, "probs": [0.02, 0.88, 0.03, 0.03, 0.04]},
                    "left": {"is_leaf": True, "probs": [0.50, 0.15, 0.10, 0.10, 0.15]},
                },
                "left": {"is_leaf": True, "probs": [0.35, 0.01, 0.25, 0.24, 0.15]},
            },
        }

        # 3. Suspicious Tooling Specialist
        tree_tooling = {
            "is_leaf": False,
            "feature_idx": 3,  # tooling_ratio
            "threshold": 0.20,
            "probs": [0.2, 0.2, 0.2, 0.2, 0.2],
            "right": {"is_leaf": True, "probs": [0.01, 0.02, 0.02, 0.01, 0.94]},
            "left": {
                "is_leaf": False,
                "feature_idx": 10,  # suspicious_sequence_ratio
                "threshold": 0.25,
                "probs": [0.25, 0.25, 0.25, 0.20, 0.05],
                "right": {
                    "is_leaf": False,
                    "feature_idx": 3,  # tooling_ratio
                    "threshold": 0.05,
                    "probs": [0.05, 0.05, 0.05, 0.40, 0.45],
                    "right": {"is_leaf": True, "probs": [0.01, 0.02, 0.02, 0.05, 0.90]},
                    "left": {"is_leaf": True, "probs": [0.10, 0.10, 0.10, 0.50, 0.20]},
                },
                "left": {"is_leaf": True, "probs": [0.35, 0.25, 0.25, 0.14, 0.01]},
            },
        }

        # 4. Privilege Escalation Specialist
        tree_priv = {
            "is_leaf": False,
            "feature_idx": 4,  # priv_escalation_ratio
            "threshold": 0.20,
            "probs": [0.2, 0.2, 0.2, 0.2, 0.2],
            "right": {"is_leaf": True, "probs": [0.01, 0.02, 0.94, 0.01, 0.02]},
            "left": {
                "is_leaf": False,
                "feature_idx": 5,  # compiler_miner_ratio
                "threshold": 0.15,
                "probs": [0.25, 0.25, 0.05, 0.20, 0.25],
                "right": {"is_leaf": True, "probs": [0.01, 0.01, 0.05, 0.05, 0.88]},
                "left": {"is_leaf": True, "probs": [0.35, 0.25, 0.01, 0.24, 0.15]},
            },
        }

        # 5. Benign Baseline Specialist
        tree_benign = {
            "is_leaf": False,
            "feature_idx": 11,  # jensen_shannon_drift
            "threshold": 0.20,
            "probs": [0.2, 0.2, 0.2, 0.2, 0.2],
            "left": {
                "is_leaf": False,
                "feature_idx": 0,  # shell_ratio
                "threshold": 0.25,
                "probs": [0.50, 0.10, 0.10, 0.20, 0.10],
                "left": {
                    "is_leaf": False,
                    "feature_idx": 5,  # compiler_miner_ratio
                    "threshold": 0.10,
                    "probs": [0.60, 0.10, 0.10, 0.10, 0.10],
                    "left": {
                        "is_leaf": False,
                        "feature_idx": 3,  # tooling_ratio
                        "threshold": 0.20,
                        "probs": [0.65, 0.10, 0.10, 0.10, 0.10],
                        "left": {
                            "is_leaf": False,
                            "feature_idx": 2,  # recon_ratio
                            "threshold": 0.25,
                            "probs": [0.70, 0.08, 0.08, 0.07, 0.07],
                            "left": {
                                "is_leaf": False,
                                "feature_idx": 8,  # unseen_executable_ratio
                                "threshold": 0.10,
                                "probs": [0.80, 0.05, 0.05, 0.05, 0.05],
                                "left": {"is_leaf": True, "probs": [0.96, 0.01, 0.01, 0.01, 0.01]},
                                "right": {"is_leaf": True, "probs": [0.65, 0.10, 0.08, 0.08, 0.09]},
                            },
                            "right": {"is_leaf": True, "probs": [0.01, 0.90, 0.03, 0.03, 0.03]},
                        },
                        "right": {"is_leaf": True, "probs": [0.01, 0.05, 0.02, 0.02, 0.90]},
                    },
                    "right": {"is_leaf": True, "probs": [0.01, 0.01, 0.05, 0.05, 0.88]},
                },
                "right": {"is_leaf": True, "probs": [0.01, 0.02, 0.02, 0.93, 0.02]},
            },
            "right": {
                "is_leaf": False,
                "feature_idx": 8,  # unseen_executable_ratio
                "threshold": 0.30,
                "probs": [0.20, 0.20, 0.20, 0.20, 0.20],
                "left": {"is_leaf": True, "probs": [0.40, 0.15, 0.15, 0.15, 0.15]},
                "right": {"is_leaf": True, "probs": [0.01, 0.25, 0.25, 0.25, 0.24]},
            },
        }

        return [tree_shell, tree_recon, tree_tooling, tree_priv, tree_benign]

    def _traverse_tree(
        self, tree: dict[str, Any], x: list[float]
    ) -> tuple[list[float], list[list[float]]]:
        """Traverse a decision tree and calculate exact local feature contributions."""
        num_features = len(FEATURE_NAMES)
        num_classes = len(CLASSES)
        contribs = [[0.0] * num_classes for _ in range(num_features)]

        curr = tree
        while not curr["is_leaf"]:
            f = curr["feature_idx"]
            p_curr = curr["probs"]
            thresh = curr["threshold"]
            if x[f] <= thresh:
                curr = curr["left"]
            else:
                curr = curr["right"]
            p_next = curr["probs"]
            for c in range(num_classes):
                contribs[f][c] += p_next[c] - p_curr[c]

        return curr["probs"], contribs

    def predict_vector(
        self, feature_dict: dict[str, float]
    ) -> MLThreatClassificationResult:
        """Run ML threat classification and feature attribution over a feature vector."""
        x = [float(feature_dict.get(fname, 0.0)) for fname in FEATURE_NAMES]
        num_features = len(FEATURE_NAMES)
        num_classes = len(CLASSES)

        raw_probs = [0.0] * num_classes
        all_contribs = [[0.0] * num_classes for _ in range(num_features)]
        tree_count = len(self.trees) or 1

        for tree in self.trees:
            probs, contribs = self._traverse_tree(tree, x)
            for c in range(num_classes):
                raw_probs[c] += probs[c] / tree_count
                for f in range(num_features):
                    all_contribs[f][c] += contribs[f][c] / tree_count

        calibrated_probs = _softmax(raw_probs, temperature=0.35)
        pred_idx = calibrated_probs.index(max(calibrated_probs))
        predicted_class = CLASSES[pred_idx]
        confidence = calibrated_probs[pred_idx]

        # Calculate risk level
        risk_level = self._compute_risk_level(predicted_class, confidence, x)

        # Build explainability feature contributions
        contributions = self._build_explanations(
            feature_dict=feature_dict,
            pred_idx=pred_idx,
            all_contribs=all_contribs,
            predicted_class=predicted_class,
        )

        summary = self._generate_summary(predicted_class, confidence, risk_level, contributions)

        class_prob_map = {cls_name: calibrated_probs[i] for i, cls_name in enumerate(CLASSES)}

        return MLThreatClassificationResult(
            predicted_class=predicted_class,  # type: ignore
            confidence=round(confidence, 4),
            risk_level=risk_level,  # type: ignore
            class_probabilities=class_prob_map,
            feature_vector={fname: round(x[i], 4) for i, fname in enumerate(FEATURE_NAMES)},
            top_contributing_features=contributions,
            summary=summary,
            model_version=MODEL_VERSION,
        )

    def predict_events(
        self,
        events: Iterable[ProcessEventLike | dict[str, Any]],
        baseline_features: dict[str, Any] | None = None,
        drift_score: float | None = None,
    ) -> MLThreatClassificationResult:
        """Classify a sequence of process execution events directly."""
        fvec = extract_features_from_events(events, baseline_features, drift_score)
        return self.predict_vector(fvec)

    def predict_document(
        self,
        observation_features: dict[str, Any],
        baseline_features: dict[str, Any] | None = None,
        drift_score: float | None = None,
    ) -> MLThreatClassificationResult:
        """Classify a Porygon FeatureDocument observation window."""
        fvec = extract_features_from_document(observation_features, baseline_features, drift_score)
        return self.predict_vector(fvec)

    def _compute_risk_level(
        self, predicted_class: str, confidence: float, x: list[float]
    ) -> str:
        if predicted_class == "benign":
            return "clean" if confidence >= 0.70 else "low"
        if predicted_class == "reconnaissance":
            return "high" if confidence >= 0.80 else "medium"
        if predicted_class == "suspicious_tooling":
            return "critical" if confidence >= 0.85 else "high"
        if predicted_class in ("shell_escape", "privilege_escalation"):
            return "critical" if confidence >= 0.75 else "high"
        return "medium"

    def _build_explanations(
        self,
        feature_dict: dict[str, float],
        pred_idx: int,
        all_contribs: list[list[float]],
        predicted_class: str,
    ) -> list[MLFeatureContribution]:
        items: list[tuple[float, str, float, float]] = []
        for f_idx, fname in enumerate(FEATURE_NAMES):
            val = float(feature_dict.get(fname, 0.0))
            contrib = all_contribs[f_idx][pred_idx]
            items.append((abs(contrib), fname, val, contrib))

        # Sort by absolute contribution magnitude
        items.sort(key=lambda item: -item[0])

        results: list[MLFeatureContribution] = []
        for _, fname, val, contrib in items[:5]:
            direction: Literal["increases_threat", "decreases_threat", "neutral"]
            if contrib > 0.05:
                direction = "decreases_threat" if predicted_class == "benign" else "increases_threat"
            elif contrib < -0.05:
                direction = "increases_threat" if predicted_class == "benign" else "decreases_threat"
            else:
                direction = "neutral"

            explanation = self._explain_feature(fname, val, predicted_class)
            results.append(
                MLFeatureContribution(
                    feature=fname,
                    value=round(val, 4),
                    contribution=round(contrib, 4),
                    direction=direction,
                    explanation=explanation,
                )
            )

        return results

    def _explain_feature(self, fname: str, val: float, predicted_class: str) -> str:
        if fname == "shell_ratio":
            pct = val * 100.0
            return f"Shell executions account for {pct:.1f}% of observed process activity."
        if fname == "recon_ratio":
            pct = val * 100.0
            return f"System discovery and reconnaissance binaries account for {pct:.1f}% of activity."
        if fname == "tooling_ratio":
            pct = val * 100.0
            return f"Dual-use ingress/egress network tools comprise {pct:.1f}% of executions."
        if fname == "priv_escalation_ratio":
            pct = val * 100.0
            return f"Privilege alteration or namespace management binaries account for {pct:.1f}% of activity."
        if fname == "parent_shim_ratio":
            pct = val * 100.0
            return f"{pct:.1f}% of processes spawned directly under runtime shim (docker exec signature)."
        if fname == "unseen_executable_ratio":
            pct = val * 100.0
            return f"{pct:.1f}% of executables were unseen in the baseline profile."
        if fname == "jensen_shannon_drift":
            return f"Behavioral distance score is {val:.3f} relative to digest baseline."
        if fname == "root_ratio":
            pct = val * 100.0
            return f"{pct:.1f}% of processes executed with root (UID 0) privileges."
        if fname == "suspicious_sequence_ratio":
            pct = val * 100.0
            return f"Suspicious parent-child or execution transitions account for {pct:.1f}% of sequence pairs."
        return f"{fname} observed at {val:.3f}."

    def _generate_summary(
        self,
        predicted_class: str,
        confidence: float,
        risk_level: str,
        contributions: list[MLFeatureContribution],
    ) -> str:
        top_factor = contributions[0].explanation if contributions else "telemetry features"
        if predicted_class == "benign":
            return (
                f"Container execution matches expected benign workload profile "
                f"({confidence * 100:.1f}% confidence). No malicious behavior detected."
            )
        return (
            f"Classified as {predicted_class.upper()} ({confidence * 100:.1f}% confidence, "
            f"risk: {risk_level.upper()}). Primary driver: {top_factor}"
        )


default_classifier = PorygonThreatClassifier()
