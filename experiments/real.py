"""Real-container pilot runner for the Porygon profile-scope study.

Safety boundary: every container is disposable, locally built from a protocol
pinned digest, labelled with its run and trial ID, published only on loopback,
and removed by exact name plus label match. No malware, no public targets, no
destructive host action, and no live response are involved. Confirmatory
collection stays refused until the protocol reports frozen status.
"""

from __future__ import annotations

import json
import math
import random
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiments.artifacts import sha256_bytes
from experiments.context import context_hash, runtime_context

ROOT = Path(__file__).resolve().parents[1]
PROFILE_SCOPE_DOC = ROOT / "docs/PROFILE_SCOPE_EXPERIMENT_V1.md"
LABEL_RUN = "porygon.experiment.run"
LABEL_TRIAL = "porygon.experiment.trial"
CANARY = "porygon-canary"
TELEMETRY_CONTAINER = "porygon-telemetry-1"
FALCO_EVENT_PATH = "/var/log/porygon/falco-events.jsonl"

_IMAGE_ROW = re.compile(
    r"^\|\s*`(?P<workload>WL-[A-Z]+-V\d)`\s*\|\s*`(?P<tag>[^`]+)`\s*\|\s*`(?P<digest>[^`]+)`\s*\|"
)


class PilotError(RuntimeError):
    """Raised when a real-container trial cannot proceed safely."""


# --------------------------------------------------------------------------
# Workload catalogue
# --------------------------------------------------------------------------

FAMILY_SPECS: dict[str, dict[str, Any]] = {
    "WL-NGX": {
        "container_port": 80,
        "env": {},
        "modes": ["idle", "steady_http", "burst_http", "alternate_read_only_config"],
        "driver": "http",
    },
    "WL-RDS": {
        "container_port": 6379,
        "env": {},
        "modes": ["idle", "steady_set_get", "burst_pipeline", "persistence_context"],
        "driver": "redis",
    },
    "WL-PG": {
        # A disposable, loopback-only container with trust auth holds no credential at all,
        # which is safer than passing a password the artifacts would then have to redact.
        "container_port": 5432,
        "env": {"POSTGRES_HOST_AUTH_METHOD": "trust", "POSTGRES_DB": "porygon_study"},
        "modes": ["idle", "read_only_queries", "read_write_transactions", "alternate_tuning_context"],
        "driver": "postgres",
    },
}

# Runtime-context variants, resolved per workload family.
#
# Every entry below was validated by `scripts/probe_context_variants.py`, which starts
# a container under each candidate and compares the executed-process multiset against
# the baseline. The registry records the measured outcome so the study cannot silently
# adopt a variant that changes the context identity without changing behaviour.
#
#   positive  the variant changes what the container executes, and the workload runs
#   negative  the variant changes the context identity only; behaviour is unchanged
#
# Negative controls are retained deliberately: a profile scope that reacts to them is
# fragmenting on configuration that carries no behavioural signal.
CONTEXT_VARIANT_KIND: dict[str, str] = {
    "baseline": "baseline",
    "direct_entrypoint": "positive",
    "init_mount": "positive",
    "nonroot_user": "positive",
    "dropped_capabilities": "negative",
    "tmpfs_scratch": "negative",
    "no_new_privileges": "negative",
}

# family -> docker arguments. A variant absent for a family is not available there,
# either because the image has no such surface or because the workload does not survive it.
CONTEXT_VARIANTS: dict[str, dict[str, list[str]]] = {
    "baseline": {"WL-NGX": [], "WL-RDS": [], "WL-PG": []},
    "direct_entrypoint": {
        "WL-NGX": ["--entrypoint", "nginx"],
        "WL-RDS": ["--entrypoint", "redis-server"],
    },
    "init_mount": {
        "WL-NGX": ["--volume", f"{ROOT}/experiments/fixtures/initdb:/docker-entrypoint.d/study:ro"],
        "WL-PG": ["--volume", f"{ROOT}/experiments/fixtures/initdb:/docker-entrypoint-initdb.d:ro"],
    },
    "nonroot_user": {"WL-RDS": ["--user", "999:1000"]},
    "dropped_capabilities": {
        "WL-NGX": ["--cap-drop", "NET_RAW"],
        "WL-RDS": ["--cap-drop", "NET_RAW"],
        "WL-PG": ["--cap-drop", "NET_RAW"],
    },
    "tmpfs_scratch": {
        "WL-NGX": ["--tmpfs", "/scratch"],
        "WL-RDS": ["--tmpfs", "/scratch"],
        "WL-PG": ["--tmpfs", "/scratch"],
    },
    "no_new_privileges": {
        "WL-NGX": ["--security-opt", "no-new-privileges"],
        "WL-RDS": ["--security-opt", "no-new-privileges"],
        "WL-PG": ["--security-opt", "no-new-privileges"],
    },
}

# Bypassing an image entrypoint means the command must be supplied explicitly.
VARIANT_COMMAND: dict[str, dict[str, list[str]]] = {
    "direct_entrypoint": {"WL-NGX": ["-g", "daemon off;"], "WL-RDS": []},
}


def variant_available(variant: str, family: str) -> bool:
    return family in CONTEXT_VARIANTS.get(variant, {})


RUNTIME_SCENARIOS = ("SCN-EXEC", "SCN-LOW", "SCN-FLOOD", "SCN-CONTEXT")
ANALYSIS_ONLY_SCENARIOS = ("SCN-CROSS", "SCN-POISON")

# The benign collection path: run the workload normally and take no scenario
# action at all. Not a member of RUNTIME_SCENARIOS/ATTACK_LIKE_SCENARIOS/
# ANALYSIS_ONLY_SCENARIOS -- it has its own dispatch branch in run_trial that
# skips run_scenario entirely (no exec, no canary).
BENIGN_SENTINEL = "SCN-NONE"

# Exploratory only. These map well-known CVEs to harmless, observable process
# shapes; they never reproduce the vulnerability or attempt a host action.
ATTACK_LIKE_SCENARIOS: dict[str, dict[str, Any]] = {
    "SCN-LOG4SHELL-SIM": {
        "cve_id": "CVE-2021-44228",
        "cvss_version": "3.1",
        "cvss_base_score": 10.0,
        "cvss_severity": "Critical",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "observable_behavior": "attacker-shaped input piped through a shell to a read-only tool",
        "command_template": "printf '%s\\n' {canary} | /bin/sh -c 'cat >/dev/null'; id",
    },
    "SCN-RUNC-ESCAPE-SIM": {
        "cve_id": "CVE-2019-5736",
        "cvss_version": "3.1",
        "cvss_base_score": 8.6,
        "cvss_severity": "High",
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
        "observable_behavior": "root/process-runtime inspection resembling an escape precursor",
        "command_template": "id; cat /proc/self/status >/dev/null; cat /proc/self/exe >/dev/null; printf '%s\\n' {canary}",
    },
}


# Mandatory hard-negative operations, per RESEARCH_PROTOCOL_V1.md's "Workloads
# and run counts" table ("Required hard negatives" column). The keys below are
# copied verbatim from that table's text (including backticks and slashes
# where the protocol embeds them, e.g. "`BGSAVE`", "traffic spike/log
# rotation") -- experiments/conformance.py:_parse_hard_negatives parses the
# live document with the exact same regex and produces these same strings, so
# a hard_negative_id recorded here can only satisfy CONF-HN-001 by matching
# the protocol's own wording exactly, never an invented name.
#
# A hard negative is benign ground truth (attack_like=False) but still an
# operator-shaped action -- run_hard_negative executes the real in-container
# command below and never injects a canary (see run_trial / module docstring
# on why: synthesizing one would contaminate the exact benign process
# distribution the false-positive rate is measured against).
#
# "driver_only" hard negatives (the traffic-volume ones) take no container
# exec at all: the action is a legitimate burst of ordinary driver-side
# workload traffic, driven the same way experiments/real.py:drive_load always
# drives load, just at a higher volume.
HARD_NEGATIVES: dict[str, dict[str, dict[str, Any]]] = {
    "WL-NGX": {
        "config validation/reload": {
            "command": "nginx -t && nginx -s reload",
            "expected_outcome": "hard_negative_config_reload",
            "description": "operator-style nginx configuration validation (`nginx -t`) followed by a reload (`nginx -s reload`)",
        },
        "maintenance shell": {
            "command": "id; uname -a; ps aux 2>/dev/null | head -n 20",
            "expected_outcome": "hard_negative_maintenance_shell",
            "description": "read-only maintenance shell inspection of identity/kernel/process state, the kind an operator runs while looking around inside a running container",
        },
        "traffic spike": {
            "driver_only": True,
            "burst_operations": 200,
            "expected_outcome": "hard_negative_traffic_spike",
            "description": "driver-side burst of ordinary HTTP request volume with zero additional container exec",
        },
        "log rotation": {
            "command": "nginx -s reopen",
            "expected_outcome": "hard_negative_log_rotation",
            "description": "log-rotation-style signal instructing nginx to reopen its log files",
        },
    },
    "WL-RDS": {
        "`BGSAVE`": {
            "command": "redis-cli BGSAVE",
            "expected_outcome": "hard_negative_bgsave",
            "description": "Redis background-save (BGSAVE) admin operation",
        },
        "admin inspection": {
            "command": "redis-cli INFO; redis-cli CLIENT LIST",
            "expected_outcome": "hard_negative_admin_inspection",
            "description": "read-only Redis admin inspection (INFO, CLIENT LIST)",
        },
        "maintenance shell": {
            "command": "id; uname -a; redis-cli PING",
            "expected_outcome": "hard_negative_maintenance_shell",
            "description": "read-only maintenance shell inspection alongside a protocol-level liveness probe",
        },
        "traffic spike/log rotation": {
            "driver_only": True,
            "burst_operations": 200,
            "expected_outcome": "hard_negative_traffic_spike",
            "description": "driver-side burst of ordinary SET/GET request volume with zero additional container exec (Redis has no on-disk request log to rotate, so the protocol pairs these two into one hard negative)",
        },
    },
    "WL-PG": {
        "`pg_dump` backup": {
            "command": "pg_dump -U postgres -d porygon_study -f /tmp/porygon-hard-negative-backup.sql",
            "expected_outcome": "hard_negative_pg_dump",
            "description": "pg_dump backup written to a disposable in-container scratch path",
        },
        "config reload": {
            "command": "psql -U postgres -d porygon_study -tAc \"SELECT pg_reload_conf();\"",
            "expected_outcome": "hard_negative_config_reload",
            "description": "PostgreSQL configuration reload via pg_reload_conf()",
        },
        "admin query/debug": {
            "command": (
                "psql -U postgres -d porygon_study -tAc \"\\l\"; "
                "psql -U postgres -d porygon_study -tAc \"SELECT count(*) FROM pg_stat_activity;\""
            ),
            "expected_outcome": "hard_negative_admin_query",
            "description": "read-only admin query/debug surface (\\l, a pg_stat_activity count)",
        },
        "maintenance shell/log rotation": {
            "command": "id; uname -a; psql -U postgres -d porygon_study -tAc \"SELECT pg_current_logfile();\"",
            "expected_outcome": "hard_negative_maintenance_shell",
            "description": (
                "read-only maintenance shell inspection plus the active log-file target "
                "(PostgreSQL log rotation is an external log-collector concern, not an in-session "
                "SQL action, so the protocol pairs these two into one hard negative)"
            ),
        },
    },
}


def load_image_coordinates(doc: Path = PROFILE_SCOPE_DOC) -> dict[str, dict[str, str]]:
    """Read the frozen workload/image table. The document stays the single source of truth."""
    coordinates: dict[str, dict[str, str]] = {}
    for line in doc.read_text(encoding="utf-8").splitlines():
        match = _IMAGE_ROW.match(line.strip())
        if match:
            coordinates[match.group("workload")] = {
                "human_tag": match.group("tag"),
                "index_digest_ref": match.group("digest"),
            }
    if not coordinates:
        raise PilotError(f"no pinned image coordinates found in {doc}")
    return coordinates


def family_of(workload_id: str) -> str:
    return workload_id.rsplit("-", 1)[0]


# --------------------------------------------------------------------------
# Docker helpers
# --------------------------------------------------------------------------


def docker(*args: str, timeout: int = 120, check: bool = True) -> str:
    completed = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )
    if check and completed.returncode != 0:
        raise PilotError(f"docker {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def pull_pinned_image(reference: str) -> dict[str, Any]:
    """Pull by immutable digest and record every identity field Docker exposes."""
    if "@sha256:" not in reference:
        raise PilotError(f"refusing a mutable image reference: {reference}")
    docker("pull", "--quiet", reference, timeout=900)
    inspection = json.loads(docker("image", "inspect", reference))[0]
    repository = reference.split("@", 1)[0]
    platform_digest = _platform_manifest_digest(reference)
    result = {
        "repository": repository,
        "reference": reference,
        "index_digest": reference.split("@", 1)[1],
        "platform_manifest_digest": platform_digest,
        "local_image_id": inspection.get("Id"),
        "repo_digests": inspection.get("RepoDigests") or [],
        "architecture": inspection.get("Architecture"),
        "os": inspection.get("Os"),
        "image_config_hash": sha256_bytes(
            json.dumps(inspection.get("Config") or {}, sort_keys=True).encode("utf-8")
        ),
    }
    return result


def _platform_manifest_digest(reference: str) -> dict[str, str]:
    """Resolve the platform manifest digest, or record why it is unmeasured."""
    completed = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", reference],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        return {"status": "unmeasured", "reason": "docker buildx imagetools is unavailable"}
    try:
        index = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "unmeasured", "reason": "manifest index is not valid JSON"}
    architecture = docker("version", "--format", "{{.Server.Arch}}") or "amd64"
    for manifest in index.get("manifests", []):
        platform = manifest.get("platform") or {}
        if platform.get("architecture") == architecture and platform.get("os") == "linux":
            return {"status": "measured", "digest": manifest.get("digest", "")}
    return {"status": "unmeasured", "reason": f"no linux/{architecture} manifest in the index"}


# --------------------------------------------------------------------------
# Cleanup — refuses anything it cannot prove belongs to this trial
# --------------------------------------------------------------------------


def _labels_of(container: str) -> dict[str, str]:
    raw = docker(
        "inspect", "--format", "{{json .Config.Labels}}", container, check=False
    )
    if not raw or raw == "null":
        return {}
    try:
        return json.loads(raw) or {}
    except json.JSONDecodeError:
        return {}


def remove_container(name: str, run_id: str, trial_id: str) -> dict[str, Any]:
    """Remove one container only when its name and both labels match this trial exactly."""
    existing = docker(
        "ps", "--all", "--filter", f"name=^{re.escape(name)}$", "--format", "{{.Names}}", check=False
    )
    matches = [line for line in existing.splitlines() if line]
    if not matches:
        return {"removed": False, "reason": "no container with that exact name"}
    if matches != [name]:
        raise PilotError(f"refusing ambiguous cleanup target: {matches}")
    labels = _labels_of(name)
    if labels.get(LABEL_RUN) != run_id or labels.get(LABEL_TRIAL) != trial_id:
        raise PilotError(f"refusing to remove unlabelled or foreign container: {name}")
    docker("rm", "--force", name, timeout=120)
    return {"removed": True, "name": name}


def remove_network(name: str, run_id: str) -> dict[str, Any]:
    raw = docker("network", "ls", "--filter", f"name=^{re.escape(name)}$", "--format", "{{.Name}}", check=False)
    matches = [line for line in raw.splitlines() if line]
    if not matches:
        return {"removed": False, "reason": "no network with that exact name"}
    if matches != [name]:
        raise PilotError(f"refusing ambiguous network cleanup target: {matches}")
    labels_raw = docker("network", "inspect", "--format", "{{json .Labels}}", name, check=False)
    labels = json.loads(labels_raw) if labels_raw and labels_raw != "null" else {}
    if (labels or {}).get(LABEL_RUN) != run_id:
        raise PilotError(f"refusing to remove unlabelled or foreign network: {name}")
    docker("network", "rm", name, check=False)
    return {"removed": True, "name": name}


# --------------------------------------------------------------------------
# Readiness and load drivers
# --------------------------------------------------------------------------


def _published_port(container: str, container_port: int) -> int:
    raw = docker("port", container, str(container_port))
    for line in raw.splitlines():
        if line.strip():
            return int(line.rsplit(":", 1)[1])
    raise PilotError(f"container {container} published no host port for {container_port}")


def _tcp_ready(port: int, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def _http_get(port: int, timeout: float = 5.0) -> tuple[int, float]:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=timeout) as response:
            response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    return status, (time.monotonic() - started) * 1000.0


def _redis_command(port: int, parts: list[str], timeout: float = 5.0) -> tuple[bytes, float]:
    payload = ("*%d\r\n" % len(parts)) + "".join(
        f"${len(part)}\r\n{part}\r\n" for part in parts
    )
    started = time.monotonic()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
        connection.sendall(payload.encode("utf-8"))
        reply = connection.recv(4096)
    return reply, (time.monotonic() - started) * 1000.0


def wait_ready(container: str, family: str, port: int, timeout_seconds: int = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    started = time.monotonic()
    if not _tcp_ready(port, deadline):
        raise PilotError(f"{container} never accepted a TCP connection on 127.0.0.1:{port}")
    while time.monotonic() < deadline:
        try:
            if family == "WL-NGX":
                status, _ = _http_get(port)
                if status < 500:
                    break
            elif family == "WL-RDS":
                reply, _ = _redis_command(port, ["PING"])
                if reply.startswith(b"+PONG"):
                    break
            elif _pg_ready(container):
                break
        except OSError:
            pass
        time.sleep(0.5)
    else:
        raise PilotError(f"{container} did not become protocol-ready within {timeout_seconds}s")
    return {"ready_after_ms": (time.monotonic() - started) * 1000.0, "probe": family}


def _pg_ready(container: str) -> bool:
    completed = subprocess.run(
        ["docker", "exec", container, "pg_isready", "-q", "-h", "127.0.0.1"],
        capture_output=True,
        timeout=30,
    )
    return completed.returncode == 0


def drive_load(
    container: str, family: str, port: int, mode: str, operations: int, seed: int
) -> dict[str, Any]:
    """Deterministic workload driver. Returns raw latency samples, never a pre-averaged summary."""
    rng = random.Random(seed)
    latencies: list[float] = []
    successes = failures = 0
    harness_execs = 0
    if mode == "idle":
        operations = 0
    for index in range(operations):
        try:
            if family == "WL-NGX":
                status, elapsed = _http_get(port)
                successes += status < 400
                failures += status >= 400
            elif family == "WL-RDS":
                key = f"porygon:{rng.randrange(1000)}"
                if index % 2:
                    reply, elapsed = _redis_command(port, ["SET", key, str(index)])
                else:
                    reply, elapsed = _redis_command(port, ["GET", key])
                successes += not reply.startswith(b"-")
                failures += reply.startswith(b"-")
            else:
                statement = (
                    "SELECT 1;" if mode == "read_only_queries" or index % 2 == 0
                    else "CREATE TABLE IF NOT EXISTS t(i int); INSERT INTO t VALUES (1);"
                )
                started = time.monotonic()
                completed = subprocess.run(
                    ["docker", "exec", container, "psql", "-U", "postgres",
                     "-d", "porygon_study", "-tAc", statement],
                    capture_output=True, timeout=30,
                )
                elapsed = (time.monotonic() - started) * 1000.0
                harness_execs += 1
                successes += completed.returncode == 0
                failures += completed.returncode != 0
            latencies.append(elapsed)
        except (OSError, subprocess.SubprocessError):
            failures += 1
    return {
        "mode": mode,
        "operations_planned": operations,
        "successes": successes,
        "failures": failures,
        "seed": seed,
        "latency_ms_samples": [round(value, 4) for value in latencies],
        "harness_induced_exec_count": harness_execs,
        "latency_definition": (
            "wall-clock per operation including connection setup and, for PostgreSQL, "
            "`docker exec` and psql process startup. This is a harness-side measurement "
            "of the request path, not a server-side service-time measurement."
        ),
        "harness_note": (
            "PostgreSQL is driven with `docker exec psql` because the Python standard "
            "library has no PostgreSQL client. Those executions are harness-induced "
            "process events, are counted here, and dominate the reported latency."
        ) if harness_execs else (
            "load was driven from the host over loopback with no container exec; each "
            "operation opens its own connection, so setup cost is included"
        ),
    }


# --------------------------------------------------------------------------
# Safe scenarios and ground truth
# --------------------------------------------------------------------------


def _canary_token(run_id: str, trial_id: str, sequence: int) -> str:
    return f"{CANARY}--{run_id}--{trial_id}--{sequence}"


def _scenario_plan(scenario_id: str) -> dict[str, Any]:
    if scenario_id in ATTACK_LIKE_SCENARIOS:
        return {
            "count": 6,
            "delay_seconds": 0.5,
            "expected": "exploratory_attack_like_deviation",
            "attack_like": ATTACK_LIKE_SCENARIOS[scenario_id],
        }
    if scenario_id == "SCN-EXEC":
        return {"count": 6, "delay_seconds": 0.5, "expected": "controlled_positive"}
    if scenario_id == "SCN-LOW":
        return {"count": 6, "delay_seconds": 3.0, "expected": "controlled_positive"}
    if scenario_id == "SCN-FLOOD":
        return {"count": 120, "delay_seconds": 0.0, "expected": "controlled_positive"}
    if scenario_id == "SCN-CONTEXT":
        return {"count": 4, "delay_seconds": 0.5, "expected": "context_shift"}
    raise PilotError(f"{scenario_id} has no runtime action in this runner")


# A fixed, inert command template: it echoes a canary marker and inspects it with a
# read-only text tool that exists in every pinned image. Nothing is written or fetched.
COMMAND_TEMPLATE = "echo {canary} | od -c | head -n 1"
COMMAND_TEMPLATE_SHA256 = sha256_bytes(COMMAND_TEMPLATE.encode("utf-8"))


def run_scenario(
    container: str, container_id: str, image_digest: str, run_id: str, trial_id: str, scenario_id: str
) -> dict[str, Any]:
    plan = _scenario_plan(scenario_id)
    sequences = list(range(1, plan["count"] + 1))
    started_utc, started_ns = now_utc(), time.monotonic_ns()
    executed: list[int] = []
    command_template = plan.get("attack_like", {}).get("command_template", COMMAND_TEMPLATE)
    for sequence in sequences:
        marker = _canary_token(run_id, trial_id, sequence)
        completed = subprocess.run(
            ["docker", "exec", container, "/bin/sh", "-c", command_template.format(canary=marker)],
            capture_output=True,
            timeout=30,
        )
        if completed.returncode == 0:
            executed.append(sequence)
        if plan["delay_seconds"]:
            time.sleep(plan["delay_seconds"])
    finished_utc, finished_ns = now_utc(), time.monotonic_ns()
    result: dict[str, Any] = {
        "schema_version": "porygon.experiment.ground-truth.v1",
        "run_id": run_id,
        "trial_id": trial_id,
        "scenario_id": scenario_id,
        "expected_outcome": plan["expected"],
        "safety_classification": "safe_disposable_local_container",
        "attack_like": bool(plan.get("attack_like")),
        "simulation_only": True,
        "exploit_executed": False,
        "public_network_access": False,
        "host_mutation_attempted": False,
        "privileged_container": False,
        "target_container_name": container,
        "target_container_id": container_id,
        "image_digest": image_digest,
        "action_started_at_utc": started_utc,
        "action_finished_at_utc": finished_utc,
        "action_started_monotonic_ns": started_ns,
        "action_finished_monotonic_ns": finished_ns,
        "canary_sequences_planned": sequences,
        "canary_sequences_executed": executed,
        "command_template": command_template,
        "command_template_sha256": sha256_bytes(command_template.encode("utf-8")),
        "randomized_fields": [],
    }
    if plan.get("attack_like"):
        result["cve"] = plan["attack_like"]
        result["deviation_interpretation"] = (
            "CVSS is vulnerability-severity metadata; this run measures observable process "
            "deviation and must not be interpreted as exploitability or attack probability."
        )
    return result


def run_benign(
    container: str, container_id: str, image_digest: str, run_id: str, trial_id: str
) -> dict[str, Any]:
    """The benign collection path (BENIGN_SENTINEL / "SCN-NONE"): the workload
    runs normally and no scenario action is taken at all -- no exec beyond the
    workload's own load driver, no canary. Ground truth is unambiguous: this
    trial is benign by construction, not by absence of detection."""
    timestamp = now_utc()
    moment_ns = time.monotonic_ns()
    return {
        "schema_version": "porygon.experiment.ground-truth.v1",
        "run_id": run_id,
        "trial_id": trial_id,
        "scenario_id": BENIGN_SENTINEL,
        "expected_outcome": "benign_no_action",
        "safety_classification": "safe_disposable_local_container",
        "attack_like": False,
        "simulation_only": True,
        "exploit_executed": False,
        "public_network_access": False,
        "host_mutation_attempted": False,
        "privileged_container": False,
        "target_container_name": container,
        "target_container_id": container_id,
        "image_digest": image_digest,
        "action_started_at_utc": timestamp,
        "action_finished_at_utc": timestamp,
        "action_started_monotonic_ns": moment_ns,
        "action_finished_monotonic_ns": moment_ns,
        "canary_sequences_planned": [],
        "canary_sequences_executed": [],
        "command_template": None,
        "command_template_sha256": None,
        "randomized_fields": [],
    }


def run_hard_negative(
    container: str, container_id: str, image_digest: str, run_id: str, trial_id: str,
    family: str, hard_negative_id: str, port: int,
) -> dict[str, Any]:
    """Execute one of the protocol's mandatory hard-negative operations
    (HARD_NEGATIVES[family][hard_negative_id]) and record it as benign ground
    truth. Mirrors run_scenario's record shape but never injects a canary --
    see the module-level safety note in run_trial for why."""
    family_negatives = HARD_NEGATIVES.get(family, {})
    if hard_negative_id not in family_negatives:
        raise PilotError(f"{hard_negative_id!r} is not a declared hard negative for {family}")
    spec = family_negatives[hard_negative_id]
    started_utc, started_ns = now_utc(), time.monotonic_ns()
    if spec.get("driver_only"):
        # A legitimate traffic-volume change, driven entirely from the host
        # load driver: no container exec. The process distribution this hard
        # negative probes is ordinary request handling, not an operator
        # action taken inside the container.
        execution: dict[str, Any] = {
            "kind": "driver_burst",
            "burst": drive_load(container, family, port, "hard_negative_burst", spec.get("burst_operations", 40), seed=0),
        }
    else:
        command = spec["command"]
        completed = subprocess.run(
            ["docker", "exec", container, "/bin/sh", "-c", command],
            capture_output=True,
            timeout=60,
        )
        execution = {
            "kind": "container_exec",
            "command": command,
            "command_sha256": sha256_bytes(command.encode("utf-8")),
            "returncode": completed.returncode,
        }
    finished_utc, finished_ns = now_utc(), time.monotonic_ns()
    return {
        "schema_version": "porygon.experiment.ground-truth.v1",
        "run_id": run_id,
        "trial_id": trial_id,
        "scenario_id": hard_negative_id,
        "hard_negative_id": hard_negative_id,
        "expected_outcome": spec["expected_outcome"],
        "description": spec["description"],
        "safety_classification": "safe_disposable_local_container",
        "attack_like": False,
        "simulation_only": True,
        "exploit_executed": False,
        "public_network_access": False,
        "host_mutation_attempted": False,
        "privileged_container": False,
        "target_container_name": container,
        "target_container_id": container_id,
        "image_digest": image_digest,
        "action_started_at_utc": started_utc,
        "action_finished_at_utc": finished_utc,
        "action_started_monotonic_ns": started_ns,
        "action_finished_monotonic_ns": finished_ns,
        "canary_sequences_planned": [],
        "canary_sequences_executed": [],
        "execution": execution,
        "randomized_fields": [],
    }


# --------------------------------------------------------------------------
# Boundary reconciliation against the live pipeline
# --------------------------------------------------------------------------


def _falco_observed(run_id: str, trial_id: str) -> dict[str, Any]:
    prefix = f"{CANARY}--{run_id}--{trial_id}--"
    completed = subprocess.run(
        # `[0-9][0-9]*` requires at least one digit: `[0-9]*` also matches the bare prefix,
        # which would then parse as an empty sequence number.
        ["docker", "exec", TELEMETRY_CONTAINER, "sh", "-c",
         f"grep -o '{prefix}[0-9][0-9]*' {FALCO_EVENT_PATH} | sort -u || true"],
        capture_output=True, text=True, timeout=300,
    )
    if completed.returncode != 0:
        return {"status": "unmeasured", "reason": "the Falco event file could not be read"}
    sequences = sorted(
        int(match.group(1))
        for match in (re.fullmatch(re.escape(prefix) + r"(\d+)", line.strip())
                      for line in completed.stdout.splitlines() if line.strip())
        if match
    )
    return {"status": "measured", "sequences": sequences}


def _database_observed(base_url: str, container_id: str, run_id: str, trial_id: str) -> dict[str, Any]:
    prefix = f"{CANARY}--{run_id}--{trial_id}--"
    pattern = re.compile(re.escape(prefix) + r"(\d+)")
    sequences: set[int] = set()
    duplicates = 0
    seen_events: set[str] = set()
    before: int | None = None
    for _ in range(50):  # bounded paging; 50 * 500 events is far beyond any pilot trial
        url = f"{base_url}/api/v1/process-events?container_id={container_id}&limit=500"
        if before is not None:
            url += f"&before_time_nano={before}"
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                page = json.loads(response.read())
        except (OSError, json.JSONDecodeError) as error:
            return {"status": "unmeasured", "reason": f"backend query failed: {error}"}
        if not page:
            break
        for event in page:
            match = pattern.search(event.get("command_line") or "")
            if match:
                sequence = int(match.group(1))
                if event["event_id"] in seen_events:
                    continue
                seen_events.add(event["event_id"])
                if sequence in sequences:
                    duplicates += 1
                sequences.add(sequence)
        before = min(event["time_nano"] for event in page)
        if len(page) < 500:
            break
    return {"status": "measured", "sequences": sorted(sequences), "duplicates": duplicates}


def reconcile_trial(
    base_url: str, container_id: str, run_id: str, trial_id: str, generated: list[int]
) -> dict[str, Any]:
    """Reconcile canaries across every boundary this deployment can actually observe."""
    expected = set(generated)
    falco = _falco_observed(run_id, trial_id)
    database = _database_observed(base_url, container_id, run_id, trial_id)
    boundaries: dict[str, Any] = {
        "generator": {
            "status": "measured",
            "observed": len(expected),
            "missing_sequences": [],
            "duplicates": 0,
            "loss_fraction": 0.0,
        },
        "spool": {
            "status": "unmeasured",
            "reason": (
                "the telemetry spool exposes process-local counters that cannot be attributed "
                "to an individual canary sequence; missing telemetry is not treated as zero loss"
            ),
        },
        "api": {
            "status": "unmeasured",
            "reason": (
                "API receipt is not separately observable from outside the backend; database "
                "persistence below is the authoritative downstream boundary"
            ),
        },
    }
    for name, result in (("source", falco), ("database", database)):
        if result["status"] != "measured":
            boundaries[name] = result
            continue
        observed = set(result["sequences"])
        missing = sorted(expected - observed)
        boundaries[name] = {
            "status": "measured",
            "observed": len(observed),
            "missing_sequences": missing,
            "unexpected_sequences": sorted(observed - expected),
            "duplicates": result.get("duplicates", 0),
            "loss_fraction": (len(missing) / len(expected)) if expected else None,
        }
    return {"generated": len(expected), "generated_sequences": sorted(expected), "boundaries": boundaries}


def _no_canary_reconciliation(reason: str) -> dict[str, Any]:
    """The reconciliation record for a trial that generated no canary at all
    (benign / hard-negative). Every boundary is explicitly "unmeasured" with
    `reason` -- the same not-measured shape reconcile_trial already uses for
    the spool/api boundaries it can never observe -- rather than a fabricated
    "0 expected, 0 missing, 0.0 loss_fraction" pass. That distinction matters:
    a boundary never exercised must never read the same as a boundary that
    was exercised and found perfect, or a true capture-loss regression on a
    boundary this run never tests could hide behind trials that all report
    it."""
    boundary = {"status": "unmeasured", "reason": reason}
    return {
        "generated": 0,
        "generated_sequences": [],
        "boundaries": {
            "generator": dict(boundary),
            "spool": dict(boundary),
            "api": dict(boundary),
            "source": dict(boundary),
            "database": dict(boundary),
        },
    }


# --------------------------------------------------------------------------
# Trial and run orchestration
# --------------------------------------------------------------------------


_UNSAFE_TRIAL_ID_CHARS = re.compile(r"[^a-z0-9_.-]+")


def _docker_safe_token(value: str) -> str:
    """Collapse anything outside Docker's container-name charset
    (`[a-zA-Z0-9][a-zA-Z0-9_.-]+`) to a single '-'.

    Every existing scenario/mode/variant identifier (SCN-EXEC, steady_http,
    dropped_capabilities, ...) is already alnum/underscore/dash, so this is a
    byte-for-byte no-op for them -- it only changes output for the new
    hard-negative IDs pulled verbatim from the protocol table, which can
    contain backticks, spaces, and slashes (e.g. "`BGSAVE`", "traffic
    spike/log rotation") that a `docker run --name` would otherwise reject.
    """
    token = _UNSAFE_TRIAL_ID_CHARS.sub("-", value.lower()).strip("-")
    return token or "x"


def trial_id_for(workload_id: str, mode: str, scenario_id: str, variant: str, replica: int) -> str:
    parts = [_docker_safe_token(part) for part in (workload_id, mode, scenario_id, variant)]
    return "-".join(parts) + f"-r{replica:02d}"


def container_name_for(run_id: str, trial_id: str) -> str:
    """Container names are capped at 63 characters, so a plain truncation could collide.

    Long names keep a deterministic hash of the full name instead.
    """
    name = f"porygon-exp-{run_id}-{trial_id}"
    if len(name) <= 63:
        return name
    return name[:52] + "-" + sha256_bytes(name.encode("utf-8"))[:10]


def start_container(
    name: str, network: str, run_id: str, trial_id: str, image: dict[str, Any],
    family: str, variant: str,
) -> str:
    spec = FAMILY_SPECS[family]
    args = [
        "run", "--detach", "--name", name,
        "--label", f"{LABEL_RUN}={run_id}",
        "--label", f"{LABEL_TRIAL}={trial_id}",
        "--network", network,
        "--publish", f"127.0.0.1::{spec['container_port']}",
        "--memory", "512m", "--pids-limit", "512",
    ]
    for key, value in spec["env"].items():
        args += ["--env", f"{key}={value}"]
    if not variant_available(variant, family):
        raise PilotError(f"context variant {variant} is not available for {family}")
    args += CONTEXT_VARIANTS[variant][family]
    args.append(image["reference"])
    args += VARIANT_COMMAND.get(variant, {}).get(family, [])
    return docker(*args, timeout=180)


def run_trial(
    *, run_id: str, trial_id: str, workload_id: str, mode: str, scenario_id: str,
    variant: str, replica: int, image: dict[str, Any], network: str, base_url: str,
    seed: int, warmup_seconds: float, operations: int, settle_seconds: float,
) -> dict[str, Any]:
    family = family_of(workload_id)
    name = container_name_for(run_id, trial_id)
    hard_negative_id = scenario_id if scenario_id in HARD_NEGATIVES.get(family, {}) else None
    record: dict[str, Any] = {
        "schema_version": "porygon.experiment.trial.v2",
        "run_id": run_id,
        "trial_id": trial_id,
        "workload_id": workload_id,
        "workload_family": family,
        "human_tag": image["human_tag"],
        "image": image,
        "mode": mode,
        "scenario_id": scenario_id,
        # CONF-HN-001 (experiments/conformance.py) reads this exact top-level
        # field; None for every ordinary/benign-sentinel/scenario trial, and
        # the protocol's own hard-negative wording for a hard-negative trial.
        "hard_negative_id": hard_negative_id,
        "context_variant": variant,
        "context_variant_kind": CONTEXT_VARIANT_KIND.get(variant, "unclassified"),
        "replica_index": replica,
        "seed": seed,
        "container_name": name,
        "split": "pilot",
        "research_eligible": False,
        "eligibility_reason": (
            "pilot evidence: the research protocol is review-pending, so this trial may inform "
            "engineering and variance estimates but may never be reported as confirmatory"
        ),
        "timeline": {"setup_started_at_utc": now_utc(), "setup_started_monotonic_ns": time.monotonic_ns()},
    }
    started = False
    try:
        container_ref = start_container(name, network, run_id, trial_id, image, family, variant)
        started = True
        record["container_id"] = container_ref[:12]
        inspection = json.loads(docker("inspect", name))[0]
        context_document = runtime_context(inspection)
        record["runtime_context"] = context_document
        record["runtime_context_hash"] = context_hash(context_document)
        record["runtime_context_source_hash"] = sha256_bytes(
            json.dumps(inspection, sort_keys=True).encode("utf-8")
        )
        port = _published_port(name, FAMILY_SPECS[family]["container_port"])
        record["timeline"]["ready_started_at_utc"] = now_utc()
        record["readiness"] = wait_ready(name, family, port)

        record["timeline"]["warmup_started_at_utc"] = now_utc()
        time.sleep(warmup_seconds)

        record["timeline"]["measurement_started_at_utc"] = now_utc()
        measurement_started_ns = time.monotonic_ns()
        record["load"] = drive_load(name, family, port, mode, operations, seed)
        record["timeline"]["measurement_finished_at_utc"] = now_utc()
        record["measurement_duration_ns"] = time.monotonic_ns() - measurement_started_ns

        if scenario_id == BENIGN_SENTINEL:
            record["ground_truth"] = run_benign(
                name, record["container_id"], image["reference"], run_id, trial_id
            )
        elif hard_negative_id is not None:
            record["ground_truth"] = run_hard_negative(
                name, record["container_id"], image["reference"], run_id, trial_id,
                family, hard_negative_id, port,
            )
        else:
            record["ground_truth"] = run_scenario(
                name, record["container_id"], image["reference"], run_id, trial_id, scenario_id
            )
        record["timeline"]["settle_started_at_utc"] = now_utc()
        time.sleep(settle_seconds)
        if scenario_id == BENIGN_SENTINEL:
            record["reconciliation"] = _no_canary_reconciliation(
                "benign trial (SCN-NONE): no scenario action was taken and no canary was "
                "injected, so every boundary is not applicable rather than a fabricated "
                "zero-loss measurement"
            )
        elif hard_negative_id is not None:
            record["reconciliation"] = _no_canary_reconciliation(
                f"hard-negative trial ({hard_negative_id!r}): no canary was injected by design "
                "-- synthesizing one would contaminate the exact benign process distribution "
                "this hard negative measures the false-positive rate against, so every boundary "
                "is not applicable rather than a fabricated pass"
            )
        else:
            record["reconciliation"] = reconcile_trial(
                base_url, record["container_id"], run_id, trial_id,
                record["ground_truth"]["canary_sequences_executed"],
            )
        record["status"] = "completed"
    except (PilotError, OSError, subprocess.SubprocessError, ValueError) as error:
        record["status"] = "failed"
        record["failure_reason"] = f"{type(error).__name__}: {error}"
    finally:
        record["timeline"]["teardown_started_at_utc"] = now_utc()
        if started:
            try:
                record["cleanup"] = remove_container(name, run_id, trial_id)
            except PilotError as error:
                record["cleanup"] = {"removed": False, "reason": str(error)}
                record["status"] = "failed"
                record.setdefault("failure_reason", f"cleanup refused: {error}")
        else:
            record["cleanup"] = {"removed": False, "reason": "container was never created"}
        record["timeline"]["cleanup_finished_at_utc"] = now_utc()
    return record


def protocol_status(protocol: Path) -> str:
    for line in protocol.read_text(encoding="utf-8").splitlines():
        if line.startswith("Status:"):
            if "**FROZEN" in line:
                return "frozen"
            return "review_pending"
    return "unknown"


def percentile(samples: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile over raw samples. Never derived from an average."""
    if not samples:
        return None
    ordered = sorted(samples)
    # Nearest-rank: rank = ceil(fraction * N), converted to a 0-based index.
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return round(ordered[index], 4)


def default_mode(family: str) -> str:
    return {"WL-NGX": "steady_http", "WL-RDS": "steady_set_get", "WL-PG": "read_only_queries"}[family]


def build_matrix(
    workloads: list[str], modes: list[str] | None, scenarios: list[str],
    variants: list[str], replicas: int,
) -> list[dict[str, Any]]:
    matrix = []
    for workload_id in workloads:
        family = family_of(workload_id)
        if family not in FAMILY_SPECS:
            raise PilotError(f"unknown workload family for {workload_id}")
        for mode in modes or [default_mode(family)]:
            if mode not in FAMILY_SPECS[family]["modes"]:
                raise PilotError(f"{mode} is not a frozen mode for {family}")
            for scenario_id in scenarios:
                if scenario_id in ANALYSIS_ONLY_SCENARIOS:
                    raise PilotError(
                        f"{scenario_id} has no runtime action; it is evaluated at analysis time "
                        "from trials that were already collected"
                    )
                is_benign_or_hard_negative = (
                    scenario_id == BENIGN_SENTINEL or scenario_id in HARD_NEGATIVES.get(family, {})
                )
                if (
                    not is_benign_or_hard_negative
                    and scenario_id not in RUNTIME_SCENARIOS
                    and scenario_id not in ATTACK_LIKE_SCENARIOS
                ):
                    raise PilotError(f"{scenario_id} is not a frozen scenario")
                for variant in variants:
                    if variant not in CONTEXT_VARIANTS:
                        raise PilotError(f"{variant} is not a declared context variant")
                    if not variant_available(variant, family):
                        raise PilotError(
                            f"context variant {variant} is not validated for {family}; "
                            f"available here: {sorted(v for v in CONTEXT_VARIANTS if variant_available(v, family))}"
                        )
                    for replica in range(1, replicas + 1):
                        matrix.append(
                            {
                                "workload_id": workload_id,
                                "mode": mode,
                                "scenario_id": scenario_id,
                                "variant": variant,
                                "replica": replica,
                                "trial_id": trial_id_for(workload_id, mode, scenario_id, variant, replica),
                            }
                        )
    return matrix
