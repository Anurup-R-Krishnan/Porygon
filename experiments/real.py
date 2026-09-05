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

# Context variants keep the image digest fixed and change one security-relevant field,
# which is exactly what SCN-CONTEXT and the digest-plus-context arm need.
CONTEXT_VARIANTS: dict[str, list[str]] = {
    "baseline": [],
    # NET_RAW and a scratch tmpfs are security-relevant and supported by all three pinned
    # images, so a divergent profile is attributable to context rather than to a broken
    # workload. `--cap-drop ALL` and `--read-only` break these images at startup and are
    # kept available for a deliberate negative-control trial only.
    "dropped_capabilities": ["--cap-drop", "NET_RAW"],
    "tmpfs_scratch": ["--tmpfs", "/scratch"],
    "read_only_rootfs": ["--read-only", "--tmpfs", "/tmp"],
    "all_capabilities_dropped": ["--cap-drop", "ALL"],
}

RUNTIME_SCENARIOS = ("SCN-EXEC", "SCN-LOW", "SCN-FLOOD", "SCN-CONTEXT")
ANALYSIS_ONLY_SCENARIOS = ("SCN-CROSS", "SCN-POISON")


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
    return {
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
    for sequence in sequences:
        marker = _canary_token(run_id, trial_id, sequence)
        completed = subprocess.run(
            ["docker", "exec", container, "/bin/sh", "-c", COMMAND_TEMPLATE.format(canary=marker)],
            capture_output=True,
            timeout=30,
        )
        if completed.returncode == 0:
            executed.append(sequence)
        if plan["delay_seconds"]:
            time.sleep(plan["delay_seconds"])
    finished_utc, finished_ns = now_utc(), time.monotonic_ns()
    return {
        "schema_version": "porygon.experiment.ground-truth.v1",
        "run_id": run_id,
        "trial_id": trial_id,
        "scenario_id": scenario_id,
        "expected_outcome": plan["expected"],
        "safety_classification": "safe_disposable_local_container",
        "target_container_name": container,
        "target_container_id": container_id,
        "image_digest": image_digest,
        "action_started_at_utc": started_utc,
        "action_finished_at_utc": finished_utc,
        "action_started_monotonic_ns": started_ns,
        "action_finished_monotonic_ns": finished_ns,
        "canary_sequences_planned": sequences,
        "canary_sequences_executed": executed,
        "command_template": COMMAND_TEMPLATE,
        "command_template_sha256": COMMAND_TEMPLATE_SHA256,
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


# --------------------------------------------------------------------------
# Trial and run orchestration
# --------------------------------------------------------------------------


def trial_id_for(workload_id: str, mode: str, scenario_id: str, variant: str, replica: int) -> str:
    return f"{workload_id}-{mode}-{scenario_id}-{variant}-r{replica:02d}".lower()


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
    args += CONTEXT_VARIANTS[variant]
    args.append(image["reference"])
    return docker(*args, timeout=180)


def run_trial(
    *, run_id: str, trial_id: str, workload_id: str, mode: str, scenario_id: str,
    variant: str, replica: int, image: dict[str, Any], network: str, base_url: str,
    seed: int, warmup_seconds: float, operations: int, settle_seconds: float,
) -> dict[str, Any]:
    family = family_of(workload_id)
    name = container_name_for(run_id, trial_id)
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
        "context_variant": variant,
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

        record["ground_truth"] = run_scenario(
            name, record["container_id"], image["reference"], run_id, trial_id, scenario_id
        )
        record["timeline"]["settle_started_at_utc"] = now_utc()
        time.sleep(settle_seconds)
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
                if scenario_id not in RUNTIME_SCENARIOS:
                    raise PilotError(f"{scenario_id} is not a frozen scenario")
                for variant in variants:
                    if variant not in CONTEXT_VARIANTS:
                        raise PilotError(f"{variant} is not a declared context variant")
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
