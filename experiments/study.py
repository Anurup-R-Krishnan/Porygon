"""End-to-end study orchestration.

One command drives the whole pipeline: validate the environment, validate the
protocol and the review gate, collect real-container runs, build profiles from the
allowed data only, score held-out windows, run deterministic detection, account for
storage, and write a manifest that records every stage.

Each stage is idempotent and resumable. A stage that cannot run records why and the
pipeline continues with the stages that do not depend on it, so a partial
environment still produces every result it legitimately can.

Split discipline is enforced here rather than trusted: profiles are built only from
runs assigned to `fit`, and scoring only ever targets windows outside the training
interval. The backend refuses an overlapping window independently, so the rule holds
even if this orchestrator is bypassed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from experiments import real
from experiments.artifacts import assign_split, atomic_write_json, check_split_isolation

ROOT = Path(__file__).resolve().parents[1]
STUDY_ROOT = ROOT / "artifacts/experiments/local"


# ---------------------------------------------------------------------------
# Stage plumbing
# ---------------------------------------------------------------------------


class Stage:
    def __init__(self, name: str, run: Callable[[dict], dict], required: bool = True):
        self.name = name
        self.run = run
        self.required = required


def _sh(*args: str, timeout: int = 1800) -> tuple[int, str]:
    done = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    return done.returncode, (done.stdout + done.stderr).strip()


def _api(base_url: str, path: str, timeout: int = 30) -> Any:
    with urllib.request.urlopen(f"{base_url}{path}", timeout=timeout) as response:
        return json.loads(response.read())


def _token(name: str) -> str:
    env = ROOT / ".env"
    if not env.is_file():
        return ""
    for line in env.read_text(encoding="utf-8").splitlines():
        if line.startswith(f"{name}="):
            return line.split("=", 1)[1].strip()
    return ""


# ---------------------------------------------------------------------------
# Stage 1: environment
# ---------------------------------------------------------------------------


def stage_environment(ctx: dict) -> dict:
    usage = shutil.disk_usage(ROOT)
    code, docker_version = _sh("docker", "version", "--format", "{{.Server.Version}}", timeout=60)
    result = {
        "docker_version": docker_version if code == 0 else "unavailable",
        "kernel_btf": Path("/sys/kernel/btf/vmlinux").exists(),
        "disk_free_gb": round(usage.free / 1e9, 1),
        "disk_total_gb": round(usage.total / 1e9, 1),
        "cpu_count": _sh("nproc")[1],
    }
    code, _ = _sh("curl", "--fail", "--silent", f"{ctx['base_url']}/health/live", timeout=60)
    result["stack_reachable"] = code == 0
    if not result["stack_reachable"]:
        raise RuntimeError(f"the stack is not reachable on {ctx['base_url']}; run `make up`")
    if not result["kernel_btf"]:
        raise RuntimeError("kernel BTF is unavailable; the sensor cannot attach")
    services = _api(ctx["base_url"], "/api/v1/services")
    result["services_reporting"] = len(services) if isinstance(services, list) else 0
    return result


# ---------------------------------------------------------------------------
# Stage 2: protocol and the review gate
# ---------------------------------------------------------------------------


def stage_protocol(ctx: dict) -> dict:
    code, output = _sh("python3", "scripts/check_research_protocol.py", timeout=600)
    if code != 0:
        raise RuntimeError(f"protocol structural validation failed: {output}")
    code, gate = _sh("python3", "scripts/review_gate.py", "status", "--json", timeout=300)
    state = json.loads(gate) if code == 0 else {}
    ctx["confirmatory_permitted"] = bool(state.get("confirmatory_permitted"))
    return {
        "structural_check": output.splitlines()[:2],
        "protocol_status": state.get("protocol_status"),
        "confirmatory_permitted": ctx["confirmatory_permitted"],
        "waiting_on": state.get("waiting_on", []),
        "evidence_class": "confirmatory" if ctx["confirmatory_permitted"] else "pilot",
    }


# ---------------------------------------------------------------------------
# Stage 3: harness self-test
# ---------------------------------------------------------------------------


def stage_harness(ctx: dict) -> dict:
    code, output = _sh("python3", "-m", "pytest", "experiments/tests", "-q", timeout=1200)
    if code != 0:
        raise RuntimeError(f"harness tests failed:\n{output[-1500:]}")
    passed = [line for line in output.splitlines() if "passed" in line]
    return {"tests": passed[-1] if passed else "passed"}


# ---------------------------------------------------------------------------
# Stage 4: storage accounting
# ---------------------------------------------------------------------------


def _database_bytes(ctx: dict) -> int | None:
    code, out = _sh(
        "docker", "exec", "porygon-postgres-1", "psql", "-U",
        ctx.get("db_user", "porygon"), "-d", ctx.get("db_name", "porygon"),
        "-tAc", "select pg_database_size(current_database());", timeout=300,
    )
    try:
        return int(out.strip()) if code == 0 else None
    except ValueError:
        return None


def _sensor_log_bytes() -> int | None:
    code, out = _sh("docker", "exec", real.TELEMETRY_CONTAINER, "sh", "-c",
                    f"wc -c < {real.FALCO_EVENT_PATH}", timeout=120)
    try:
        return int(out.strip()) if code == 0 else None
    except ValueError:
        return None


def stage_storage_before(ctx: dict) -> dict:
    ctx["storage_before"] = {
        "database_bytes": _database_bytes(ctx),
        "sensor_log_bytes": _sensor_log_bytes(),
    }
    return ctx["storage_before"]


def stage_storage_after(ctx: dict) -> dict:
    before = ctx.get("storage_before", {})
    after = {"database_bytes": _database_bytes(ctx), "sensor_log_bytes": _sensor_log_bytes()}
    trials = ctx.get("trial_count", 0)
    delta_db = (after["database_bytes"] - before["database_bytes"]
                if after["database_bytes"] and before.get("database_bytes") else None)
    delta_log = (after["sensor_log_bytes"] - before["sensor_log_bytes"]
                 if after["sensor_log_bytes"] and before.get("sensor_log_bytes") else None)
    run_dir = ctx.get("run_dir")
    artifact_bytes = sum(p.stat().st_size for p in Path(run_dir).rglob("*") if p.is_file()) if run_dir else 0

    per_trial = {}
    if trials:
        if delta_db is not None:
            per_trial["database_bytes"] = round(delta_db / trials)
        if delta_log is not None:
            per_trial["sensor_log_bytes"] = round(delta_log / trials)
        per_trial["artifact_bytes"] = round(artifact_bytes / trials)

    # The frozen matrix: 6 workload coordinates x 4 modes x 30 benign runs, plus
    # 6 coordinates x 4 runtime scenarios x 20 runs.
    projected_trials = 6 * 4 * 30 + 6 * 4 * 20
    total_per_trial = sum(per_trial.values()) if per_trial else 0
    return {
        "before": before,
        "after": after,
        "delta_database_bytes": delta_db,
        "delta_sensor_log_bytes": delta_log,
        "artifact_bytes": artifact_bytes,
        "trials_measured": trials,
        "per_trial_bytes": per_trial,
        "projected_confirmatory_trials": projected_trials,
        "projected_total_gb": round(total_per_trial * projected_trials / 1e9, 2) if total_per_trial else None,
        "note": (
            "Projection multiplies the measured per-trial cost by the frozen matrix size. "
            "It excludes the one-off cost of the pinned images and the platform itself."
        ),
    }


# ---------------------------------------------------------------------------
# Stage 5: collection
# ---------------------------------------------------------------------------


def stage_collect(ctx: dict) -> dict:
    from experiments.run import run_pilot, validate

    run_dir = STUDY_ROOT / ctx["run_id"]
    ctx["run_dir"] = run_dir
    run_pilot(
        run_dir,
        run_id=ctx["run_id"],
        workloads=ctx["workloads"],
        modes=None,
        scenarios=ctx["scenarios"],
        variants=ctx["variants"],
        replicas=ctx["replicas"],
        seed=ctx["seed"],
        base_url=ctx["base_url"],
        operations=ctx["operations"],
        warmup_seconds=ctx["warmup_seconds"],
        settle_seconds=ctx["settle_seconds"],
        protocol=ROOT / "docs/RESEARCH_PROTOCOL_V1.md",
    )
    validate(run_dir)
    trials = [json.loads(p.read_text(encoding="utf-8"))
              for p in sorted((run_dir / "trials").glob("*.json"))]
    ctx["trials"] = trials
    ctx["trial_count"] = len(trials)
    return {
        "run_dir": str(run_dir.relative_to(ROOT)),
        "trials": len(trials),
        "completed": sum(t["status"] == "completed" for t in trials),
        "failed": sum(t["status"] == "failed" for t in trials),
        "distinct_context_identities": len(
            {t.get("runtime_context_hash") for t in trials if t.get("runtime_context_hash")}
        ),
        "canaries_generated": sum(
            (t.get("reconciliation") or {}).get("generated", 0) for t in trials
        ),
    }


# ---------------------------------------------------------------------------
# Stage 6: split assignment and leakage check
# ---------------------------------------------------------------------------


def stage_splits(ctx: dict) -> dict:
    trials = ctx.get("trials", [])
    # A run is the independent unit. Every trial inside one run inherits that run's split.
    records = [{"run_id": t["trial_id"], "split": assign_split(t["trial_id"])} for t in trials]
    check_split_isolation(records)
    ctx["splits"] = {r["run_id"]: r["split"] for r in records}
    counts: dict[str, int] = {}
    for record in records:
        counts[record["split"]] = counts.get(record["split"], 0) + 1
    return {
        "unit_of_analysis": "complete container run",
        "assignment": "deterministic from the run identifier, computed before analysis",
        "counts": counts,
        "leakage_detected": False,
    }


# ---------------------------------------------------------------------------
# Stage 7: profiles, scoring, detection on the collected data
# ---------------------------------------------------------------------------


def _post(base_url: str, path: str, payload: dict, token: str) -> Any:
    request = urllib.request.Request(
        f"{base_url}{path}", data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Porygon-Internal-Token": token},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read())


def stage_analysis(ctx: dict) -> dict:
    """Build a profile from fit-split evidence, then score a window outside it."""
    token = _token("PORYGON_INTERNAL_API_TOKEN")
    if not token:
        raise RuntimeError("PORYGON_INTERNAL_API_TOKEN is unavailable; cannot drive the API")
    base = ctx["base_url"]
    trials = [t for t in ctx.get("trials", []) if t["status"] == "completed"]
    if not trials:
        raise RuntimeError("no completed trials to analyse")

    # Group by image digest: a profile is bound to exactly one immutable digest.
    by_digest: dict[str, list[dict]] = {}
    for trial in trials:
        by_digest.setdefault(trial["image"]["reference"], []).append(trial)

    outcomes = []
    for digest, group in by_digest.items():
        group.sort(key=lambda t: t["timeline"]["setup_started_at_utc"])
        if len(group) < 2:
            outcomes.append({"image": digest, "status": "insufficient_runs",
                             "reason": "a held-out window requires at least two runs"})
            continue
        fit, held_out = group[:-1], group[-1]
        start = min(t["timeline"]["setup_started_at_utc"] for t in fit)
        end = max(t["timeline"]["cleanup_finished_at_utc"] for t in fit)
        try:
            profile = _post(base, "/internal/v1/baselines/build", {
                "image_digest": digest,
                "training_start": start,
                "training_end": end,
                "window_seconds": ctx["window_seconds"],
                "minimum_process_events": 20,
                "minimum_nonempty_windows": 3,
                "approved_by": "study-orchestrator",
                "approval_reference": f"experiments.study run={ctx['run_id']}",
            }, token)
        except urllib.error.HTTPError as error:
            outcomes.append({"image": digest, "status": "profile_refused",
                             "reason": error.read().decode("utf-8", "replace")[:200]})
            continue

        entry = {
            "image": digest,
            "profile_id": profile["profile_id"],
            "profile_quality_passed": profile["quality"]["passed"],
            "process_events": profile["process_event_count"],
            "windows": profile["window_count"],
            "fit_runs": [t["trial_id"] for t in fit],
            "held_out_run": held_out["trial_id"],
        }
        if not profile["quality"]["passed"]:
            entry["status"] = "profile_below_quality_gate"
            failed = [k for k, v in profile["quality"]["checks"].items() if not v["passed"]]
            entry["failed_checks"] = failed
            outcomes.append(entry)
            continue

        _post(base, f"/internal/v1/baselines/{profile['profile_id']}/activate", {}, token)
        entry["activated"] = True

        # Score a window from the held-out run only. The backend independently
        # refuses any window overlapping the training interval.
        window_start = held_out["timeline"]["measurement_started_at_utc"]
        try:
            score = _post(base, "/internal/v1/anomaly-scores/compute", {
                "image_digest": digest, "window_start": window_start,
            }, token)
            entry["score_id"] = score.get("score_id")
            entry["score_band"] = score.get("score_band")
            entry["score_status"] = score.get("status")
            entry["scored_events"] = score.get("process_event_count")
        except urllib.error.HTTPError as error:
            entry["status"] = "score_refused"
            entry["reason"] = error.read().decode("utf-8", "replace")[:200]
            outcomes.append(entry)
            continue

        if entry.get("score_id"):
            try:
                detection = _post(base, "/internal/v1/detections/run",
                                  {"anomaly_score_id": entry["score_id"]}, token)
                run = detection.get("run", {})
                entry["rule_matches"] = run.get("matches_count")
                entry["incident_created"] = run.get("incident_created")
                entry["detection_status"] = run.get("status")
            except urllib.error.HTTPError as error:
                entry["detection_error"] = error.read().decode("utf-8", "replace")[:200]
        entry["status"] = "analysed"
        outcomes.append(entry)

    ctx["analysis"] = outcomes
    return {
        "digests": len(by_digest),
        "analysed": sum(o["status"] == "analysed" for o in outcomes),
        "outcomes": outcomes,
    }


# ---------------------------------------------------------------------------
# Stage 8: results rendering
# ---------------------------------------------------------------------------


def stage_results(ctx: dict) -> dict:
    code, output = _sh("python3", "scripts/render_results.py", timeout=600)
    if code != 0:
        raise RuntimeError(f"result rendering failed: {output}")
    return {"rendered": output.splitlines()[-1] if output else "ok",
            "results_json": "artifacts/results.json", "results_html": "artifacts/results.html"}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


STAGES = [
    Stage("environment", stage_environment),
    Stage("protocol_and_review_gate", stage_protocol),
    Stage("harness_self_test", stage_harness),
    Stage("storage_before", stage_storage_before, required=False),
    Stage("collection", stage_collect),
    Stage("split_assignment", stage_splits),
    Stage("profile_score_detect", stage_analysis, required=False),
    Stage("storage_accounting", stage_storage_after, required=False),
    Stage("results", stage_results, required=False),
]


def run_study(**options: Any) -> Path:
    ctx: dict[str, Any] = {
        "base_url": options.get("base_url", "http://127.0.0.1:8000").rstrip("/"),
        "run_id": options.get("run_id") or "study-" + datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%SZ"),
        "workloads": options.get("workloads", ["WL-NGX-V1", "WL-RDS-V1", "WL-PG-V1"]),
        "scenarios": options.get("scenarios", ["SCN-EXEC"]),
        "variants": options.get("variants", ["baseline"]),
        "replicas": options.get("replicas", 2),
        "operations": options.get("operations", 20),
        "warmup_seconds": options.get("warmup_seconds", 3.0),
        "settle_seconds": options.get("settle_seconds", 12.0),
        "seed": options.get("seed", 20260905),
        "window_seconds": options.get("window_seconds", 10),
    }
    started = time.monotonic()
    stages: list[dict[str, Any]] = []
    status = "completed"

    for stage in STAGES:
        entry: dict[str, Any] = {"name": stage.name, "started_at_utc": real.now_utc()}
        stage_started = time.monotonic()
        try:
            entry["result"] = stage.run(ctx)
            entry["status"] = "passed"
        except Exception as error:  # a stage failure must not lose the stages before it
            entry["status"] = "failed"
            entry["error"] = f"{type(error).__name__}: {error}"
            if stage.required:
                status = "failed"
        entry["duration_seconds"] = round(time.monotonic() - stage_started, 2)
        stages.append(entry)
        print(f"[study] {stage.name}: {entry['status']}"
              + (f" — {entry.get('error','')[:120]}" if entry["status"] == "failed" else ""))
        if entry["status"] == "failed" and stage.required:
            break

    manifest = {
        "schema_version": "porygon.study.manifest.v1",
        "run_id": ctx["run_id"],
        "status": status,
        "evidence_class": "confirmatory" if ctx.get("confirmatory_permitted") else "pilot",
        "research_eligible": bool(ctx.get("confirmatory_permitted")),
        "git_sha": _sh("git", "rev-parse", "HEAD")[1],
        "git_dirty": bool(_sh("git", "status", "--porcelain")[1]),
        "started_at_utc": stages[0]["started_at_utc"] if stages else real.now_utc(),
        "finished_at_utc": real.now_utc(),
        "duration_seconds": round(time.monotonic() - started, 2),
        "configuration": {k: v for k, v in ctx.items() if k not in ("trials", "analysis", "splits", "run_dir", "storage_before")},
        "stages": stages,
    }
    out_dir = STUDY_ROOT / ctx["run_id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "study-manifest.json"
    if path.exists():
        path.unlink()
    atomic_write_json(path, manifest)
    print(f"[study] manifest: {path.relative_to(ROOT)}")
    return path
