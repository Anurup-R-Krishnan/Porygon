from __future__ import annotations

import argparse
import csv
import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiments import real
from experiments.artifacts import (
    ArtifactError,
    atomic_write_json,
    atomic_write_bytes,
    canonical_json,
    reconcile_boundaries,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_ID = "porygon.research.protocol.v1"
BOUNDARIES = ["generator", "source", "spool", "api", "database"]


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _git_dirty() -> bool:
    try:
        return bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    except (OSError, subprocess.CalledProcessError):
        return True


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = "".join(canonical_json(row) + "\n" for row in rows).encode("utf-8")
    return atomic_write_bytes(path, encoded)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _smoke_trial(run_id: str, index: int, scenario: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    trial_id = f"smoke-{index:03d}"
    events: list[dict[str, Any]] = []
    for sequence in range(1, 13):
        observed = list(BOUNDARIES)
        if index == 1 and sequence in (3, 9):
            observed.remove("source")
        events.append(
            {
                "run_id": run_id,
                "trial_id": trial_id,
                "sequence": sequence,
                "scenario": scenario,
                "observed_at": observed,
                "occurred_ns": 1_000_000_000 * sequence,
                "persisted_ns": 1_000_000_000 * sequence + 2_000_000 + index * 100_000,
            }
        )
    trial = {
        "schema_version": "porygon.experiment.trial.v1",
        "run_id": run_id,
        "trial_id": trial_id,
        "workload_id": "WL-NGX-V1",
        "scenario_id": scenario,
        "split": "smoke_fixture",
        "research_eligible": False,
        "image_digest": "nginx@sha256:" + "0" * 64,
        "seed": 20260821 + index,
        "event_count": len(events),
    }
    return trial, events


def _write_summary(path: Path, trials: list[dict[str, Any]], events: list[dict[str, Any]], reconciliation: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for trial in trials:
        trial_events = [event for event in events if event["trial_id"] == trial["trial_id"]]
        latencies_us = [(event["persisted_ns"] - event["occurred_ns"]) / 1_000 for event in trial_events]
        rows.append(
            {
                "trial_id": trial["trial_id"],
                "scenario_id": trial["scenario_id"],
                "research_eligible": str(trial["research_eligible"]).lower(),
                "event_count": len(trial_events),
                "latency_p50_us": f"{sorted(latencies_us)[len(latencies_us) // 2]:.1f}",
                "source_loss_fraction": reconciliation["boundaries"]["source"]["loss_fraction"],
            }
        )
    fieldnames = list(rows[0])
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return sha256_file(path)


def run_smoke(run_dir: Path, run_id: str = "smoke-fixture") -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    if (run_dir / "artifact-manifest.json").exists():
        validate(run_dir)
        return run_dir
    trials_and_events = [_smoke_trial(run_id, 0, "SCN-LOW"), _smoke_trial(run_id, 1, "SCN-FLOOD")]
    trials = [item[0] for item in trials_and_events]
    events = [event for _, trial_events in trials_and_events for event in trial_events]
    metadata = {
        "schema_version": "porygon.experiment.run.v1",
        "run_id": run_id,
        "kind": "smoke_fixture",
        "research_eligible": False,
        "protocol_id": PROTOCOL_ID,
        "protocol_status_at_creation": "review_pending",
        "git_sha": _git_sha(),
        "git_dirty": _git_dirty(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "monotonic_origin_ns": time.monotonic_ns(),
        "seed": 20260821,
        "boundaries": BOUNDARIES,
        "disclaimer": "Synthetic integrity fixture only; not a pilot, confirmatory result, or paper evidence.",
    }
    atomic_write_json(run_dir / "run.json", metadata)
    trial_hash = _write_jsonl(run_dir / "trials.jsonl", trials)
    event_hash = _write_jsonl(run_dir / "events.jsonl", events)
    reconciliation = reconcile_boundaries(events, BOUNDARIES)
    atomic_write_json(run_dir / "reconciliation.json", reconciliation)
    summary_hash = _write_summary(run_dir / "summary.csv", trials, events, reconciliation)
    manifest = {
        "schema_version": "porygon.experiment.artifact-manifest.v1",
        "run_id": run_id,
        "artifact_hashes": {
            "run.json": sha256_file(run_dir / "run.json"),
            "trials.jsonl": trial_hash,
            "events.jsonl": event_hash,
            "reconciliation.json": sha256_file(run_dir / "reconciliation.json"),
            "summary.csv": summary_hash,
        },
        "source_of_truth": "events.jsonl",
        "analysis_status": "smoke_only",
    }
    atomic_write_json(run_dir / "artifact-manifest.json", manifest)
    return run_dir


def validate(run_dir: Path) -> None:
    if not (run_dir / "run.json").is_file() or not (run_dir / "artifact-manifest.json").is_file():
        raise ArtifactError("missing artifact: run.json or artifact-manifest.json")
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "artifact-manifest.json").read_text(encoding="utf-8"))
    if manifest.get("run_id") != run.get("run_id"):
        raise ArtifactError("manifest run_id does not match run.json")
    for name, expected in manifest["artifact_hashes"].items():
        path = run_dir / name
        if not path.is_file():
            raise ArtifactError(f"missing artifact: {name}")
        if sha256_file(path) != expected:
            raise ArtifactError(f"artifact hash mismatch: {name}")
    present = {
        str(path.relative_to(run_dir))
        for path in run_dir.rglob("*")
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    unlisted = sorted(present - set(manifest["artifact_hashes"]))
    if unlisted:
        raise ArtifactError(f"artifacts present but absent from the manifest: {unlisted}")
    if run.get("kind") != "smoke_fixture":
        _validate_pilot(run_dir, run)
        return
    _validate_smoke(run_dir, run)


def _validate_pilot(run_dir: Path, run: dict[str, Any]) -> None:
    trials = [json.loads(path.read_text(encoding="utf-8")) for path in sorted((run_dir / "trials").glob("*.json"))]
    if not trials:
        raise ArtifactError("a real-container run must contain at least one trial record")
    if len({trial["trial_id"] for trial in trials}) != len(trials):
        raise ArtifactError("duplicate trial_id")
    for trial in trials:
        if trial["run_id"] != run["run_id"]:
            raise ArtifactError(f"trial {trial['trial_id']} belongs to another run")
        if trial.get("research_eligible") is not False:
            raise ArtifactError("pilot trials must record research_eligible=false")
        if trial["status"] not in ("completed", "failed"):
            raise ArtifactError(f"trial {trial['trial_id']} has no terminal status")
        if trial["status"] == "failed":
            if not trial.get("failure_reason"):
                raise ArtifactError(f"failed trial {trial['trial_id']} records no reason")
            continue
        if "@sha256:" not in trial["image"]["reference"]:
            raise ArtifactError(f"trial {trial['trial_id']} did not pin an immutable digest")
        for name, boundary in trial["reconciliation"]["boundaries"].items():
            if boundary["status"] not in ("measured", "unmeasured"):
                raise ArtifactError(f"boundary {name} has an undeclared status")
            if boundary["status"] == "unmeasured" and not boundary.get("reason"):
                raise ArtifactError(f"unmeasured boundary {name} records no reason")


def _validate_smoke(run_dir: Path, run: dict[str, Any]) -> None:
    for name in ("trials.jsonl", "events.jsonl", "reconciliation.json", "summary.csv"):
        if not (run_dir / name).is_file():
            raise ArtifactError(f"missing artifact: {name}")
    trials = _read_jsonl(run_dir / "trials.jsonl")
    events = _read_jsonl(run_dir / "events.jsonl")
    if len({trial["trial_id"] for trial in trials}) != len(trials):
        raise ArtifactError("duplicate trial_id")
    if any(event["run_id"] != run["run_id"] for event in events):
        raise ArtifactError("event run_id mismatch")
    expected = reconcile_boundaries(events, run["boundaries"])
    actual = json.loads((run_dir / "reconciliation.json").read_text(encoding="utf-8"))
    if expected != actual:
        raise ArtifactError("reconciliation does not match raw events")


def replay(run_dir: Path) -> None:
    validate(run_dir)
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    if run.get("kind") != "smoke_fixture":
        _replay_pilot(run_dir)
        return
    trials = _read_jsonl(run_dir / "trials.jsonl")
    events = _read_jsonl(run_dir / "events.jsonl")
    reconciliation = reconcile_boundaries(events, run["boundaries"])
    replay_path = run_dir / ".replay-summary.csv"
    _write_summary(replay_path, trials, events, reconciliation)
    if replay_path.read_bytes() != (run_dir / "summary.csv").read_bytes():
        replay_path.unlink()
        raise ArtifactError("analysis replay differs from the recorded summary")
    replay_path.unlink()


PILOT_SUMMARY_FIELDS = [
    "trial_id", "workload_id", "human_tag", "mode", "scenario_id", "context_variant",
    "replica_index", "status", "research_eligible", "runtime_context_hash",
    "canaries_generated", "source_observed", "source_missing", "database_observed",
    "database_missing", "database_duplicates", "operations_planned", "operations_succeeded",
    "operations_failed", "workload_latency_p50_ms", "workload_latency_p95_ms",
    "workload_latency_p99_ms", "harness_induced_execs",
]


def _pilot_rows(trials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for trial in sorted(trials, key=lambda item: item["trial_id"]):
        boundaries = (trial.get("reconciliation") or {}).get("boundaries", {})
        load = trial.get("load") or {}
        samples = load.get("latency_ms_samples") or []

        def boundary(name: str, field: str) -> Any:
            entry = boundaries.get(name) or {}
            if entry.get("status") != "measured":
                return "unmeasured"
            return len(entry["missing_sequences"]) if field == "missing" else entry.get(field, "")

        rows.append(
            {
                "trial_id": trial["trial_id"],
                "workload_id": trial["workload_id"],
                "human_tag": trial["human_tag"],
                "mode": trial["mode"],
                "scenario_id": trial["scenario_id"],
                "context_variant": trial["context_variant"],
                "replica_index": trial["replica_index"],
                "status": trial["status"],
                "research_eligible": str(trial["research_eligible"]).lower(),
                "runtime_context_hash": trial.get("runtime_context_hash", "unmeasured"),
                "canaries_generated": (trial.get("reconciliation") or {}).get("generated", "unmeasured"),
                "source_observed": boundary("source", "observed"),
                "source_missing": boundary("source", "missing"),
                "database_observed": boundary("database", "observed"),
                "database_missing": boundary("database", "missing"),
                "database_duplicates": boundary("database", "duplicates"),
                "operations_planned": load.get("operations_planned", "unmeasured"),
                "operations_succeeded": load.get("successes", "unmeasured"),
                "operations_failed": load.get("failures", "unmeasured"),
                "workload_latency_p50_ms": real.percentile(samples, 0.50) if samples else "unmeasured",
                "workload_latency_p95_ms": real.percentile(samples, 0.95) if samples else "unmeasured",
                "workload_latency_p99_ms": real.percentile(samples, 0.99) if samples else "unmeasured",
                "harness_induced_execs": load.get("harness_induced_exec_count", "unmeasured"),
            }
        )
    return rows


def _write_pilot_summary(path: Path, trials: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PILOT_SUMMARY_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(_pilot_rows(trials))


def _load_pilot_trials(run_dir: Path) -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((run_dir / "trials").glob("*.json"))
    ]


def _replay_pilot(run_dir: Path) -> None:
    replay_path = run_dir / ".replay-summary.csv"
    _write_pilot_summary(replay_path, _load_pilot_trials(run_dir))
    same = replay_path.read_bytes() == (run_dir / "summary.csv").read_bytes()
    replay_path.unlink()
    if not same:
        raise ArtifactError("analysis replay differs from the recorded summary")


def _write_manifest(run_dir: Path, run_id: str, analysis_status: str, source_of_truth: str) -> None:
    hashes = {
        str(path.relative_to(run_dir)): sha256_file(path)
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and path.name != "artifact-manifest.json"
    }
    manifest_path = run_dir / "artifact-manifest.json"
    if manifest_path.exists():
        manifest_path.unlink()
    atomic_write_json(
        manifest_path,
        {
            "schema_version": "porygon.experiment.artifact-manifest.v1",
            "run_id": run_id,
            "artifact_hashes": hashes,
            "source_of_truth": source_of_truth,
            "analysis_status": analysis_status,
        },
    )


def run_pilot(
    run_dir: Path,
    *,
    run_id: str,
    workloads: list[str],
    modes: list[str] | None,
    scenarios: list[str],
    variants: list[str],
    replicas: int,
    seed: int,
    base_url: str,
    operations: int,
    warmup_seconds: float,
    settle_seconds: float,
    protocol: Path,
) -> Path:
    """Execute a real-container pilot. Pilot evidence is never confirmatory evidence."""
    status = real.protocol_status(protocol)
    matrix = real.build_matrix(workloads, modes, scenarios, variants, replicas)
    coordinates = real.load_image_coordinates()
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "trials").mkdir(exist_ok=True)

    images = {}
    for workload_id in sorted({entry["workload_id"] for entry in matrix}):
        if workload_id not in coordinates:
            raise ArtifactError(f"{workload_id} has no pinned digest in the profile-scope document")
        image = real.pull_pinned_image(coordinates[workload_id]["index_digest_ref"])
        image["human_tag"] = coordinates[workload_id]["human_tag"]
        images[workload_id] = image

    # run.json is written before the first trial so a resumed run keeps its original
    # provenance instead of silently re-stamping the creation time.
    run_path = run_dir / "run.json"
    if not run_path.exists():
        atomic_write_json(
            run_path,
            {
                "schema_version": "porygon.experiment.run.v2",
                "run_id": run_id,
                "kind": "real_container_pilot",
                "research_eligible": False,
                "eligibility_reason": (
                    "pilot data informs engineering decisions and variance estimates only; the "
                    "protocol prohibits confirmatory collection until both human reviews complete"
                ),
                "protocol_id": PROTOCOL_ID,
                "protocol_status_at_creation": status,
                "git_sha": _git_sha(),
                "git_dirty": _git_dirty(),
                "python": platform.python_version(),
                "platform": platform.platform(),
                "docker_version": real.docker("version", "--format", "{{.Server.Version}}", check=False),
                "kernel_btf_present": Path("/sys/kernel/btf/vmlinux").exists(),
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "monotonic_origin_ns": time.monotonic_ns(),
                "seed": seed,
                "boundaries": ["generator", "source", "spool", "api", "database"],
                "matrix": matrix,
            },
        )
    if not (run_dir / "images.json").exists():
        atomic_write_json(run_dir / "images.json", images)

    network = f"porygon-exp-{run_id}"
    real.docker("network", "create", "--label", f"{real.LABEL_RUN}={run_id}", network)
    try:
        for entry in matrix:
            trial_path = run_dir / "trials" / f"{entry['trial_id']}.json"
            if trial_path.exists():  # resume: a completed trial is immutable
                continue
            record = real.run_trial(
                run_id=run_id,
                trial_id=entry["trial_id"],
                workload_id=entry["workload_id"],
                mode=entry["mode"],
                scenario_id=entry["scenario_id"],
                variant=entry["variant"],
                replica=entry["replica"],
                image=images[entry["workload_id"]],
                network=network,
                base_url=base_url,
                seed=seed + entry["replica"],
                warmup_seconds=warmup_seconds,
                operations=operations,
                settle_seconds=settle_seconds,
            )
            atomic_write_json(trial_path, record)
            print(f"[pilot] {entry['trial_id']}: {record['status']}")
    finally:
        real.remove_network(network, run_id)

    trials = _load_pilot_trials(run_dir)
    _write_pilot_summary(run_dir / "summary.csv", trials)
    _write_manifest(run_dir, run_id, "pilot_only", "trials/")
    return run_dir


def confirmatory(protocol: Path) -> None:
    text = protocol.read_text(encoding="utf-8")
    if "Status: **FROZEN" not in text:
        raise ArtifactError("confirmatory collection is refused until the protocol is frozen by human review")
    raise ArtifactError("confirmatory runner is intentionally gated until the approved workload matrix is implemented")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Porygon reproducible experiment artifacts")
    subparsers = parser.add_subparsers(dest="command", required=True)
    smoke = subparsers.add_parser("smoke")
    smoke.add_argument("--run-dir", type=Path, default=Path("artifacts/experiments/local/smoke-fixture"))
    smoke.add_argument("--run-id", default="smoke-fixture")
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("run_dir", type=Path)
    pilot = subparsers.add_parser("pilot", help="real-container pilot; never confirmatory evidence")
    pilot.add_argument("--run-id", default=None)
    pilot.add_argument("--run-dir", type=Path, default=None)
    pilot.add_argument("--workloads", default="WL-NGX-V1,WL-RDS-V1,WL-PG-V1")
    pilot.add_argument("--modes", default=None, help="default: the steady mode of each family")
    pilot.add_argument("--scenarios", default="SCN-EXEC")
    pilot.add_argument("--variants", default="baseline")
    pilot.add_argument("--replicas", type=int, default=1)
    pilot.add_argument("--operations", type=int, default=40)
    pilot.add_argument("--warmup-seconds", type=float, default=3.0)
    pilot.add_argument("--settle-seconds", type=float, default=12.0)
    pilot.add_argument("--seed", type=int, default=20260905)
    pilot.add_argument("--base-url", default="http://127.0.0.1:8000")
    pilot.add_argument("--protocol", type=Path, default=ROOT / "docs/RESEARCH_PROTOCOL_V1.md")
    confirm = subparsers.add_parser("confirmatory")
    confirm.add_argument("--protocol", type=Path, default=ROOT / "docs/RESEARCH_PROTOCOL_V1.md")
    args = parser.parse_args(argv)
    try:
        if args.command == "smoke":
            run_smoke(args.run_dir, args.run_id)
            validate(args.run_dir)
            print(f"smoke artifacts validated: {args.run_dir}")
        elif args.command == "replay":
            replay(args.run_dir)
            print(f"replay matched recorded summary: {args.run_dir}")
        elif args.command == "pilot":
            run_id = args.run_id or "pilot-" + datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%SZ")
            run_dir = args.run_dir or ROOT / "artifacts/experiments/local" / run_id
            run_pilot(
                run_dir,
                run_id=run_id,
                workloads=[item for item in args.workloads.split(",") if item],
                modes=[item for item in args.modes.split(",") if item] if args.modes else None,
                scenarios=[item for item in args.scenarios.split(",") if item],
                variants=[item for item in args.variants.split(",") if item],
                replicas=args.replicas,
                seed=args.seed,
                base_url=args.base_url.rstrip("/"),
                operations=args.operations,
                warmup_seconds=args.warmup_seconds,
                settle_seconds=args.settle_seconds,
                protocol=args.protocol,
            )
            validate(run_dir)
            print(f"pilot artifacts validated: {run_dir}")
        else:
            confirmatory(args.protocol)
    except real.PilotError as exc:
        print(f"[blocked] {exc}", file=sys.stderr)
        return 2
    except ArtifactError as exc:
        print(f"[blocked] {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
