#!/usr/bin/env python3
"""Measure which deployment variants actually change what a container executes.

A runtime-context variant is only useful to the profile-scope study if it changes
the executed-process evidence. A variant that changes the context identity but
leaves the process multiset identical fragments the strata for no gain.

This probe starts one container per candidate variant, lets it settle, reads the
executed-process multiset straight out of the sensor stream, and reports which
candidates differ from the baseline. Every container is disposable, labelled, and
removed by exact name.

Usage:
    python3 scripts/probe_context_variants.py [--workload WL-NGX-V1] [--settle 12]
"""
from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TELEMETRY = "porygon-telemetry-1"
FALCO_LOG = "/var/log/porygon/falco-events.jsonl"
LABEL = "porygon.variant.probe"

# Candidate deployment differences. Each is security-relevant and therefore a
# legitimate member of the runtime-context identity; the probe decides which of
# them are also behaviourally visible.
CANDIDATES: dict[str, list[str]] = {
    "baseline": [],
    "dropped_capabilities": ["--cap-drop", "NET_RAW"],
    "tmpfs_scratch": ["--tmpfs", "/scratch"],
    "no_new_privileges": ["--security-opt", "no-new-privileges"],
    "direct_entrypoint": [],          # filled per workload: bypasses the image entrypoint
    "nonroot_user": [],               # filled per workload: runs as a non-root account
    "init_mount": [],                 # filled per workload: an attached start-up script directory
}

WORKLOAD_PROBE: dict[str, dict[str, list[str]]] = {
    "WL-NGX": {
        "direct_entrypoint": ["--entrypoint", "nginx"],
        "nonroot_user": ["--user", "101:101"],
        "init_mount": ["--volume", "/tmp/pgprobe:/docker-entrypoint.d/study:ro"],
        "cmd": ["-g", "daemon off;"],
    },
    "WL-RDS": {
        "direct_entrypoint": ["--entrypoint", "redis-server"],
        "nonroot_user": ["--user", "999:1000"],
        "cmd": [],
    },
    "WL-PG": {
        "direct_entrypoint": ["--entrypoint", "postgres"],
        "nonroot_user": ["--user", "999:999"],
        "init_mount": ["--volume", "/tmp/pgprobe:/docker-entrypoint-initdb.d:ro"],
        "cmd": [],
    },
}

ENV = {"WL-PG": ["--env", "POSTGRES_HOST_AUTH_METHOD=trust", "--env", "POSTGRES_DB=probe"]}


def docker(*args: str, check: bool = True, timeout: int = 120) -> str:
    done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and done.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout.strip()


def executed_processes(container_name: str) -> collections.Counter:
    """Read the executed-process multiset for one container from the sensor stream."""
    done = subprocess.run(
        ["docker", "exec", TELEMETRY, "sh", "-c", f"grep '{container_name}' {FALCO_LOG} || true"],
        capture_output=True, text=True, timeout=300,
    )
    counts: collections.Counter = collections.Counter()
    for line in done.stdout.splitlines():
        try:
            fields = json.loads(line)["output_fields"]
        except (json.JSONDecodeError, KeyError):
            continue
        if fields.get("container.name") != container_name:
            continue
        counts[(fields.get("proc.name"), fields.get("proc.exepath"))] += 1
    return counts


def probe(workload_id: str, reference: str, variant: str, settle: float, token: str) -> dict:
    family = workload_id.rsplit("-", 1)[0]
    spec = WORKLOAD_PROBE[family]
    # The sensor stream is append-only and keyed by container name, so a name reused
    # across workloads would attribute the previous workload's events to this one.
    name = f"porygon-varprobe-{token}-{variant.replace('_', '-')}"
    extra = list(CANDIDATES[variant]) or list(spec.get(variant, []))
    args = ["run", "--detach", "--name", name, "--label", f"{LABEL}=1",
            "--memory", "512m", "--pids-limit", "512", *ENV.get(family, []), *extra, reference]
    if variant == "direct_entrypoint":
        args += spec.get("cmd", [])
    record = {"variant": variant, "container": name, "started": False}
    try:
        docker(*args, timeout=180)
        record["started"] = True
        time.sleep(settle)
        record["running"] = docker("inspect", "--format", "{{.State.Running}}", name, check=False) == "true"
        record["processes"] = executed_processes(name)
    except (RuntimeError, subprocess.SubprocessError) as error:
        record["error"] = f"{type(error).__name__}: {error}"
    finally:
        if record["started"]:
            labels = docker("inspect", "--format", "{{index .Config.Labels \"" + LABEL + "\"}}",
                            name, check=False)
            if labels == "1":
                docker("rm", "--force", name, check=False, timeout=120)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", default="WL-NGX-V1")
    parser.add_argument("--settle", type=float, default=12.0)
    parser.add_argument("--variants", default=",".join(CANDIDATES))
    args = parser.parse_args()

    from experiments.real import load_image_coordinates, pull_pinned_image

    coordinates = load_image_coordinates()
    if args.workload not in coordinates:
        print(f"unknown workload {args.workload}", file=sys.stderr)
        return 2
    image = pull_pinned_image(coordinates[args.workload]["index_digest_ref"])

    token = f"{args.workload.lower()}-{int(time.time())}"
    results = [probe(args.workload, image["reference"], v, args.settle, token)
               for v in args.variants.split(",") if v]
    baseline = next((r for r in results if r["variant"] == "baseline"), None)
    if baseline is None or "processes" not in baseline:
        print("baseline probe failed; cannot compare", file=sys.stderr)
        return 1

    print(f"\nworkload={args.workload}  image={image['reference'][:40]}…\n")
    print(f"{'variant':24}{'running':>9}{'events':>8}{'distinct':>10}  behaviourally different?")
    for record in results:
        if "processes" not in record:
            print(f"{record['variant']:24}{'failed':>9}{'-':>8}{'-':>10}  {record.get('error','')[:40]}")
            continue
        counts = record["processes"]
        same = counts == baseline["processes"]
        mark = "baseline" if record["variant"] == "baseline" else ("no" if same else "YES")
        print(f"{record['variant']:24}{str(record.get('running')):>9}"
              f"{sum(counts.values()):>8}{len(counts):>10}  {mark}")
        if not same and record["variant"] != "baseline":
            added = counts - baseline["processes"]
            removed = baseline["processes"] - counts
            for label, delta in (("only in variant", added), ("only in baseline", removed)):
                if delta:
                    shown = ", ".join(f"{n}×{p[0]}" for p, n in list(delta.items())[:5])
                    print(f"{'':24}  {label}: {shown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
