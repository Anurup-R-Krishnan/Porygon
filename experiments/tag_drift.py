"""Mutable-tag drift experiment: distinguishes ARM-TAG from ARM-DIGEST for real.

PROFILE_SCOPE_EXPERIMENT_V1.md's "Immutable workload coordinates" section
specifies exactly this mechanism: a controlled local alias
(porygon-study/<repo>:mutable) that resolves to a workload's V1 coordinate
for fit runs, then is repointed to V2 for predeclared drift runs, exposing
tag-selection failure deterministically without touching the real upstream
tags.

Until this script, nothing in the codebase implemented that alias, so every
prior scope-comparison result had ARM-TAG and ARM-DIGEST scoring identically
(every human_tag happened to map to exactly one digest). This is what makes
them actually distinguishable: an ARM-TAG profile keyed on the literal tag
`porygon-study/nginx:mutable` gets contaminated by both V1 and V2 behaviour
if a naive implementation resolves the tag at scoring time; a correct
ARM-DIGEST profile never can be, because it is keyed on the resolved digest
which V1 and V2 never share.

Usage:
    python3 -m experiments.tag_drift --workload WL-NGX --replicas 5
"""
from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiments import real
from experiments.artifacts import atomic_write_json

ROOT = Path(__file__).resolve().parents[1]

_IMAGE_ROW = re.compile(
    r"\|\s*`(?P<workload>WL-[A-Z]+-V[12])`\s*\|\s*`(?P<tag>[^`]+)`\s*\|\s*`(?P<digest>[^`]+)`\s*\|"
)


def load_versions(family: str, doc: Path = real.PROFILE_SCOPE_DOC) -> dict[str, dict[str, str]]:
    """Read both V1 and V2 coordinates for one workload family from the frozen
    profile-scope document (real.py's load_image_coordinates only keeps one
    row per workload family key; this keeps both versions by their full
    WL-*-V1/V2 id)."""
    versions: dict[str, dict[str, str]] = {}
    for line in doc.read_text(encoding="utf-8").splitlines():
        match = _IMAGE_ROW.match(line.strip())
        if match and match.group("workload").startswith(family):
            versions[match.group("workload")] = {
                "human_tag": match.group("tag"),
                "index_digest_ref": match.group("digest"),
            }
    if "V1" not in {k[-2:] for k in versions} or "V2" not in {k[-2:] for k in versions}:
        raise real.PilotError(f"{family} does not have both V1 and V2 coordinates pinned")
    return versions


def build_mutable_alias(repository: str) -> str:
    """A controlled local tag this harness owns, never an upstream tag.
    PROFILE_SCOPE_EXPERIMENT_V1.md names this exact pattern."""
    return f"porygon-study/{repository}:mutable"


def point_alias_at(alias: str, real_reference: str) -> None:
    """docker tag <digest-pinned image> <mutable alias>, so the alias
    resolves locally to whichever digest is currently pinned, without any
    network pull or upstream registry mutation."""
    real.docker("tag", real_reference, alias)


def run_tag_drift_experiment(
    *,
    family: str,
    fit_replicas: int,
    drift_replicas: int,
    run_id: str | None = None,
    base_url: str = "http://127.0.0.1:8000",
    operations: int = 10,
    warmup_seconds: float = 3.0,
    settle_seconds: float = 12.0,
    seed: int = 20260905,
) -> Path:
    """Collects real trials against a controlled local mutable tag: V1
    coordinate for the fit-phase runs, V2 for drift-phase runs, both recorded
    under the identical human_tag so ARM-TAG's pooled reference genuinely
    spans two different real digests, exactly as the protocol specifies.
    """
    run_id = run_id or "tagdrift-" + datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%SZ")
    versions = load_versions(family)
    v1_key = next(k for k in versions if k.endswith("V1"))
    v2_key = next(k for k in versions if k.endswith("V2"))
    v1 = real.pull_pinned_image(versions[v1_key]["index_digest_ref"])
    v2 = real.pull_pinned_image(versions[v2_key]["index_digest_ref"])

    repository = v1["repository"]
    alias = build_mutable_alias(repository)

    run_dir = ROOT / "artifacts/experiments/local" / run_id
    (run_dir / "trials").mkdir(parents=True, exist_ok=True)

    network = f"porygon-exp-{run_id}"
    real.docker("network", "create", "--label", f"{real.LABEL_RUN}={run_id}", network)

    manifest_entries: list[dict[str, Any]] = []
    try:
        # Fit-phase runs: alias points at V1, matching the frozen protocol's
        # "Fit runs resolve the alias to each family's V1 coordinate."
        point_alias_at(alias, v1["reference"])
        for replica in range(1, fit_replicas + 1):
            trial_id = f"tagdrift-{family.lower()}-fit-r{replica:02d}"
            trial_path = run_dir / "trials" / f"{trial_id}.json"
            if not trial_path.exists():
                image = dict(v1)
                image["human_tag"] = alias  # the literal alias, not the frozen human tag
                record = real.run_trial(
                    run_id=run_id, trial_id=trial_id, workload_id=v1_key,
                    mode=real.default_mode(family), scenario_id="SCN-EXEC", variant="baseline",
                    replica=replica, image=image, network=network, base_url=base_url,
                    seed=seed + replica, warmup_seconds=warmup_seconds, operations=operations,
                    settle_seconds=settle_seconds,
                )
                record["tag_drift_phase"] = "fit_v1"
                record["alias"] = alias
                record["resolved_digest"] = v1["reference"]
                atomic_write_json(trial_path, record)
            manifest_entries.append({"trial_id": trial_id, "phase": "fit_v1"})
            print(f"[tag-drift] {trial_id}: completed (alias -> V1)")

        # Drift-phase runs: repoint the same alias at V2, matching
        # "predeclared drift runs move the same alias to V2." The literal
        # human_tag string never changes; only what it resolves to does.
        point_alias_at(alias, v2["reference"])
        for replica in range(1, drift_replicas + 1):
            trial_id = f"tagdrift-{family.lower()}-drift-r{replica:02d}"
            trial_path = run_dir / "trials" / f"{trial_id}.json"
            if not trial_path.exists():
                image = dict(v2)
                image["human_tag"] = alias
                record = real.run_trial(
                    run_id=run_id, trial_id=trial_id, workload_id=v2_key,
                    mode=real.default_mode(family), scenario_id="SCN-EXEC", variant="baseline",
                    replica=replica, image=image, network=network, base_url=base_url,
                    seed=seed + fit_replicas + replica, warmup_seconds=warmup_seconds,
                    operations=operations, settle_seconds=settle_seconds,
                )
                record["tag_drift_phase"] = "drift_v2"
                record["alias"] = alias
                record["resolved_digest"] = v2["reference"]
                atomic_write_json(trial_path, record)
            manifest_entries.append({"trial_id": trial_id, "phase": "drift_v2"})
            print(f"[tag-drift] {trial_id}: completed (alias -> V2)")
    finally:
        real.remove_network(network, run_id)

    atomic_write_json(
        run_dir / "run.json",
        {
            "schema_version": "porygon.experiment.tag-drift-run.v1",
            "run_id": run_id,
            "kind": "tag_drift_experiment",
            "family": family,
            "alias": alias,
            "v1_digest": v1["reference"],
            "v2_digest": v2["reference"],
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "entries": manifest_entries,
        },
    )
    return run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", default="WL-NGX", help="Workload family, e.g. WL-NGX")
    parser.add_argument("--fit-replicas", type=int, default=5)
    parser.add_argument("--drift-replicas", type=int, default=5)
    parser.add_argument("--run-id")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--operations", type=int, default=10)
    args = parser.parse_args(argv)

    run_dir = run_tag_drift_experiment(
        family=args.workload, fit_replicas=args.fit_replicas, drift_replicas=args.drift_replicas,
        run_id=args.run_id, base_url=args.base_url, operations=args.operations,
    )
    print(f"tag-drift artifacts written: {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
