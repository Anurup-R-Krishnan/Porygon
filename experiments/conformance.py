"""ART-DES-001-adjacent gate: does a run directory's own recorded evidence
satisfy RESEARCH_PROTOCOL_V1.md's structural requirements for a confirmatory
result?

This module answers that question and only that question. It never starts a
container, never calls the backend, never writes an artifact, and never
decides anything a human should decide -- `CONF-REV-001` reads
`scripts/review_gate.py:gate_state()` exactly as it stands, it does not
second-guess it. Every other check reads only:

  - `docs/RESEARCH_PROTOCOL_V1.md`'s machine-readable manifest, via
    `scripts/review_gate.py:manifest_of` (reused, not re-parsed);
  - `docs/PROFILE_SCOPE_EXPERIMENT_V1.md`'s frozen image table, via
    `experiments/real.py:load_image_coordinates` (reused, not re-parsed);
  - the run directory's own `run.json`, `images.json`, `environment.json`,
    and `trials/*.json` records;
  - the current `ART-DES-001` sample-size lock, via
    `experiments/sample_size.py`'s own default lock directory.

Every individual requirement is its own named, stable check ID
(`CONF-*`), so a caller can see exactly which requirement failed and why --
never a single opaque "not ready" verdict. A check that cannot be evaluated
because the data it needs is missing reports `satisfied: False` with a
`detail` naming what is missing; it never silently passes and never silently
skips.

`check_run_conformance` is a pure, read-only function of its inputs: it does
not build the default manifest/lock itself unless the caller omits them, so
tests can hand it a small synthetic manifest instead of always exercising the
frozen protocol document.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from experiments import sample_size
from experiments.artifacts import ArtifactError, assign_split, load_json, versioned_artifact_paths
from experiments.environment import SCHEMA_VERSION as ENVIRONMENT_SCHEMA_VERSION
from experiments.real import (
    ANALYSIS_ONLY_SCENARIOS,
    PROFILE_SCOPE_DOC,
    RUNTIME_SCENARIOS,
    family_of,
    load_image_coordinates,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "docs" / "RESEARCH_PROTOCOL_V1.md"

# Frozen protocol constants (RESEARCH_PROTOCOL_V1.md, "Workloads and run counts" /
# "Deterministic assignment and seeds"). Hardcoded here exactly like every other
# frozen numeric constant in this package (experiments/sample_size.py's
# MIN_CANDIDATE_COUNT/TARGET_POWER/..., experiments/real.py's FAMILY_SPECS) rather
# than re-derived from a fragile prose parse; load_protocol_manifest asserts the
# defining sentence for each is still present in the live document so drift is
# caught rather than silently ignored.
MIN_CONFIRMATORY_BENIGN_PER_CELL = 30
MIN_CONFIRMATORY_SCENARIO_PER_CELL = 20
MIN_FIT_CALIBRATION_PER_STRATUM = 10
MIN_REPLICAS_PER_SPLIT = 3

_DRIFT_GUARDS: tuple[tuple[str, str], ...] = (
    ("confirmatory benign evaluation requires 30 runs per workload-version-mode cell", "MIN_CONFIRMATORY_BENIGN_PER_CELL"),
    ("requires 20 runs per applicable workload-version-scenario cell", "MIN_CONFIRMATORY_SCENARIO_PER_CELL"),
    ("require 10 independent clean runs per supported profile stratum", "MIN_FIT_CALIBRATION_PER_STRATUM"),
    ("at least three distinct same-digest replica containers per split", "MIN_REPLICAS_PER_SPLIT"),
)

_HARD_NEG_ROW = re.compile(r"^\|\s*(nginx|Redis|PostgreSQL)\s*\|([^|]+)\|([^|]+)\|\s*$", re.IGNORECASE)
_FAMILY_DISPLAY_TO_ID = {"nginx": "WL-NGX", "redis": "WL-RDS", "postgresql": "WL-PG"}

SPLITS = ("fit", "calibration", "test")


def _load_review_gate():
    """scripts/review_gate.py has no package __init__.py; reuse the exact
    load-by-path pattern experiments/sample_size.py already uses, so this
    module's view of the review gate can never disagree with that one's."""
    return sample_size._load_review_gate()


# ---------------------------------------------------------------------------
# Protocol manifest
# ---------------------------------------------------------------------------


def _parse_hard_negatives(text: str) -> dict[str, list[str]]:
    """Parse the "Workloads and run counts" table's hard-negative column.

    Not covered by scripts/review_gate.py:manifest_of's JSON manifest block
    (that block has no hard-negative field at all), so this is genuinely new
    parsing, not a second parser for something already machine-readable.
    """
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = _HARD_NEG_ROW.match(line.strip())
        if not match:
            continue
        family_display, _benign_modes, hard_negatives = match.groups()
        family_id = _FAMILY_DISPLAY_TO_ID[family_display.lower()]
        result[family_id] = [item.strip() for item in hard_negatives.split(",") if item.strip()]
    if not result:
        raise RuntimeError(
            f"could not parse the hard-negative table out of {PROTOCOL_PATH}; "
            "the 'Workloads and run counts' table shape may have changed"
        )
    return result


def _assert_frozen_constants_match_text(text: str) -> None:
    # Prose lines wrap at ~80 columns in the source document, so a needle spanning a
    # wrap point would never match the raw text; collapse all whitespace runs (including
    # newlines) to a single space before searching, exactly for that reason.
    flat = re.sub(r"\s+", " ", text).lower()
    for needle, constant_name in _DRIFT_GUARDS:
        if needle not in flat:
            raise RuntimeError(
                f"{PROTOCOL_PATH} no longer contains {needle!r}; the hardcoded "
                f"{constant_name} in experiments/conformance.py may be stale and "
                "must be reconciled with the current protocol text before this "
                "gate can be trusted"
            )


def load_protocol_manifest(path: Path | None = None) -> dict[str, Any]:
    """Everything check_run_conformance needs to know about what the protocol
    requires, as one self-contained, JSON-safe dict. Reuses
    scripts/review_gate.py:manifest_of for the structured (workloads/
    scenarios/arms/...) part rather than re-parsing the document twice.
    """
    review_gate = _load_review_gate()
    protocol_path = path or PROTOCOL_PATH
    text = protocol_path.read_text(encoding="utf-8")
    manifest = review_gate.manifest_of(text)
    _assert_frozen_constants_match_text(text)

    workloads = [
        {"id": w["id"], "versions": list(w["versions"]), "modes": list(w["modes"])}
        for w in manifest["workloads"]
    ]
    return {
        "protocol_id": manifest.get("protocol_id"),
        "protocol_status": manifest.get("protocol_status"),
        "protocol_sha256": review_gate.protocol_digest(text),
        "workloads": workloads,
        "scenario_ids": [s["id"] for s in manifest["scenarios"]],
        "runtime_scenario_ids": list(RUNTIME_SCENARIOS),
        "analysis_only_scenario_ids": list(ANALYSIS_ONLY_SCENARIOS),
        "hard_negatives": _parse_hard_negatives(text),
        "image_coordinates": load_image_coordinates(PROFILE_SCOPE_DOC),
        "min_replicas_per_split": MIN_REPLICAS_PER_SPLIT,
        "min_fit_calibration_per_stratum": MIN_FIT_CALIBRATION_PER_STRATUM,
        "min_confirmatory_benign_per_cell": MIN_CONFIRMATORY_BENIGN_PER_CELL,
        "min_confirmatory_scenario_per_cell": MIN_CONFIRMATORY_SCENARIO_PER_CELL,
    }


def required_cells(manifest: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Expand `manifest` into every (workload-version, mode) benign cell and
    every (workload-version, scenario) scenario cell that must be satisfied,
    with each cell's minimum required count.

    Scenario cells are built only from `runtime_scenario_ids` -- scenarios in
    `analysis_only_scenario_ids` are evaluated from already-collected benign
    trials at analysis time and never occupy a cell of their own here (see
    CONF-SCN-001 for how those are still required, just not as a cell count).
    """
    benign_cells: dict[str, int] = {}
    scenario_cells: dict[str, int] = {}
    for workload in manifest["workloads"]:
        for version in workload["versions"]:
            for mode in workload["modes"]:
                benign_cells[f"{version}|{mode}"] = manifest["min_confirmatory_benign_per_cell"]
            for scenario_id in manifest["runtime_scenario_ids"]:
                scenario_cells[f"{version}|{scenario_id}"] = manifest["min_confirmatory_scenario_per_cell"]
    return {"benign_cells": benign_cells, "scenario_cells": scenario_cells}


# ---------------------------------------------------------------------------
# Report shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConformanceFinding:
    check_id: str
    required: Any
    observed: Any
    satisfied: bool
    detail: str


@dataclass(frozen=True)
class ConformanceReport:
    run_id: str
    protocol_sha256: str
    findings: list[ConformanceFinding]
    satisfied: bool
    failing_check_ids: list[str]


def confirmatory_eligible(report: ConformanceReport) -> tuple[bool, list[str]]:
    return report.satisfied, report.failing_check_ids


# ---------------------------------------------------------------------------
# Run-directory loading
# ---------------------------------------------------------------------------


def _load_trial_records(run_dir: Path) -> list[dict[str, Any]]:
    """Every raw trial record under run_dir/trials, whatever its status.

    Mirrors the identical `glob("*.json") + json.loads` pattern already used
    verbatim by experiments/run.py:_load_pilot_trials,
    experiments/scope.py:load_trial_identities, and
    experiments/context_delta.py:load_context_trials -- this is that same
    pattern, not a fourth incompatible one, kept local (rather than importing
    a same-module-private helper from experiments.run) because none of those
    existing loaders retain the raw fields (workload_id, mode, scenario_id,
    replica_index, image, ...) this module's cell/version/mode checks need.
    """
    trials_dir = run_dir / "trials"
    if not trials_dir.is_dir():
        return []
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(trials_dir.glob("*.json"))]


def _load_run_manifest(run_dir: Path) -> dict[str, Any] | None:
    path = run_dir / "run.json"
    if not path.is_file():
        return None
    try:
        return load_json(path)
    except ArtifactError:
        return None


def _load_images_manifest(run_dir: Path) -> dict[str, Any] | None:
    path = run_dir / "images.json"
    if not path.is_file():
        return None
    try:
        return load_json(path)
    except ArtifactError:
        return None


def _resolve_lock_path(lock_path: Path | None) -> Path | None:
    if lock_path is not None:
        return lock_path if Path(lock_path).is_file() else None
    candidates = versioned_artifact_paths(sample_size.DEFAULT_LOCK_DIR, "sample-size-lock")
    return candidates[-1] if candidates else None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _finding(check_id: str, required: Any, observed: Any, satisfied: bool, detail: str) -> ConformanceFinding:
    return ConformanceFinding(check_id=check_id, required=required, observed=observed, satisfied=satisfied, detail=detail)


def _check_scn_001(manifest: dict[str, Any], completed: list[dict[str, Any]]) -> ConformanceFinding:
    present = {t.get("scenario_id") for t in completed}
    required = list(manifest["runtime_scenario_ids"])
    missing = [s for s in required if s not in present]
    analysis_only = list(manifest["analysis_only_scenario_ids"])
    satisfied = not missing
    detail = (
        f"analysis-only scenarios {analysis_only} are satisfied via already-collected "
        "benign trials and never require a fresh collection trial. "
        + (f"missing runtime scenario(s) requiring live collection: {missing}" if missing
           else "every runtime scenario requiring live collection is present")
    )
    return _finding("CONF-SCN-001", required, sorted(present), satisfied, detail)


def _check_scn_002(manifest: dict[str, Any], completed: list[dict[str, Any]]) -> ConformanceFinding:
    known = set(manifest["scenario_ids"])
    present = {t.get("scenario_id") for t in completed if t.get("scenario_id")}
    exploratory = sorted(present - known)
    detail = (
        f"non-protocol/exploratory scenario_id(s) present (informational only, excluded from "
        f"CONF-CNT-001 cells, never a failure here): {exploratory}"
        if exploratory else "no exploratory/non-protocol scenario_id found in this run"
    )
    # Never an outright failure: exploratory scenarios are allowed to exist.
    return _finding("CONF-SCN-002", sorted(known), exploratory, True, detail)


def _check_ver_001(
    manifest: dict[str, Any], completed: list[dict[str, Any]], images_manifest: dict[str, Any] | None
) -> ConformanceFinding:
    required_versions = sorted({v for w in manifest["workloads"] for v in w["versions"]})
    present_versions = {t.get("workload_id") for t in completed}
    missing = [v for v in required_versions if v not in present_versions]

    mismatches: list[str] = []
    for version in required_versions:
        if version in missing:
            continue
        expected = manifest["image_coordinates"].get(version, {}).get("index_digest_ref")
        observed_ref = None
        if images_manifest and version in images_manifest:
            observed_ref = images_manifest[version].get("reference")
        else:
            for trial in completed:
                if trial.get("workload_id") == version:
                    observed_ref = (trial.get("image") or {}).get("reference")
                    break
        if expected is not None and observed_ref is not None and observed_ref != expected:
            mismatches.append(f"{version}: expected {expected!r}, observed {observed_ref!r}")

    satisfied = not missing and not mismatches
    detail_parts = []
    if missing:
        detail_parts.append(f"missing workload version(s): {missing}")
    if mismatches:
        detail_parts.append(f"digest mismatch(es): {mismatches}")
    if not detail_parts:
        detail_parts.append("every required workload version is present at its pinned digest")
    return _finding(
        "CONF-VER-001", required_versions, sorted(present_versions), satisfied, "; ".join(detail_parts)
    )


def _check_mode_001(manifest: dict[str, Any], completed: list[dict[str, Any]]) -> ConformanceFinding:
    present_modes_by_version: dict[str, set[str]] = {}
    for trial in completed:
        present_modes_by_version.setdefault(trial.get("workload_id"), set()).add(trial.get("mode"))

    missing: dict[str, list[str]] = {}
    required: dict[str, list[str]] = {}
    for workload in manifest["workloads"]:
        for version in workload["versions"]:
            required[version] = list(workload["modes"])
            present = present_modes_by_version.get(version, set())
            gap = [m for m in workload["modes"] if m not in present]
            if gap:
                missing[version] = gap

    satisfied = not missing
    detail = f"missing benign mode(s) per version: {missing}" if missing else "every required benign mode is present per version"
    observed = {version: sorted(modes) for version, modes in present_modes_by_version.items()}
    return _finding("CONF-MODE-001", required, observed, satisfied, detail)


def _check_hn_001(manifest: dict[str, Any], completed: list[dict[str, Any]]) -> ConformanceFinding:
    required = manifest["hard_negatives"]
    present_by_family: dict[str, set[str]] = {family: set() for family in required}
    for trial in completed:
        hard_negative_id = trial.get("hard_negative_id")
        if not hard_negative_id:
            continue
        family = family_of(trial.get("workload_id", "")) if trial.get("workload_id") else None
        if family in present_by_family:
            present_by_family[family].add(hard_negative_id)

    missing: dict[str, list[str]] = {}
    counts: dict[str, str] = {}
    for family, names in required.items():
        present = present_by_family.get(family, set())
        gap = [n for n in names if n not in present]
        counts[family] = f"{len(names) - len(gap)} of {len(names)} present"
        if gap:
            missing[family] = gap

    satisfied = not missing
    detail = (
        "no hard-negative trial data exists in this codebase yet (no trial record carries a "
        f"hard_negative_id); counts per family: {counts}" if all(len(p) == 0 for p in present_by_family.values())
        else f"missing hard negative(s) per family: {missing}"
    )
    return _finding("CONF-HN-001", required, counts, satisfied, detail)


def _check_gt_001(completed: list[dict[str, Any]]) -> ConformanceFinding:
    missing_ids = [
        t.get("trial_id", "<unknown>") for t in completed
        if not isinstance(t.get("ground_truth"), dict) or "expected_outcome" not in (t.get("ground_truth") or {})
    ]
    satisfied = not missing_ids
    detail = (
        "every completed trial records an explicit ground_truth.expected_outcome, written "
        "directly by experiments/real.py:run_scenario at collection time (this codebase has no "
        "inference path for this field, so 'inferred vs explicit' is not currently a live "
        "distinction to check)" if satisfied
        else f"{len(missing_ids)} completed trial(s) carry no explicit ground-truth classification: {missing_ids[:20]}"
    )
    return _finding("CONF-GT-001", "ground_truth.expected_outcome present on every completed trial", len(missing_ids), satisfied, detail)


def _check_rep_001(manifest: dict[str, Any], completed: list[dict[str, Any]]) -> ConformanceFinding:
    minimum = manifest["min_replicas_per_split"]
    required_versions = sorted({v for w in manifest["workloads"] for v in w["versions"]})
    replicas: dict[tuple[str, str], set[Any]] = {}
    for trial in completed:
        version = trial.get("workload_id")
        if version not in required_versions:
            continue
        split = assign_split(trial["trial_id"])
        replicas.setdefault((version, split), set()).add(trial.get("replica_index"))

    failing: dict[str, int] = {}
    for version in required_versions:
        for split in SPLITS:
            count = len(replicas.get((version, split), set()))
            if count < minimum:
                failing[f"{version}|{split}"] = count

    satisfied = not failing
    detail = (
        f"cell(s) below the required {minimum} distinct same-digest replicas per split: {failing}"
        if failing else f"every workload version has at least {minimum} distinct replicas in every split"
    )
    return _finding("CONF-REP-001", minimum, failing, satisfied, detail)


def _check_fit_001(manifest: dict[str, Any], completed: list[dict[str, Any]]) -> ConformanceFinding:
    minimum = manifest["min_fit_calibration_per_stratum"]
    counts: dict[tuple[str, str, str], int] = {}
    for trial in completed:
        ground_truth = trial.get("ground_truth") or {}
        if bool(ground_truth.get("attack_like")):
            continue  # exploratory attack-like trials never contribute to a clean fit/calibration stratum
        version = trial.get("workload_id")
        variant = trial.get("context_variant")
        split = assign_split(trial["trial_id"])
        if split not in ("fit", "calibration"):
            continue
        counts[(version, variant, split)] = counts.get((version, variant, split), 0) + 1

    strata = sorted({(version, variant) for version, variant, _ in counts})
    failing: dict[str, dict[str, int]] = {}
    for version, variant in strata:
        fit_n = counts.get((version, variant, "fit"), 0)
        cal_n = counts.get((version, variant, "calibration"), 0)
        if fit_n < minimum or cal_n < minimum:
            failing[f"{version}|{variant}"] = {"fit": fit_n, "calibration": cal_n}

    satisfied = bool(strata) and not failing
    if not strata:
        detail = "no clean (non-attack-like) fit/calibration trials found at all"
    elif failing:
        detail = f"stratum/split cell(s) below the required {minimum} clean runs: {failing}"
    else:
        detail = f"every observed (version, context-variant) stratum has at least {minimum} clean runs in fit and calibration"
    return _finding("CONF-FIT-001", minimum, failing or {s: {"fit": counts.get((*s, "fit"), 0), "calibration": counts.get((*s, "calibration"), 0)} for s in strata}, satisfied, detail)


def _check_cnt_001(
    manifest: dict[str, Any], completed: list[dict[str, Any]], lock_doc: dict[str, Any] | None
) -> ConformanceFinding:
    locked = None
    if lock_doc is not None:
        locked = ((lock_doc.get("lock") or {}).get("locked_per_cell_count"))
    benign_min = max(manifest["min_confirmatory_benign_per_cell"], locked or 0)
    scenario_min = max(manifest["min_confirmatory_scenario_per_cell"], locked or 0)

    effective_manifest = dict(manifest)
    effective_manifest["min_confirmatory_benign_per_cell"] = benign_min
    effective_manifest["min_confirmatory_scenario_per_cell"] = scenario_min
    cells = required_cells(effective_manifest)

    benign_counts: dict[str, int] = {}
    scenario_counts: dict[str, int] = {}
    for trial in completed:
        version = trial.get("workload_id")
        ground_truth = trial.get("ground_truth") or {}
        if not bool(ground_truth.get("attack_like")):
            key = f"{version}|{trial.get('mode')}"
            benign_counts[key] = benign_counts.get(key, 0) + 1
        scenario_id = trial.get("scenario_id")
        if scenario_id in manifest["runtime_scenario_ids"]:
            key = f"{version}|{scenario_id}"
            scenario_counts[key] = scenario_counts.get(key, 0) + 1

    failing_benign = {
        key: benign_counts.get(key, 0) for key, minimum in cells["benign_cells"].items() if benign_counts.get(key, 0) < minimum
    }
    failing_scenario = {
        key: scenario_counts.get(key, 0) for key, minimum in cells["scenario_cells"].items() if scenario_counts.get(key, 0) < minimum
    }

    satisfied = not failing_benign and not failing_scenario
    detail_parts = [f"effective per-cell minimum: benign={benign_min}, scenario={scenario_min}"]
    if locked:
        detail_parts.append(f"raised above the protocol default by the sample-size lock's locked_per_cell_count={locked}")
    if failing_benign:
        detail_parts.append(f"benign cell(s) below minimum: {failing_benign}")
    if failing_scenario:
        detail_parts.append(f"scenario cell(s) below minimum: {failing_scenario}")
    if not failing_benign and not failing_scenario:
        detail_parts.append("every required cell meets its minimum count")

    return _finding(
        "CONF-CNT-001",
        {"benign_min": benign_min, "scenario_min": scenario_min},
        {"failing_benign_cells": failing_benign, "failing_scenario_cells": failing_scenario},
        satisfied,
        "; ".join(detail_parts),
    )


def _check_des_001(run_manifest: dict[str, Any] | None, lock_path: Path | None) -> ConformanceFinding:
    required = "an ART-DES-001 lock with reviewer_approval_status='approved' whose created_at_utc predates the run's own created_at_utc"
    if lock_path is None:
        return _finding(
            "CONF-DES-001", required, None, False,
            "no sample-size lock artifact exists yet at "
            f"{sample_size.DEFAULT_LOCK_DIR}/sample-size-lock*.json",
        )
    try:
        lock_doc = load_json(lock_path)
    except ArtifactError as exc:
        return _finding("CONF-DES-001", required, str(lock_path), False, f"lock file unreadable: {exc}")

    problems: list[str] = []
    status = lock_doc.get("reviewer_approval_status")
    if status != "approved":
        problems.append(f"reviewer_approval_status is {status!r}, not 'approved'")

    lock_created = lock_doc.get("created_at_utc")
    run_created = (run_manifest or {}).get("created_at_utc")
    if run_created is None:
        problems.append("the run has no created_at_utc (missing or unreadable run.json); cannot verify the lock predates it")
    elif lock_created is None:
        problems.append("the lock has no created_at_utc")
    else:
        try:
            lock_dt = datetime.fromisoformat(lock_created)
            run_dt = datetime.fromisoformat(run_created)
        except ValueError:
            problems.append("lock or run created_at_utc is not a parseable ISO-8601 timestamp")
        else:
            if not lock_dt < run_dt:
                problems.append(
                    f"lock created_at_utc ({lock_created}) does not predate the run's "
                    f"created_at_utc ({run_created}) -- a lock computed after (or during) the run "
                    "it gates could not have constrained the collection it claims to govern"
                )

    satisfied = not problems
    detail = "; ".join(problems) if problems else "the lock is approved and predates this run"
    return _finding("CONF-DES-001", required, {"status": status, "created_at_utc": lock_created}, satisfied, detail)


def _check_rev_001() -> ConformanceFinding:
    review_gate = _load_review_gate()
    state = review_gate.gate_state()
    satisfied = bool(state.get("confirmatory_permitted"))
    detail = (
        "scripts/review_gate.py:gate_state()['confirmatory_permitted'] is true" if satisfied
        else "confirmatory_permitted is false: waiting_on="
        f"{state.get('waiting_on')}, independence={state.get('independence')}"
    )
    return _finding("CONF-REV-001", True, state.get("confirmatory_permitted"), satisfied, detail)


def _check_env_001(run_dir: Path) -> ConformanceFinding:
    path = run_dir / "environment.json"
    if not path.is_file():
        return _finding("CONF-ENV-001", "environment.json present in the run directory", False, False, f"missing {path}")
    try:
        doc = load_json(path)
    except ArtifactError as exc:
        return _finding("CONF-ENV-001", True, False, False, f"environment.json is not valid JSON: {exc}")
    schema_ok = isinstance(doc, dict) and doc.get("schema_version") == ENVIRONMENT_SCHEMA_VERSION
    detail = (
        "environment.json is present with the expected schema_version" if schema_ok
        else f"environment.json is present but its schema_version is {doc.get('schema_version') if isinstance(doc, dict) else None!r}, expected {ENVIRONMENT_SCHEMA_VERSION!r}"
    )
    return _finding("CONF-ENV-001", True, schema_ok, schema_ok, detail)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def check_run_conformance(
    run_dir: Path, *, manifest: dict[str, Any] | None = None, lock_path: Path | None = None
) -> ConformanceReport:
    """Evaluate every CONF-* check against `run_dir`. Purely read-only: never
    writes to `run_dir` or anywhere else, and never starts a container."""
    run_dir = Path(run_dir)
    manifest = manifest if manifest is not None else load_protocol_manifest()
    run_manifest = _load_run_manifest(run_dir)
    images_manifest = _load_images_manifest(run_dir)
    trials = _load_trial_records(run_dir)
    completed = [t for t in trials if t.get("status") == "completed"]

    resolved_lock_path = _resolve_lock_path(lock_path)
    lock_doc: dict[str, Any] | None = None
    if resolved_lock_path is not None:
        try:
            lock_doc = load_json(resolved_lock_path)
        except ArtifactError:
            lock_doc = None

    findings = [
        _check_scn_001(manifest, completed),
        _check_scn_002(manifest, completed),
        _check_ver_001(manifest, completed, images_manifest),
        _check_mode_001(manifest, completed),
        _check_hn_001(manifest, completed),
        _check_gt_001(completed),
        _check_rep_001(manifest, completed),
        _check_fit_001(manifest, completed),
        _check_cnt_001(manifest, completed, lock_doc),
        _check_des_001(run_manifest, resolved_lock_path),
        _check_rev_001(),
        _check_env_001(run_dir),
    ]

    failing_ids = [f.check_id for f in findings if not f.satisfied]
    run_id = (run_manifest or {}).get("run_id") or run_dir.name
    return ConformanceReport(
        run_id=run_id,
        protocol_sha256=manifest["protocol_sha256"],
        findings=findings,
        satisfied=not failing_ids,
        failing_check_ids=failing_ids,
    )


def report_to_dict(report: ConformanceReport) -> dict[str, Any]:
    return dataclasses.asdict(report)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _print_table(report: ConformanceReport) -> None:
    print(f"run_id           : {report.run_id}")
    print(f"protocol_sha256  : {report.protocol_sha256}")
    print(f"{'CHECK':<16} {'STATUS':<8} DETAIL")
    for finding in report.findings:
        status = "PASS" if finding.satisfied else "FAIL"
        print(f"{finding.check_id:<16} {status:<8} {finding.detail}")
    print()
    print(f"satisfied        : {report.satisfied}")
    if report.failing_check_ids:
        print(f"failing checks   : {', '.join(report.failing_check_ids)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = check_run_conformance(args.run_dir)
    if args.json:
        print(json.dumps(report_to_dict(report), indent=2, default=str))
    else:
        _print_table(report)
    return 0 if report.satisfied else 1


if __name__ == "__main__":
    sys.exit(main())
