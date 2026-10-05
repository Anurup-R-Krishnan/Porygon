"""Integrity manifest for the profile-scope protocol's published result tables.

`build_results_manifest` hashes every table/figure artifact under a results
directory (default: `artifacts/experiments/protocol-v1/tables/`) together with
enough provenance to detect later drift or silent corruption: the frozen
research protocol document's own sha256 and recorded version, the git commit
the manifest was built from, and -- for every hashed JSON file that records
its own source run (every `analyze_scope_run.py` / `context_delta.py` output
does, via a top-level `"source_run"` field) -- that run's id.

`verify_results_manifest` re-hashes the same directory against a previously
written manifest and returns a list of every mismatch found; an empty list
means every recorded file still matches exactly what the manifest recorded.

The manifest itself is written through `experiments.artifacts.write_versioned_json`,
so it gets the same atomicity/immutability/secret-scanning guarantee as every
other experiment artifact: a manifest that has already been completed for a
given set of table contents can never be silently rewritten in place, only
versioned forward.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from experiments.artifacts import (
    ArtifactError,
    load_json,
    sha256_file,
    versioned_artifact_paths,
    write_versioned_json,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "docs" / "RESEARCH_PROTOCOL_V1.md"
DEFAULT_TABLES_DIR = ROOT / "artifacts" / "experiments" / "protocol-v1" / "tables"
MANIFEST_STEM = "results-manifest"


def _git_sha() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _protocol_sha256(protocol_path: Path) -> str | None:
    if not protocol_path.is_file():
        return None
    return sha256_file(protocol_path)


def _protocol_version(protocol_path: Path) -> str | None:
    """Best-effort: RESEARCH_PROTOCOL_V1.md records its own version as a line
    like "Document version: `1.0.0-frozen`" near the top of the file."""
    if not protocol_path.is_file():
        return None
    for line in protocol_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("document version"):
            return stripped.split(":", 1)[1].strip().strip("`") if ":" in stripped else None
    return None


def _source_run_id(path: Path) -> str | None:
    """A hashed JSON table that records its own source_run names the run it was
    computed from; anything else (a non-JSON figure, a CSV, a malformed/secret-
    bearing JSON file that load_json refuses) has none discoverable here."""
    if path.suffix != ".json":
        return None
    try:
        value = load_json(path)
    except ArtifactError:
        return None
    if isinstance(value, dict):
        source_run = value.get("source_run")
        if isinstance(source_run, str):
            return source_run
    return None


def _is_manifest_file(path: Path) -> bool:
    return path.name == MANIFEST_STEM or path.name.startswith(f"{MANIFEST_STEM}.")


def _iter_hashable_files(analysis_dir: Path) -> list[Path]:
    """Every regular file under analysis_dir, recursively, excluding the
    manifest itself (and any of its prior versions) so the manifest never
    hashes its own contents."""
    return [
        path
        for path in sorted(analysis_dir.rglob("*"))
        if path.is_file() and not _is_manifest_file(path)
    ]


def build_results_manifest(analysis_dir: Path = DEFAULT_TABLES_DIR) -> dict[str, Any]:
    """Hash every table/figure artifact under analysis_dir plus provenance metadata."""
    if not analysis_dir.is_dir():
        raise ArtifactError(f"results directory does not exist: {analysis_dir}")

    files: dict[str, dict[str, Any]] = {}
    for path in _iter_hashable_files(analysis_dir):
        rel = str(path.relative_to(analysis_dir).as_posix())
        files[rel] = {
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
            "source_run": _source_run_id(path),
        }

    protocol_path_display = (
        str(PROTOCOL_PATH.relative_to(ROOT).as_posix()) if PROTOCOL_PATH.is_absolute() else str(PROTOCOL_PATH)
    )
    return {
        "schema_version": "porygon.results-manifest.v1",
        "analysis_dir": str(analysis_dir.relative_to(ROOT).as_posix()) if analysis_dir.is_relative_to(ROOT) else str(analysis_dir),
        "git_sha": _git_sha(),
        "protocol_path": protocol_path_display,
        "protocol_version": _protocol_version(PROTOCOL_PATH),
        "protocol_sha256": _protocol_sha256(PROTOCOL_PATH),
        "files": files,
    }


def _load_latest_manifest(analysis_dir: Path) -> dict[str, Any]:
    versions = versioned_artifact_paths(analysis_dir, MANIFEST_STEM)
    if not versions:
        raise ArtifactError(f"no {MANIFEST_STEM}.json found under {analysis_dir}")
    return load_json(versions[-1])


def verify_results_manifest(
    analysis_dir: Path = DEFAULT_TABLES_DIR, manifest: dict[str, Any] | None = None
) -> list[str]:
    """Re-hash analysis_dir and report every mismatch against a manifest.

    If `manifest` is not given, the latest on-disk `<MANIFEST_STEM>[.vN].json`
    inside analysis_dir is loaded. Returns a list of human-readable mismatch
    descriptions; an empty list means every recorded file still matches
    exactly what the manifest recorded, and nothing extra has appeared.
    """
    if manifest is None:
        manifest = _load_latest_manifest(analysis_dir)

    problems: list[str] = []
    recorded: dict[str, Any] = manifest.get("files", {})
    current = {str(path.relative_to(analysis_dir).as_posix()): path for path in _iter_hashable_files(analysis_dir)}

    for rel, meta in recorded.items():
        path = current.get(rel)
        if path is None:
            problems.append(f"missing file recorded in manifest: {rel}")
            continue
        actual = sha256_file(path)
        expected = meta.get("sha256") if isinstance(meta, dict) else None
        if actual != expected:
            problems.append(f"hash mismatch for {rel}: manifest={expected} actual={actual}")

    for rel in current:
        if rel not in recorded:
            problems.append(f"file present on disk but not recorded in manifest: {rel}")

    return problems


def write_results_manifest(analysis_dir: Path = DEFAULT_TABLES_DIR) -> Path:
    """Build the manifest and write it through the versioned artifact writer."""
    manifest = build_results_manifest(analysis_dir)
    return write_versioned_json(analysis_dir, MANIFEST_STEM, manifest)


if __name__ == "__main__":
    import json
    import sys

    target = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_TABLES_DIR
    written = write_results_manifest(target)
    print(json.dumps({"wrote": str(written)}, indent=2))
