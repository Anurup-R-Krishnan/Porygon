from __future__ import annotations

import json
from pathlib import Path

import pytest

from experiments.artifacts import ArtifactError
from experiments.results_manifest import (
    build_results_manifest,
    verify_results_manifest,
    write_results_manifest,
)


def _tables_dir(tmp_path: Path) -> Path:
    tables = tmp_path / "tables"
    tables.mkdir()
    (tables / "profile-scope-primary.json").write_text(
        json.dumps({"schema_version": "porygon.profile-scope-analysis.v1", "source_run": "run-abc"}),
        encoding="utf-8",
    )
    (tables / "context-delta-finding.json").write_text(
        json.dumps({"schema_version": "porygon.context-delta-exploratory.v1", "source_run": "run-xyz"}),
        encoding="utf-8",
    )
    (tables / "notes.txt").write_text("not json\n", encoding="utf-8")
    return tables


def test_build_results_manifest_hashes_every_file_and_records_source_run(tmp_path) -> None:
    tables = _tables_dir(tmp_path)
    manifest = build_results_manifest(tables)

    assert manifest["schema_version"] == "porygon.results-manifest.v1"
    assert set(manifest["files"]) == {"profile-scope-primary.json", "context-delta-finding.json", "notes.txt"}
    assert manifest["files"]["profile-scope-primary.json"]["source_run"] == "run-abc"
    assert manifest["files"]["context-delta-finding.json"]["source_run"] == "run-xyz"
    assert manifest["files"]["notes.txt"]["source_run"] is None
    # Provenance: the frozen protocol document is real and hashed/versioned.
    assert manifest["protocol_sha256"] is not None
    assert len(manifest["protocol_sha256"]) == 64
    assert manifest["protocol_version"] is not None
    assert isinstance(manifest["git_sha"], str) and manifest["git_sha"]


def test_build_results_manifest_rejects_a_missing_directory(tmp_path) -> None:
    with pytest.raises(ArtifactError):
        build_results_manifest(tmp_path / "does-not-exist")


def test_verify_results_manifest_is_clean_immediately_after_building(tmp_path) -> None:
    tables = _tables_dir(tmp_path)
    manifest = build_results_manifest(tables)
    assert verify_results_manifest(tables, manifest=manifest) == []


def test_verify_results_manifest_detects_tampering(tmp_path) -> None:
    tables = _tables_dir(tmp_path)
    manifest = build_results_manifest(tables)

    (tables / "notes.txt").write_text("silently changed\n", encoding="utf-8")

    problems = verify_results_manifest(tables, manifest=manifest)
    assert len(problems) == 1
    assert "notes.txt" in problems[0]
    assert "hash mismatch" in problems[0]


def test_verify_results_manifest_detects_a_missing_file(tmp_path) -> None:
    tables = _tables_dir(tmp_path)
    manifest = build_results_manifest(tables)

    (tables / "notes.txt").unlink()

    problems = verify_results_manifest(tables, manifest=manifest)
    assert any("missing file" in p and "notes.txt" in p for p in problems)


def test_verify_results_manifest_detects_an_unrecorded_new_file(tmp_path) -> None:
    tables = _tables_dir(tmp_path)
    manifest = build_results_manifest(tables)

    (tables / "new-figure.json").write_text("{}\n", encoding="utf-8")

    problems = verify_results_manifest(tables, manifest=manifest)
    assert any("not recorded in manifest" in p and "new-figure.json" in p for p in problems)


def test_write_results_manifest_uses_the_versioned_artifact_writer(tmp_path) -> None:
    tables = _tables_dir(tmp_path)

    first = write_results_manifest(tables)
    assert first.name == "results-manifest.json"
    original_content = json.loads(first.read_text(encoding="utf-8"))
    # The manifest never hashes itself.
    assert "results-manifest.json" not in original_content["files"]

    # Idempotent: same table contents produce a no-op re-write, not a new version.
    second = write_results_manifest(tables)
    assert second == first

    # A real change to a tracked table produces a new manifest version, leaving the
    # original manifest file untouched (the same immutability guarantee every other
    # experiment artifact gets from write_versioned_json).
    (tables / "notes.txt").write_text("changed\n", encoding="utf-8")
    third = write_results_manifest(tables)
    assert third.name == "results-manifest.v2.json"
    assert json.loads(first.read_text(encoding="utf-8")) == original_content


def test_verify_results_manifest_loads_the_latest_written_version_by_default(tmp_path) -> None:
    tables = _tables_dir(tmp_path)
    write_results_manifest(tables)
    assert verify_results_manifest(tables) == []

    (tables / "notes.txt").write_text("changed\n", encoding="utf-8")
    problems = verify_results_manifest(tables)
    assert any("hash mismatch" in p for p in problems)
