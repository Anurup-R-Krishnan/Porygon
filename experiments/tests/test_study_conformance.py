"""Tests for the conformance-gated evidence class (experiments/study.py) and the
accurate, review-gate-driven refusal in experiments/run.py:confirmatory().

Both are defense-in-depth: no real confirmatory collection path exists in this
codebase yet, so neither of these is reachable from a real run today. That is
exactly what makes them easy to get subtly wrong -- there is no live traffic to
catch a mistake -- so the guarantees are pinned down here instead:

  - a `confirmatory` evidence-class label can only ever be narrowed to `pilot`,
    never the reverse, by either the run's own `research_eligible` flag or the
    full protocol-conformance gate;
  - `confirmatory()` always refuses, and always says exactly why.
"""
from __future__ import annotations

import json
import types
from pathlib import Path

import pytest

from experiments import conformance, run, sample_size, study
from experiments.artifacts import ArtifactError, atomic_write_json


def _build_pilot_run(run_dir: Path, run_id: str) -> None:
    """A minimal, real-shaped pilot run directory, same shape as
    test_study_manifest.py's helper of the same name."""
    (run_dir / "trials").mkdir(parents=True)
    atomic_write_json(
        run_dir / "run.json",
        {
            "schema_version": "porygon.experiment.run.v2",
            "run_id": run_id,
            "kind": "real_container_pilot",
            "research_eligible": False,
        },
    )
    trial = {
        "schema_version": "porygon.experiment.trial.v2",
        "run_id": run_id,
        "trial_id": "t-1",
        "workload_id": "WL-NGX-V1",
        "human_tag": "nginx:1.26.3-alpine",
        "mode": "steady_http",
        "scenario_id": "SCN-EXEC",
        "context_variant": "baseline",
        "replica_index": 1,
        "status": "completed",
        "research_eligible": False,
        "runtime_context_hash": "a" * 64,
        "image": {"reference": "nginx@sha256:" + "b" * 64},
        "load": {
            "operations_planned": 2, "successes": 2, "failures": 0,
            "latency_ms_samples": [1.0, 2.0], "harness_induced_exec_count": 0,
        },
        "reconciliation": {
            "generated": 1,
            "boundaries": {
                "generator": {"status": "measured", "observed": 1, "missing_sequences": []},
            },
        },
    }
    atomic_write_json(run_dir / "trials" / "t-1.json", trial)
    run._write_pilot_summary(run_dir / "summary.csv", [trial])
    run._write_manifest(run_dir, run_id, "pilot_only", "trials/")


# ---------------------------------------------------------------------------
# Task 1: evidence class narrows on a failing conformance gate, never widens
# ---------------------------------------------------------------------------


def test_evidence_class_narrows_to_pilot_when_conformance_fails_despite_declared_eligibility(
    tmp_path, monkeypatch
) -> None:
    """run.json says research_eligible=True, but the run's own directory would fail the
    protocol-conformance gate (e.g. no sample-size lock exists). The label must narrow
    to pilot -- a bare declaration in run.json is not sufficient by itself."""
    run_dir = tmp_path / "would-be-confirmatory"
    run_dir.mkdir()
    atomic_write_json(run_dir / "run.json", {"run_id": "run-x", "research_eligible": True})

    failing_report = conformance.ConformanceReport(
        run_id="run-x",
        protocol_sha256="deadbeef",
        findings=[
            conformance.ConformanceFinding(
                check_id="CONF-DES-001",
                required="an approved sample-size lock",
                observed=None,
                satisfied=False,
                detail="no sample-size lock artifact exists yet",
            ),
        ],
        satisfied=False,
        failing_check_ids=["CONF-DES-001"],
    )
    monkeypatch.setattr(study.conformance, "check_run_conformance", lambda run_dir: failing_report)

    assert study._run_evidence_class(run_dir) == ("pilot", False)


def test_evidence_class_stays_pilot_when_run_json_says_ineligible_even_if_conformance_would_pass(
    tmp_path, monkeypatch
) -> None:
    """run.json already says research_eligible=False. Even mocking the conformance
    check to report full satisfaction must not widen the label -- and the check must
    not even be consulted, since run.json's own flag already settles it."""
    run_dir = tmp_path / "pilot-declared"
    run_dir.mkdir()
    atomic_write_json(run_dir / "run.json", {"run_id": "run-y", "research_eligible": False})

    def _must_not_be_called(run_dir_arg):
        raise AssertionError("check_run_conformance must not be consulted when run.json already says ineligible")

    monkeypatch.setattr(study.conformance, "check_run_conformance", _must_not_be_called)

    assert study._run_evidence_class(run_dir) == ("pilot", False)


def test_evidence_class_narrows_to_pilot_when_conformance_check_itself_errors(tmp_path, monkeypatch) -> None:
    """An unevaluable conformance gate (e.g. it raises) must be treated exactly like a
    failed one -- uncertainty must never resolve in favour of the stronger claim."""
    run_dir = tmp_path / "unevaluable"
    run_dir.mkdir()
    atomic_write_json(run_dir / "run.json", {"run_id": "run-z", "research_eligible": True})

    def _boom(run_dir_arg):
        raise RuntimeError("protocol manifest could not be parsed")

    monkeypatch.setattr(study.conformance, "check_run_conformance", _boom)

    assert study._run_evidence_class(run_dir) == ("pilot", False)


# ---------------------------------------------------------------------------
# Task 1: the conformance stage's findings land in the written study manifest
# ---------------------------------------------------------------------------


def test_conformance_stage_findings_land_in_the_study_manifest(tmp_path, monkeypatch) -> None:
    run_id = "study-conformance-fixture"
    run_dir = tmp_path / run_id
    _build_pilot_run(run_dir, run_id)
    monkeypatch.setattr(study, "STUDY_ROOT", tmp_path)
    monkeypatch.setattr(study, "ROOT", tmp_path)

    fake_report = conformance.ConformanceReport(
        run_id=run_id,
        protocol_sha256="cafebabe",
        findings=[
            conformance.ConformanceFinding(
                check_id="CONF-ENV-001",
                required=True,
                observed=False,
                satisfied=False,
                detail="environment.json is missing from this synthetic fixture",
            ),
            conformance.ConformanceFinding(
                check_id="CONF-GT-001",
                required="ground_truth.expected_outcome present on every completed trial",
                observed=0,
                satisfied=True,
                detail="every completed trial records an explicit ground_truth.expected_outcome",
            ),
        ],
        satisfied=False,
        failing_check_ids=["CONF-ENV-001"],
    )
    monkeypatch.setattr(study.conformance, "check_run_conformance", lambda rd: fake_report)

    def fake_collect(ctx):
        ctx["run_dir"] = run_dir
        ctx["trial_count"] = 1
        return {"run_dir": str(run_dir)}

    monkeypatch.setattr(
        study, "STAGES",
        [study.Stage("collection", fake_collect), study.Stage("conformance", study.stage_conformance, required=False)],
    )

    path = study.run_study(run_id=run_id)
    manifest = json.loads(path.read_text(encoding="utf-8"))

    conformance_stage = next(s for s in manifest["stages"] if s["name"] == "conformance")
    assert conformance_stage["status"] == "passed"
    findings = conformance_stage["result"]["findings"]
    check_ids = {f["check_id"] for f in findings}
    assert check_ids == {"CONF-ENV-001", "CONF-GT-001"}
    env_finding = next(f for f in findings if f["check_id"] == "CONF-ENV-001")
    assert env_finding["satisfied"] is False
    assert env_finding["detail"] == "environment.json is missing from this synthetic fixture"
    assert conformance_stage["result"]["satisfied"] is False
    assert conformance_stage["result"]["failing_check_ids"] == ["CONF-ENV-001"]

    # The conformance stage is required=False and this run.json still declares
    # research_eligible=False, so the run's own label stays pilot regardless.
    assert manifest["evidence_class"] == "pilot"


# ---------------------------------------------------------------------------
# Task 2: run.py's confirmatory() always refuses, with specific reasons
# ---------------------------------------------------------------------------


def test_confirmatory_reports_specific_blocking_reasons_from_the_live_review_gate() -> None:
    """Against the real, current state of this repository's review gate, confirmatory()
    must still refuse -- and its message must name the actual blocker (today: the two
    reviews are not independent) rather than a generic string."""
    with pytest.raises(ArtifactError) as excinfo:
        run.confirmatory(run.ROOT / "docs/RESEARCH_PROTOCOL_V1.md")
    message = str(excinfo.value)
    assert message.startswith("confirmatory collection is refused:")
    assert "independence" in message.lower()


def test_confirmatory_always_refuses_even_when_the_review_gate_is_fully_satisfied(monkeypatch) -> None:
    """Even a hypothetical fully-satisfied review gate must not make confirmatory()
    actually run anything -- no real confirmatory runner exists, and that refusal is
    deliberate, not a side effect of an unmet review gate."""
    fake_module = types.SimpleNamespace(
        gate_state=lambda: {
            "confirmatory_permitted": True,
            "protocol_status": "frozen",
            "approval_problems": {"security": [], "methodology": []},
            "independence": {"independent": True, "reason": "reviewers are distinct"},
        }
    )
    monkeypatch.setattr(sample_size, "_load_review_gate", lambda: fake_module)
    with pytest.raises(ArtifactError, match="no real confirmatory collection path exists"):
        run.confirmatory(run.ROOT / "docs/RESEARCH_PROTOCOL_V1.md")


def test_confirmatory_surfaces_every_specific_approval_problem(monkeypatch) -> None:
    fake_module = types.SimpleNamespace(
        gate_state=lambda: {
            "confirmatory_permitted": False,
            "protocol_status": "review_pending",
            "approval_problems": {
                "security": ["reviewer_name is empty or still the placeholder"],
                "methodology": ["date is not a real parseable YYYY-MM-DD date"],
            },
            "independence": {"independent": True, "reason": "reviewers are distinct"},
        }
    )
    monkeypatch.setattr(sample_size, "_load_review_gate", lambda: fake_module)
    with pytest.raises(ArtifactError) as excinfo:
        run.confirmatory(run.ROOT / "docs/RESEARCH_PROTOCOL_V1.md")
    message = str(excinfo.value)
    assert "security review: reviewer_name is empty or still the placeholder" in message
    assert "methodology review: date is not a real parseable YYYY-MM-DD date" in message
    assert "protocol_status is 'review_pending', not 'frozen'" in message
    # A fully satisfied independence check must not itself be reported as a problem.
    assert "reviewer independence:" not in message


def test_confirmatory_surfaces_non_independence_as_the_blocker_when_reviews_are_otherwise_clean(
    monkeypatch,
) -> None:
    fake_module = types.SimpleNamespace(
        gate_state=lambda: {
            "confirmatory_permitted": False,
            "protocol_status": "frozen",
            "approval_problems": {"security": [], "methodology": []},
            "independence": {
                "independent": False,
                "reason": "security and methodology reviews name the same reviewer ('Jane Doe')",
            },
        }
    )
    monkeypatch.setattr(sample_size, "_load_review_gate", lambda: fake_module)
    with pytest.raises(ArtifactError) as excinfo:
        run.confirmatory(run.ROOT / "docs/RESEARCH_PROTOCOL_V1.md")
    message = str(excinfo.value)
    assert "reviewer independence: security and methodology reviews name the same reviewer ('Jane Doe')" in message
