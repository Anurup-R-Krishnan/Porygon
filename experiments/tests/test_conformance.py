"""Tests for experiments/conformance.py, the confirmatory-eligibility gate.

The most important property this file proves is negative: no amount of
collected trial data can ever satisfy the gate on its own. A synthetic run
that satisfies every scenario/version/mode/cell-count/replica/stratum
requirement is still correctly blocked when the ART-DES-001 sample-size lock
is missing, pending, or postdates the run, and separately when the two human
reviews are not independent of each other. Those two facts are asserted in
isolation from each other (each test mocks away the other gate so a failure
can only come from the one thing under test), and a regression test proves
the gate reports the right, complete set of failures against the actual
216-trial confirmatory run directory already committed to this repository.
"""
from __future__ import annotations

import json
from pathlib import Path

from experiments import conformance
from experiments.artifacts import assign_split

ROOT = Path(__file__).resolve().parents[2]
REAL_CONFIRMATORY_200_RUN_DIR = ROOT / "artifacts/experiments/local/study-confirmatory-200-20260906t071234Z"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tiny_manifest(
    *, min_benign: int = 3, min_scenario: int = 2, min_fit_cal: int = 2, min_replicas: int = 1
) -> dict:
    """A minimal, self-contained manifest so tests never need to satisfy the
    real protocol's full 3-family/2-version/4-mode/216+-trial surface just to
    exercise the gate logic. check_run_conformance is a pure function of
    whatever manifest it is handed, by design."""
    return {
        "protocol_id": "test.protocol",
        "protocol_status": "frozen",
        "protocol_sha256": "test-protocol-sha256",
        "workloads": [{"id": "WL-FAKE", "versions": ["WL-FAKE-V1"], "modes": ["steady"]}],
        "scenario_ids": ["SCN-EXEC"],
        "runtime_scenario_ids": ["SCN-EXEC"],
        "analysis_only_scenario_ids": [],
        "hard_negatives": {"WL-FAKE": []},
        "image_coordinates": {"WL-FAKE-V1": {"human_tag": "fake:1", "index_digest_ref": "fake@sha256:" + "a" * 64}},
        "min_replicas_per_split": min_replicas,
        "min_fit_calibration_per_stratum": min_fit_cal,
        "min_confirmatory_benign_per_cell": min_benign,
        "min_confirmatory_scenario_per_cell": min_scenario,
    }


def _write_trial(
    trials_dir: Path,
    trial_id: str,
    *,
    workload_id: str,
    mode: str,
    scenario_id: str,
    variant: str,
    replica_index: int,
    image_reference: str,
    attack_like: bool = False,
    status: str = "completed",
) -> None:
    record = {
        "trial_id": trial_id,
        "status": status,
        "workload_id": workload_id,
        "mode": mode,
        "scenario_id": scenario_id,
        "context_variant": variant,
        "replica_index": replica_index,
        "human_tag": "fake:1",
        "image": {"reference": image_reference},
        "ground_truth": {"expected_outcome": "controlled_positive", "attack_like": attack_like},
    }
    (trials_dir / f"{trial_id}.json").write_text(json.dumps(record), encoding="utf-8")


def _write_run_json(run_dir: Path, *, created_at_utc: str) -> None:
    (run_dir / "run.json").write_text(
        json.dumps({"run_id": run_dir.name, "created_at_utc": created_at_utc, "kind": "real_container_pilot"}),
        encoding="utf-8",
    )


def _write_environment_json(run_dir: Path) -> None:
    (run_dir / "environment.json").write_text(
        json.dumps({"schema_version": "porygon.run-environment.v1", "captured_at_utc": "2026-06-01T00:00:00+00:00"}),
        encoding="utf-8",
    )


def _write_lock(path: Path, *, status: str, created_at_utc: str, locked_per_cell_count: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "reviewer_approval_status": status,
                "created_at_utc": created_at_utc,
                "lock": {"locked_per_cell_count": locked_per_cell_count},
            }
        ),
        encoding="utf-8",
    )


def _build_fully_satisfying_run(tmp_path: Path, *, n_replicas: int = 30) -> Path:
    """A run directory that satisfies CONF-SCN-001, CONF-VER-001,
    CONF-MODE-001, CONF-HN-001 (vacuously -- the tiny manifest requires no
    hard negatives), CONF-GT-001, CONF-REP-001, CONF-FIT-001, and
    CONF-CNT-001 against `_tiny_manifest()`'s minimums, plus CONF-ENV-001.
    Only CONF-DES-001 and CONF-REV-001 are left for the calling test to
    control (via `lock_path` and a monkeypatched review gate).
    """
    run_dir = tmp_path / "study-fake-run"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    _write_run_json(run_dir, created_at_utc="2026-06-01T00:00:00+00:00")
    _write_environment_json(run_dir)

    for replica in range(1, n_replicas + 1):
        trial_id = f"wl-fake-v1-steady-scn-exec-baseline-r{replica:02d}"
        _write_trial(
            trials_dir, trial_id,
            workload_id="WL-FAKE-V1", mode="steady", scenario_id="SCN-EXEC", variant="baseline",
            replica_index=replica, image_reference="fake@sha256:" + "a" * 64,
        )
    return run_dir


# ---------------------------------------------------------------------------
# required_cells
# ---------------------------------------------------------------------------


def test_required_cells_expands_every_mode_and_runtime_scenario_combination():
    manifest = _tiny_manifest(min_benign=30, min_scenario=20)
    cells = conformance.required_cells(manifest)
    assert cells["benign_cells"] == {"WL-FAKE-V1|steady": 30}
    assert cells["scenario_cells"] == {"WL-FAKE-V1|SCN-EXEC": 20}


def test_required_cells_never_creates_a_cell_for_an_analysis_only_scenario():
    manifest = _tiny_manifest()
    manifest["analysis_only_scenario_ids"] = ["SCN-POISON"]
    manifest["runtime_scenario_ids"] = ["SCN-EXEC"]  # unchanged: analysis-only scenarios stay excluded from cells
    cells = conformance.required_cells(manifest)
    assert all("SCN-POISON" not in key for key in cells["scenario_cells"])


# ---------------------------------------------------------------------------
# load_protocol_manifest against the real, frozen protocol document
# ---------------------------------------------------------------------------


def test_load_protocol_manifest_reflects_the_real_frozen_protocol():
    manifest = conformance.load_protocol_manifest()
    assert manifest["protocol_status"] == "frozen"
    assert {w["id"] for w in manifest["workloads"]} == {"WL-NGX", "WL-RDS", "WL-PG"}
    for workload in manifest["workloads"]:
        assert len(workload["versions"]) == 2
        assert len(workload["modes"]) == 4
    assert set(manifest["scenario_ids"]) == {
        "SCN-EXEC", "SCN-LOW", "SCN-FLOOD", "SCN-CROSS", "SCN-CONTEXT", "SCN-POISON",
    }
    assert set(manifest["runtime_scenario_ids"]) == {"SCN-EXEC", "SCN-LOW", "SCN-FLOOD", "SCN-CONTEXT"}
    assert set(manifest["analysis_only_scenario_ids"]) == {"SCN-CROSS", "SCN-POISON"}
    assert set(manifest["hard_negatives"]) == {"WL-NGX", "WL-RDS", "WL-PG"}
    for family, items in manifest["hard_negatives"].items():
        assert len(items) == 4, f"{family} hard negatives: {items}"
    assert set(manifest["image_coordinates"]) == {
        "WL-NGX-V1", "WL-NGX-V2", "WL-RDS-V1", "WL-RDS-V2", "WL-PG-V1", "WL-PG-V2",
    }
    assert manifest["min_confirmatory_benign_per_cell"] == 30
    assert manifest["min_confirmatory_scenario_per_cell"] == 20
    assert manifest["min_fit_calibration_per_stratum"] == 10
    assert manifest["min_replicas_per_split"] == 3


# ---------------------------------------------------------------------------
# The real, committed 216-trial confirmatory run directory: a live regression
# proof, not synthetic data.
# ---------------------------------------------------------------------------


def test_real_216_trial_run_is_not_confirmatory_eligible():
    assert REAL_CONFIRMATORY_200_RUN_DIR.is_dir(), "expected the real committed run directory to exist"
    report = conformance.check_run_conformance(REAL_CONFIRMATORY_200_RUN_DIR)

    eligible, failing = conformance.confirmatory_eligible(report)
    assert eligible is False
    assert set(failing) == {
        "CONF-SCN-001",   # SCN-LOW/SCN-FLOOD/SCN-CONTEXT never collected
        "CONF-VER-001",   # only the *-V1 image versions were ever run
        "CONF-MODE-001",  # only each family's default mode was ever run
        "CONF-HN-001",    # no hard-negative trial data exists anywhere yet
        "CONF-REP-001",   # zero replicas for every *-V2 workload version
        "CONF-FIT-001",   # every observed stratum is far below 10 clean runs/split
        "CONF-CNT-001",   # every cell is far below the 30/20 minimums
        "CONF-DES-001",   # no ART-DES-001 sample-size lock has ever been written
        "CONF-REV-001",   # both reviews name the same reviewer (not independent)
        "CONF-ENV-001",   # this run predates experiments/environment.py
    }
    # CONF-SCN-002 and CONF-GT-001 must NOT be in the failing set: exploratory
    # scenario_ids are allowed to exist (informational only), and every
    # completed trial does carry an explicit ground-truth classification.
    assert "CONF-SCN-002" not in failing
    assert "CONF-GT-001" not in failing

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-SCN-002"].satisfied is True
    assert by_id["CONF-GT-001"].satisfied is True
    assert report.run_id == "study-confirmatory-200-20260906t071234Z"


# ---------------------------------------------------------------------------
# The single most important property: data volume alone can never satisfy
# the gate. Each test below isolates exactly one human/process gate
# (CONF-DES-001 or CONF-REV-001) by mocking the other one to a passing
# state, against an otherwise fully-satisfying synthetic run.
# ---------------------------------------------------------------------------


class _FakeReviewGate:
    def __init__(self, state: dict) -> None:
        self._state = state

    def gate_state(self) -> dict:
        return self._state


_INDEPENDENT_APPROVED_STATE = {
    "confirmatory_permitted": True,
    "waiting_on": [],
    "independence": {"independent": True, "reason": "reviewers are distinct", "names": {}},
}

_NOT_INDEPENDENT_STATE = {
    "confirmatory_permitted": False,
    "waiting_on": ["security", "methodology"],
    "independence": {
        "independent": False,
        "reason": "security and methodology reviews name the same reviewer ('Fake Reviewer')",
        "names": {"security": "Fake Reviewer", "methodology": "Fake Reviewer"},
    },
}


def _sanity_check_fully_satisfying(report: conformance.ConformanceReport, *, except_ids: set[str]) -> None:
    """Assert every check outside `except_ids` actually passed, so a failure
    inside `except_ids` cannot be explained away by some unrelated gap."""
    for finding in report.findings:
        if finding.check_id in except_ids:
            continue
        assert finding.satisfied is True, f"expected {finding.check_id} to pass but it did not: {finding.detail}"


def test_missing_sample_size_lock_blocks_confirmatory_eligibility_even_with_full_data(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))

    report = conformance.check_run_conformance(
        run_dir, manifest=_tiny_manifest(), lock_path=tmp_path / "no-such-lock.json",
    )

    assert report.satisfied is False
    assert "CONF-DES-001" in report.failing_check_ids
    assert "CONF-REV-001" not in report.failing_check_ids
    _sanity_check_fully_satisfying(report, except_ids={"CONF-DES-001"})


def test_pending_sample_size_lock_blocks_confirmatory_eligibility_even_with_full_data(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="pending", created_at_utc="2026-01-01T00:00:00+00:00")

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    assert report.satisfied is False
    assert "CONF-DES-001" in report.failing_check_ids
    assert "CONF-REV-001" not in report.failing_check_ids
    _sanity_check_fully_satisfying(report, except_ids={"CONF-DES-001"})


def test_non_independent_review_blocks_confirmatory_eligibility_even_with_full_data_and_an_approved_lock(
    tmp_path, monkeypatch
):
    run_dir = _build_fully_satisfying_run(tmp_path)
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_NOT_INDEPENDENT_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    # Approved and well before the run: CONF-DES-001 must pass here, isolating
    # the failure to CONF-REV-001 alone.
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00")

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    assert report.satisfied is False
    assert "CONF-REV-001" in report.failing_check_ids
    assert "CONF-DES-001" not in report.failing_check_ids
    _sanity_check_fully_satisfying(report, except_ids={"CONF-REV-001"})


def test_real_current_review_gate_state_is_not_independent_and_blocks_the_gate(tmp_path, monkeypatch):
    """Same proof, but against this repository's actual, current review-gate
    state rather than a mock -- as of this change both docs/review/*.json
    genuinely name the same reviewer (see experiments/tests/test_review_gate.py's
    own docstring), so the real gate_state() is itself a live example of a
    non-independent review blocking confirmatory eligibility."""
    run_dir = _build_fully_satisfying_run(tmp_path)
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00")

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    assert report.satisfied is False
    assert "CONF-REV-001" in report.failing_check_ids
    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-REV-001"].observed is False


# ---------------------------------------------------------------------------
# CONF-DES-001: a lock that exists but postdates the run it claims to gate.
# ---------------------------------------------------------------------------


def test_lock_created_after_the_run_started_fails_conf_des_001(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)  # created_at_utc = 2026-06-01
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-06-02T00:00:00+00:00")  # after the run

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-DES-001"].satisfied is False
    assert "does not predate" in by_id["CONF-DES-001"].detail
    assert "CONF-DES-001" in report.failing_check_ids


def test_lock_created_before_the_run_and_approved_satisfies_conf_des_001(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)  # created_at_utc = 2026-06-01
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00")  # before the run

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-DES-001"].satisfied is True
    assert report.satisfied is True, [f.check_id for f in report.findings if not f.satisfied]


# ---------------------------------------------------------------------------
# CONF-ENV-001
# ---------------------------------------------------------------------------


def test_run_missing_environment_json_fails_conf_env_001(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)
    (run_dir / "environment.json").unlink()
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00")

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-ENV-001"].satisfied is False
    assert "CONF-ENV-001" in report.failing_check_ids


def test_run_with_environment_json_present_satisfies_conf_env_001(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00")

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-ENV-001"].satisfied is True


# ---------------------------------------------------------------------------
# A few individual checks in isolation, to pin down edge-case behaviour.
# ---------------------------------------------------------------------------


def test_conf_hn_001_reports_zero_of_n_present_when_no_hard_negative_data_exists(tmp_path, monkeypatch):
    run_dir = _build_fully_satisfying_run(tmp_path)
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00")
    manifest = _tiny_manifest()
    manifest["hard_negatives"] = {"WL-FAKE": ["fixture_a", "fixture_b"]}

    report = conformance.check_run_conformance(run_dir, manifest=manifest, lock_path=lock_path)

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-HN-001"].satisfied is False
    assert by_id["CONF-HN-001"].observed == {"WL-FAKE": "0 of 2 present"}


def test_conf_ver_001_flags_a_digest_mismatch_against_the_pinned_coordinate(tmp_path, monkeypatch):
    run_dir = tmp_path / "study-bad-digest"
    trials_dir = run_dir / "trials"
    trials_dir.mkdir(parents=True)
    _write_run_json(run_dir, created_at_utc="2026-06-01T00:00:00+00:00")
    _write_environment_json(run_dir)
    for replica in range(1, 5):
        _write_trial(
            trials_dir, f"t-{replica}",
            workload_id="WL-FAKE-V1", mode="steady", scenario_id="SCN-EXEC", variant="baseline",
            replica_index=replica, image_reference="fake@sha256:" + "b" * 64,  # wrong digest
        )
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))

    report = conformance.check_run_conformance(
        run_dir, manifest=_tiny_manifest(), lock_path=tmp_path / "no-such-lock.json",
    )

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-VER-001"].satisfied is False
    assert "digest mismatch" in by_id["CONF-VER-001"].detail


def test_conf_cnt_001_uses_the_sample_size_locks_higher_count_when_present(tmp_path, monkeypatch):
    """The protocol's own rule: counts only ever increase. A lock whose
    locked_per_cell_count exceeds the tiny manifest's default minimums must
    raise the effective bar, so a run that cleared the manifest default can
    still correctly fail CONF-CNT-001 against the locked (higher) count."""
    run_dir = _build_fully_satisfying_run(tmp_path, n_replicas=5)  # clears min_benign=3/min_scenario=2 but not 50
    monkeypatch.setattr(conformance, "_load_review_gate", lambda: _FakeReviewGate(_INDEPENDENT_APPROVED_STATE))
    lock_path = tmp_path / "sample-size-lock.json"
    _write_lock(lock_path, status="approved", created_at_utc="2026-01-01T00:00:00+00:00", locked_per_cell_count=50)

    report = conformance.check_run_conformance(run_dir, manifest=_tiny_manifest(), lock_path=lock_path)

    by_id = {f.check_id: f for f in report.findings}
    assert by_id["CONF-CNT-001"].satisfied is False
    assert by_id["CONF-CNT-001"].required == {"benign_min": 50, "scenario_min": 50}


def test_confirmatory_eligible_is_exactly_report_satisfied_and_failing_ids():
    report = conformance.ConformanceReport(
        run_id="r", protocol_sha256="x",
        findings=[
            conformance.ConformanceFinding("CONF-A", True, True, True, "ok"),
            conformance.ConformanceFinding("CONF-B", True, False, False, "nope"),
        ],
        satisfied=False, failing_check_ids=["CONF-B"],
    )
    eligible, failing = conformance.confirmatory_eligible(report)
    assert eligible is False
    assert failing == ["CONF-B"]


def test_assign_split_is_reused_not_reimplemented():
    """Sanity check that experiments.conformance imports the real
    assign_split rather than a parallel reimplementation that could drift."""
    from experiments.conformance import assign_split as imported

    assert imported is assign_split
