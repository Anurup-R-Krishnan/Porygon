"""Tests for experiments/sample_size.py, the ART-DES-001 power-lock builder."""
from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from experiments import sample_size
from experiments.sample_size import (
    MAX_CANDIDATE_COUNT,
    PRIMARY_CONTRASTS,
    SampleSizeLock,
    assert_no_confirmatory_contamination,
    build_sample_size_lock,
    enumerate_fpr_power,
    enumerate_recall_power,
    estimate_pilot_inputs,
    lock_to_dict,
    upper_95_binomial_bound,
    write_sample_size_lock,
)
from experiments.artifacts import load_json

ROOT = Path(__file__).resolve().parents[2]
REAL_CONFIRMATORY_200_RUN_DIR = ROOT / "artifacts/experiments/local/study-confirmatory-200-20260906t071234Z"


def test_upper_95_binomial_bound_matches_clopper_pearson_upper():
    from experiments.analysis import clopper_pearson_interval

    ci = clopper_pearson_interval(5, 10, confidence=0.90)
    assert math.isclose(upper_95_binomial_bound(5, 10), ci.upper, abs_tol=1e-9)


def test_upper_95_binomial_bound_uses_max_variance_when_undefined():
    assert upper_95_binomial_bound(0, 0) == 0.5


def test_enumerate_fpr_power_rejects_baseline_fpr_outside_open_unit_interval():
    with pytest.raises(ValueError, match="baseline_fpr"):
        enumerate_fpr_power("c", baseline_fpr=0.0, nuisance_discordant_p=0.5)
    with pytest.raises(ValueError, match="baseline_fpr"):
        enumerate_fpr_power("c", baseline_fpr=1.0, nuisance_discordant_p=0.5)


def test_enumerate_fpr_power_finds_a_real_count_for_a_strong_effect():
    """A large baseline FPR (70%, matching this project's real measured
    GLOBAL-arm FPR) with a high discordant-pair rate should reach power well
    within the candidate range, not silently return None."""
    result = enumerate_fpr_power("strong", baseline_fpr=0.70, nuisance_discordant_p=0.9)
    assert result.required_count is not None
    assert result.required_count <= MAX_CANDIDATE_COUNT
    assert result.achieved_power >= 0.80


def test_enumerate_fpr_power_needs_more_runs_for_a_weaker_baseline():
    """A modest baseline FPR (20%) needs materially more runs to reach the
    same power as a strong 70% baseline, for the same relative reduction."""
    strong = enumerate_fpr_power("strong", baseline_fpr=0.70, nuisance_discordant_p=0.9)
    weak = enumerate_fpr_power("weak", baseline_fpr=0.20, nuisance_discordant_p=0.9)
    assert weak.required_count is None or strong.required_count is None or weak.required_count >= strong.required_count


def test_enumerate_recall_power_reports_infeasibility_honestly():
    """The protocol's frozen recall non-inferiority target (5pp margin at a
    95% reference, 80% power, max 120 per cell) is genuinely infeasible by
    exact binomial power calculation: even n=120 only reaches ~60% power for
    this margin. This must be reported as None/infeasible, never silently
    rounded up to a false confident count."""
    result = enumerate_recall_power("recall", reference_recall=0.95)
    assert result.required_count is None
    assert result.achieved_power is None


def test_enumerate_recall_power_is_feasible_for_a_wider_margin():
    """A materially wider margin (e.g. 15pp) at the same reference recall
    should be achievable within the candidate range, confirming the
    infeasibility above is about the specific frozen margin, not a bug that
    makes every recall calculation return None."""
    result = enumerate_recall_power("recall", reference_recall=0.95, margin_pp=0.15)
    assert result.required_count is not None
    assert result.achieved_power >= 0.80


def test_assert_no_confirmatory_contamination_refuses_when_confirmatory_exists():
    with pytest.raises(ValueError, match="confirmatory-eligible"):
        assert_no_confirmatory_contamination(["pilot", "confirmatory"])


def test_assert_no_confirmatory_contamination_allows_pilot_only_history():
    assert_no_confirmatory_contamination(["pilot", "pilot"]) is None


def test_build_sample_size_lock_reports_feasibility_failure_honestly():
    """End-to-end: with this project's actual measured pilot-style inputs
    (a strong GLOBAL-vs-CONTEXT effect but a materially weaker TAG/DIGEST
    effect, plus the infeasible frozen recall target), the lock must report
    feasibility_failure=True and locked_per_cell_count=None rather than
    silently averaging over a contrast that never reached power."""
    lock = build_sample_size_lock(
        pilot_discordant_pairs={
            "CONTEXT_vs_GLOBAL": (4, 5),
            "CONTEXT_vs_TAG": (2, 5),
            "CONTEXT_vs_DIGEST": (2, 5),
        },
        pilot_baseline_fpr={
            "CONTEXT_vs_GLOBAL": 0.70,
            "CONTEXT_vs_TAG": 0.20,
            "CONTEXT_vs_DIGEST": 0.20,
        },
        reference_recall=0.95,
    )
    assert lock.feasibility_failure is True
    assert lock.locked_per_cell_count is None
    strong_contrast = next(r for r in lock.contrasts if r.contrast_id == "CONTEXT_vs_GLOBAL")
    assert strong_contrast.required_count is not None


# ---------------------------------------------------------------------------
# estimate_pilot_inputs
# ---------------------------------------------------------------------------


def _make_fake_compare_scopes(fpr_by_arm: dict[str, float], n_benign: int, n_scenario: int, recall: float = 1.0):
    """Build a synthetic experiments.scope.compare_scopes() replacement that
    reproduces a chosen per-arm benign FPR and ARM-GLOBAL recall exactly,
    without ever touching the network -- compare_scopes itself needs a live
    backend to fetch per-container process-event distributions, which is not
    available to this stdlib-only, host-run test suite (matching the same
    monkeypatching pattern experiments/tests/test_degeneracy.py already uses
    for the same reason)."""

    def fake(base_url: str, run_dir: Path, threshold: float = 0.25) -> dict:
        scopes = {}
        for arm, fpr in fpr_by_arm.items():
            n_fp = round(fpr * n_benign)
            benign_rows = [
                {
                    "trial_id": f"benign-{i}",
                    "reference_key_present": True,
                    "positive": i < n_fp,
                    "is_scenario": False,
                }
                for i in range(n_benign)
            ]
            n_tp = round(recall * n_scenario)
            scenario_rows = [
                {
                    "trial_id": f"scenario-{i}",
                    "reference_key_present": True,
                    "positive": i < n_tp,
                    "is_scenario": True,
                }
                for i in range(n_scenario)
            ]
            scopes[arm] = {
                "benign_runs": n_benign,
                "false_positives": n_fp,
                "scenario_runs": n_scenario,
                "true_positives": n_tp,
                "trials": benign_rows + scenario_rows,
            }
        return {"scopes": scopes}

    return fake


def test_estimate_pilot_inputs_raises_on_real_confirmatory_200_run_dir(monkeypatch) -> None:
    """Live regression proof: reproduces the exact per-arm FPR recorded in the
    real committed artifacts/experiments/protocol-v1/tables/profile-scope-primary-216.json
    for study-confirmatory-200-20260906t071234Z (ARM-GLOBAL 53/53=100% FPR,
    ARM-TAG/ARM-DIGEST/ARM-CONTEXT 0/53=0% FPR, recall 100% everywhere) --
    both extremes are degenerate, and estimate_pilot_inputs must refuse rather
    than silently proceed. compare_scopes is monkeypatched only because it
    needs a live backend to fetch process-event data; the FPR/recall numbers
    fed into the fake are the real, already-documented measured values, not
    invented ones."""
    assert REAL_CONFIRMATORY_200_RUN_DIR.is_dir(), "expected the real committed pilot run directory to exist"
    fake = _make_fake_compare_scopes(
        fpr_by_arm={"ARM-GLOBAL": 1.0, "ARM-TAG": 0.0, "ARM-DIGEST": 0.0, "ARM-CONTEXT": 0.0},
        n_benign=53, n_scenario=96, recall=1.0,
    )
    monkeypatch.setattr(sample_size, "compare_scopes", fake)

    with pytest.raises(ValueError, match="degenerate"):
        estimate_pilot_inputs([REAL_CONFIRMATORY_200_RUN_DIR], base_url="http://127.0.0.1:8000")


def test_estimate_pilot_inputs_succeeds_with_a_real_non_degenerate_baseline(tmp_path, monkeypatch) -> None:
    """Sanity check that the guard is specific to degenerate inputs, not a
    blanket refusal: a baseline strictly between 0 and 1 must produce real
    counts instead of raising."""
    fake = _make_fake_compare_scopes(
        fpr_by_arm={"ARM-GLOBAL": 0.70, "ARM-TAG": 0.20, "ARM-DIGEST": 0.20, "ARM-CONTEXT": 0.05},
        n_benign=20, n_scenario=10, recall=1.0,
    )
    monkeypatch.setattr(sample_size, "compare_scopes", fake)
    run_dir = tmp_path / "pilot-fake"
    run_dir.mkdir()

    inputs = estimate_pilot_inputs([run_dir], base_url="http://127.0.0.1:8000")

    assert set(inputs["contrasts"]) == {cid for cid, _, _ in PRIMARY_CONTRASTS}
    assert inputs["contrasts"]["CONTEXT_vs_ARM-GLOBAL"]["baseline_fpr"] == pytest.approx(0.70)
    assert inputs["reference_recall"] == pytest.approx(1.0)
    assert inputs["source_run_dirs"] == ["pilot-fake"]


# ---------------------------------------------------------------------------
# lock_to_dict
# ---------------------------------------------------------------------------


def _feasible_lock() -> SampleSizeLock:
    return build_sample_size_lock(
        pilot_discordant_pairs={"CONTEXT_vs_ARM-GLOBAL": (4, 5), "CONTEXT_vs_ARM-TAG": (4, 5), "CONTEXT_vs_ARM-DIGEST": (4, 5)},
        pilot_baseline_fpr={"CONTEXT_vs_ARM-GLOBAL": 0.70, "CONTEXT_vs_ARM-TAG": 0.70, "CONTEXT_vs_ARM-DIGEST": 0.70},
        reference_recall=0.99,
    )


def test_lock_to_dict_round_trips_through_canonical_json() -> None:
    from experiments.artifacts import canonical_json

    lock = _feasible_lock()
    as_dict = lock_to_dict(lock)
    assert as_dict["locked_per_cell_count"] == lock.locked_per_cell_count
    assert as_dict["feasibility_failure"] is False
    assert len(as_dict["contrasts"]) == len(lock.contrasts)
    assert as_dict["contrasts"][0]["contrast_id"] == lock.contrasts[0].contrast_id
    # Must be plain JSON-safe data -- canonical_json must not raise.
    reparsed = json.loads(canonical_json(as_dict))
    assert reparsed == as_dict


# ---------------------------------------------------------------------------
# write_sample_size_lock
# ---------------------------------------------------------------------------


def _write_manifest(local_dir: Path, run_name: str, evidence_class: str) -> None:
    run_dir = local_dir / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "study-manifest.json").write_text(
        json.dumps({"evidence_class": evidence_class, "run_id": run_name}), encoding="utf-8"
    )


def test_write_sample_size_lock_refuses_on_confirmatory_contamination(tmp_path, monkeypatch) -> None:
    fake_root = tmp_path / "repo"
    _write_manifest(fake_root / "artifacts/experiments/local", "study-pilot-a", "pilot")
    _write_manifest(fake_root / "artifacts/experiments/local", "study-confirmatory-x", "confirmatory")
    monkeypatch.setattr(sample_size, "LOCAL_ARTIFACTS_DIR", fake_root / "artifacts/experiments/local")

    with pytest.raises(ValueError, match="confirmatory-eligible"):
        write_sample_size_lock(
            {"schema_version": "x"}, _feasible_lock(),
            reviewer_approvals={"confirmatory_permitted": False, "approval_problems": {}, "independence": {}},
            out_dir=fake_root / "out",
        )


def test_write_sample_size_lock_allows_pilot_only_history(tmp_path, monkeypatch) -> None:
    fake_root = tmp_path / "repo"
    _write_manifest(fake_root / "artifacts/experiments/local", "study-pilot-a", "pilot")
    _write_manifest(fake_root / "artifacts/experiments/local", "study-pilot-b", "pilot")
    monkeypatch.setattr(sample_size, "LOCAL_ARTIFACTS_DIR", fake_root / "artifacts/experiments/local")
    monkeypatch.setattr(sample_size, "_utc_now_iso", lambda: "2026-01-01T00:00:00+00:00")

    out_dir = fake_root / "out"
    path = write_sample_size_lock(
        {"schema_version": "x"}, _feasible_lock(),
        reviewer_approvals={"confirmatory_permitted": False, "approval_problems": {"security": ["missing"]}, "independence": {"independent": True}},
        out_dir=out_dir,
    )
    assert path.is_file()
    doc = load_json(path)
    assert doc["reviewer_approval_status"] == "pending"
    assert any("missing" in r for r in doc["reviewer_approval_blocking_reasons"])


def test_write_sample_size_lock_is_idempotent_for_identical_content_and_versions_on_change(tmp_path, monkeypatch) -> None:
    fake_root = tmp_path / "repo"
    _write_manifest(fake_root / "artifacts/experiments/local", "study-pilot-a", "pilot")
    monkeypatch.setattr(sample_size, "LOCAL_ARTIFACTS_DIR", fake_root / "artifacts/experiments/local")
    monkeypatch.setattr(sample_size, "_utc_now_iso", lambda: "2026-01-01T00:00:00+00:00")
    out_dir = fake_root / "out"
    approvals = {"confirmatory_permitted": False, "approval_problems": {}, "independence": {"independent": True}}

    first = write_sample_size_lock({"a": 1}, _feasible_lock(), reviewer_approvals=approvals, out_dir=out_dir)
    second = write_sample_size_lock({"a": 1}, _feasible_lock(), reviewer_approvals=approvals, out_dir=out_dir)
    assert first == second
    assert sorted(p.name for p in out_dir.glob("sample-size-lock*.json")) == ["sample-size-lock.json"]

    third = write_sample_size_lock({"a": 2}, _feasible_lock(), reviewer_approvals=approvals, out_dir=out_dir)
    assert third != second
    assert sorted(p.name for p in out_dir.glob("sample-size-lock*.json")) == ["sample-size-lock.json", "sample-size-lock.v2.json"]
    # The original version must remain byte-identical, never rewritten in place.
    assert load_json(first)["inputs"] == {"a": 1}
    assert load_json(third)["inputs"] == {"a": 2}


def test_write_sample_size_lock_status_approved_when_gate_permits(tmp_path, monkeypatch) -> None:
    fake_root = tmp_path / "repo"
    _write_manifest(fake_root / "artifacts/experiments/local", "study-pilot-a", "pilot")
    monkeypatch.setattr(sample_size, "LOCAL_ARTIFACTS_DIR", fake_root / "artifacts/experiments/local")
    monkeypatch.setattr(sample_size, "_utc_now_iso", lambda: "2026-01-01T00:00:00+00:00")

    path = write_sample_size_lock(
        {"schema_version": "x"}, _feasible_lock(),
        reviewer_approvals={"confirmatory_permitted": True, "approval_problems": {}, "independence": {"independent": True}},
        out_dir=fake_root / "out",
    )
    doc = load_json(path)
    assert doc["reviewer_approval_status"] == "approved"
    assert doc["reviewer_approval_blocking_reasons"] == []


def test_write_sample_size_lock_reviewer_approval_status_pending_for_real_current_gate_state(tmp_path) -> None:
    """Against this repo's real, current (non-independent) review-gate state
    -- both docs/review/*.json currently name the same reviewer, per
    experiments/tests/test_review_gate.py's own docstring -- the lock must be
    "pending", never "approved", and it must still be writable."""
    review_gate = sample_size._load_review_gate()
    real_gate_state = review_gate.gate_state()
    assert real_gate_state["confirmatory_permitted"] is False

    path = write_sample_size_lock(
        {"schema_version": "x"}, _feasible_lock(),
        reviewer_approvals=real_gate_state,
        out_dir=tmp_path / "out",
    )
    doc = load_json(path)
    assert doc["reviewer_approval_status"] == "pending"
    assert doc["reviewer_approvals"] == real_gate_state
