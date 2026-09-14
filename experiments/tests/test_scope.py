"""Tests for experiments/scope.py, the GLOBAL/TAG/DIGEST/CONTEXT comparison.

Network calls (fetch_process_name_distribution) are monkeypatched to fixed
distributions per container_id, so these tests exercise the real scoping,
splitting, and scoring logic without a live backend.
"""
from __future__ import annotations

import json

import pytest

from experiments import scope


def _write_trial(
    trials_dir,
    trial_id,
    *,
    container_id,
    image_ref,
    human_tag,
    context_hash,
    attack_like,
    status="completed",
):
    record = {
        "trial_id": trial_id,
        "container_id": container_id,
        "status": status,
        "image": {"reference": image_ref},
        "human_tag": human_tag,
        "runtime_context_hash": context_hash,
        "ground_truth": {"attack_like": attack_like},
    }
    (trials_dir / f"{trial_id}.json").write_text(json.dumps(record), encoding="utf-8")


@pytest.fixture
def fake_distributions(monkeypatch):
    """Map container_id -> process_name distribution, replacing the real
    HTTP fetch so tests never depend on a live backend."""
    store: dict[str, dict[str, float]] = {}

    def _fake_fetch(base_url, container_id, page_size=500):
        return dict(store.get(container_id, {}))

    monkeypatch.setattr(scope, "fetch_process_name_distribution", _fake_fetch)
    return store


def test_scope_key_matches_each_arm_definition():
    identity = scope.TrialIdentity(
        trial_id="t1", container_id="c1", image_digest="nginx@sha256:aaa",
        human_tag="nginx:1.26", runtime_context_hash="ctxhash1", split="fit", is_scenario=False,
    )
    assert scope.scope_key(identity, "ARM-GLOBAL") == "global"
    assert scope.scope_key(identity, "ARM-TAG") == "nginx:1.26"
    assert scope.scope_key(identity, "ARM-DIGEST") == "nginx@sha256:aaa"
    assert scope.scope_key(identity, "ARM-CONTEXT") == "nginx@sha256:aaa::ctxhash1"
    with pytest.raises(ValueError):
        scope.scope_key(identity, "ARM-NOT-REAL")


def test_load_trial_identities_skips_incomplete_trials(tmp_path):
    trials_dir = tmp_path / "trials"
    trials_dir.mkdir()
    _write_trial(trials_dir, "t-ok", container_id="c1", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)
    _write_trial(trials_dir, "t-failed", container_id="c2", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False, status="failed")

    identities = scope.load_trial_identities(tmp_path)
    assert [i.trial_id for i in identities] == ["t-ok"]


def test_load_trial_identities_reads_attack_like_as_is_scenario(tmp_path):
    trials_dir = tmp_path / "trials"
    trials_dir.mkdir()
    _write_trial(trials_dir, "benign", container_id="c1", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)
    _write_trial(trials_dir, "attack", container_id="c2", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=True)

    identities = {i.trial_id: i for i in scope.load_trial_identities(tmp_path)}
    assert identities["benign"].is_scenario is False
    assert identities["attack"].is_scenario is True


def test_fetch_process_name_distribution_rejects_page_size_above_backend_limit():
    with pytest.raises(ValueError, match="page_size"):
        scope.fetch_process_name_distribution("http://x", "c1", page_size=2000)


def test_compare_scopes_excludes_scenario_trials_from_the_fit_reference(tmp_path, fake_distributions):
    """Regression test for a real bug found while analysing a live 144-trial
    run: assign_split has no notion of scenario vs benign, so a scenario
    (attack-like) trial could land in the fit split by chance. If used to
    build the reference, attack-shaped processes (id, cat) contaminate
    "normal" and inflate JS distance on ordinary benign test trials,
    producing false positives that have nothing to do with scope. The fit
    set must only ever contain benign trials."""
    trials_dir = tmp_path / "trials"
    trials_dir.mkdir()

    # Two fit-eligible trials by hash: one benign, one (by bad luck) a
    # scenario. Both share the same image/tag/context so they'd normally
    # pool into the same DIGEST reference.
    fake_distributions["c-fit-benign"] = {"nginx": 1, "sh": 6, "head": 6}
    fake_distributions["c-fit-attack"] = {"nginx": 1, "sh": 6, "head": 6, "id": 6, "cat": 6}
    fake_distributions["c-test-benign"] = {"nginx": 1, "sh": 6, "head": 6}

    _write_trial(trials_dir, "fit-benign", container_id="c-fit-benign", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)
    _write_trial(trials_dir, "fit-attack", container_id="c-fit-attack", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=True)
    _write_trial(trials_dir, "test-benign", container_id="c-test-benign", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)

    # Force the split assignment deterministically via monkeypatching
    # assign_split so the test does not depend on real trial_id hashes
    # landing in a particular split by chance.
    import experiments.scope as scope_module

    def _fake_split(trial_id):
        return {"fit-benign": "fit", "fit-attack": "fit", "test-benign": "test"}[trial_id]

    orig_assign_split = scope_module.assign_split
    scope_module.assign_split = _fake_split
    try:
        result = scope.compare_scopes("http://x", tmp_path)
    finally:
        scope_module.assign_split = orig_assign_split

    digest_data = result["scopes"]["ARM-DIGEST"]
    # Only fit-benign should have contributed to the reference; the identical
    # test-benign distribution must score exactly zero distance and never be
    # a false positive.
    test_trial = next(t for t in digest_data["trials"] if t["trial_id"] == "test-benign")
    assert test_trial["js_distance"] == 0.0
    assert test_trial["positive"] is False
    assert digest_data["false_positives"] == 0


def test_score_trial_under_scope_reports_insufficient_profile_when_no_reference(fake_distributions):
    identity = scope.TrialIdentity(
        trial_id="t1", container_id="c-missing", image_digest="redis@sha256:bbb",
        human_tag="redis:7", runtime_context_hash="h9", split="test", is_scenario=False,
    )
    fake_distributions["c-missing"] = {"redis-server": 5}
    scored = scope.score_trial_under_scope("http://x", identity, "ARM-DIGEST", references={}, threshold=0.25)
    assert scored.reference_key_present is False
    assert scored.positive is False
    assert scored.js_distance is None


def test_score_trial_under_scope_uses_the_real_production_js_distance(fake_distributions):
    """Confirms this module scores using the exact same function the
    production anomaly scorer uses (backend/scoring.py), not a
    reimplementation that could silently drift from it."""
    identity = scope.TrialIdentity(
        trial_id="t1", container_id="c1", image_digest="nginx@sha256:aaa",
        human_tag="nginx:1.26", runtime_context_hash="h1", split="test", is_scenario=False,
    )
    fake_distributions["c1"] = {"a": 10}
    references = {"nginx@sha256:aaa": {"b": 10}}  # fully disjoint support -> distance 1.0
    scored = scope.score_trial_under_scope("http://x", identity, "ARM-DIGEST", references, threshold=0.25)
    assert scored.js_distance == 1.0
    assert scored.positive is True


# ---------------------------------------------------------------------------
# Split-leak regression tests (calibration must never pool into the scored
# test set) and MET-CAL-001 calibration-coverage tests.
# ---------------------------------------------------------------------------


def _write_three_split_run(trials_dir, fake_distributions):
    """One fit, one calibration, one test trial, all sharing a digest so they
    pool into the same ARM-DIGEST reference/coverage group."""
    fake_distributions["c-fit"] = {"nginx": 1, "sh": 6, "head": 6}
    fake_distributions["c-cal"] = {"nginx": 1, "sh": 6, "head": 6}
    fake_distributions["c-test"] = {"nginx": 1, "sh": 6, "head": 6}

    _write_trial(trials_dir, "fit-r01", container_id="c-fit", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)
    _write_trial(trials_dir, "cal-r01", container_id="c-cal", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)
    _write_trial(trials_dir, "test-r01", container_id="c-test", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)


def _force_split(monkeypatch, mapping):
    import experiments.scope as scope_module

    monkeypatch.setattr(scope_module, "assign_split", lambda trial_id: mapping[trial_id])


def test_compare_scopes_never_scores_a_calibration_trial_as_test(tmp_path, fake_distributions, monkeypatch):
    """Regression test for the calibration-into-test pooling bug: a
    calibration-split trial_id must never appear among the test-scored trials
    of any scope, and must be counted in calibration_trials instead."""
    trials_dir = tmp_path / "trials"
    trials_dir.mkdir()
    _write_three_split_run(trials_dir, fake_distributions)
    _force_split(monkeypatch, {"fit-r01": "fit", "cal-r01": "calibration", "test-r01": "test"})

    result = scope.compare_scopes("http://x", tmp_path)

    assert result["test_trials"] == 1
    assert result["calibration_trials"] == 1
    for scope_name in scope.SCOPES:
        scored_ids = {t["trial_id"] for t in result["scopes"][scope_name]["trials"]}
        assert "cal-r01" not in scored_ids
        assert scored_ids == {"test-r01"}


def test_calibration_coverage_returns_a_sane_interval(tmp_path, fake_distributions, monkeypatch):
    trials_dir = tmp_path / "trials"
    trials_dir.mkdir()
    _write_three_split_run(trials_dir, fake_distributions)
    _force_split(monkeypatch, {"fit-r01": "fit", "cal-r01": "calibration", "test-r01": "test"})

    result = scope.compare_scopes("http://x", tmp_path)

    coverage = result["scopes"]["ARM-DIGEST"]["calibration_coverage"]
    assert coverage["calibration_trials"] == 1
    assert coverage["alpha"] == scope.CALIBRATION_COVERAGE_ALPHA
    interval = coverage["coverage"]
    assert interval["trials"] == 1
    assert 0.0 <= interval["lower"] <= interval["upper"] <= 1.0
    # Identical distribution -> zero distance -> maximal p-value -> covered.
    assert coverage["covered"] == 1
    assert coverage["trials"][0]["status"] == "scored"
    assert coverage["trials"][0]["covered"] is True


def test_calibration_coverage_reports_drift_for_an_unseen_digest(tmp_path, fake_distributions, monkeypatch):
    """A calibration trial whose (digest, context_hash) never trained the
    scope's fit-split reference is drift, not an ordinary scored outcome, for
    any scope whose key still resolves (e.g. ARM-GLOBAL/ARM-TAG pool
    multiple digests into one reference key)."""
    trials_dir = tmp_path / "trials"
    trials_dir.mkdir()
    fake_distributions["c-fit"] = {"nginx": 1, "sh": 6}
    fake_distributions["c-cal-drift"] = {"nginx": 1, "sh": 6}
    _write_trial(trials_dir, "fit-r01", container_id="c-fit", image_ref="nginx@sha256:aaa",
                 human_tag="nginx:1.26", context_hash="h1", attack_like=False)
    _write_trial(trials_dir, "cal-r01", container_id="c-cal-drift", image_ref="nginx@sha256:bbb",
                 human_tag="nginx:1.26", context_hash="h2", attack_like=False)
    _force_split(monkeypatch, {"fit-r01": "fit", "cal-r01": "calibration"})

    result = scope.compare_scopes("http://x", tmp_path)

    # ARM-GLOBAL pools every digest into one "global" key, so cal-r01's key
    # resolves, but its own (digest, context_hash) never trained that key.
    global_coverage = result["scopes"]["ARM-GLOBAL"]["calibration_coverage"]
    assert global_coverage["drift_detected_runs"] == 1
    assert global_coverage["calibration_trials"] == 1
    row = global_coverage["trials"][0]
    assert row["status"] == "drift_detected"
    assert row["covered"] is False

    # ARM-DIGEST never even resolves a reference for the unseen digest.
    digest_coverage = result["scopes"]["ARM-DIGEST"]["calibration_coverage"]
    assert digest_coverage["insufficient_profile_runs"] == 1


def test_check_calibration_test_isolation_raises_on_container_id_collision():
    """The isolation check must be capable of catching a real cross-split
    leak: two records that share the same container_id (the real Docker
    runtime identity) but disagree on split is exactly that, and must raise
    -- unlike keying by trial_id, whose split is a pure function of itself
    and can never disagree with itself."""
    from experiments.artifacts import ArtifactError

    calibration = [
        scope.TrialIdentity(
            trial_id="cal-r01", container_id="shared-container", image_digest="nginx@sha256:aaa",
            human_tag="nginx:1.26", runtime_context_hash="h1", split="calibration", is_scenario=False,
        )
    ]
    test = [
        scope.TrialIdentity(
            trial_id="test-r01", container_id="shared-container", image_digest="nginx@sha256:aaa",
            human_tag="nginx:1.26", runtime_context_hash="h1", split="test", is_scenario=False,
        )
    ]
    with pytest.raises(ArtifactError, match="split leakage"):
        scope.check_calibration_test_isolation([], calibration, test)


def test_check_calibration_test_isolation_passes_when_containers_are_distinct():
    calibration = [
        scope.TrialIdentity(
            trial_id="cal-r01", container_id="c-cal", image_digest="nginx@sha256:aaa",
            human_tag="nginx:1.26", runtime_context_hash="h1", split="calibration", is_scenario=False,
        )
    ]
    test = [
        scope.TrialIdentity(
            trial_id="test-r01", container_id="c-test", image_digest="nginx@sha256:aaa",
            human_tag="nginx:1.26", runtime_context_hash="h1", split="test", is_scenario=False,
        )
    ]
    scope.check_calibration_test_isolation([], calibration, test)
