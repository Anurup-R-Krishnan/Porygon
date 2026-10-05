from __future__ import annotations

import copy
import json

import pytest

from experiments import environment


# --------------------------------------------------------------------------
# Every individual probe must never raise, and must degrade honestly.
# --------------------------------------------------------------------------

PROBE_FUNCTIONS = (
    environment.kernel_fingerprint,
    environment.falco_ruleset_fingerprint,
    environment.service_image_fingerprint,
    environment.scoring_config_fingerprint,
    environment.code_fingerprint,
)


@pytest.mark.parametrize("probe", PROBE_FUNCTIONS, ids=[fn.__name__ for fn in PROBE_FUNCTIONS])
def test_probe_never_raises(probe):
    result = probe()
    assert isinstance(result, dict)


def _statuses(node) -> list[str]:
    """Every "status" value found anywhere in a fingerprint document."""
    found = []
    if isinstance(node, dict):
        if "status" in node:
            found.append(node["status"])
        for value in node.values():
            found.extend(_statuses(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_statuses(item))
    return found


@pytest.mark.parametrize("probe", PROBE_FUNCTIONS, ids=[fn.__name__ for fn in PROBE_FUNCTIONS])
def test_probe_only_declares_measured_or_unavailable(probe):
    statuses = _statuses(probe())
    assert statuses, "expected at least one status-bearing node"
    assert set(statuses) <= {"measured", "unavailable"}


def test_unavailable_nodes_always_carry_a_reason():
    def walk(node):
        if isinstance(node, dict):
            if node.get("status") == "unavailable":
                assert isinstance(node.get("reason"), str) and node["reason"]
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(environment.run_environment())


def test_kernel_fingerprint_is_measured_in_this_environment():
    # This host genuinely has /sys/kernel/btf and /sys/fs/cgroup, so the probe should
    # succeed here rather than degrade -- a silently-swallowed exception would also
    # look like "unavailable", so this pins down the happy path too.
    result = environment.kernel_fingerprint()
    assert result["status"] == "measured"
    assert result["kernel_release"]
    assert result["cgroup_version"] in ("v1", "v2")
    assert isinstance(result["btf_present"], bool)


def test_falco_ruleset_hash_is_measured_from_the_repo_falco_directory():
    result = environment.falco_ruleset_fingerprint()
    assert result["ruleset"]["status"] == "measured"
    assert "porygon_rules.yaml" in result["ruleset"]["files"]
    # image fingerprint is best-effort: it must still be one of the two honest states
    assert result["image"]["status"] in ("measured", "unavailable")


def test_service_image_fingerprint_has_an_entry_per_service_and_never_fails_wholesale(monkeypatch):
    # Force every docker call to fail, simulating an unreachable daemon; the function
    # must still return one entry per service, each degraded, rather than raising.
    def _boom(*args, **kwargs):
        raise OSError("docker daemon unreachable")

    monkeypatch.setattr(environment, "_run", _boom)
    result = environment.service_image_fingerprint()
    assert set(result) == set(environment.SERVICE_NAMES)
    for entry in result.values():
        assert entry["status"] == "unavailable"
        assert entry["reason"]


def test_scoring_config_fingerprint_degrades_when_backend_is_not_importable(monkeypatch):
    def _boom():
        raise ModuleNotFoundError("no porygon_api on this host")

    monkeypatch.setattr(environment, "_import_scoring_module", _boom)
    result = environment.scoring_config_fingerprint()
    assert result["config_constant"]["status"] == "unavailable"
    assert result["config_constant"]["reason"]
    # the plain file hashes are independent of the import and should still measure
    assert all(entry["status"] == "measured" for entry in result["files"].values())


def test_scoring_config_fingerprint_degrades_per_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(environment, "BACKEND_SRC", tmp_path)
    result = environment.scoring_config_fingerprint()
    for entry in result["files"].values():
        assert entry["status"] == "unavailable"
    assert result["config_constant"]["status"] == "unavailable"


def test_code_fingerprint_hashes_experiments_and_reuses_git_probes(monkeypatch):
    monkeypatch.setattr(environment, "_git_sha", lambda: "deadbeef")
    monkeypatch.setattr(environment, "_git_dirty", lambda: True)
    result = environment.code_fingerprint()
    assert result["git_sha"] == "deadbeef"
    assert result["git_dirty"] is True
    assert result["experiments_py"]["status"] == "measured"
    assert result["experiments_py"]["file_count"] > 0


def test_code_fingerprint_degrades_when_the_directory_cannot_be_hashed(monkeypatch, tmp_path):
    missing = tmp_path / "does-not-exist"
    monkeypatch.setattr(environment, "EXPERIMENTS_DIR", missing)
    result = environment.code_fingerprint()
    assert result["experiments_py"]["status"] == "unavailable"
    assert result["experiments_py"]["reason"]


def test_git_probes_degrade_instead_of_raising(monkeypatch):
    def _boom(*args, **kwargs):
        raise OSError("git not installed")

    monkeypatch.setattr(environment, "_run", _boom)
    assert environment._git_sha() == "unknown"
    assert environment._git_dirty() is True


# --------------------------------------------------------------------------
# run_environment / environment_hash
# --------------------------------------------------------------------------


def test_run_environment_has_the_expected_top_level_shape():
    document = environment.run_environment()
    assert document["schema_version"] == environment.SCHEMA_VERSION
    assert document["captured_at_utc"]
    for key in ("kernel", "falco_ruleset", "service_images", "scoring_config", "code"):
        assert key in document


def test_environment_hash_requires_the_declared_schema_version():
    document = environment.run_environment() | {"schema_version": "other.v9"}
    with pytest.raises(ValueError):
        environment.environment_hash(document)


def test_environment_hash_is_deterministic_and_order_stable():
    document = environment.run_environment()
    reordered = json.loads(json.dumps(dict(reversed(list(document.items())))))
    # Reverse nested dict key order too, to be sure sort_keys is doing the work.
    def reverse_keys(node):
        if isinstance(node, dict):
            return {key: reverse_keys(node[key]) for key in reversed(list(node))}
        if isinstance(node, list):
            return [reverse_keys(item) for item in node]
        return node

    reordered = reverse_keys(document)
    assert environment.environment_hash(document) == environment.environment_hash(reordered)
    assert environment.environment_hash(document) == environment.environment_hash(copy.deepcopy(document))


# --------------------------------------------------------------------------
# compare_environments
# --------------------------------------------------------------------------


def test_compare_environments_reports_no_differences_for_identical_documents():
    document = environment.run_environment()
    assert environment.compare_environments(document, copy.deepcopy(document)) == []


def test_compare_environments_names_a_differing_measured_field():
    a = environment.run_environment()
    b = copy.deepcopy(a)
    b["kernel"] = {**b["kernel"], "status": "measured", "kernel_release": "6.1.0-fake"}
    a["kernel"] = {**a["kernel"], "status": "measured", "kernel_release": "5.15.0-fake"}
    diffs = environment.compare_environments(a, b)
    assert any("kernel.kernel_release" in item and "5.15.0-fake" in item and "6.1.0-fake" in item for item in diffs)


def test_compare_environments_does_not_false_flag_when_one_side_is_unavailable():
    a = environment.run_environment()
    b = copy.deepcopy(a)
    a["falco_ruleset"]["image"] = {"status": "unavailable", "reason": "docker unreachable on run a"}
    b["falco_ruleset"]["image"] = {"status": "measured", "reference": "falcosecurity/falco:0.44.1@sha256:deadbeef"}
    diffs = environment.compare_environments(a, b)
    assert not any(item.startswith("falco_ruleset.image") for item in diffs)


def test_compare_environments_flags_a_service_image_digest_drift():
    a = environment.run_environment()
    b = copy.deepcopy(a)
    a["service_images"]["backend"] = {
        "status": "measured", "reference": "porygon-backend:latest",
        "image_id": "sha256:aaaa", "repo_digests": [],
    }
    b["service_images"]["backend"] = {
        "status": "measured", "reference": "porygon-backend:latest",
        "image_id": "sha256:bbbb", "repo_digests": [],
    }
    diffs = environment.compare_environments(a, b)
    assert any("service_images.backend.image_id" in item for item in diffs)


def test_compare_environments_ignores_both_sides_unavailable():
    a = environment.run_environment()
    b = copy.deepcopy(a)
    a["scoring_config"]["config_constant"] = {"status": "unavailable", "reason": "x"}
    b["scoring_config"]["config_constant"] = {"status": "unavailable", "reason": "y"}
    diffs = environment.compare_environments(a, b)
    assert not any(item.startswith("scoring_config.config_constant") for item in diffs)
