from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from experiments.artifacts import ArtifactError, atomic_write_json
from experiments.context import (
    SCHEMA_VERSION,
    argv_shape,
    context_hash,
    runtime_context,
)

DOC = Path(__file__).resolve().parents[2] / "docs/PROFILE_SCOPE_EXPERIMENT_V1.md"


def _doc_example(name: str) -> dict:
    """Read a canonical example straight from the specification so the test cannot drift."""
    match = re.search(rf"```json {name}\n(.*?)```", DOC.read_text(encoding="utf-8"), re.DOTALL)
    assert match, f"canonical example {name} is missing from {DOC.name}"
    return json.loads(match.group(1))


def test_specification_examples_agree_with_the_implementation():
    equivalent_a = _doc_example("context-example-equivalent-a")
    equivalent_b = _doc_example("context-example-equivalent-b")
    security_change = _doc_example("context-example-security-change")
    assert context_hash(equivalent_a) == context_hash(equivalent_b)
    assert context_hash(security_change) != context_hash(equivalent_a)


def test_hash_requires_the_declared_schema_version():
    document = _doc_example("context-example-equivalent-a") | {"schema_version": "other.v9"}
    with pytest.raises(ValueError):
        context_hash(document)


def test_argv_shape_keeps_structure_and_drops_every_literal_value():
    shape = argv_shape(["/usr/sbin/nginx", "-g", "daemon off;", "--port", "8080", "/etc/nginx.conf"])
    assert shape == [
        "exe:nginx",
        "flag:-g",
        "<flag-value>",
        "flag:--port",
        "<flag-value>",
        "<path>",
    ]
    assert "daemon off;" not in shape
    assert "8080" not in shape


def test_argv_shape_redacts_secret_bearing_flags():
    assert argv_shape(["app", "--password", "hunter2"]) == [
        "exe:app",
        "flag:<secret>",
        "<secret-value>",
    ]
    assert argv_shape(["app", "--api-key=abc123"]) == ["exe:app", "flag:<secret>", "<secret-value>"]


def test_redaction_placeholders_survive_the_secret_scanner(tmp_path):
    """The placeholders prove redaction happened; rejecting them would be a false positive."""
    document = runtime_context(
        {"Config": {"Cmd": ["app", "--token", "abc"]}, "HostConfig": {}, "Mounts": []}
    )
    assert document["command_shape"] == ["exe:app", "flag:<secret>", "<secret-value>"]
    atomic_write_json(tmp_path / "context.json", document)


def test_real_secret_values_are_still_rejected(tmp_path):
    with pytest.raises(ArtifactError):
        atomic_write_json(tmp_path / "leak.json", {"note": "postgres_password=hunter2"})


def test_missing_fields_are_explicit_rather_than_assumed():
    document = runtime_context({"Config": {}, "HostConfig": {}})
    assert document["schema_version"] == SCHEMA_VERSION
    assert document["entrypoint_shape"] == "missing"
    assert document["configured_user"] == "missing"
    assert document["privileged"] == "missing"
    assert document["mounts"] == "missing"
    assert document["capabilities"] == {"add": [], "drop": []}


def test_reordered_collections_produce_one_hash():
    base = {
        "schema_version": SCHEMA_VERSION,
        "entrypoint_shape": ["exe:a"],
        "command_shape": ["exe:a"],
        "configured_user": "root",
        "privileged": False,
        "read_only_rootfs": False,
        "network_mode": "bridge",
        "capabilities": {"add": ["CHOWN", "SETUID"], "drop": []},
        "devices": [],
        "ports": [],
        "mounts": [
            {"destination": "/b", "type": "bind", "read_only": True},
            {"destination": "/a", "type": "volume", "read_only": False},
        ],
    }
    reordered = base | {
        "capabilities": {"drop": [], "add": ["SETUID", "CHOWN"]},
        "mounts": list(reversed(base["mounts"])),
    }
    assert context_hash(base) == context_hash(reordered)


def test_command_order_is_significant():
    first = {**runtime_context({"Config": {"Cmd": ["a", "-x", "1"]}, "HostConfig": {}, "Mounts": []})}
    second = {**runtime_context({"Config": {"Cmd": ["a", "1", "-x"]}, "HostConfig": {}, "Mounts": []})}
    assert context_hash(first) != context_hash(second)


def test_capability_prefix_is_normalised_across_docker_versions():
    prefixed = runtime_context(
        {"Config": {}, "HostConfig": {"CapDrop": ["CAP_NET_RAW"]}, "Mounts": []}
    )
    bare = runtime_context({"Config": {}, "HostConfig": {"CapDrop": ["net_raw"]}, "Mounts": []})
    assert prefixed["capabilities"]["drop"] == ["NET_RAW"]
    assert context_hash(prefixed) == context_hash(bare)


def test_tmpfs_is_part_of_the_runtime_context():
    without = runtime_context({"Config": {}, "HostConfig": {}, "Mounts": []})
    with_tmpfs = runtime_context(
        {"Config": {}, "HostConfig": {"Tmpfs": {"/scratch": ""}}, "Mounts": []}
    )
    assert {"destination": "/scratch", "type": "tmpfs", "read_only": False} in with_tmpfs["mounts"]
    assert context_hash(without) != context_hash(with_tmpfs)


def test_network_mode_keeps_its_security_class_not_its_ephemeral_name():
    from experiments.context import normalise_network_mode

    assert normalise_network_mode("host") == "host"
    assert normalise_network_mode("none") == "none"
    assert normalise_network_mode("bridge") == "bridge"
    assert normalise_network_mode("default") == "bridge"
    assert normalise_network_mode("container:abc123") == "container"
    assert normalise_network_mode("porygon-exp-run-a") == "user-defined"
    assert normalise_network_mode(None) == "missing"


def test_two_identical_deployments_share_one_identity_across_runs():
    """A per-run network name must not fragment the context strata.

    If it did, no stratum would ever reach its minimum fit-run count and the
    digest-plus-context arm would return insufficient_profile forever.
    """
    def deployment(network):
        return runtime_context({
            "Config": {"Cmd": ["nginx", "-g", "daemon off;"], "ExposedPorts": {"80/tcp": {}}},
            "HostConfig": {
                "NetworkMode": network,
                "PortBindings": {"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": ""}]},
                "Privileged": False,
            },
            "Mounts": [],
        })

    run_a = deployment("porygon-exp-pilot-20260905a")
    run_b = deployment("porygon-exp-pilot-20260905b")
    assert run_a["network_mode"] == "user-defined"
    assert context_hash(run_a) == context_hash(run_b)


def test_a_real_network_class_change_still_changes_the_identity():
    def deployment(network):
        return runtime_context(
            {"Config": {}, "HostConfig": {"NetworkMode": network}, "Mounts": []}
        )

    assert context_hash(deployment("bridge")) != context_hash(deployment("host"))
    assert context_hash(deployment("host")) != context_hash(deployment("none"))
