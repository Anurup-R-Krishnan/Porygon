from __future__ import annotations

from porygon_collector.normalizer import normalize_event, select_primary_repo_digest
from porygon_collector.spool import OutboxStore


class FakeDockerAPI:
    def inspect_container(self, container_id: str):
        return {
            "Id": container_id,
            "Name": "/phase2-probe",
            "Created": "2026-07-21T10:00:00Z",
            "RestartCount": 0,
            "Platform": "linux",
            "Image": "sha256:image-id",
            "State": {"Status": "running", "Running": True, "Pid": 100},
            "Config": {
                "Image": "alpine:3.20",
                "User": "1000",
                "Cmd": ["sleep", "300"],
                "Entrypoint": None,
                "Labels": {"io.porygon.phase2.probe": "true"},
            },
            "HostConfig": {
                "Privileged": False,
                "ReadonlyRootfs": False,
                "NetworkMode": "bridge",
                "CapAdd": None,
                "CapDrop": None,
                "SecurityOpt": None,
                "Devices": None,
            },
            "NetworkSettings": {"Networks": {}},
            "Mounts": [],
        }

    def inspect_image(self, image_id: str):
        return {
            "Id": image_id,
            "RepoDigests": [
                "example/other@sha256:" + "b" * 64,
                "alpine@sha256:" + "a" * 64,
            ],
            "RepoTags": ["alpine:3.20"],
            "Os": "linux",
            "Architecture": "amd64",
        }


def test_digest_selection_prefers_matching_repository() -> None:
    expected = "alpine@sha256:" + "a" * 64
    assert select_primary_repo_digest(
        "docker.io/library/alpine:3.20",
        ["example/other@sha256:" + "b" * 64, expected],
    ) == expected


def test_normalization_is_deterministic_and_excludes_environment(tmp_path) -> None:
    store = OutboxStore(str(tmp_path / "outbox.db"), max_events=10)
    raw = {
        "Type": "container",
        "Action": "exec_start",
        "Actor": {
            "ID": "container-1",
            "Attributes": {
                "name": "phase2-probe",
                "image": "alpine:3.20",
                "execCommand": "sh -c echo porygon",
            },
        },
        "scope": "local",
        "time": 1784628000,
        "timeNano": 1784628000123456789,
    }

    first = normalize_event(FakeDockerAPI(), store, "daemon-1", raw)
    second = normalize_event(FakeDockerAPI(), store, "daemon-1", raw)

    assert first["event_id"] == second["event_id"]
    assert first["image_digest"] == "alpine@sha256:" + "a" * 64
    assert first["image_digest_status"] == "resolved"
    assert first["command"] == "sh -c echo porygon"
    assert "environment" not in first["container_snapshot"]["config"]


def test_exec_action_excludes_command_detail_but_preserves_raw_event(tmp_path) -> None:
    store = OutboxStore(str(tmp_path / "outbox.db"), max_events=10)
    command = "sh -c " + " ".join(["echo-safe"] * 100)
    raw = {
        "Type": "container",
        "Action": f"exec_start: {command}",
        "Actor": {
            "ID": "container-1",
            "Attributes": {
                "name": "phase2-probe",
                "image": "alpine:3.20",
            },
        },
        "scope": "local",
        "timeNano": 1784628000123456789,
    }

    event = normalize_event(FakeDockerAPI(), store, "daemon-1", raw)

    assert event["action"] == "exec_start"
    assert event["command"] == command
    assert event["raw_event"]["Action"] == raw["Action"]
    assert len(event["action"]) <= 64
