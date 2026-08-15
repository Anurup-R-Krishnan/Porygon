from porygon_telemetry.normalizer import normalize_falco_event


def _raw_event() -> dict[str, object]:
    return {
        "hostname": "porygon-falco",
        "output": "process execution",
        "priority": "Notice",
        "rule": "Porygon Container Process Execution",
        "source": "syscall",
        "tags": ["porygon", "phase3"],
        "time": "2026-07-21T10:00:00.123456789Z",
        "output_fields": {
            "evt.rawtime": 1784628000123456789,
            "evt.num": 42,
            "evt.type": "execve",
            "container.id": "0123456789ab",
            "container.name": "probe",
            "container.image.repository": "docker.io/library/alpine",
            "container.image.tag": "3.20",
            "proc.pid": 101,
            "proc.ppid": 100,
            "thread.vpid": 2,
            "proc.name": "sleep",
            "proc.exepath": "/bin/sleep",
            "proc.cmdline": "sleep 2",
            "proc.cwd": "/",
            "proc.tty": 0,
            "proc.pname": "sh",
            "proc.pexepath": "/bin/sh",
            "proc.pcmdline": "sh -c sleep 2",
            "user.uid": 0,
            "user.name": "root",
            "group.gid": 0,
            "group.name": "root",
        },
    }


def test_normalizer_is_deterministic_and_preserves_parent_context() -> None:
    first = normalize_falco_event(
        _raw_event(),
        sensor_instance_id="sensor-1",
        expected_rule="Porygon Container Process Execution",
        reported_docker_host_id=None,
    )
    second = normalize_falco_event(
        _raw_event(),
        sensor_instance_id="sensor-1",
        expected_rule="Porygon Container Process Execution",
        reported_docker_host_id=None,
    )

    assert first is not None and second is not None
    assert first["event_id"] == second["event_id"]
    assert first["reported_image_ref"] == "docker.io/library/alpine:3.20"
    assert first["process_ppid"] == 100
    assert first["parent_name"] == "sh"
    assert "proc.env" not in first["output_fields"]


def test_non_porygon_rule_is_ignored() -> None:
    event = _raw_event()
    event["rule"] = "Terminal shell in container"
    assert (
        normalize_falco_event(
            event,
            sensor_instance_id="sensor-1",
            expected_rule="Porygon Container Process Execution",
            reported_docker_host_id=None,
        )
        is None
    )
