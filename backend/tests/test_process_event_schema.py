from porygon_api.schemas import ProcessExecEventBatchIn


def test_process_event_schema_accepts_falco_event() -> None:
    payload = ProcessExecEventBatchIn.model_validate(
        {
            "events": [
                {
                    "event_id": "c" * 64,
                    "sensor_instance_id": "falco-local-01",
                    "sensor_hostname": "porygon-falco",
                    "source": "falco",
                    "rule_name": "Porygon Container Process Execution",
                    "priority": "Notice",
                    "occurred_at": "2026-07-21T10:00:00+00:00",
                    "time_nano": 1784628000123456789,
                    "event_number": 123,
                    "event_type": "execve",
                    "reported_container_id": "0123456789ab",
                    "reported_container_name": "probe",
                    "reported_image_ref": "alpine:3.20",
                    "process_pid": 101,
                    "process_ppid": 100,
                    "process_vpid": 2,
                    "process_name": "sleep",
                    "executable": "/bin/sleep",
                    "command_line": "sleep 2",
                    "working_directory": "/",
                    "tty": 0,
                    "parent_name": "sh",
                    "parent_executable": "/bin/sh",
                    "parent_command_line": "sh -c sleep 2",
                    "user_uid": 0,
                    "user_name": "root",
                    "group_gid": 0,
                    "group_name": "root",
                    "tags": ["porygon", "phase3"],
                    "output_fields": {"proc.name": "sleep"},
                    "raw_event": {"rule": "Porygon Container Process Execution"},
                }
            ]
        }
    )
    assert payload.events[0].process_ppid == 100
    assert payload.events[0].reported_container_id == "0123456789ab"
