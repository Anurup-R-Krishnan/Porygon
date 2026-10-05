from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from porygon_api.main import _find_parent_event_id
from porygon_api.models import ProcessExecEvent


def _event(event_id: str, occurred_at: datetime, pid: int) -> ProcessExecEvent:
    return ProcessExecEvent(
        event_id=event_id,
        sensor_instance_id="sensor-1",
        sensor_hostname="host",
        source="falco",
        rule_name="Porygon Container Process Execution",
        priority="Notice",
        occurred_at=occurred_at,
        time_nano=int(occurred_at.timestamp() * 1_000_000_000),
        event_number=1,
        event_type="execve",
        reported_docker_host_id="host-1",
        reported_container_id="c1",
        docker_host_id="host-1",
        container_id="c1",
        container_name="probe",
        image_id="sha256:image",
        image_ref="example/app:latest",
        image_digest="example/app@sha256:" + "a" * 64,
        correlation_status="resolved",
        process_pid=pid,
        process_ppid=1,
        process_vpid=pid,
        process_name="parent",
        executable="/usr/bin/parent",
        command_line="parent",
        working_directory="/",
        tty=0,
        parent_name="init",
        parent_executable="/sbin/init",
        parent_command_line="init",
        parent_event_id=None,
        user_uid=1000,
        user_name="user",
        group_gid=1000,
        group_name="user",
        tags=[],
        output=None,
        output_fields={},
        raw_event={},
        received_at=occurred_at,
    )


def test_parent_lookup_rejects_stale_pid_reuse() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    ProcessExecEvent.__table__.create(engine)
    now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)

    with Session(engine) as db:
        db.add(_event("a" * 64, now - timedelta(hours=2), 42))
        db.commit()

        result = _find_parent_event_id(
            db,
            sensor_instance_id="sensor-1",
            docker_host_id="host-1",
            container_id="c1",
            process_ppid=42,
            occurred_at=now,
            time_nano=int(now.timestamp() * 1_000_000_000),
        )
        assert result is None

        recent = _event("b" * 64, now - timedelta(seconds=30), 42)
        db.add(recent)
        db.commit()
        result = _find_parent_event_id(
            db,
            sensor_instance_id="sensor-1",
            docker_host_id="host-1",
            container_id="c1",
            process_ppid=42,
            occurred_at=now,
            time_nano=int(now.timestamp() * 1_000_000_000),
        )
        assert result == recent.event_id
