from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from porygon_api.db import Base
from porygon_api.models import ProcessExecEvent, RuntimeEvent
from porygon_api.retention import apply_retention, plan_retention

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=timezone.utc)


def _process_event(event_id: str, occurred_at: datetime) -> ProcessExecEvent:
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
        process_pid=100,
        process_ppid=1,
        process_vpid=100,
        process_name="echo",
        executable="/bin/echo",
        command_line="echo hi",
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


def _runtime_event(event_id: str, occurred_at: datetime) -> RuntimeEvent:
    return RuntimeEvent(
        event_id=event_id,
        docker_host_id="host-1",
        event_type="container",
        action="start",
        scope="local",
        actor_id="c1",
        occurred_at=occurred_at,
        time_nano=int(occurred_at.timestamp() * 1_000_000_000),
        container_id="c1",
        container_name="probe",
        image_id="sha256:image",
        image_ref="example/app:latest",
        image_digest="example/app@sha256:" + "a" * 64,
        image_digest_status="resolved",
        command=None,
        container_user=None,
        attributes={},
        container_snapshot={},
        raw_event={},
        received_at=occurred_at,
    )


def _seeded_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    old = NOW - timedelta(days=45)
    recent = NOW - timedelta(days=1)
    db.add(_process_event("old-process", old))
    db.add(_process_event("recent-process", recent))
    db.add(_runtime_event("old-runtime", old))
    db.add(_runtime_event("recent-runtime", recent))
    db.commit()
    return db


def test_plan_retention_reports_only_rows_older_than_the_cutoff() -> None:
    db = _seeded_session()

    plan = plan_retention(db, retention_days=30, now=NOW)

    assert plan.process_exec_events_eligible == 1
    assert plan.runtime_events_eligible == 1
    assert plan.cutoff == NOW - timedelta(days=30)


def test_dry_run_deletes_nothing() -> None:
    db = _seeded_session()

    result = apply_retention(db, retention_days=30, max_delete_batch=1000, dry_run=True, now=NOW)

    assert result.dry_run is True
    assert result.process_exec_events_deleted == 1
    assert result.runtime_events_deleted == 1
    assert db.scalar(select(ProcessExecEvent.event_id).where(ProcessExecEvent.event_id == "old-process")) is not None
    assert db.scalar(select(RuntimeEvent.event_id).where(RuntimeEvent.event_id == "old-runtime")) is not None


def test_real_run_deletes_only_rows_past_the_cutoff() -> None:
    db = _seeded_session()

    result = apply_retention(db, retention_days=30, max_delete_batch=1000, dry_run=False, now=NOW)
    db.commit()

    assert result.dry_run is False
    assert result.process_exec_events_deleted == 1
    assert result.runtime_events_deleted == 1
    remaining_process = set(db.scalars(select(ProcessExecEvent.event_id)).all())
    remaining_runtime = set(db.scalars(select(RuntimeEvent.event_id)).all())
    assert remaining_process == {"recent-process"}
    assert remaining_runtime == {"recent-runtime"}


def test_batch_limit_caps_a_single_deletion_pass() -> None:
    """A single call never deletes more than max_delete_batch rows per table,
    so a large backlog cannot hold one unbounded transaction/lock."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    old = NOW - timedelta(days=90)
    for i in range(5):
        db.add(_process_event(f"old-process-{i}", old))
    db.commit()

    result = apply_retention(db, retention_days=30, max_delete_batch=2, dry_run=False, now=NOW)
    db.commit()

    assert result.process_exec_events_deleted == 2
    remaining = db.scalar(select(ProcessExecEvent.event_id).where(ProcessExecEvent.event_id.like("old-process-%")).limit(1))
    assert remaining is not None  # 3 of 5 should still remain


def test_recent_rows_are_never_touched_regardless_of_batch_size() -> None:
    db = _seeded_session()

    apply_retention(db, retention_days=30, max_delete_batch=1000, dry_run=False, now=NOW)
    db.commit()

    assert db.scalar(select(ProcessExecEvent.event_id).where(ProcessExecEvent.event_id == "recent-process")) == "recent-process"
    assert db.scalar(select(RuntimeEvent.event_id).where(RuntimeEvent.event_id == "recent-runtime")) == "recent-runtime"
