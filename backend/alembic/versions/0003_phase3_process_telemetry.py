"""Add Falco/eBPF process execution telemetry.

Revision ID: 0003_phase3
Revises: 0002_phase2
Create Date: 2026-07-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_phase3"
down_revision: Union[str, None] = "0002_phase2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "process_exec_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("sensor_instance_id", sa.String(length=128), nullable=False),
        sa.Column("sensor_hostname", sa.String(length=255), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("priority", sa.String(length=32), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("time_nano", sa.BigInteger(), nullable=False),
        sa.Column("event_number", sa.BigInteger(), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("reported_docker_host_id", sa.String(length=128), nullable=True),
        sa.Column("reported_container_id", sa.String(length=128), nullable=True),
        sa.Column("docker_host_id", sa.String(length=128), nullable=True),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("container_name", sa.String(length=255), nullable=True),
        sa.Column("image_id", sa.String(length=128), nullable=True),
        sa.Column("image_ref", sa.Text(), nullable=True),
        sa.Column("image_digest", sa.String(length=255), nullable=True),
        sa.Column("correlation_status", sa.String(length=32), nullable=False),
        sa.Column("process_pid", sa.BigInteger(), nullable=False),
        sa.Column("process_ppid", sa.BigInteger(), nullable=True),
        sa.Column("process_vpid", sa.BigInteger(), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("executable", sa.Text(), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column("working_directory", sa.Text(), nullable=True),
        sa.Column("tty", sa.BigInteger(), nullable=True),
        sa.Column("parent_name", sa.String(length=255), nullable=True),
        sa.Column("parent_executable", sa.Text(), nullable=True),
        sa.Column("parent_command_line", sa.Text(), nullable=True),
        sa.Column("parent_event_id", sa.String(length=64), nullable=True),
        sa.Column("user_uid", sa.BigInteger(), nullable=True),
        sa.Column("user_name", sa.String(length=255), nullable=True),
        sa.Column("group_gid", sa.BigInteger(), nullable=True),
        sa.Column("group_name", sa.String(length=255), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("output_fields", sa.JSON(), nullable=False),
        sa.Column("raw_event", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_process_exec_events_occurred_at", "process_exec_events", ["occurred_at"])
    op.create_index(
        "ix_process_exec_events_container_time",
        "process_exec_events",
        ["container_id", "time_nano"],
    )
    op.create_index(
        "ix_process_exec_events_reported_container",
        "process_exec_events",
        ["reported_container_id"],
    )
    op.create_index(
        "ix_process_exec_events_image_digest",
        "process_exec_events",
        ["image_digest"],
    )
    op.create_index(
        "ix_process_exec_events_process_name",
        "process_exec_events",
        ["process_name"],
    )
    op.create_index(
        "ix_process_exec_events_pid",
        "process_exec_events",
        ["docker_host_id", "process_pid", "occurred_at"],
    )
    op.create_index(
        "ix_process_exec_events_parent_event",
        "process_exec_events",
        ["parent_event_id"],
    )
    op.create_index(
        "ix_process_exec_events_correlation",
        "process_exec_events",
        ["correlation_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_process_exec_events_correlation", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_parent_event", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_pid", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_process_name", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_image_digest", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_reported_container", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_container_time", table_name="process_exec_events")
    op.drop_index("ix_process_exec_events_occurred_at", table_name="process_exec_events")
    op.drop_table("process_exec_events")
