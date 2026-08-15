"""Add Docker runtime event and identity tables.

Revision ID: 0002_phase2
Revises: 0001_phase1
Create Date: 2026-07-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_phase2"
down_revision: Union[str, None] = "0001_phase1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "runtime_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("docker_host_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=64), nullable=True),
        sa.Column("actor_id", sa.String(length=128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("time_nano", sa.BigInteger(), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("container_name", sa.String(length=255), nullable=True),
        sa.Column("image_id", sa.String(length=128), nullable=True),
        sa.Column("image_ref", sa.Text(), nullable=True),
        sa.Column("image_digest", sa.String(length=255), nullable=True),
        sa.Column("image_digest_status", sa.String(length=32), nullable=False),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("container_user", sa.String(length=255), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("container_snapshot", sa.JSON(), nullable=False),
        sa.Column("raw_event", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_runtime_events_occurred_at", "runtime_events", ["occurred_at"])
    op.create_index("ix_runtime_events_type_action", "runtime_events", ["event_type", "action"])
    op.create_index("ix_runtime_events_container_id", "runtime_events", ["container_id"])
    op.create_index("ix_runtime_events_container_name", "runtime_events", ["container_name"])
    op.create_index("ix_runtime_events_image_digest", "runtime_events", ["image_digest"])
    op.create_index("ix_runtime_events_docker_host_time", "runtime_events", ["docker_host_id", "time_nano"])

    op.create_table(
        "image_identities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("docker_host_id", sa.String(length=128), nullable=False),
        sa.Column("image_id", sa.String(length=128), nullable=False),
        sa.Column("image_ref", sa.Text(), nullable=True),
        sa.Column("primary_repo_digest", sa.String(length=255), nullable=True),
        sa.Column("repo_digests", sa.JSON(), nullable=False),
        sa.Column("repo_tags", sa.JSON(), nullable=False),
        sa.Column("os", sa.String(length=64), nullable=True),
        sa.Column("architecture", sa.String(length=64), nullable=True),
        sa.Column("digest_status", sa.String(length=32), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("docker_host_id", "image_id", name="uq_image_identity_host_image"),
    )
    op.create_index("ix_image_identities_primary_digest", "image_identities", ["primary_repo_digest"])
    op.create_index("ix_image_identities_last_seen_at", "image_identities", ["last_seen_at"])

    op.create_table(
        "container_identities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("docker_host_id", sa.String(length=128), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=False),
        sa.Column("container_name", sa.String(length=255), nullable=True),
        sa.Column("image_id", sa.String(length=128), nullable=True),
        sa.Column("image_ref", sa.Text(), nullable=True),
        sa.Column("image_digest", sa.String(length=255), nullable=True),
        sa.Column("image_digest_status", sa.String(length=32), nullable=False),
        sa.Column("current_snapshot", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("docker_host_id", "container_id", name="uq_container_identity_host_container"),
    )
    op.create_index("ix_container_identities_name", "container_identities", ["container_name"])
    op.create_index("ix_container_identities_image_digest", "container_identities", ["image_digest"])
    op.create_index("ix_container_identities_last_seen_at", "container_identities", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("ix_container_identities_last_seen_at", table_name="container_identities")
    op.drop_index("ix_container_identities_image_digest", table_name="container_identities")
    op.drop_index("ix_container_identities_name", table_name="container_identities")
    op.drop_table("container_identities")

    op.drop_index("ix_image_identities_last_seen_at", table_name="image_identities")
    op.drop_index("ix_image_identities_primary_digest", table_name="image_identities")
    op.drop_table("image_identities")

    op.drop_index("ix_runtime_events_docker_host_time", table_name="runtime_events")
    op.drop_index("ix_runtime_events_image_digest", table_name="runtime_events")
    op.drop_index("ix_runtime_events_container_name", table_name="runtime_events")
    op.drop_index("ix_runtime_events_container_id", table_name="runtime_events")
    op.drop_index("ix_runtime_events_type_action", table_name="runtime_events")
    op.drop_index("ix_runtime_events_occurred_at", table_name="runtime_events")
    op.drop_table("runtime_events")
