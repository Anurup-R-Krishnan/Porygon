"""Create service heartbeat registry.

Revision ID: 0001_phase1
Revises:
Create Date: 2026-07-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_phase1"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "service_heartbeats",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("service_name", sa.String(length=64), nullable=False),
        sa.Column("instance_id", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("service_metadata", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("service_name", "instance_id", name="uq_service_heartbeat_identity"),
    )
    op.create_index("ix_service_heartbeats_last_seen_at", "service_heartbeats", ["last_seen_at"])


def downgrade() -> None:
    op.drop_index("ix_service_heartbeats_last_seen_at", table_name="service_heartbeats")
    op.drop_table("service_heartbeats")
