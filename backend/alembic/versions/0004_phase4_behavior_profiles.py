"""Add immutable digest-bound behavioural profiles.

Revision ID: 0004_phase4
Revises: 0003_phase3
Create Date: 2026-07-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_phase4"
down_revision: Union[str, None] = "0003_phase3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "behavior_profiles",
        sa.Column("profile_id", sa.String(length=36), primary_key=True),
        sa.Column("image_digest", sa.String(length=255), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("feature_schema_version", sa.String(length=64), nullable=False),
        sa.Column("model_hash", sa.String(length=64), nullable=False),
        sa.Column("training_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("training_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=False),
        sa.Column("approval_reference", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("process_event_count", sa.Integer(), nullable=False),
        sa.Column("runtime_event_count", sa.Integer(), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("window_count", sa.Integer(), nullable=False),
        sa.Column("quality", sa.JSON(), nullable=False),
        sa.Column("training_manifest", sa.JSON(), nullable=False),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("profile_version >= 1", name="ck_behavior_profiles_version_positive"),
        sa.CheckConstraint("window_seconds >= 1", name="ck_behavior_profiles_window_positive"),
        sa.CheckConstraint(
            "status IN ('draft', 'active', 'retired')",
            name="ck_behavior_profiles_status",
        ),
        sa.UniqueConstraint(
            "image_digest",
            "profile_version",
            name="uq_behavior_profiles_digest_version",
        ),
        sa.UniqueConstraint(
            "image_digest",
            "model_hash",
            name="uq_behavior_profiles_digest_model_hash",
        ),
    )
    op.create_index("ix_behavior_profiles_image_digest", "behavior_profiles", ["image_digest"])
    op.create_index("ix_behavior_profiles_created_at", "behavior_profiles", ["created_at"])
    op.create_index("ix_behavior_profiles_status", "behavior_profiles", ["status"])
    op.create_index(
        "uq_behavior_profiles_one_active_digest",
        "behavior_profiles",
        ["image_digest"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index("uq_behavior_profiles_one_active_digest", table_name="behavior_profiles")
    op.drop_index("ix_behavior_profiles_status", table_name="behavior_profiles")
    op.drop_index("ix_behavior_profiles_created_at", table_name="behavior_profiles")
    op.drop_index("ix_behavior_profiles_image_digest", table_name="behavior_profiles")
    op.drop_table("behavior_profiles")
