"""Add explainable behavioural-distance scores.

Revision ID: 0005_phase5
Revises: 0004_phase4
Create Date: 2026-07-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_phase5"
down_revision: Union[str, None] = "0004_phase4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "anomaly_scores",
        sa.Column("score_id", sa.String(length=36), primary_key=True),
        sa.Column("observation_key", sa.String(length=64), nullable=False),
        sa.Column(
            "profile_id",
            sa.String(length=36),
            sa.ForeignKey("behavior_profiles.profile_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("image_digest", sa.String(length=255), nullable=False),
        sa.Column("profile_version", sa.Integer(), nullable=False),
        sa.Column("profile_model_hash", sa.String(length=64), nullable=False),
        sa.Column("algorithm_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("score_band", sa.String(length=32), nullable=False),
        sa.Column("total_score", sa.Float(), nullable=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_seconds", sa.Integer(), nullable=False),
        sa.Column("process_event_count", sa.Integer(), nullable=False),
        sa.Column("runtime_event_count", sa.Integer(), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("observation_manifest", sa.JSON(), nullable=False),
        sa.Column("scoring_config", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('scored', 'insufficient_data')",
            name="ck_anomaly_scores_status",
        ),
        sa.CheckConstraint(
            "score_band IN ('baseline_like', 'elevated', 'high', 'extreme', 'insufficient_data')",
            name="ck_anomaly_scores_band",
        ),
        sa.CheckConstraint(
            "total_score IS NULL OR (total_score >= 0 AND total_score <= 1)",
            name="ck_anomaly_scores_total_range",
        ),
        sa.CheckConstraint("window_seconds >= 1", name="ck_anomaly_scores_window_positive"),
        sa.UniqueConstraint("observation_key", name="uq_anomaly_scores_observation_key"),
    )
    op.create_index(
        "ix_anomaly_scores_image_digest_window",
        "anomaly_scores",
        ["image_digest", "window_start"],
    )
    op.create_index("ix_anomaly_scores_profile_id", "anomaly_scores", ["profile_id"])
    op.create_index("ix_anomaly_scores_total_score", "anomaly_scores", ["total_score"])
    op.create_index("ix_anomaly_scores_created_at", "anomaly_scores", ["created_at"])
    op.create_index("ix_anomaly_scores_status", "anomaly_scores", ["status"])


def downgrade() -> None:
    op.drop_index("ix_anomaly_scores_status", table_name="anomaly_scores")
    op.drop_index("ix_anomaly_scores_created_at", table_name="anomaly_scores")
    op.drop_index("ix_anomaly_scores_total_score", table_name="anomaly_scores")
    op.drop_index("ix_anomaly_scores_profile_id", table_name="anomaly_scores")
    op.drop_index("ix_anomaly_scores_image_digest_window", table_name="anomaly_scores")
    op.drop_table("anomaly_scores")
