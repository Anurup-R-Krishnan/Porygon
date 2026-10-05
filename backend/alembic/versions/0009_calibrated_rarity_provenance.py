"""add additive calibrated rarity model provenance tables

Revision ID: 0009_calibrated_rarity
Revises: 0008_phase8
Create Date: 2026-08-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_calibrated_rarity"
down_revision: str | None = "0008_phase8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "calibrated_rarity_models",
        sa.Column("model_id", sa.String(36), primary_key=True),
        sa.Column("model_key", sa.String(64), nullable=False),
        sa.Column("protocol_id", sa.String(64), nullable=False),
        sa.Column("profile_scope_id", sa.String(128), nullable=False),
        sa.Column("profile_context_hash", sa.String(64), nullable=False),
        sa.Column("algorithm_id", sa.String(64), nullable=False),
        sa.Column("component_registry_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("min_calibration_runs", sa.Integer(), nullable=False),
        sa.Column("fit_run_count", sa.Integer(), nullable=False),
        sa.Column("calibration_run_count", sa.Integer(), nullable=False),
        sa.Column("fit_run_set_hash", sa.String(64), nullable=False),
        sa.Column("calibration_run_set_hash", sa.String(64), nullable=False),
        sa.Column("calibration_hash", sa.String(64), nullable=False),
        sa.Column("provenance_hash", sa.String(64), nullable=False),
        sa.Column("model_document", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("status IN ('draft', 'active', 'retired')", name="ck_calibrated_rarity_models_status"),
        sa.CheckConstraint("min_calibration_runs >= 1", name="ck_calibrated_rarity_models_min_calibration"),
        sa.CheckConstraint("fit_run_count >= 0", name="ck_calibrated_rarity_models_fit_count"),
        sa.CheckConstraint("calibration_run_count >= 1", name="ck_calibrated_rarity_models_calibration_count"),
        sa.UniqueConstraint("model_key", name="uq_calibrated_rarity_models_model_key"),
    )
    op.create_index("ix_calibrated_rarity_models_scope_status", "calibrated_rarity_models", ["profile_scope_id", "status"])
    op.create_index("ix_calibrated_rarity_models_protocol", "calibrated_rarity_models", ["protocol_id"])

    op.create_table(
        "calibrated_model_runs",
        sa.Column("model_run_id", sa.String(36), primary_key=True),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("split_role", sa.String(16), nullable=False),
        sa.Column("feature_hash", sa.String(64), nullable=False),
        sa.Column("window_count", sa.Integer(), nullable=False),
        sa.Column("feature_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("split_role IN ('fit', 'calibration')", name="ck_calibrated_model_runs_role"),
        sa.ForeignKeyConstraint(["model_id"], ["calibrated_rarity_models.model_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("model_id", "run_id", name="uq_calibrated_model_runs_model_run"),
    )
    op.create_index("ix_calibrated_model_runs_model_role", "calibrated_model_runs", ["model_id", "split_role"])
    op.create_index("ix_calibrated_model_runs_run", "calibrated_model_runs", ["run_id"])

    op.create_table(
        "calibrated_calibration_blocks",
        sa.Column("block_id", sa.String(36), primary_key=True),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("block_statistic_id", sa.String(64), nullable=False),
        sa.Column("block_statistic", sa.Float(), nullable=False),
        sa.Column("block_hash", sa.String(64), nullable=False),
        sa.Column("window_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("block_statistic >= 0", name="ck_calibrated_calibration_blocks_stat"),
        sa.ForeignKeyConstraint(["model_id"], ["calibrated_rarity_models.model_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("model_id", "run_id", name="uq_calibrated_calibration_blocks_model_run"),
    )
    op.create_index("ix_calibrated_calibration_blocks_model", "calibrated_calibration_blocks", ["model_id"])
    op.create_index("ix_calibrated_calibration_blocks_run", "calibrated_calibration_blocks", ["run_id"])

    op.create_table(
        "calibrated_rarity_scores",
        sa.Column("score_id", sa.String(36), primary_key=True),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("protocol_id", sa.String(64), nullable=False),
        sa.Column("profile_scope_id", sa.String(128), nullable=False),
        sa.Column("profile_context_hash", sa.String(64), nullable=False),
        sa.Column("algorithm_id", sa.String(64), nullable=False),
        sa.Column("component_registry_id", sa.String(64), nullable=False),
        sa.Column("test_run_id", sa.String(128), nullable=False),
        sa.Column("evidence_set_hash", sa.String(64), nullable=False),
        sa.Column("test_statistic", sa.Float(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("p_value", sa.Float(), nullable=True),
        sa.Column("rarity", sa.Float(), nullable=True),
        sa.Column("calibration_hash", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("explanation", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('scored', 'insufficient_data')", name="ck_calibrated_rarity_scores_status"),
        sa.CheckConstraint("p_value IS NULL OR (p_value >= 0 AND p_value <= 1)", name="ck_calibrated_rarity_scores_p_value"),
        sa.CheckConstraint("rarity IS NULL OR (rarity >= 0 AND rarity <= 1)", name="ck_calibrated_rarity_scores_rarity"),
        sa.CheckConstraint("test_statistic >= 0", name="ck_calibrated_rarity_scores_statistic"),
        sa.ForeignKeyConstraint(["model_id"], ["calibrated_rarity_models.model_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("idempotency_key", name="uq_calibrated_rarity_scores_idempotency"),
    )
    op.create_index("ix_calibrated_rarity_scores_model_created", "calibrated_rarity_scores", ["model_id", "created_at"])
    op.create_index("ix_calibrated_rarity_scores_test_run", "calibrated_rarity_scores", ["test_run_id"])


def downgrade() -> None:
    op.drop_table("calibrated_rarity_scores")
    op.drop_table("calibrated_calibration_blocks")
    op.drop_table("calibrated_model_runs")
    op.drop_table("calibrated_rarity_models")
