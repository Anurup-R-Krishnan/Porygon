"""add additive v2 rarity model provenance tables

Revision ID: 0009_rarity_v2
Revises: 0008_phase8
Create Date: 2026-08-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_rarity_v2"
down_revision: str | None = "0008_phase8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rarity_models_v2",
        sa.Column("model_id", sa.String(36), primary_key=True),
        sa.Column("model_key", sa.String(64), nullable=False),
        sa.Column("protocol_id", sa.String(64), nullable=False),
        sa.Column("profile_scope_id", sa.String(128), nullable=False),
        sa.Column("profile_context_hash", sa.String(64), nullable=False),
        sa.Column("algorithm_version", sa.String(64), nullable=False),
        sa.Column("component_registry_version", sa.String(64), nullable=False),
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
        sa.CheckConstraint("status IN ('draft', 'active', 'retired')", name="ck_rarity_models_v2_status"),
        sa.CheckConstraint("min_calibration_runs >= 1", name="ck_rarity_models_v2_min_calibration"),
        sa.CheckConstraint("fit_run_count >= 0", name="ck_rarity_models_v2_fit_count"),
        sa.CheckConstraint("calibration_run_count >= 1", name="ck_rarity_models_v2_calibration_count"),
        sa.UniqueConstraint("model_key", name="uq_rarity_models_v2_model_key"),
    )
    op.create_index("ix_rarity_models_v2_scope_status", "rarity_models_v2", ["profile_scope_id", "status"])
    op.create_index("ix_rarity_models_v2_protocol", "rarity_models_v2", ["protocol_id"])

    op.create_table(
        "rarity_model_runs_v2",
        sa.Column("model_run_id", sa.String(36), primary_key=True),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("split_role", sa.String(16), nullable=False),
        sa.Column("feature_hash", sa.String(64), nullable=False),
        sa.Column("window_count", sa.Integer(), nullable=False),
        sa.Column("feature_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("split_role IN ('fit', 'calibration')", name="ck_rarity_model_runs_v2_role"),
        sa.ForeignKeyConstraint(["model_id"], ["rarity_models_v2.model_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("model_id", "run_id", name="uq_rarity_model_runs_v2_model_run"),
    )
    op.create_index("ix_rarity_model_runs_v2_model_role", "rarity_model_runs_v2", ["model_id", "split_role"])
    op.create_index("ix_rarity_model_runs_v2_run", "rarity_model_runs_v2", ["run_id"])

    op.create_table(
        "rarity_calibration_blocks_v2",
        sa.Column("block_id", sa.String(36), primary_key=True),
        sa.Column("model_id", sa.String(36), nullable=False),
        sa.Column("run_id", sa.String(128), nullable=False),
        sa.Column("block_statistic_version", sa.String(64), nullable=False),
        sa.Column("block_statistic", sa.Float(), nullable=False),
        sa.Column("block_hash", sa.String(64), nullable=False),
        sa.Column("window_summary", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("block_statistic >= 0", name="ck_rarity_calibration_blocks_v2_stat"),
        sa.ForeignKeyConstraint(["model_id"], ["rarity_models_v2.model_id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("model_id", "run_id", name="uq_rarity_calibration_blocks_v2_model_run"),
    )
    op.create_index("ix_rarity_calibration_blocks_v2_model", "rarity_calibration_blocks_v2", ["model_id"])
    op.create_index("ix_rarity_calibration_blocks_v2_run", "rarity_calibration_blocks_v2", ["run_id"])


def downgrade() -> None:
    op.drop_table("rarity_calibration_blocks_v2")
    op.drop_table("rarity_model_runs_v2")
    op.drop_table("rarity_models_v2")
