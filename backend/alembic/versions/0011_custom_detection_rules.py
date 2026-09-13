"""Add user-defined custom detection rules, additive to the built-in ruleset.

Revision ID: 0011_custom_detection_rules
Revises: 0010_calibrated_rarity_drift
Create Date: 2026-09-09
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0011_custom_detection_rules"
down_revision: Union[str, None] = "0010_calibrated_rarity_drift"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "custom_detection_rules",
        sa.Column("custom_rule_id", sa.String(length=36), primary_key=True),
        sa.Column("slug", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=16), nullable=False),
        sa.Column("condition", sa.JSON(), nullable=False),
        sa.Column("severity_weight", sa.Float(), nullable=False),
        sa.Column("confidence_weight", sa.Float(), nullable=False),
        sa.Column("incident_eligible", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disabled_by", sa.String(length=128), nullable=True),
        sa.CheckConstraint("target IN ('process', 'runtime')", name="ck_custom_detection_rules_target"),
        sa.CheckConstraint(
            "severity_weight >= 0 AND severity_weight <= 1",
            name="ck_custom_detection_rules_severity_range",
        ),
        sa.CheckConstraint(
            "confidence_weight >= 0 AND confidence_weight <= 1",
            name="ck_custom_detection_rules_confidence_range",
        ),
        sa.UniqueConstraint("slug", name="uq_custom_detection_rules_slug"),
    )
    op.create_index(
        "ix_custom_detection_rules_enabled",
        "custom_detection_rules",
        ["enabled"],
    )

    op.add_column(
        "detection_runs",
        sa.Column("custom_ruleset_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.drop_constraint(
        "uq_detection_runs_score_ruleset_allowlists",
        "detection_runs",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_detection_runs_score_ruleset_allowlists",
        "detection_runs",
        ["score_id", "ruleset_version", "allowlist_set_hash", "custom_ruleset_hash"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_detection_runs_score_ruleset_allowlists",
        "detection_runs",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_detection_runs_score_ruleset_allowlists",
        "detection_runs",
        ["score_id", "ruleset_version", "allowlist_set_hash"],
    )
    op.drop_column("detection_runs", "custom_ruleset_hash")

    op.drop_index("ix_custom_detection_rules_enabled", table_name="custom_detection_rules")
    op.drop_table("custom_detection_rules")
