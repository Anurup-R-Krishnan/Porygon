"""add drift detection to calibrated rarity scores

Adds an optional test_context_hash to calibrated_rarity_scores so a scoring
request can declare the identity (image digest + runtime context) of the run
being scored, and widens the status constraint to include 'drift_detected'
so a mismatch against the model's profile_context_hash is surfaced as an
explicit outcome rather than silently scored as if exchangeable.

Revision ID: 0010_calibrated_rarity_drift
Revises: 0009_calibrated_rarity
Create Date: 2026-09-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_calibrated_rarity_drift"
down_revision: str | None = "0009_calibrated_rarity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "calibrated_rarity_scores",
        sa.Column("test_context_hash", sa.String(64), nullable=True),
    )
    op.drop_constraint("ck_calibrated_rarity_scores_status", "calibrated_rarity_scores", type_="check")
    op.create_check_constraint(
        "ck_calibrated_rarity_scores_status",
        "calibrated_rarity_scores",
        "status IN ('scored', 'insufficient_data', 'drift_detected')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_calibrated_rarity_scores_status", "calibrated_rarity_scores", type_="check")
    op.create_check_constraint(
        "ck_calibrated_rarity_scores_status",
        "calibrated_rarity_scores",
        "status IN ('scored', 'insufficient_data')",
    )
    op.drop_column("calibrated_rarity_scores", "test_context_hash")
