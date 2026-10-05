"""Custom detection rule lifecycle: partial slug uniqueness and custom-rule allowlisting.

A disabled custom rule previously burned its slug forever (a plain UniqueConstraint
covered every row regardless of `enabled`), so re-creating a rule under the same slug
after fixing and disabling the old one always hit 409. This narrows the uniqueness to
enabled rows only. It also widens the `detection_allowlists.rule_id` check constraint
so operators can allowlist a custom rule's matches (`POR-CUS-<slug>`), not just the
three fixed built-in rule ids.

Revision ID: 0012_custom_rule_lifecycle
Revises: 0011_custom_detection_rules
Create Date: 2026-09-13
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0012_custom_rule_lifecycle"
down_revision: Union[str, None] = "0011_custom_detection_rules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("uq_custom_detection_rules_slug", "custom_detection_rules", type_="unique")
    op.create_index(
        "uq_custom_detection_rules_slug_enabled",
        "custom_detection_rules",
        ["slug"],
        unique=True,
        postgresql_where=sa.text("enabled"),
    )

    op.drop_constraint("ck_detection_allowlists_rule_id", "detection_allowlists", type_="check")
    op.create_check_constraint(
        "ck_detection_allowlists_rule_id",
        "detection_allowlists",
        "rule_id IN ('POR-DET-002', 'POR-DET-003', 'POR-DET-004') OR rule_id LIKE 'POR-CUS-%'",
    )


def downgrade() -> None:
    op.drop_constraint("ck_detection_allowlists_rule_id", "detection_allowlists", type_="check")
    op.create_check_constraint(
        "ck_detection_allowlists_rule_id",
        "detection_allowlists",
        "rule_id IN ('POR-DET-002', 'POR-DET-003', 'POR-DET-004')",
    )

    op.drop_index("uq_custom_detection_rules_slug_enabled", table_name="custom_detection_rules")
    op.create_unique_constraint(
        "uq_custom_detection_rules_slug", "custom_detection_rules", ["slug"]
    )
