"""phase 7 response recommendations and controlled execution

Revision ID: 0007_phase7
Revises: 0006_phase6
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_phase7"
down_revision: str | None = "0006_phase6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "response_recommendations",
        sa.Column("recommendation_id", sa.String(length=36), nullable=False),
        sa.Column("recommendation_key", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("target_container_id", sa.String(length=128), nullable=True),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("policy_hash", sa.String(length=64), nullable=False),
        sa.Column("recommended_action", sa.String(length=32), nullable=False),
        sa.Column("allowed_actions", sa.JSON(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("risk_notes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decided_by", sa.String(length=128), nullable=True),
        sa.Column("decision_note", sa.Text(), nullable=True),
        sa.Column("approved_action", sa.String(length=32), nullable=True),
        sa.CheckConstraint(
            "status IN ('proposed', 'approved', 'rejected')",
            name="ck_response_recommendations_status",
        ),
        sa.CheckConstraint(
            "recommended_action IN ('observe_only', 'pause_container', 'stop_container')",
            name="ck_response_recommendations_action",
        ),
        sa.CheckConstraint(
            "approved_action IS NULL OR approved_action IN ('observe_only', 'pause_container', 'stop_container')",
            name="ck_response_recommendations_approved_action",
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("recommendation_id"),
        sa.UniqueConstraint("recommendation_key", name="uq_response_recommendations_key"),
    )
    op.create_index("ix_response_recommendations_incident", "response_recommendations", ["incident_id", "created_at"])
    op.create_index("ix_response_recommendations_status", "response_recommendations", ["status"])
    op.create_index("ix_response_recommendations_target", "response_recommendations", ["target_container_id"])

    op.create_table(
        "response_executions",
        sa.Column("execution_id", sa.String(length=36), nullable=False),
        sa.Column("recommendation_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("target_container_id", sa.String(length=128), nullable=True),
        sa.Column("action_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("executor_instance_id", sa.String(length=128), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("pre_state", sa.JSON(), nullable=False),
        sa.Column("post_state", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_requested_by", sa.String(length=128), nullable=True),
        sa.Column("rollback_note", sa.Text(), nullable=True),
        sa.Column("rollback_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'succeeded', 'failed', 'rollback_pending', 'rollback_claimed', 'rolled_back', 'rollback_failed')",
            name="ck_response_executions_status",
        ),
        sa.CheckConstraint(
            "action_type IN ('observe_only', 'pause_container', 'stop_container')",
            name="ck_response_executions_action",
        ),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["recommendation_id"], ["response_recommendations.recommendation_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("execution_id"),
        sa.UniqueConstraint("recommendation_id", name="uq_response_executions_recommendation"),
        sa.UniqueConstraint("idempotency_key", name="uq_response_executions_idempotency"),
    )
    op.create_index("ix_response_executions_status_created", "response_executions", ["status", "created_at"])
    op.create_index("ix_response_executions_incident", "response_executions", ["incident_id"])
    op.create_index("ix_response_executions_target", "response_executions", ["target_container_id"])
    op.create_index("ix_response_executions_lease", "response_executions", ["lease_expires_at"])

    op.create_table(
        "response_audit_events",
        sa.Column("audit_id", sa.String(length=36), nullable=False),
        sa.Column("incident_id", sa.String(length=36), nullable=False),
        sa.Column("recommendation_id", sa.String(length=36), nullable=True),
        sa.Column("execution_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["execution_id"], ["response_executions.execution_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["recommendation_id"], ["response_recommendations.recommendation_id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("audit_id"),
    )
    op.create_index("ix_response_audit_incident_time", "response_audit_events", ["incident_id", "created_at"])
    op.create_index("ix_response_audit_recommendation", "response_audit_events", ["recommendation_id"])
    op.create_index("ix_response_audit_execution", "response_audit_events", ["execution_id"])
    op.create_index("ix_response_audit_type", "response_audit_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_response_audit_type", table_name="response_audit_events")
    op.drop_index("ix_response_audit_execution", table_name="response_audit_events")
    op.drop_index("ix_response_audit_recommendation", table_name="response_audit_events")
    op.drop_index("ix_response_audit_incident_time", table_name="response_audit_events")
    op.drop_table("response_audit_events")
    op.drop_index("ix_response_executions_lease", table_name="response_executions")
    op.drop_index("ix_response_executions_target", table_name="response_executions")
    op.drop_index("ix_response_executions_incident", table_name="response_executions")
    op.drop_index("ix_response_executions_status_created", table_name="response_executions")
    op.drop_table("response_executions")
    op.drop_index("ix_response_recommendations_target", table_name="response_recommendations")
    op.drop_index("ix_response_recommendations_status", table_name="response_recommendations")
    op.drop_index("ix_response_recommendations_incident", table_name="response_recommendations")
    op.drop_table("response_recommendations")
