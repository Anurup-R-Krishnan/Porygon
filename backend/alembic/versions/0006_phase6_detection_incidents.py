"""Add deterministic detection runs, incidents, and evidence timelines.

Revision ID: 0006_phase6
Revises: 0005_phase5
Create Date: 2026-07-21
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_phase6"
down_revision: Union[str, None] = "0005_phase5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detection_allowlists",
        sa.Column("allowlist_id", sa.String(length=36), primary_key=True),
        sa.Column("matcher_hash", sa.String(length=64), nullable=False),
        sa.Column("image_digest", sa.String(length=255), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=False),
        sa.Column("executable", sa.Text(), nullable=True),
        sa.Column("parent_executable", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=False),
        sa.Column("approval_reference", sa.String(length=255), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivated_by", sa.String(length=128), nullable=True),
        sa.CheckConstraint(
            "rule_id IN ('POR-DET-002', 'POR-DET-003', 'POR-DET-004')",
            name="ck_detection_allowlists_rule_id",
        ),
    )
    op.create_index(
        "uq_detection_allowlists_active_matcher",
        "detection_allowlists",
        ["matcher_hash"],
        unique=True,
        postgresql_where=sa.text("active"),
    )
    op.create_index(
        "ix_detection_allowlists_digest_active",
        "detection_allowlists",
        ["image_digest", "active"],
    )
    op.create_index(
        "ix_detection_allowlists_expires_at",
        "detection_allowlists",
        ["expires_at"],
    )

    op.create_table(
        "detection_runs",
        sa.Column("run_id", sa.String(length=36), primary_key=True),
        sa.Column("run_key", sa.String(length=64), nullable=False),
        sa.Column(
            "score_id",
            sa.String(length=36),
            sa.ForeignKey("anomaly_scores.score_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("ruleset_version", sa.String(length=64), nullable=False),
        sa.Column("ruleset_hash", sa.String(length=64), nullable=False),
        sa.Column("allowlist_set_hash", sa.String(length=64), nullable=False),
        sa.Column("applied_allowlist_ids", sa.JSON(), nullable=False),
        sa.Column("image_digest", sa.String(length=255), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("matches_count", sa.Integer(), nullable=False),
        sa.Column("incident_created", sa.Boolean(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('insufficient_data', 'no_findings', 'findings_only', 'incident_created')",
            name="ck_detection_runs_status",
        ),
        sa.UniqueConstraint("run_key", name="uq_detection_runs_run_key"),
        sa.UniqueConstraint(
            "score_id",
            "ruleset_version",
            "allowlist_set_hash",
            name="uq_detection_runs_score_ruleset_allowlists",
        ),
    )
    op.create_index(
        "ix_detection_runs_image_digest_window",
        "detection_runs",
        ["image_digest", "window_start"],
    )
    op.create_index("ix_detection_runs_created_at", "detection_runs", ["created_at"])
    op.create_index("ix_detection_runs_status", "detection_runs", ["status"])

    op.create_table(
        "incidents",
        sa.Column("incident_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "detection_run_id",
            sa.String(length=36),
            sa.ForeignKey("detection_runs.run_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "score_id",
            sa.String(length=36),
            sa.ForeignKey("anomaly_scores.score_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("image_digest", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("anomaly_score", sa.Float(), nullable=False),
        sa.Column("severity_score", sa.Float(), nullable=False),
        sa.Column("severity_level", sa.String(length=16), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=False),
        sa.Column("confidence_level", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("container_ids", sa.JSON(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=128), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_by", sa.String(length=128), nullable=True),
        sa.Column("closure_note", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'dismissed')",
            name="ck_incidents_status",
        ),
        sa.CheckConstraint(
            "severity_level IN ('low', 'medium', 'high', 'critical')",
            name="ck_incidents_severity_level",
        ),
        sa.CheckConstraint(
            "confidence_level IN ('low', 'medium', 'high')",
            name="ck_incidents_confidence_level",
        ),
        sa.CheckConstraint(
            "anomaly_score >= 0 AND anomaly_score <= 1",
            name="ck_incidents_anomaly_range",
        ),
        sa.CheckConstraint(
            "severity_score >= 0 AND severity_score <= 1",
            name="ck_incidents_severity_range",
        ),
        sa.CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 1",
            name="ck_incidents_confidence_range",
        ),
        sa.UniqueConstraint("detection_run_id", name="uq_incidents_detection_run"),
    )
    op.create_index(
        "ix_incidents_image_digest_first_seen",
        "incidents",
        ["image_digest", "first_seen_at"],
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_severity", "incidents", ["severity_score"])
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])

    op.create_table(
        "incident_evidence",
        sa.Column("evidence_id", sa.String(length=36), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=36),
            sa.ForeignKey("incidents.incident_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence_no", sa.Integer(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_type", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column("rule_id", sa.String(length=32), nullable=True),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "incident_id",
            "sequence_no",
            name="uq_incident_evidence_sequence",
        ),
    )
    op.create_index(
        "ix_incident_evidence_incident_time",
        "incident_evidence",
        ["incident_id", "occurred_at"],
    )
    op.create_index(
        "ix_incident_evidence_source",
        "incident_evidence",
        ["source_type", "source_id"],
    )
    op.create_index("ix_incident_evidence_rule", "incident_evidence", ["rule_id"])


def downgrade() -> None:
    op.drop_index("ix_incident_evidence_rule", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_source", table_name="incident_evidence")
    op.drop_index("ix_incident_evidence_incident_time", table_name="incident_evidence")
    op.drop_table("incident_evidence")

    op.drop_index("ix_incidents_created_at", table_name="incidents")
    op.drop_index("ix_incidents_severity", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_image_digest_first_seen", table_name="incidents")
    op.drop_table("incidents")

    op.drop_index("ix_detection_runs_status", table_name="detection_runs")
    op.drop_index("ix_detection_runs_created_at", table_name="detection_runs")
    op.drop_index("ix_detection_runs_image_digest_window", table_name="detection_runs")
    op.drop_table("detection_runs")

    op.drop_index("ix_detection_allowlists_expires_at", table_name="detection_allowlists")
    op.drop_index("ix_detection_allowlists_digest_active", table_name="detection_allowlists")
    op.drop_index("uq_detection_allowlists_active_matcher", table_name="detection_allowlists")
    op.drop_table("detection_allowlists")
