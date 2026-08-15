from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from porygon_api.db import Base


class ServiceHeartbeat(Base):
    __tablename__ = "service_heartbeats"
    __table_args__ = (
        UniqueConstraint("service_name", "instance_id", name="uq_service_heartbeat_identity"),
        Index("ix_service_heartbeats_last_seen_at", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    service_name: Mapped[str] = mapped_column(String(64), nullable=False)
    instance_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    service_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RuntimeEvent(Base):
    __tablename__ = "runtime_events"
    __table_args__ = (
        Index("ix_runtime_events_occurred_at", "occurred_at"),
        Index("ix_runtime_events_type_action", "event_type", "action"),
        Index("ix_runtime_events_container_id", "container_id"),
        Index("ix_runtime_events_container_name", "container_name"),
        Index("ix_runtime_events_image_digest", "image_digest"),
        Index("ix_runtime_events_docker_host_time", "docker_host_id", "time_nano"),
    )

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    docker_host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    time_nano: Mapped[int] = mapped_column(BigInteger, nullable=False)

    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    container_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    image_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_digest_status: Mapped[str] = mapped_column(String(32), nullable=False)
    command: Mapped[str | None] = mapped_column(Text, nullable=True)
    container_user: Mapped[str | None] = mapped_column(String(255), nullable=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    container_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ImageIdentity(Base):
    __tablename__ = "image_identities"
    __table_args__ = (
        UniqueConstraint("docker_host_id", "image_id", name="uq_image_identity_host_image"),
        Index("ix_image_identities_primary_digest", "primary_repo_digest"),
        Index("ix_image_identities_last_seen_at", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    docker_host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    image_id: Mapped[str] = mapped_column(String(128), nullable=False)
    image_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_repo_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    repo_digests: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    repo_tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    os: Mapped[str | None] = mapped_column(String(64), nullable=True)
    architecture: Mapped[str | None] = mapped_column(String(64), nullable=True)
    digest_status: Mapped[str] = mapped_column(String(32), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ContainerIdentity(Base):
    __tablename__ = "container_identities"
    __table_args__ = (
        UniqueConstraint("docker_host_id", "container_id", name="uq_container_identity_host_container"),
        Index("ix_container_identities_name", "container_name"),
        Index("ix_container_identities_image_digest", "image_digest"),
        Index("ix_container_identities_last_seen_at", "last_seen_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    docker_host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    container_id: Mapped[str] = mapped_column(String(128), nullable=False)
    container_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    image_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_digest_status: Mapped[str] = mapped_column(String(32), nullable=False)
    current_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ProcessExecEvent(Base):
    __tablename__ = "process_exec_events"
    __table_args__ = (
        Index("ix_process_exec_events_occurred_at", "occurred_at"),
        Index("ix_process_exec_events_container_time", "container_id", "time_nano"),
        Index("ix_process_exec_events_reported_container", "reported_container_id"),
        Index("ix_process_exec_events_image_digest", "image_digest"),
        Index("ix_process_exec_events_process_name", "process_name"),
        Index("ix_process_exec_events_pid", "docker_host_id", "process_pid", "occurred_at"),
        Index("ix_process_exec_events_parent_event", "parent_event_id"),
        Index("ix_process_exec_events_correlation", "correlation_status"),
    )

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    sensor_instance_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sensor_hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    time_nano: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)

    reported_docker_host_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reported_container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    docker_host_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    container_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    image_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    correlation_status: Mapped[str] = mapped_column(String(32), nullable=False)

    process_pid: Mapped[int] = mapped_column(BigInteger, nullable=False)
    process_ppid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    process_vpid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    executable: Mapped[str | None] = mapped_column(Text, nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    working_directory: Mapped[str | None] = mapped_column(Text, nullable=True)
    tty: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    parent_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    parent_executable: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_event_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    user_uid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    user_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    group_gid: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    group_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_fields: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    raw_event: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BehaviorProfile(Base):
    __tablename__ = "behavior_profiles"
    __table_args__ = (
        UniqueConstraint(
            "image_digest",
            "profile_version",
            name="uq_behavior_profiles_digest_version",
        ),
        UniqueConstraint(
            "image_digest",
            "model_hash",
            name="uq_behavior_profiles_digest_model_hash",
        ),
        CheckConstraint("profile_version >= 1", name="ck_behavior_profiles_version_positive"),
        CheckConstraint("window_seconds >= 1", name="ck_behavior_profiles_window_positive"),
        CheckConstraint(
            "status IN ('draft', 'active', 'retired')",
            name="ck_behavior_profiles_status",
        ),
        Index("ix_behavior_profiles_image_digest", "image_digest"),
        Index("ix_behavior_profiles_created_at", "created_at"),
        Index("ix_behavior_profiles_status", "status"),
        Index(
            "uq_behavior_profiles_one_active_digest",
            "image_digest",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
    )

    profile_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    model_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    training_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    training_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approval_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    process_event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    runtime_event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    container_count: Mapped[int] = mapped_column(Integer, nullable=False)
    window_count: Mapped[int] = mapped_column(Integer, nullable=False)
    quality: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    training_manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AnomalyScore(Base):
    __tablename__ = "anomaly_scores"
    __table_args__ = (
        CheckConstraint(
            "status IN ('scored', 'insufficient_data')",
            name="ck_anomaly_scores_status",
        ),
        CheckConstraint(
            "score_band IN ('baseline_like', 'elevated', 'high', 'extreme', 'insufficient_data')",
            name="ck_anomaly_scores_band",
        ),
        CheckConstraint(
            "total_score IS NULL OR (total_score >= 0 AND total_score <= 1)",
            name="ck_anomaly_scores_total_range",
        ),
        CheckConstraint("window_seconds >= 1", name="ck_anomaly_scores_window_positive"),
        UniqueConstraint("observation_key", name="uq_anomaly_scores_observation_key"),
        Index("ix_anomaly_scores_image_digest_window", "image_digest", "window_start"),
        Index("ix_anomaly_scores_profile_id", "profile_id"),
        Index("ix_anomaly_scores_total_score", "total_score"),
        Index("ix_anomaly_scores_created_at", "created_at"),
        Index("ix_anomaly_scores_status", "status"),
    )

    score_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    observation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("behavior_profiles.profile_id", ondelete="RESTRICT"),
        nullable=False,
    )
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_version: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_model_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm_version: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    score_band: Mapped[str] = mapped_column(String(32), nullable=False)
    total_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    process_event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    runtime_event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    container_count: Mapped[int] = mapped_column(Integer, nullable=False)
    components: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    observation_manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    scoring_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DetectionAllowlist(Base):
    __tablename__ = "detection_allowlists"
    __table_args__ = (
        CheckConstraint(
            "rule_id IN ('POR-DET-002', 'POR-DET-003', 'POR-DET-004')",
            name="ck_detection_allowlists_rule_id",
        ),
        Index(
            "uq_detection_allowlists_active_matcher",
            "matcher_hash",
            unique=True,
            postgresql_where=text("active"),
        ),
        Index("ix_detection_allowlists_digest_active", "image_digest", "active"),
        Index("ix_detection_allowlists_expires_at", "expires_at"),
    )

    allowlist_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    matcher_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(32), nullable=False)
    executable: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_executable: Mapped[str | None] = mapped_column(Text, nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approval_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deactivated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class DetectionRun(Base):
    __tablename__ = "detection_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('insufficient_data', 'no_findings', 'findings_only', 'incident_created')",
            name="ck_detection_runs_status",
        ),
        UniqueConstraint("run_key", name="uq_detection_runs_run_key"),
        UniqueConstraint(
            "score_id",
            "ruleset_version",
            "allowlist_set_hash",
            name="uq_detection_runs_score_ruleset_allowlists",
        ),
        Index("ix_detection_runs_image_digest_window", "image_digest", "window_start"),
        Index("ix_detection_runs_created_at", "created_at"),
        Index("ix_detection_runs_status", "status"),
    )

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_key: Mapped[str] = mapped_column(String(64), nullable=False)
    score_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("anomaly_scores.score_id", ondelete="RESTRICT"),
        nullable=False,
    )
    ruleset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    ruleset_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    allowlist_set_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    applied_allowlist_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    matches_count: Mapped[int] = mapped_column(Integer, nullable=False)
    incident_created: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'dismissed')",
            name="ck_incidents_status",
        ),
        CheckConstraint(
            "severity_level IN ('low', 'medium', 'high', 'critical')",
            name="ck_incidents_severity_level",
        ),
        CheckConstraint(
            "confidence_level IN ('low', 'medium', 'high')",
            name="ck_incidents_confidence_level",
        ),
        CheckConstraint(
            "anomaly_score >= 0 AND anomaly_score <= 1",
            name="ck_incidents_anomaly_range",
        ),
        CheckConstraint(
            "severity_score >= 0 AND severity_score <= 1",
            name="ck_incidents_severity_range",
        ),
        CheckConstraint(
            "confidence_score >= 0 AND confidence_score <= 1",
            name="ck_incidents_confidence_range",
        ),
        UniqueConstraint("detection_run_id", name="uq_incidents_detection_run"),
        Index("ix_incidents_image_digest_first_seen", "image_digest", "first_seen_at"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_severity", "severity_score"),
        Index("ix_incidents_created_at", "created_at"),
    )

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    detection_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("detection_runs.run_id", ondelete="RESTRICT"),
        nullable=False,
    )
    score_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("anomaly_scores.score_id", ondelete="RESTRICT"),
        nullable=False,
    )
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity_level: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence_level: Mapped[str] = mapped_column(String(16), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    container_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    closure_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    __table_args__ = (
        UniqueConstraint(
            "incident_id",
            "sequence_no",
            name="uq_incident_evidence_sequence",
        ),
        Index("ix_incident_evidence_incident_time", "incident_id", "occurred_at"),
        Index("ix_incident_evidence_source", "source_type", "source_id"),
        Index("ix_incident_evidence_rule", "rule_id"),
    )

    evidence_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="CASCADE"),
        nullable=False,
    )
    sequence_no: Mapped[int] = mapped_column(Integer, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence_type: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ResponseRecommendation(Base):
    __tablename__ = "response_recommendations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('proposed', 'approved', 'rejected')",
            name="ck_response_recommendations_status",
        ),
        CheckConstraint(
            "recommended_action IN ('observe_only', 'pause_container', 'stop_container')",
            name="ck_response_recommendations_action",
        ),
        CheckConstraint(
            "approved_action IS NULL OR approved_action IN ('observe_only', 'pause_container', 'stop_container')",
            name="ck_response_recommendations_approved_action",
        ),
        UniqueConstraint("recommendation_key", name="uq_response_recommendations_key"),
        Index("ix_response_recommendations_incident", "incident_id", "created_at"),
        Index("ix_response_recommendations_status", "status"),
        Index("ix_response_recommendations_target", "target_container_id"),
    )

    recommendation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recommendation_key: Mapped[str] = mapped_column(String(64), nullable=False)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(32), nullable=False)
    allowed_actions: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    risk_notes: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_action: Mapped[str | None] = mapped_column(String(32), nullable=True)


class ResponseExecution(Base):
    __tablename__ = "response_executions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'claimed', 'succeeded', 'failed', "
            "'rollback_pending', 'rollback_claimed', 'rolled_back', 'rollback_failed')",
            name="ck_response_executions_status",
        ),
        CheckConstraint(
            "action_type IN ('observe_only', 'pause_container', 'stop_container')",
            name="ck_response_executions_action",
        ),
        UniqueConstraint("recommendation_id", name="uq_response_executions_recommendation"),
        UniqueConstraint("idempotency_key", name="uq_response_executions_idempotency"),
        Index("ix_response_executions_status_created", "status", "created_at"),
        Index("ix_response_executions_incident", "incident_id"),
        Index("ix_response_executions_target", "target_container_id"),
        Index("ix_response_executions_lease", "lease_expires_at"),
    )

    execution_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    recommendation_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("response_recommendations.recommendation_id", ondelete="RESTRICT"),
        nullable=False,
    )
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    target_container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    executor_instance_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    pre_state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    post_state: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rollback_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    rollback_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ResponseAuditEvent(Base):
    __tablename__ = "response_audit_events"
    __table_args__ = (
        Index("ix_response_audit_incident_time", "incident_id", "created_at"),
        Index("ix_response_audit_recommendation", "recommendation_id"),
        Index("ix_response_audit_execution", "execution_id"),
        Index("ix_response_audit_type", "event_type"),
    )

    audit_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("incidents.incident_id", ondelete="RESTRICT"),
        nullable=False,
    )
    recommendation_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("response_recommendations.recommendation_id", ondelete="SET NULL"),
        nullable=True,
    )
    execution_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("response_executions.execution_id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ImageScan(Base):
    __tablename__ = "image_scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'claimed', 'completed', 'failed')",
            name="ck_image_scans_status",
        ),
        UniqueConstraint("scan_key", name="uq_image_scans_key"),
        Index("ix_image_scans_digest_created", "image_digest", "created_at"),
        Index("ix_image_scans_status_created", "status", "created_at"),
        Index("ix_image_scans_lease", "lease_expires_at"),
    )

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_key: Mapped[str] = mapped_column(String(64), nullable=False)
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    image_id: Mapped[str] = mapped_column(String(128), nullable=False)
    docker_host_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scanner_name: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    request_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_instance_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    scanner_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class SbomArtifact(Base):
    __tablename__ = "sbom_artifacts"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_sbom_artifacts_scan"),
        Index("ix_sbom_artifacts_image_digest", "image_digest"),
    )

    artifact_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("image_scans.scan_id", ondelete="CASCADE"), nullable=False
    )
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    spec_version: Mapped[str] = mapped_column(String(32), nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VulnerabilityReportArtifact(Base):
    __tablename__ = "vulnerability_report_artifacts"
    __table_args__ = (
        UniqueConstraint("scan_id", name="uq_vulnerability_report_artifacts_scan"),
        Index("ix_vulnerability_report_artifacts_digest", "image_digest"),
    )

    artifact_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("image_scans.scan_id", ondelete="CASCADE"), nullable=False
    )
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    document_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    document: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VulnerabilityIntel(Base):
    __tablename__ = "vulnerability_intel"
    __table_args__ = (
        CheckConstraint("epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)", name="ck_vulnerability_intel_epss_score"),
        CheckConstraint("epss_percentile IS NULL OR (epss_percentile >= 0 AND epss_percentile <= 1)", name="ck_vulnerability_intel_epss_percentile"),
        Index("ix_vulnerability_intel_kev", "kev"),
        Index("ix_vulnerability_intel_epss", "epss_score"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    kev_date_added: Mapped[str | None] = mapped_column(String(10), nullable=True)
    kev_due_date: Mapped[str | None] = mapped_column(String(10), nullable=True)
    kev_vendor_project: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kev_vulnerability_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_required_action: Mapped[str | None] = mapped_column(Text, nullable=True)
    kev_known_ransomware_use: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class VulnerabilityFinding(Base):
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_id", "cve_id", "target", "package_type", "package_name", "installed_version",
            name="uq_vulnerability_findings_identity",
        ),
        Index("ix_vulnerability_findings_scan", "scan_id"),
        Index("ix_vulnerability_findings_digest", "image_digest"),
        Index("ix_vulnerability_findings_cve", "cve_id"),
        Index("ix_vulnerability_findings_severity", "severity"),
    )

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("image_scans.scan_id", ondelete="CASCADE"), nullable=False
    )
    image_digest: Mapped[str] = mapped_column(String(255), nullable=False)
    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("vulnerability_intel.cve_id", ondelete="RESTRICT"), nullable=False
    )
    target: Mapped[str] = mapped_column(Text, nullable=False)
    class_name: Mapped[str] = mapped_column(String(64), nullable=False)
    package_type: Mapped[str] = mapped_column(String(64), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    package_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    installed_version: Mapped[str] = mapped_column(Text, nullable=False)
    fixed_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    severity_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(Text, nullable=True)
    cvss_source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    data_source: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_stage: Mapped[str] = mapped_column(String(64), nullable=False)
    exploit_status: Mapped[str] = mapped_column(String(32), nullable=False)
    exposure_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    intel_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
