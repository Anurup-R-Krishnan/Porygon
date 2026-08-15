from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class HealthResponse(BaseModel):
    status: Literal["ok", "not_ready"]
    service: str
    version: str
    database: Literal["up", "down", "not_checked"]


class HeartbeatIn(BaseModel):
    service_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    instance_id: str = Field(min_length=1, max_length=128)
    status: Literal["starting", "healthy", "degraded"]
    observed_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("observed_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must include a timezone offset")
        return value


class HeartbeatOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    service_name: str
    instance_id: str
    status: str
    service_metadata: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime


class RuntimeEventIn(BaseModel):
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    docker_host_id: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=32)
    action: str = Field(min_length=1, max_length=64)
    scope: str | None = Field(default=None, max_length=64)
    actor_id: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    time_nano: int = Field(ge=0)

    container_id: str | None = Field(default=None, max_length=128)
    container_name: str | None = Field(default=None, max_length=255)
    image_id: str | None = Field(default=None, max_length=128)
    image_ref: str | None = None
    image_digest: str | None = Field(default=None, max_length=255)
    image_digest_status: Literal["resolved", "unavailable", "inspection_failed", "not_applicable"]
    command: str | None = None
    container_user: str | None = Field(default=None, max_length=255)

    attributes: dict[str, Any] = Field(default_factory=dict)
    container_snapshot: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any]

    @field_validator("occurred_at")
    @classmethod
    def require_event_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone offset")
        return value


class RuntimeEventBatchIn(BaseModel):
    events: list[RuntimeEventIn] = Field(min_length=1, max_length=250)


class RuntimeEventBatchOut(BaseModel):
    received: int
    inserted: int
    duplicates: int


class RuntimeEventOut(RuntimeEventIn):
    model_config = ConfigDict(from_attributes=True)
    received_at: datetime


class ProcessExecEventIn(BaseModel):
    event_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    sensor_instance_id: str = Field(min_length=1, max_length=128)
    sensor_hostname: str | None = Field(default=None, max_length=255)
    source: Literal["falco"]
    rule_name: str = Field(min_length=1, max_length=255)
    priority: str = Field(min_length=1, max_length=32)
    occurred_at: datetime
    time_nano: int = Field(ge=0)
    event_number: int | None = Field(default=None, ge=0)
    event_type: str = Field(min_length=1, max_length=64)

    reported_docker_host_id: str | None = Field(default=None, max_length=128)
    reported_container_id: str | None = Field(default=None, max_length=128)
    reported_container_name: str | None = Field(default=None, max_length=255)
    reported_image_ref: str | None = None

    process_pid: int = Field(ge=0)
    process_ppid: int | None = Field(default=None, ge=0)
    process_vpid: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)
    executable: str | None = None
    command_line: str | None = None
    working_directory: str | None = None
    tty: int | None = Field(default=None, ge=0)

    parent_name: str | None = Field(default=None, max_length=255)
    parent_executable: str | None = None
    parent_command_line: str | None = None

    user_uid: int | None = Field(default=None, ge=0)
    user_name: str | None = Field(default=None, max_length=255)
    group_gid: int | None = Field(default=None, ge=0)
    group_name: str | None = Field(default=None, max_length=255)

    tags: list[str] = Field(default_factory=list, max_length=64)
    output: str | None = None
    output_fields: dict[str, Any] = Field(default_factory=dict)
    raw_event: dict[str, Any]

    @field_validator("occurred_at")
    @classmethod
    def require_process_event_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("occurred_at must include a timezone offset")
        return value


class ProcessExecEventBatchIn(BaseModel):
    events: list[ProcessExecEventIn] = Field(min_length=1, max_length=250)


class ProcessExecEventBatchOut(BaseModel):
    received: int
    inserted: int
    duplicates: int
    resolved: int
    unresolved: int
    ambiguous: int


class ProcessExecEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    sensor_instance_id: str
    sensor_hostname: str | None
    source: str
    rule_name: str
    priority: str
    occurred_at: datetime
    time_nano: int
    event_number: int | None
    event_type: str

    reported_docker_host_id: str | None
    reported_container_id: str | None
    docker_host_id: str | None
    container_id: str | None
    container_name: str | None
    image_id: str | None
    image_ref: str | None
    image_digest: str | None
    correlation_status: str

    process_pid: int
    process_ppid: int | None
    process_vpid: int | None
    process_name: str | None
    executable: str | None
    command_line: str | None
    working_directory: str | None
    tty: int | None

    parent_name: str | None
    parent_executable: str | None
    parent_command_line: str | None
    parent_event_id: str | None

    user_uid: int | None
    user_name: str | None
    group_gid: int | None
    group_name: str | None

    tags: list[str]
    output: str | None
    output_fields: dict[str, Any]
    raw_event: dict[str, Any]
    received_at: datetime


class ProcessEventSummary(BaseModel):
    total_events: int
    distinct_containers: int
    resolved_events: int
    unresolved_events: int
    ambiguous_events: int
    linked_parent_events: int
    by_process_name: dict[str, int]


class ImageIdentityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    docker_host_id: str
    image_id: str
    image_ref: str | None
    primary_repo_digest: str | None
    repo_digests: list[str]
    repo_tags: list[str]
    os: str | None
    architecture: str | None
    digest_status: str
    first_seen_at: datetime
    last_seen_at: datetime


class ContainerIdentityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    docker_host_id: str
    container_id: str
    container_name: str | None
    image_id: str | None
    image_ref: str | None
    image_digest: str | None
    image_digest_status: str
    current_snapshot: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime


class EventSummary(BaseModel):
    total_events: int
    distinct_containers: int
    resolved_digest_events: int
    unresolved_digest_events: int
    by_action: dict[str, int]


class SystemInfo(BaseModel):
    name: str
    version: str
    phase: str
    environment: str
    registered_services: int
    runtime_events: int
    process_exec_events: int
    known_containers: int
    known_images: int
    behavior_profiles: int
    active_behavior_profiles: int
    anomaly_scores: int
    scored_observations: int
    insufficient_observations: int
    detection_allowlists: int
    active_detection_allowlists: int
    detection_runs: int
    incidents: int
    open_incidents: int
    response_recommendations: int
    approved_response_recommendations: int
    response_executions: int
    pending_response_executions: int
    successful_response_executions: int
    image_scans: int = 0
    completed_image_scans: int = 0
    sbom_artifacts: int = 0
    vulnerability_reports: int = 0
    vulnerability_findings: int = 0
    cisa_kev_findings: int = 0


class BehaviorProfileBuildIn(BaseModel):
    image_digest: str = Field(
        min_length=72,
        max_length=255,
        pattern=r"^[^\s@]+@sha256:[0-9a-f]{64}$",
    )
    training_start: datetime
    training_end: datetime
    window_seconds: int = Field(default=60, ge=5, le=3600)
    minimum_process_events: int = Field(default=20, ge=1, le=1000000)
    minimum_nonempty_windows: int = Field(default=3, ge=1, le=100000)
    approved_by: str = Field(min_length=1, max_length=128)
    approval_reference: str | None = Field(default=None, max_length=255)
    notes: str | None = Field(default=None, max_length=4000)

    @field_validator("training_start", "training_end")
    @classmethod
    def require_training_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("training timestamps must include a timezone offset")
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> "BehaviorProfileBuildIn":
        if self.training_end <= self.training_start:
            raise ValueError("training_end must be after training_start")
        return self


class BehaviorProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    profile_id: str
    image_digest: str
    profile_version: int
    status: Literal["draft", "active", "retired"]
    feature_schema_version: str
    model_hash: str
    training_start: datetime
    training_end: datetime
    window_seconds: int
    approved_by: str
    approval_reference: str | None
    notes: str | None
    process_event_count: int
    runtime_event_count: int
    container_count: int
    window_count: int
    quality: dict[str, Any]
    training_manifest: dict[str, Any]
    features: dict[str, Any]
    created_at: datetime
    activated_at: datetime | None
    retired_at: datetime | None


class AnomalyScoreComputeIn(BaseModel):
    image_digest: str = Field(
        min_length=72,
        max_length=255,
        pattern=r"^[^\s@]+@sha256:[0-9a-f]{64}$",
    )
    window_start: datetime
    profile_id: str | None = Field(default=None, min_length=36, max_length=36)

    @field_validator("window_start")
    @classmethod
    def require_window_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("window_start must include a timezone offset")
        return value


class AnomalyScoreOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    score_id: str
    observation_key: str
    profile_id: str
    image_digest: str
    profile_version: int
    profile_model_hash: str
    algorithm_version: str
    status: Literal["scored", "insufficient_data"]
    score_band: Literal[
        "baseline_like",
        "elevated",
        "high",
        "extreme",
        "insufficient_data",
    ]
    total_score: float | None
    window_start: datetime
    window_end: datetime
    window_seconds: int
    process_event_count: int
    runtime_event_count: int
    container_count: int
    components: dict[str, Any]
    explanation: dict[str, Any]
    observation_manifest: dict[str, Any]
    scoring_config: dict[str, Any]
    created_at: datetime


class DetectionRunIn(BaseModel):
    anomaly_score_id: str = Field(min_length=36, max_length=36)


class DetectionRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    run_key: str
    score_id: str
    ruleset_version: str
    ruleset_hash: str
    allowlist_set_hash: str
    applied_allowlist_ids: list[str]
    image_digest: str
    window_start: datetime
    window_end: datetime
    status: Literal[
        "insufficient_data",
        "no_findings",
        "findings_only",
        "incident_created",
    ]
    matches_count: int
    incident_created: bool
    result: dict[str, Any]
    created_at: datetime


class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    detection_run_id: str
    score_id: str
    image_digest: str
    title: str
    status: Literal["open", "acknowledged", "resolved", "dismissed"]
    anomaly_score: float
    severity_score: float
    severity_level: Literal["low", "medium", "high", "critical"]
    confidence_score: float
    confidence_level: Literal["low", "medium", "high"]
    summary: str
    findings: list[dict[str, Any]]
    container_ids: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    closed_at: datetime | None
    closed_by: str | None
    closure_note: str | None


class IncidentEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    incident_id: str
    sequence_no: int
    occurred_at: datetime
    source_type: str
    source_id: str
    rule_id: str | None
    evidence_type: str
    summary: str
    details: dict[str, Any]
    created_at: datetime


class DetectionExecutionOut(BaseModel):
    run: DetectionRunOut
    incident: IncidentOut | None
    timeline: list[IncidentEvidenceOut]


class IncidentStatusUpdateIn(BaseModel):
    status: Literal["acknowledged", "resolved", "dismissed"]
    actor: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=4000)


class DetectionAllowlistCreateIn(BaseModel):
    image_digest: str = Field(
        min_length=72,
        max_length=255,
        pattern=r"^[^\s@]+@sha256:[0-9a-f]{64}$",
    )
    rule_id: Literal["POR-DET-002", "POR-DET-003", "POR-DET-004"]
    executable: str = Field(min_length=1, max_length=4096)
    parent_executable: str | None = Field(default=None, min_length=1, max_length=4096)
    reason: str = Field(min_length=1, max_length=4000)
    approved_by: str = Field(min_length=1, max_length=128)
    approval_reference: str | None = Field(default=None, max_length=255)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def require_expiry_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("expires_at must include a timezone offset")
        return value


class DetectionAllowlistOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    allowlist_id: str
    matcher_hash: str
    image_digest: str
    rule_id: str
    executable: str | None
    parent_executable: str | None
    reason: str
    approved_by: str
    approval_reference: str | None
    active: bool
    created_at: datetime
    expires_at: datetime | None
    deactivated_at: datetime | None
    deactivated_by: str | None


class DetectionAllowlistDeactivateIn(BaseModel):
    actor: str = Field(min_length=1, max_length=128)


class ResponseRecommendationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    recommendation_id: str
    recommendation_key: str
    incident_id: str
    target_container_id: str | None
    policy_version: str
    policy_hash: str
    recommended_action: Literal["observe_only", "pause_container", "stop_container"]
    allowed_actions: list[Literal["observe_only", "pause_container", "stop_container"]]
    rationale: str
    risk_notes: list[str]
    status: Literal["proposed", "approved", "rejected"]
    created_at: datetime
    decided_at: datetime | None
    decided_by: str | None
    decision_note: str | None
    approved_action: Literal["observe_only", "pause_container", "stop_container"] | None


class ResponseRecommendationGenerateOut(BaseModel):
    incident_id: str
    recommendations: list[ResponseRecommendationOut]


class ResponseRecommendationDecisionIn(BaseModel):
    actor: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=4000)


class ResponseRecommendationApproveIn(ResponseRecommendationDecisionIn):
    action_type: Literal["observe_only", "pause_container", "stop_container"]
    acknowledge_disruption: bool = False


class ResponseExecutionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    execution_id: str
    recommendation_id: str
    incident_id: str
    target_container_id: str | None
    action_type: Literal["observe_only", "pause_container", "stop_container"]
    status: Literal[
        "pending",
        "claimed",
        "succeeded",
        "failed",
        "rollback_pending",
        "rollback_claimed",
        "rolled_back",
        "rollback_failed",
    ]
    idempotency_key: str
    executor_instance_id: str | None
    lease_expires_at: datetime | None
    attempt_count: int
    pre_state: dict[str, Any]
    post_state: dict[str, Any]
    result: dict[str, Any]
    error_code: str | None
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    rollback_requested_at: datetime | None
    rollback_requested_by: str | None
    rollback_note: str | None
    rollback_started_at: datetime | None
    rollback_completed_at: datetime | None


class ResponseClaimIn(BaseModel):
    executor_instance_id: str = Field(min_length=1, max_length=128)
    lease_seconds: int = Field(default=30, ge=10, le=300)


class ResponseClaimOut(BaseModel):
    execution: ResponseExecutionOut | None
    operation: Literal["execute", "rollback"] | None


class ResponseExecutionCompleteIn(BaseModel):
    executor_instance_id: str = Field(min_length=1, max_length=128)
    success: bool
    pre_state: dict[str, Any] = Field(default_factory=dict)
    post_state: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error_code: str | None = Field(default=None, max_length=64)
    error_message: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def validate_error(self) -> "ResponseExecutionCompleteIn":
        if self.success and (self.error_code or self.error_message):
            raise ValueError("successful completion cannot include an error")
        if not self.success and not self.error_code:
            raise ValueError("failed completion requires error_code")
        return self


class ResponseRollbackRequestIn(BaseModel):
    actor: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=4000)
    acknowledge_limitations: bool = False


class ResponseRetryRequestIn(BaseModel):
    actor: str = Field(min_length=1, max_length=128)
    note: str = Field(min_length=1, max_length=4000)
    acknowledge_retry: bool = False


class ResponseAuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    audit_id: str
    incident_id: str
    recommendation_id: str | None
    execution_id: str | None
    event_type: str
    actor: str
    details: dict[str, Any]
    created_at: datetime


class ImageScanCreateIn(BaseModel):
    image_digest: str = Field(min_length=72, max_length=255, pattern=r"^[^\s@]+@sha256:[0-9a-f]{64}$")
    requested_by: str = Field(min_length=1, max_length=128)
    docker_host_id: str | None = Field(default=None, max_length=128)
    scan_reference: str = Field(default="initial", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    note: str | None = Field(default=None, max_length=4000)
    scanner_name: Literal["trivy"] = "trivy"
    scanner_version: str = Field(default="0.72.0", pattern=r"^\d+\.\d+\.\d+$", max_length=32)


class ImageScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    scan_key: str
    image_digest: str
    image_id: str
    docker_host_id: str
    scanner_name: str
    scanner_version: str
    scan_reference: str
    status: Literal["queued", "claimed", "completed", "failed"]
    requested_by: str
    request_note: str | None
    scanner_instance_id: str | None
    lease_expires_at: datetime | None
    attempt_count: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_code: str | None
    error_message: str | None
    scanner_metadata: dict[str, Any]
    summary: dict[str, Any]


class ImageScanClaimIn(BaseModel):
    scanner_instance_id: str = Field(min_length=1, max_length=128)
    scanner_name: Literal["trivy"] = "trivy"
    scanner_version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    lease_seconds: int = Field(default=900, ge=60, le=7200)


class ImageScanClaimOut(BaseModel):
    scan: ImageScanOut | None


class ImageScanRenewIn(BaseModel):
    scanner_instance_id: str = Field(min_length=1, max_length=128)
    lease_seconds: int = Field(default=900, ge=60, le=20000)


class VulnerabilityIntelIn(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$", max_length=32)
    epss_score: float | None = Field(default=None, ge=0, le=1)
    epss_percentile: float | None = Field(default=None, ge=0, le=1)
    epss_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    kev: bool = False
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_vendor_project: str | None = Field(default=None, max_length=255)
    kev_product: str | None = Field(default=None, max_length=255)
    kev_vulnerability_name: str | None = None
    kev_required_action: str | None = None
    kev_known_ransomware_use: str | None = Field(default=None, max_length=32)
    source_metadata: dict[str, Any] = Field(default_factory=dict)


class ImageScanCompleteIn(BaseModel):
    scanner_instance_id: str = Field(min_length=1, max_length=128)
    scanner_metadata: dict[str, Any] = Field(default_factory=dict)
    trivy_report: dict[str, Any]
    cyclonedx_sbom: dict[str, Any]
    vulnerability_intel: list[VulnerabilityIntelIn] = Field(default_factory=list, max_length=10000)


class ImageScanFailIn(BaseModel):
    scanner_instance_id: str = Field(min_length=1, max_length=128)
    error_code: Literal[
        "image_identity_mismatch",
        "image_not_found",
        "scanner_error",
        "scanner_timeout",
        "intel_fetch_error",
        "invalid_scanner_output",
        "executor_internal_error",
    ]
    error_message: str = Field(min_length=1, max_length=8000)
    scanner_metadata: dict[str, Any] = Field(default_factory=dict)


class SbomArtifactSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: str
    scan_id: str
    image_digest: str
    format: str
    spec_version: str
    component_count: int
    document_sha256: str
    summary: dict[str, Any]
    created_at: datetime


class SbomArtifactOut(SbomArtifactSummaryOut):
    document: dict[str, Any]


class VulnerabilityReportArtifactSummaryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: str
    scan_id: str
    image_digest: str
    format: str
    schema_version: int | None
    finding_count: int
    document_sha256: str
    summary: dict[str, Any]
    created_at: datetime


class VulnerabilityReportArtifactOut(VulnerabilityReportArtifactSummaryOut):
    document: dict[str, Any]


class VulnerabilityIntelOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cve_id: str
    epss_score: float | None
    epss_percentile: float | None
    epss_date: str | None
    kev: bool
    kev_date_added: str | None
    kev_due_date: str | None
    kev_vendor_project: str | None
    kev_product: str | None
    kev_vulnerability_name: str | None
    kev_required_action: str | None
    kev_known_ransomware_use: str | None
    source_metadata: dict[str, Any]
    fetched_at: datetime


class VulnerabilityFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    scan_id: str
    image_digest: str
    cve_id: str
    target: str
    class_name: str
    package_type: str
    package_name: str
    package_path: str | None
    installed_version: str
    fixed_version: str | None
    status: str | None
    severity: str
    severity_source: str | None
    cvss_score: float | None
    cvss_vector: str | None
    cvss_source: str | None
    title: str | None
    description: str | None
    primary_url: str | None
    references: list[str]
    data_source: dict[str, Any]
    evidence_stage: str
    exploit_status: Literal["not_established"]
    exposure_evidence: dict[str, Any]
    intel_snapshot: dict[str, Any]
    limitations: list[str]
    created_at: datetime


class ImageScanDetailOut(BaseModel):
    scan: ImageScanOut
    sbom: SbomArtifactSummaryOut | None
    report: VulnerabilityReportArtifactSummaryOut | None
    vulnerabilities: list[VulnerabilityFindingOut]
    intel: list[VulnerabilityIntelOut]
