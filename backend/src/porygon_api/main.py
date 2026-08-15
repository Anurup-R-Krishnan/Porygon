from __future__ import annotations

import logging
import math
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, status
from sqlalchemy import case, desc, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from porygon_api.baseline import FEATURE_SCHEMA_VERSION, build_profile_document
from porygon_api.config import get_settings
from porygon_api.detection import (
    CORRELATION_WINDOW_SECONDS,
    DETECTION_RULES,
    RULESET_VERSION,
    allowlist_set_hash,
    build_allowlist_matcher_hash,
    build_detection_run_key,
    evaluate_detection,
    ruleset_hash,
)
from porygon_api.db import get_db
from porygon_api.models import (
    AnomalyScore,
    BehaviorProfile,
    DetectionAllowlist,
    DetectionRun,
    Incident,
    IncidentEvidence,
    ResponseAuditEvent,
    ResponseExecution,
    ResponseRecommendation,
    ContainerIdentity,
    ImageIdentity,
    ProcessExecEvent,
    RuntimeEvent,
    ServiceHeartbeat,
    ImageScan,
    SbomArtifact,
    VulnerabilityReportArtifact,
    VulnerabilityFinding,
    VulnerabilityIntel,
)
from porygon_api.schemas import (
    AnomalyScoreComputeIn,
    AnomalyScoreOut,
    BehaviorProfileBuildIn,
    BehaviorProfileOut,
    ContainerIdentityOut,
    DetectionAllowlistCreateIn,
    DetectionAllowlistDeactivateIn,
    DetectionAllowlistOut,
    DetectionExecutionOut,
    DetectionRunIn,
    DetectionRunOut,
    EventSummary,
    HealthResponse,
    HeartbeatIn,
    HeartbeatOut,
    ImageIdentityOut,
    IncidentEvidenceOut,
    IncidentOut,
    IncidentStatusUpdateIn,
    ResponseAuditEventOut,
    ResponseClaimIn,
    ResponseClaimOut,
    ResponseExecutionCompleteIn,
    ResponseExecutionOut,
    ResponseRecommendationApproveIn,
    ResponseRecommendationDecisionIn,
    ResponseRecommendationGenerateOut,
    ResponseRecommendationOut,
    ResponseRollbackRequestIn,
    ResponseRetryRequestIn,
    ProcessEventSummary,
    ProcessExecEventBatchIn,
    ProcessExecEventBatchOut,
    ProcessExecEventOut,
    RuntimeEventBatchIn,
    RuntimeEventBatchOut,
    RuntimeEventOut,
    SystemInfo,
    ImageScanCreateIn,
    ImageScanOut,
    ImageScanClaimIn,
    ImageScanClaimOut,
    ImageScanRenewIn,
    ImageScanCompleteIn,
    ImageScanFailIn,
    ImageScanDetailOut,
    SbomArtifactOut,
    VulnerabilityReportArtifactOut,
    VulnerabilityFindingOut,
    VulnerabilityIntelOut,
)
from porygon_api.scoring import (
    ALGORITHM_VERSION,
    SCORING_CONFIG,
    build_observation_key,
    score_feature_documents,
)
from porygon_api.response import (
    RESPONSE_POLICY,
    build_execution_idempotency_key,
    build_recommendation_document,
    build_recommendation_key,
    response_policy_hash,
)
from porygon_api.security import require_internal_token, require_operator_token
from porygon_api.vulnerability import (
    assess_exposure,
    build_scan_key,
    normalize_trivy_report,
    sbom_summary,
    sha256_document,
    summarize_findings,
)

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("porygon.api")

APP_VERSION = "0.8.0"
PHASE_ID = "8-sbom-vulnerability-enrichment"

app = FastAPI(
    title=settings.app_name,
    version=APP_VERSION,
    description=(
        "Porygon Phase 8 control plane for Docker identity, runtime telemetry, digest-bound profiles, "
        "explainable scoring, incidents, human-approved response, and evidence-staged vulnerability enrichment."
    ),
)


@app.get("/", include_in_schema=False)
def root() -> dict[str, str]:
    return {
        "name": settings.app_name,
        "version": APP_VERSION,
        "phase": PHASE_ID,
        "docs": "/docs",
    }


@app.get("/health/live", response_model=HealthResponse, tags=["health"])
def health_live() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="backend",
        version=APP_VERSION,
        database="not_checked",
    )


@app.get(
    "/health/ready",
    response_model=HealthResponse,
    tags=["health"],
    responses={503: {"description": "Database is unavailable"}},
)
def health_ready(db: Session = Depends(get_db)) -> HealthResponse:
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        logger.warning("Database readiness check failed: %s", exc.__class__.__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        ) from exc

    return HealthResponse(
        status="ok",
        service="backend",
        version=APP_VERSION,
        database="up",
    )


@app.post(
    "/internal/v1/heartbeats",
    response_model=HeartbeatOut,
    tags=["internal"],
    dependencies=[Depends(require_internal_token)],
)
def record_heartbeat(payload: HeartbeatIn, db: Session = Depends(get_db)) -> ServiceHeartbeat:
    heartbeat = db.scalar(
        select(ServiceHeartbeat).where(
            ServiceHeartbeat.service_name == payload.service_name,
            ServiceHeartbeat.instance_id == payload.instance_id,
        )
    )

    now = datetime.now(timezone.utc)
    observed_at = payload.observed_at.astimezone(timezone.utc)
    effective_seen_at = min(observed_at, now)

    if heartbeat is None:
        heartbeat = ServiceHeartbeat(
            service_name=payload.service_name,
            instance_id=payload.instance_id,
            status=payload.status,
            service_metadata=payload.metadata,
            first_seen_at=effective_seen_at,
            last_seen_at=effective_seen_at,
        )
        db.add(heartbeat)
    else:
        heartbeat.status = payload.status
        heartbeat.service_metadata = payload.metadata
        heartbeat.last_seen_at = max(heartbeat.last_seen_at, effective_seen_at)

    db.commit()
    db.refresh(heartbeat)
    return heartbeat


def _upsert_image_identity(db: Session, event, observed_at: datetime) -> None:
    if not event.image_id:
        return

    image = event.container_snapshot.get("image", {})
    values = {
        "docker_host_id": event.docker_host_id,
        "image_id": event.image_id,
        "image_ref": event.image_ref,
        "primary_repo_digest": event.image_digest,
        "repo_digests": image.get("repo_digests", []),
        "repo_tags": image.get("repo_tags", []),
        "os": image.get("os"),
        "architecture": image.get("architecture"),
        "digest_status": event.image_digest_status,
        "first_seen_at": observed_at,
        "last_seen_at": observed_at,
    }
    statement = pg_insert(ImageIdentity).values(**values)
    newer_or_equal = statement.excluded.last_seen_at >= ImageIdentity.last_seen_at
    has_fresh_image_metadata = bool(image) and event.image_digest_status != "inspection_failed"
    digest_status_value = (
        statement.excluded.digest_status
        if event.image_digest_status != "inspection_failed"
        else ImageIdentity.digest_status
    )
    statement = statement.on_conflict_do_update(
        constraint="uq_image_identity_host_image",
        set_={
            "image_ref": case(
                (newer_or_equal, func.coalesce(statement.excluded.image_ref, ImageIdentity.image_ref)),
                else_=ImageIdentity.image_ref,
            ),
            "primary_repo_digest": case(
                (
                    newer_or_equal,
                    func.coalesce(
                        statement.excluded.primary_repo_digest,
                        ImageIdentity.primary_repo_digest,
                    ),
                ),
                else_=ImageIdentity.primary_repo_digest,
            ),
            "repo_digests": case(
                (
                    newer_or_equal,
                    statement.excluded.repo_digests
                    if has_fresh_image_metadata
                    else ImageIdentity.repo_digests,
                ),
                else_=ImageIdentity.repo_digests,
            ),
            "repo_tags": case(
                (
                    newer_or_equal,
                    statement.excluded.repo_tags
                    if has_fresh_image_metadata
                    else ImageIdentity.repo_tags,
                ),
                else_=ImageIdentity.repo_tags,
            ),
            "os": case(
                (newer_or_equal, func.coalesce(statement.excluded.os, ImageIdentity.os)),
                else_=ImageIdentity.os,
            ),
            "architecture": case(
                (
                    newer_or_equal,
                    func.coalesce(statement.excluded.architecture, ImageIdentity.architecture),
                ),
                else_=ImageIdentity.architecture,
            ),
            "digest_status": case(
                (newer_or_equal, digest_status_value),
                else_=ImageIdentity.digest_status,
            ),
            "first_seen_at": func.least(
                ImageIdentity.first_seen_at,
                statement.excluded.first_seen_at,
            ),
            "last_seen_at": func.greatest(
                ImageIdentity.last_seen_at,
                statement.excluded.last_seen_at,
            ),
        },
    )
    db.execute(statement)


def _upsert_container_identity(db: Session, event, observed_at: datetime) -> None:
    if not event.container_id:
        return

    values = {
        "docker_host_id": event.docker_host_id,
        "container_id": event.container_id,
        "container_name": event.container_name,
        "image_id": event.image_id,
        "image_ref": event.image_ref,
        "image_digest": event.image_digest,
        "image_digest_status": event.image_digest_status,
        "current_snapshot": event.container_snapshot,
        "first_seen_at": observed_at,
        "last_seen_at": observed_at,
    }
    statement = pg_insert(ContainerIdentity).values(**values)
    newer_or_equal = statement.excluded.last_seen_at >= ContainerIdentity.last_seen_at
    snapshot_value = (
        statement.excluded.current_snapshot
        if event.container_snapshot
        else ContainerIdentity.current_snapshot
    )
    digest_status_value = (
        statement.excluded.image_digest_status
        if event.image_digest_status != "inspection_failed"
        else ContainerIdentity.image_digest_status
    )
    statement = statement.on_conflict_do_update(
        constraint="uq_container_identity_host_container",
        set_={
            "container_name": case(
                (
                    newer_or_equal,
                    func.coalesce(
                        statement.excluded.container_name,
                        ContainerIdentity.container_name,
                    ),
                ),
                else_=ContainerIdentity.container_name,
            ),
            "image_id": case(
                (
                    newer_or_equal,
                    func.coalesce(statement.excluded.image_id, ContainerIdentity.image_id),
                ),
                else_=ContainerIdentity.image_id,
            ),
            "image_ref": case(
                (
                    newer_or_equal,
                    func.coalesce(statement.excluded.image_ref, ContainerIdentity.image_ref),
                ),
                else_=ContainerIdentity.image_ref,
            ),
            "image_digest": case(
                (
                    newer_or_equal,
                    func.coalesce(
                        statement.excluded.image_digest,
                        ContainerIdentity.image_digest,
                    ),
                ),
                else_=ContainerIdentity.image_digest,
            ),
            "image_digest_status": case(
                (newer_or_equal, digest_status_value),
                else_=ContainerIdentity.image_digest_status,
            ),
            "current_snapshot": case(
                (newer_or_equal, snapshot_value),
                else_=ContainerIdentity.current_snapshot,
            ),
            "first_seen_at": func.least(
                ContainerIdentity.first_seen_at,
                statement.excluded.first_seen_at,
            ),
            "last_seen_at": func.greatest(
                ContainerIdentity.last_seen_at,
                statement.excluded.last_seen_at,
            ),
        },
    )
    db.execute(statement)


@app.post(
    "/internal/v1/events/batch",
    response_model=RuntimeEventBatchOut,
    tags=["internal"],
    dependencies=[Depends(require_internal_token)],
)
def ingest_runtime_events(
    payload: RuntimeEventBatchIn,
    db: Session = Depends(get_db),
) -> RuntimeEventBatchOut:
    received_at = datetime.now(timezone.utc)
    inserted = 0

    try:
        for event in payload.events:
            values = event.model_dump()
            values["occurred_at"] = event.occurred_at.astimezone(timezone.utc)
            values["received_at"] = received_at

            statement = pg_insert(RuntimeEvent).values(**values)
            result = db.execute(statement.on_conflict_do_nothing(index_elements=["event_id"]))
            inserted += int(result.rowcount or 0)

            observed_at = min(values["occurred_at"], received_at)
            _upsert_image_identity(db, event, observed_at)
            _upsert_container_identity(db, event, observed_at)

        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Runtime event batch failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Runtime event persistence failed",
        ) from exc

    return RuntimeEventBatchOut(
        received=len(payload.events),
        inserted=inserted,
        duplicates=len(payload.events) - inserted,
    )


def _resolve_container_identity(
    db: Session,
    reported_container_id: str | None,
    reported_docker_host_id: str | None,
) -> tuple[str, ContainerIdentity | None]:
    if not reported_container_id or reported_container_id == "host":
        return "unresolved", None

    statement = select(ContainerIdentity).where(
        or_(
            ContainerIdentity.container_id == reported_container_id,
            ContainerIdentity.container_id.startswith(reported_container_id),
        )
    )
    if reported_docker_host_id:
        statement = statement.where(ContainerIdentity.docker_host_id == reported_docker_host_id)

    candidates = list(db.scalars(statement.order_by(desc(ContainerIdentity.last_seen_at)).limit(2)))
    if len(candidates) == 1:
        return "resolved", candidates[0]
    if len(candidates) > 1:
        return "ambiguous", None
    return "unresolved", None


def _find_parent_event_id(
    db: Session,
    *,
    sensor_instance_id: str,
    docker_host_id: str | None,
    container_id: str | None,
    process_ppid: int | None,
    occurred_at: datetime,
    time_nano: int,
) -> str | None:
    if process_ppid is None or process_ppid <= 0:
        return None

    earliest_parent_time = occurred_at - timedelta(
        seconds=settings.parent_correlation_lookback_seconds
    )
    statement = select(ProcessExecEvent.event_id).where(
        ProcessExecEvent.process_pid == process_ppid,
        ProcessExecEvent.time_nano <= time_nano,
        ProcessExecEvent.occurred_at <= occurred_at,
        ProcessExecEvent.occurred_at >= earliest_parent_time,
    )
    if docker_host_id:
        statement = statement.where(ProcessExecEvent.docker_host_id == docker_host_id)
    if container_id:
        statement = statement.where(ProcessExecEvent.container_id == container_id)
    if not docker_host_id and not container_id:
        statement = statement.where(ProcessExecEvent.sensor_instance_id == sensor_instance_id)

    return db.scalar(statement.order_by(desc(ProcessExecEvent.time_nano)).limit(1))


@app.post(
    "/internal/v1/process-events/batch",
    response_model=ProcessExecEventBatchOut,
    tags=["internal"],
    dependencies=[Depends(require_internal_token)],
)
def ingest_process_events(
    payload: ProcessExecEventBatchIn,
    db: Session = Depends(get_db),
) -> ProcessExecEventBatchOut:
    received_at = datetime.now(timezone.utc)
    inserted = 0
    correlation_counts = {"resolved": 0, "unresolved": 0, "ambiguous": 0}

    try:
        ordered_events = sorted(payload.events, key=lambda item: (item.time_nano, item.event_id))
        for event in ordered_events:
            occurred_at = event.occurred_at.astimezone(timezone.utc)
            correlation_status, identity = _resolve_container_identity(
                db,
                event.reported_container_id,
                event.reported_docker_host_id,
            )
            correlation_counts[correlation_status] += 1

            docker_host_id = identity.docker_host_id if identity else event.reported_docker_host_id
            container_id = identity.container_id if identity else None
            container_name = identity.container_name if identity else event.reported_container_name
            image_id = identity.image_id if identity else None
            image_ref = identity.image_ref if identity else event.reported_image_ref
            image_digest = identity.image_digest if identity else None

            parent_event_id = _find_parent_event_id(
                db,
                sensor_instance_id=event.sensor_instance_id,
                docker_host_id=docker_host_id,
                container_id=container_id,
                process_ppid=event.process_ppid,
                occurred_at=occurred_at,
                time_nano=event.time_nano,
            )

            values = event.model_dump(
                exclude={"reported_container_name", "reported_image_ref"}
            )
            values.update(
                {
                    "occurred_at": occurred_at,
                    "received_at": received_at,
                    "docker_host_id": docker_host_id,
                    "container_id": container_id,
                    "container_name": container_name,
                    "image_id": image_id,
                    "image_ref": image_ref,
                    "image_digest": image_digest,
                    "correlation_status": correlation_status,
                    "parent_event_id": parent_event_id,
                }
            )

            statement = pg_insert(ProcessExecEvent).values(**values)
            result = db.execute(statement.on_conflict_do_nothing(index_elements=["event_id"]))
            inserted += int(result.rowcount or 0)

        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Process event batch failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Process event persistence failed",
        ) from exc

    return ProcessExecEventBatchOut(
        received=len(payload.events),
        inserted=inserted,
        duplicates=len(payload.events) - inserted,
        resolved=correlation_counts["resolved"],
        unresolved=correlation_counts["unresolved"],
        ambiguous=correlation_counts["ambiguous"],
    )


@app.get("/api/v1/services", response_model=list[HeartbeatOut], tags=["system"])
def list_services(db: Session = Depends(get_db)) -> list[ServiceHeartbeat]:
    return list(db.scalars(select(ServiceHeartbeat).order_by(ServiceHeartbeat.service_name)).all())


@app.get("/api/v1/events", response_model=list[RuntimeEventOut], tags=["runtime-events"])
def list_runtime_events(
    event_type: str | None = Query(default=None, max_length=32),
    action: str | None = Query(default=None, max_length=64),
    container_id: str | None = Query(default=None, max_length=128),
    container_name: str | None = Query(default=None, max_length=255),
    image_digest: str | None = Query(default=None, max_length=255),
    docker_host_id: str | None = Query(default=None, max_length=128),
    before_time_nano: int | None = Query(default=None, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[RuntimeEvent]:
    statement = select(RuntimeEvent)
    if event_type:
        statement = statement.where(RuntimeEvent.event_type == event_type)
    if action:
        statement = statement.where(RuntimeEvent.action == action)
    if container_id:
        statement = statement.where(RuntimeEvent.container_id == container_id)
    if container_name:
        statement = statement.where(RuntimeEvent.container_name == container_name)
    if image_digest:
        statement = statement.where(RuntimeEvent.image_digest == image_digest)
    if docker_host_id:
        statement = statement.where(RuntimeEvent.docker_host_id == docker_host_id)
    if before_time_nano is not None:
        statement = statement.where(RuntimeEvent.time_nano < before_time_nano)

    statement = statement.order_by(desc(RuntimeEvent.time_nano), RuntimeEvent.event_id).limit(limit)
    return list(db.scalars(statement).all())


@app.get("/api/v1/events/summary", response_model=EventSummary, tags=["runtime-events"])
def runtime_event_summary(
    container_name: str | None = Query(default=None, max_length=255),
    db: Session = Depends(get_db),
) -> EventSummary:
    filters = []
    if container_name:
        filters.append(RuntimeEvent.container_name == container_name)

    total = db.scalar(select(func.count()).select_from(RuntimeEvent).where(*filters)) or 0
    distinct_containers = (
        db.scalar(
            select(func.count(func.distinct(RuntimeEvent.container_id)))
            .select_from(RuntimeEvent)
            .where(RuntimeEvent.container_id.is_not(None), *filters)
        )
        or 0
    )
    resolved = (
        db.scalar(
            select(func.count())
            .select_from(RuntimeEvent)
            .where(RuntimeEvent.image_digest_status == "resolved", *filters)
        )
        or 0
    )
    unresolved = (
        db.scalar(
            select(func.count())
            .select_from(RuntimeEvent)
            .where(
                RuntimeEvent.container_id.is_not(None),
                RuntimeEvent.image_digest_status != "resolved",
                *filters,
            )
        )
        or 0
    )
    action_rows = db.execute(
        select(RuntimeEvent.action, func.count())
        .where(*filters)
        .group_by(RuntimeEvent.action)
        .order_by(RuntimeEvent.action)
    ).all()

    return EventSummary(
        total_events=total,
        distinct_containers=distinct_containers,
        resolved_digest_events=resolved,
        unresolved_digest_events=unresolved,
        by_action={action: count for action, count in action_rows},
    )


@app.get("/api/v1/events/{event_id}", response_model=RuntimeEventOut, tags=["runtime-events"])
def get_runtime_event(event_id: str, db: Session = Depends(get_db)) -> RuntimeEvent:
    event = db.get(RuntimeEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return event


@app.get(
    "/api/v1/process-events",
    response_model=list[ProcessExecEventOut],
    tags=["process-telemetry"],
)
def list_process_events(
    container_id: str | None = Query(default=None, max_length=128),
    container_name: str | None = Query(default=None, max_length=255),
    image_digest: str | None = Query(default=None, max_length=255),
    process_name: str | None = Query(default=None, max_length=255),
    correlation_status: str | None = Query(default=None, max_length=32),
    before_time_nano: int | None = Query(default=None, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ProcessExecEvent]:
    statement = select(ProcessExecEvent)
    if container_id:
        statement = statement.where(
            or_(
                ProcessExecEvent.container_id == container_id,
                ProcessExecEvent.reported_container_id == container_id,
                ProcessExecEvent.container_id.startswith(container_id),
            )
        )
    if container_name:
        statement = statement.where(ProcessExecEvent.container_name == container_name)
    if image_digest:
        statement = statement.where(ProcessExecEvent.image_digest == image_digest)
    if process_name:
        statement = statement.where(ProcessExecEvent.process_name == process_name)
    if correlation_status:
        statement = statement.where(ProcessExecEvent.correlation_status == correlation_status)
    if before_time_nano is not None:
        statement = statement.where(ProcessExecEvent.time_nano < before_time_nano)

    statement = statement.order_by(
        desc(ProcessExecEvent.time_nano), ProcessExecEvent.event_id
    ).limit(limit)
    return list(db.scalars(statement).all())


@app.get(
    "/api/v1/process-events/summary",
    response_model=ProcessEventSummary,
    tags=["process-telemetry"],
)
def process_event_summary(
    container_name: str | None = Query(default=None, max_length=255),
    db: Session = Depends(get_db),
) -> ProcessEventSummary:
    filters = []
    if container_name:
        filters.append(ProcessExecEvent.container_name == container_name)

    total = db.scalar(select(func.count()).select_from(ProcessExecEvent).where(*filters)) or 0
    distinct_containers = (
        db.scalar(
            select(func.count(func.distinct(ProcessExecEvent.container_id)))
            .select_from(ProcessExecEvent)
            .where(ProcessExecEvent.container_id.is_not(None), *filters)
        )
        or 0
    )
    resolved = (
        db.scalar(
            select(func.count())
            .select_from(ProcessExecEvent)
            .where(ProcessExecEvent.correlation_status == "resolved", *filters)
        )
        or 0
    )
    unresolved = (
        db.scalar(
            select(func.count())
            .select_from(ProcessExecEvent)
            .where(ProcessExecEvent.correlation_status == "unresolved", *filters)
        )
        or 0
    )
    ambiguous = (
        db.scalar(
            select(func.count())
            .select_from(ProcessExecEvent)
            .where(ProcessExecEvent.correlation_status == "ambiguous", *filters)
        )
        or 0
    )
    linked = (
        db.scalar(
            select(func.count())
            .select_from(ProcessExecEvent)
            .where(ProcessExecEvent.parent_event_id.is_not(None), *filters)
        )
        or 0
    )
    process_rows = db.execute(
        select(ProcessExecEvent.process_name, func.count())
        .where(ProcessExecEvent.process_name.is_not(None), *filters)
        .group_by(ProcessExecEvent.process_name)
        .order_by(desc(func.count()), ProcessExecEvent.process_name)
        .limit(50)
    ).all()

    return ProcessEventSummary(
        total_events=total,
        distinct_containers=distinct_containers,
        resolved_events=resolved,
        unresolved_events=unresolved,
        ambiguous_events=ambiguous,
        linked_parent_events=linked,
        by_process_name={name: count for name, count in process_rows},
    )


@app.get(
    "/api/v1/process-events/{event_id}",
    response_model=ProcessExecEventOut,
    tags=["process-telemetry"],
)
def get_process_event(event_id: str, db: Session = Depends(get_db)) -> ProcessExecEvent:
    event = db.get(ProcessExecEvent, event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Process event not found")
    return event


@app.post(
    "/internal/v1/baselines/build",
    response_model=BehaviorProfileOut,
    status_code=status.HTTP_201_CREATED,
    tags=["internal", "behaviour-profiles"],
    dependencies=[Depends(require_internal_token)],
)
def build_behavior_profile(
    payload: BehaviorProfileBuildIn,
    db: Session = Depends(get_db),
) -> BehaviorProfile:
    training_start = payload.training_start.astimezone(timezone.utc)
    training_end = payload.training_end.astimezone(timezone.utc)
    duration_seconds = (training_end - training_start).total_seconds()
    window_count = math.ceil(duration_seconds / payload.window_seconds)
    if window_count > settings.baseline_max_windows:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Training interval creates {window_count} windows; "
                f"maximum is {settings.baseline_max_windows}"
            ),
        )

    process_filters = (
        ProcessExecEvent.image_digest == payload.image_digest,
        ProcessExecEvent.correlation_status == "resolved",
        ProcessExecEvent.occurred_at >= training_start,
        ProcessExecEvent.occurred_at < training_end,
    )
    runtime_filters = (
        RuntimeEvent.image_digest == payload.image_digest,
        RuntimeEvent.occurred_at >= training_start,
        RuntimeEvent.occurred_at < training_end,
    )

    process_count = (
        db.scalar(select(func.count()).select_from(ProcessExecEvent).where(*process_filters)) or 0
    )
    runtime_count = db.scalar(select(func.count()).select_from(RuntimeEvent).where(*runtime_filters)) or 0
    if process_count + runtime_count > settings.baseline_max_events:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Training selection contains {process_count + runtime_count} events; "
                f"maximum is {settings.baseline_max_events}"
            ),
        )

    process_events = list(
        db.scalars(
            select(ProcessExecEvent)
            .where(*process_filters)
            .order_by(ProcessExecEvent.occurred_at, ProcessExecEvent.event_id)
        ).all()
    )
    runtime_events = list(
        db.scalars(
            select(RuntimeEvent)
            .where(*runtime_filters)
            .order_by(RuntimeEvent.occurred_at, RuntimeEvent.event_id)
        ).all()
    )

    features, quality, manifest, model_hash = build_profile_document(
        image_digest=payload.image_digest,
        start_at=training_start,
        end_at=training_end,
        window_seconds=payload.window_seconds,
        process_events=process_events,
        runtime_events=runtime_events,
        minimum_process_events=payload.minimum_process_events,
        minimum_nonempty_windows=payload.minimum_nonempty_windows,
    )

    try:
        # Serialise version assignment and activation decisions for this digest.
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext(payload.image_digest))))
        duplicate = db.scalar(
            select(BehaviorProfile).where(
                BehaviorProfile.image_digest == payload.image_digest,
                BehaviorProfile.model_hash == model_hash,
            )
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Identical profile already exists as {duplicate.profile_id}",
            )

        latest_version = (
            db.scalar(
                select(func.max(BehaviorProfile.profile_version)).where(
                    BehaviorProfile.image_digest == payload.image_digest
                )
            )
            or 0
        )
        now = datetime.now(timezone.utc)
        profile = BehaviorProfile(
            profile_id=str(uuid4()),
            image_digest=payload.image_digest,
            profile_version=latest_version + 1,
            status="draft",
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            model_hash=model_hash,
            training_start=training_start,
            training_end=training_end,
            window_seconds=payload.window_seconds,
            approved_by=payload.approved_by,
            approval_reference=payload.approval_reference,
            notes=payload.notes,
            process_event_count=manifest["process_event_count"],
            runtime_event_count=manifest["runtime_event_count"],
            container_count=manifest["container_count"],
            window_count=manifest["window_count"],
            quality=quality,
            training_manifest=manifest,
            features=features,
            created_at=now,
            activated_at=None,
            retired_at=None,
        )
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A concurrent profile build created the same version or model",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Behaviour profile build failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Behaviour profile persistence failed",
        ) from exc


@app.post(
    "/internal/v1/baselines/{profile_id}/activate",
    response_model=BehaviorProfileOut,
    tags=["internal", "behaviour-profiles"],
    dependencies=[Depends(require_internal_token)],
)
def activate_behavior_profile(profile_id: str, db: Session = Depends(get_db)) -> BehaviorProfile:
    profile = db.get(BehaviorProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    if profile.status == "active":
        return profile
    if profile.status == "retired":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Retired profiles cannot be reactivated; build a new version",
        )
    if not bool(profile.quality.get("passed")):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Profile failed its recorded data-quality gates and cannot be activated",
        )

    try:
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext(profile.image_digest))))
        now = datetime.now(timezone.utc)
        db.execute(
            update(BehaviorProfile)
            .where(
                BehaviorProfile.image_digest == profile.image_digest,
                BehaviorProfile.status == "active",
                BehaviorProfile.profile_id != profile.profile_id,
            )
            .values(status="retired", retired_at=now)
        )
        profile.status = "active"
        profile.activated_at = now
        profile.retired_at = None
        db.commit()
        db.refresh(profile)
        return profile
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another profile activation won the concurrent update",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Behaviour profile activation failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Behaviour profile activation failed",
        ) from exc


@app.get(
    "/api/v1/baselines",
    response_model=list[BehaviorProfileOut],
    tags=["behaviour-profiles"],
)
def list_behavior_profiles(
    image_digest: str | None = Query(default=None, max_length=255),
    profile_status: str | None = Query(default=None, alias="status", max_length=16),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[BehaviorProfile]:
    statement = select(BehaviorProfile)
    if image_digest:
        statement = statement.where(BehaviorProfile.image_digest == image_digest)
    if profile_status:
        if profile_status not in {"draft", "active", "retired"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="status must be draft, active, or retired",
            )
        statement = statement.where(BehaviorProfile.status == profile_status)
    return list(
        db.scalars(
            statement.order_by(
                desc(BehaviorProfile.created_at),
                desc(BehaviorProfile.profile_version),
            ).limit(limit)
        ).all()
    )


@app.get(
    "/api/v1/baselines/active",
    response_model=BehaviorProfileOut,
    tags=["behaviour-profiles"],
)
def get_active_behavior_profile(
    image_digest: str = Query(min_length=72, max_length=255),
    db: Session = Depends(get_db),
) -> BehaviorProfile:
    profile = db.scalar(
        select(BehaviorProfile).where(
            BehaviorProfile.image_digest == image_digest,
            BehaviorProfile.status == "active",
        )
    )
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active profile not found")
    return profile


@app.get(
    "/api/v1/baselines/{profile_id}",
    response_model=BehaviorProfileOut,
    tags=["behaviour-profiles"],
)
def get_behavior_profile(profile_id: str, db: Session = Depends(get_db)) -> BehaviorProfile:
    profile = db.get(BehaviorProfile, profile_id)
    if profile is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
    return profile


@app.post(
    "/internal/v1/anomaly-scores/compute",
    response_model=AnomalyScoreOut,
    tags=["internal", "anomaly-scores"],
    dependencies=[Depends(require_internal_token)],
)
def compute_anomaly_score(
    payload: AnomalyScoreComputeIn,
    db: Session = Depends(get_db),
) -> AnomalyScore:
    """Score one fixed window against an immutable-digest behaviour profile.

    The result is a distance measurement, not a maliciousness verdict. A window
    without process telemetry is persisted as insufficient_data so telemetry loss
    is not silently interpreted as normal or anomalous behaviour.
    """

    if payload.profile_id:
        profile = db.get(BehaviorProfile, payload.profile_id)
        if profile is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found")
        if profile.image_digest != payload.image_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Profile image digest does not match requested image digest",
            )
        if profile.status == "draft" or not bool(profile.quality.get("passed")):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Only quality-passing active or retired profiles may be used for scoring",
            )
    else:
        profile = db.scalar(
            select(BehaviorProfile).where(
                BehaviorProfile.image_digest == payload.image_digest,
                BehaviorProfile.status == "active",
            )
        )
        if profile is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No active profile exists for the requested image digest",
            )

    window_start = payload.window_start.astimezone(timezone.utc)
    window_end = window_start + timedelta(seconds=profile.window_seconds)
    if window_end > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The fixed observation window has not completed yet",
        )
    if window_start < profile.training_end and window_end > profile.training_start:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scoring windows must not overlap the profile training interval",
        )

    process_filters = (
        ProcessExecEvent.image_digest == payload.image_digest,
        ProcessExecEvent.correlation_status == "resolved",
        ProcessExecEvent.occurred_at >= window_start,
        ProcessExecEvent.occurred_at < window_end,
    )
    runtime_filters = (
        RuntimeEvent.image_digest == payload.image_digest,
        RuntimeEvent.occurred_at >= window_start,
        RuntimeEvent.occurred_at < window_end,
    )
    process_count = (
        db.scalar(select(func.count()).select_from(ProcessExecEvent).where(*process_filters)) or 0
    )
    runtime_count = (
        db.scalar(select(func.count()).select_from(RuntimeEvent).where(*runtime_filters)) or 0
    )
    if process_count + runtime_count > settings.anomaly_max_events:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(
                f"Observation window contains {process_count + runtime_count} events; "
                f"maximum is {settings.anomaly_max_events}"
            ),
        )

    process_events = list(
        db.scalars(
            select(ProcessExecEvent)
            .where(*process_filters)
            .order_by(ProcessExecEvent.occurred_at, ProcessExecEvent.event_id)
        ).all()
    )
    runtime_events = list(
        db.scalars(
            select(RuntimeEvent)
            .where(*runtime_filters)
            .order_by(RuntimeEvent.occurred_at, RuntimeEvent.event_id)
        ).all()
    )

    observation_features, _, observation_manifest, _ = build_profile_document(
        image_digest=payload.image_digest,
        start_at=window_start,
        end_at=window_end,
        window_seconds=profile.window_seconds,
        process_events=process_events,
        runtime_events=runtime_events,
        minimum_process_events=0,
        minimum_nonempty_windows=0,
    )
    observation_key = build_observation_key(
        profile_id=profile.profile_id,
        profile_model_hash=profile.model_hash,
        window_start=window_start.isoformat(),
        window_end=window_end.isoformat(),
        selected_event_ids_sha256=observation_manifest["selected_event_ids_sha256"],
    )

    try:
        db.execute(select(func.pg_advisory_xact_lock(func.hashtext(observation_key))))
        existing = db.scalar(
            select(AnomalyScore).where(AnomalyScore.observation_key == observation_key)
        )
        if existing is not None:
            return existing

        if process_count < settings.anomaly_min_process_events:
            score_status = "insufficient_data"
            band = "insufficient_data"
            total_score = None
            components = {
                "available": False,
                "reason": "Insufficient process-execution telemetry",
                "required_process_events": settings.anomaly_min_process_events,
                "observed_process_events": process_count,
                "observed_runtime_events": runtime_count,
            }
            explanation = {
                "band": band,
                "interpretation": (
                    "The observation was not scored because the process-execution evidence did not "
                    "meet the configured minimum. This is not evidence of normal behaviour."
                ),
                "top_contributors": [],
                "unseen_tokens": [],
                "highest_numeric_deviations": [],
            }
        else:
            try:
                total_score, band, components, explanation = score_feature_documents(
                    baseline_features=profile.features,
                    observation_features=observation_features,
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=str(exc),
                ) from exc
            score_status = "scored"

        now = datetime.now(timezone.utc)
        record = AnomalyScore(
            score_id=str(uuid4()),
            observation_key=observation_key,
            profile_id=profile.profile_id,
            image_digest=payload.image_digest,
            profile_version=profile.profile_version,
            profile_model_hash=profile.model_hash,
            algorithm_version=ALGORITHM_VERSION,
            status=score_status,
            score_band=band,
            total_score=total_score,
            window_start=window_start,
            window_end=window_end,
            window_seconds=profile.window_seconds,
            process_event_count=observation_manifest["process_event_count"],
            runtime_event_count=observation_manifest["runtime_event_count"],
            container_count=observation_manifest["container_count"],
            components=components,
            explanation=explanation,
            observation_manifest=observation_manifest,
            scoring_config=SCORING_CONFIG,
            created_at=now,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        existing = db.scalar(
            select(AnomalyScore).where(AnomalyScore.observation_key == observation_key)
        )
        if existing is not None:
            return existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A concurrent scoring request created a conflicting record",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Anomaly-score persistence failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Anomaly-score persistence failed",
        ) from exc


@app.get(
    "/api/v1/anomaly-scores/config",
    response_model=dict[str, object],
    tags=["anomaly-scores"],
)
def get_anomaly_scoring_config() -> dict[str, object]:
    """Expose the immutable v1 scoring definition used for reproducibility."""

    return {
        "algorithm_version": ALGORITHM_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "scoring_config": SCORING_CONFIG,
        "interpretation": (
            "Bands are provisional distance labels, not validated attack thresholds. "
            "Threshold selection belongs to the evaluation phase."
        ),
    }


@app.get(
    "/api/v1/anomaly-scores",
    response_model=list[AnomalyScoreOut],
    tags=["anomaly-scores"],
)
def list_anomaly_scores(
    image_digest: str | None = Query(default=None, max_length=255),
    profile_id: str | None = Query(default=None, min_length=36, max_length=36),
    score_status: str | None = Query(default=None, alias="status", max_length=32),
    minimum_score: float | None = Query(default=None, ge=0.0, le=1.0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[AnomalyScore]:
    statement = select(AnomalyScore)
    if image_digest:
        statement = statement.where(AnomalyScore.image_digest == image_digest)
    if profile_id:
        statement = statement.where(AnomalyScore.profile_id == profile_id)
    if score_status:
        if score_status not in {"scored", "insufficient_data"}:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="status must be scored or insufficient_data",
            )
        statement = statement.where(AnomalyScore.status == score_status)
    if minimum_score is not None:
        statement = statement.where(AnomalyScore.total_score >= minimum_score)
    return list(
        db.scalars(
            statement.order_by(desc(AnomalyScore.window_start), desc(AnomalyScore.created_at)).limit(limit)
        ).all()
    )


@app.get(
    "/api/v1/anomaly-scores/{score_id}",
    response_model=AnomalyScoreOut,
    tags=["anomaly-scores"],
)
def get_anomaly_score(score_id: str, db: Session = Depends(get_db)) -> AnomalyScore:
    record = db.get(AnomalyScore, score_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly score not found")
    return record




def _detection_execution(db: Session, run: DetectionRun) -> dict[str, object]:
    incident = db.scalar(select(Incident).where(Incident.detection_run_id == run.run_id))
    timeline: list[IncidentEvidence] = []
    if incident is not None:
        timeline = list(
            db.scalars(
                select(IncidentEvidence)
                .where(IncidentEvidence.incident_id == incident.incident_id)
                .order_by(IncidentEvidence.sequence_no)
            ).all()
        )
    return {"run": run, "incident": incident, "timeline": timeline}


@app.get(
    "/api/v1/detection-rules/config",
    response_model=dict[str, object],
    tags=["detection"],
)
def get_detection_rules_config() -> dict[str, object]:
    return {
        "ruleset_version": RULESET_VERSION,
        "ruleset_hash": ruleset_hash(),
        "correlation_window_seconds": CORRELATION_WINDOW_SECONDS,
        "rules": list(DETECTION_RULES),
        "interpretation": (
            "Rules are deterministic evidence conditions. Severity estimates potential impact; "
            "confidence estimates evidence support. Neither is a probability of compromise."
        ),
    }


@app.get(
    "/api/v1/detection-allowlists",
    response_model=list[DetectionAllowlistOut],
    tags=["detection"],
)
def list_detection_allowlists(
    image_digest: str | None = Query(default=None, max_length=255),
    active: bool | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[DetectionAllowlist]:
    statement = select(DetectionAllowlist)
    if image_digest is not None:
        statement = statement.where(DetectionAllowlist.image_digest == image_digest)
    if active is not None:
        statement = statement.where(DetectionAllowlist.active == active)
    return list(
        db.scalars(
            statement.order_by(DetectionAllowlist.created_at.desc(), DetectionAllowlist.allowlist_id)
        ).all()
    )


@app.post(
    "/internal/v1/detection-allowlists",
    response_model=DetectionAllowlistOut,
    status_code=status.HTTP_201_CREATED,
    tags=["internal", "detection"],
    dependencies=[Depends(require_internal_token)],
)
def create_detection_allowlist(
    payload: DetectionAllowlistCreateIn,
    db: Session = Depends(get_db),
) -> DetectionAllowlist:
    now = datetime.now(timezone.utc)
    known_profile = db.scalar(
        select(BehaviorProfile.profile_id).where(BehaviorProfile.image_digest == payload.image_digest).limit(1)
    )
    if known_profile is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No behaviour profile exists for the requested image digest",
        )
    if payload.expires_at is not None and payload.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="expires_at must be in the future",
        )

    matcher_hash = build_allowlist_matcher_hash(
        image_digest=payload.image_digest,
        rule_id=payload.rule_id,
        executable=payload.executable,
        parent_executable=payload.parent_executable,
    )
    existing = db.scalar(
        select(DetectionAllowlist).where(
            DetectionAllowlist.matcher_hash == matcher_hash,
            DetectionAllowlist.active.is_(True),
        )
    )
    if existing is not None and (existing.expires_at is None or existing.expires_at > now):
        return existing
    if existing is not None:
        existing.active = False
        existing.deactivated_at = now
        existing.deactivated_by = "system-expiry"
        db.flush()

    record = DetectionAllowlist(
        allowlist_id=str(uuid4()),
        matcher_hash=matcher_hash,
        image_digest=payload.image_digest,
        rule_id=payload.rule_id,
        executable=payload.executable,
        parent_executable=payload.parent_executable,
        reason=payload.reason,
        approved_by=payload.approved_by,
        approval_reference=payload.approval_reference,
        active=True,
        created_at=now,
        expires_at=payload.expires_at,
        deactivated_at=None,
        deactivated_by=None,
    )
    db.add(record)
    try:
        db.commit()
        db.refresh(record)
        return record
    except IntegrityError as exc:
        db.rollback()
        existing = db.scalar(
            select(DetectionAllowlist).where(
                DetectionAllowlist.matcher_hash == matcher_hash,
                DetectionAllowlist.active.is_(True),
            )
        )
        if existing is not None:
            return existing
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A concurrent request created a conflicting allowlist",
        ) from exc


@app.post(
    "/internal/v1/detection-allowlists/{allowlist_id}/deactivate",
    response_model=DetectionAllowlistOut,
    tags=["internal", "detection"],
    dependencies=[Depends(require_internal_token)],
)
def deactivate_detection_allowlist(
    allowlist_id: str,
    payload: DetectionAllowlistDeactivateIn,
    db: Session = Depends(get_db),
) -> DetectionAllowlist:
    record = db.get(DetectionAllowlist, allowlist_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Allowlist not found")
    if not record.active:
        return record
    record.active = False
    record.deactivated_at = datetime.now(timezone.utc)
    record.deactivated_by = payload.actor
    db.commit()
    db.refresh(record)
    return record


@app.post(
    "/internal/v1/detections/run",
    response_model=DetectionExecutionOut,
    tags=["internal", "detection"],
    dependencies=[Depends(require_internal_token)],
)
def run_detection(
    payload: DetectionRunIn,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    score = db.get(AnomalyScore, payload.anomaly_score_id)
    if score is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Anomaly score not found")

    now = datetime.now(timezone.utc)
    active_allowlists = list(
        db.scalars(
            select(DetectionAllowlist)
            .where(
                DetectionAllowlist.image_digest == score.image_digest,
                DetectionAllowlist.active.is_(True),
                or_(DetectionAllowlist.expires_at.is_(None), DetectionAllowlist.expires_at > now),
            )
            .order_by(DetectionAllowlist.allowlist_id)
        ).all()
    )
    selected_allowlist_hash = allowlist_set_hash(active_allowlists)
    run_key = build_detection_run_key(score.score_id, selected_allowlist_hash)
    existing = db.scalar(select(DetectionRun).where(DetectionRun.run_key == run_key))
    if existing is not None:
        return _detection_execution(db, existing)

    profile = db.get(BehaviorProfile, score.profile_id)
    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The immutable profile referenced by the anomaly score no longer exists",
        )

    process_events = list(
        db.scalars(
            select(ProcessExecEvent)
            .where(
                ProcessExecEvent.image_digest == score.image_digest,
                ProcessExecEvent.correlation_status == "resolved",
                ProcessExecEvent.occurred_at >= score.window_start,
                ProcessExecEvent.occurred_at < score.window_end,
            )
            .order_by(ProcessExecEvent.occurred_at, ProcessExecEvent.event_id)
        ).all()
    )
    runtime_events = list(
        db.scalars(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.image_digest == score.image_digest,
                RuntimeEvent.occurred_at >= score.window_start,
                RuntimeEvent.occurred_at < score.window_end,
            )
            .order_by(RuntimeEvent.occurred_at, RuntimeEvent.event_id)
        ).all()
    )

    result = evaluate_detection(
        anomaly_score=score,
        profile=profile,
        process_events=process_events,
        runtime_events=runtime_events,
        allowlists=active_allowlists,
    )
    run = DetectionRun(
        run_id=str(uuid4()),
        run_key=run_key,
        score_id=score.score_id,
        ruleset_version=RULESET_VERSION,
        ruleset_hash=ruleset_hash(),
        allowlist_set_hash=selected_allowlist_hash,
        applied_allowlist_ids=[item.allowlist_id for item in active_allowlists],
        image_digest=score.image_digest,
        window_start=score.window_start,
        window_end=score.window_end,
        status=result["status"],
        matches_count=len(result["matches"]),
        incident_created=bool(result["incident_eligible"]),
        result=result,
        created_at=now,
    )
    db.add(run)

    incident: Incident | None = None
    timeline: list[IncidentEvidence] = []
    if result["incident_eligible"]:
        matches = list(result["matches"])
        incident_matches = [item for item in matches if item["incident_eligible"]]
        times = [datetime.fromisoformat(item["occurred_at"]) for item in matches]
        container_ids = sorted({item["container_id"] for item in matches if item["container_id"]})
        leading = max(
            incident_matches,
            key=lambda item: (item["severity_weight"], item["confidence_weight"], item["rule_id"]),
        )
        incident = Incident(
            incident_id=str(uuid4()),
            detection_run_id=run.run_id,
            score_id=score.score_id,
            image_digest=score.image_digest,
            title=f"{leading['name']} in {score.image_digest.split('@', 1)[0]}",
            status="open",
            anomaly_score=float(result["anomaly_score"]),
            severity_score=float(result["severity_score"]),
            severity_level=str(result["severity_level"]),
            confidence_score=float(result["confidence_score"]),
            confidence_level=str(result["confidence_level"]),
            summary=str(result["summary"]),
            findings=matches,
            container_ids=container_ids,
            first_seen_at=min(times) if times else score.window_start,
            last_seen_at=max(times) if times else score.window_end,
            created_at=now,
            updated_at=now,
            acknowledged_at=None,
            acknowledged_by=None,
            closed_at=None,
            closed_by=None,
            closure_note=None,
        )
        db.add(incident)

        evidence_documents = [
            {
                "occurred_at": score.window_end,
                "source_type": "anomaly_score",
                "source_id": score.score_id,
                "rule_id": None,
                "evidence_type": "behavioural_distance",
                "summary": (
                    f"Phase 5 behavioural distance was {score.total_score:.3f} "
                    f"({score.score_band})."
                ),
                "details": {
                    "algorithm_version": score.algorithm_version,
                    "profile_id": score.profile_id,
                    "profile_version": score.profile_version,
                    "total_score": score.total_score,
                    "score_band": score.score_band,
                },
            }
        ]
        evidence_documents.extend(
            {
                "occurred_at": datetime.fromisoformat(item["occurred_at"]),
                "source_type": item["source_type"],
                "source_id": item["source_id"],
                "rule_id": item["rule_id"],
                "evidence_type": item["category"],
                "summary": item["summary"],
                "details": item["details"],
            }
            for item in matches
        )
        evidence_documents.sort(
            key=lambda item: (item["occurred_at"], item["source_type"], item["source_id"])
        )
        for sequence_no, item in enumerate(evidence_documents, start=1):
            evidence = IncidentEvidence(
                evidence_id=str(uuid4()),
                incident_id=incident.incident_id,
                sequence_no=sequence_no,
                occurred_at=item["occurred_at"],
                source_type=item["source_type"],
                source_id=item["source_id"],
                rule_id=item["rule_id"],
                evidence_type=item["evidence_type"],
                summary=item["summary"],
                details=item["details"],
                created_at=now,
            )
            db.add(evidence)
            timeline.append(evidence)

    try:
        db.commit()
        db.refresh(run)
        if incident is not None:
            db.refresh(incident)
        return {"run": run, "incident": incident, "timeline": timeline}
    except IntegrityError as exc:
        db.rollback()
        existing = db.scalar(select(DetectionRun).where(DetectionRun.run_key == run_key))
        if existing is not None:
            return _detection_execution(db, existing)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A concurrent detection request created a conflicting run",
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("Phase 6 detection persistence failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection persistence failed",
        ) from exc


@app.get(
    "/api/v1/detection-runs",
    response_model=list[DetectionRunOut],
    tags=["detection"],
)
def list_detection_runs(
    image_digest: str | None = Query(default=None, max_length=255),
    run_status: str | None = Query(default=None, alias="status", max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[DetectionRun]:
    statement = select(DetectionRun)
    if image_digest:
        statement = statement.where(DetectionRun.image_digest == image_digest)
    if run_status:
        allowed = {"insufficient_data", "no_findings", "findings_only", "incident_created"}
        if run_status not in allowed:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(allowed)}")
        statement = statement.where(DetectionRun.status == run_status)
    return list(db.scalars(statement.order_by(desc(DetectionRun.created_at)).limit(limit)).all())


@app.get(
    "/api/v1/detection-runs/{run_id}",
    response_model=DetectionExecutionOut,
    tags=["detection"],
)
def get_detection_run(run_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    run = db.get(DetectionRun, run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection run not found")
    return _detection_execution(db, run)


@app.get("/api/v1/incidents", response_model=list[IncidentOut], tags=["incidents"])
def list_incidents(
    image_digest: str | None = Query(default=None, max_length=255),
    incident_status: str | None = Query(default=None, alias="status", max_length=32),
    minimum_severity: float | None = Query(default=None, ge=0.0, le=1.0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[Incident]:
    statement = select(Incident)
    if image_digest:
        statement = statement.where(Incident.image_digest == image_digest)
    if incident_status:
        allowed = {"open", "acknowledged", "resolved", "dismissed"}
        if incident_status not in allowed:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(allowed)}")
        statement = statement.where(Incident.status == incident_status)
    if minimum_severity is not None:
        statement = statement.where(Incident.severity_score >= minimum_severity)
    return list(db.scalars(statement.order_by(desc(Incident.created_at)).limit(limit)).all())


@app.get("/api/v1/incidents/{incident_id}", response_model=IncidentOut, tags=["incidents"])
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@app.get(
    "/api/v1/incidents/{incident_id}/timeline",
    response_model=list[IncidentEvidenceOut],
    tags=["incidents"],
)
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
) -> list[IncidentEvidence]:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return list(
        db.scalars(
            select(IncidentEvidence)
            .where(IncidentEvidence.incident_id == incident_id)
            .order_by(IncidentEvidence.sequence_no)
        ).all()
    )


@app.post(
    "/internal/v1/incidents/{incident_id}/status",
    response_model=IncidentOut,
    tags=["internal", "incidents"],
    dependencies=[Depends(require_internal_token)],
)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdateIn,
    db: Session = Depends(get_db),
) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    transitions = {
        "open": {"acknowledged", "resolved", "dismissed"},
        "acknowledged": {"resolved", "dismissed"},
        "resolved": set(),
        "dismissed": set(),
    }
    if payload.status == incident.status:
        return incident
    if payload.status not in transitions[incident.status]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Incident cannot transition from {incident.status} to {payload.status}",
        )

    now = datetime.now(timezone.utc)
    incident.status = payload.status
    incident.updated_at = now
    if payload.status == "acknowledged":
        incident.acknowledged_at = now
        incident.acknowledged_by = payload.actor
    else:
        incident.closed_at = now
        incident.closed_by = payload.actor
        incident.closure_note = payload.note

    next_sequence = (
        db.scalar(
            select(func.coalesce(func.max(IncidentEvidence.sequence_no), 0)).where(
                IncidentEvidence.incident_id == incident.incident_id
            )
        )
        or 0
    ) + 1
    db.add(
        IncidentEvidence(
            evidence_id=str(uuid4()),
            incident_id=incident.incident_id,
            sequence_no=next_sequence,
            occurred_at=now,
            source_type="incident_status",
            source_id=incident.incident_id,
            rule_id=None,
            evidence_type="status_change",
            summary=f"Incident status changed to {payload.status} by {payload.actor}.",
            details={"status": payload.status, "actor": payload.actor, "note": payload.note},
            created_at=now,
        )
    )
    db.commit()
    db.refresh(incident)
    return incident


@app.get("/api/v1/images", response_model=list[ImageIdentityOut], tags=["identity"])
def list_images(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ImageIdentity]:
    return list(
        db.scalars(select(ImageIdentity).order_by(desc(ImageIdentity.last_seen_at)).limit(limit)).all()
    )


@app.get("/api/v1/containers", response_model=list[ContainerIdentityOut], tags=["identity"])
def list_containers(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ContainerIdentity]:
    return list(
        db.scalars(
            select(ContainerIdentity).order_by(desc(ContainerIdentity.last_seen_at)).limit(limit)
        ).all()
    )


@app.get("/api/v1/system/info", response_model=SystemInfo, tags=["system"])
def system_info(db: Session = Depends(get_db)) -> SystemInfo:
    registered_services = db.scalar(select(func.count()).select_from(ServiceHeartbeat)) or 0
    runtime_events = db.scalar(select(func.count()).select_from(RuntimeEvent)) or 0
    process_exec_events = db.scalar(select(func.count()).select_from(ProcessExecEvent)) or 0
    known_containers = db.scalar(select(func.count()).select_from(ContainerIdentity)) or 0
    known_images = db.scalar(select(func.count()).select_from(ImageIdentity)) or 0
    behavior_profiles = db.scalar(select(func.count()).select_from(BehaviorProfile)) or 0
    active_behavior_profiles = (
        db.scalar(
            select(func.count()).select_from(BehaviorProfile).where(BehaviorProfile.status == "active")
        )
        or 0
    )
    anomaly_scores = db.scalar(select(func.count()).select_from(AnomalyScore)) or 0
    scored_observations = (
        db.scalar(
            select(func.count()).select_from(AnomalyScore).where(AnomalyScore.status == "scored")
        )
        or 0
    )
    insufficient_observations = (
        db.scalar(
            select(func.count())
            .select_from(AnomalyScore)
            .where(AnomalyScore.status == "insufficient_data")
        )
        or 0
    )
    detection_allowlists = db.scalar(select(func.count()).select_from(DetectionAllowlist)) or 0
    now = datetime.now(timezone.utc)
    active_detection_allowlists = (
        db.scalar(
            select(func.count())
            .select_from(DetectionAllowlist)
            .where(
                DetectionAllowlist.active.is_(True),
                or_(DetectionAllowlist.expires_at.is_(None), DetectionAllowlist.expires_at > now),
            )
        )
        or 0
    )
    detection_runs = db.scalar(select(func.count()).select_from(DetectionRun)) or 0
    incidents = db.scalar(select(func.count()).select_from(Incident)) or 0
    open_incidents = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(("open", "acknowledged")))
        )
        or 0
    )
    response_recommendations = db.scalar(select(func.count()).select_from(ResponseRecommendation)) or 0
    approved_response_recommendations = (
        db.scalar(
            select(func.count())
            .select_from(ResponseRecommendation)
            .where(ResponseRecommendation.status == "approved")
        )
        or 0
    )
    response_executions = db.scalar(select(func.count()).select_from(ResponseExecution)) or 0
    pending_response_executions = (
        db.scalar(
            select(func.count())
            .select_from(ResponseExecution)
            .where(
                ResponseExecution.status.in_(
                    ("pending", "claimed", "rollback_pending", "rollback_claimed")
                )
            )
        )
        or 0
    )
    successful_response_executions = (
        db.scalar(
            select(func.count())
            .select_from(ResponseExecution)
            .where(ResponseExecution.status.in_(("succeeded", "rolled_back")))
        )
        or 0
    )
    image_scans = db.scalar(select(func.count()).select_from(ImageScan)) or 0
    completed_image_scans = (
        db.scalar(select(func.count()).select_from(ImageScan).where(ImageScan.status == "completed"))
        or 0
    )
    sbom_artifacts = db.scalar(select(func.count()).select_from(SbomArtifact)) or 0
    vulnerability_reports = (
        db.scalar(select(func.count()).select_from(VulnerabilityReportArtifact)) or 0
    )
    vulnerability_findings = db.scalar(select(func.count()).select_from(VulnerabilityFinding)) or 0
    cisa_kev_findings = (
        db.scalar(
            select(func.count())
            .select_from(VulnerabilityFinding)
            .join(VulnerabilityIntel, VulnerabilityIntel.cve_id == VulnerabilityFinding.cve_id)
            .where(VulnerabilityIntel.kev.is_(True))
        )
        or 0
    )
    return SystemInfo(
        name="Porygon",
        version=APP_VERSION,
        phase="Phase 8: digest-bound SBOM, vulnerability, and exposure enrichment",
        environment=settings.environment,
        registered_services=registered_services,
        runtime_events=runtime_events,
        process_exec_events=process_exec_events,
        known_containers=known_containers,
        known_images=known_images,
        behavior_profiles=behavior_profiles,
        active_behavior_profiles=active_behavior_profiles,
        anomaly_scores=anomaly_scores,
        scored_observations=scored_observations,
        insufficient_observations=insufficient_observations,
        detection_allowlists=detection_allowlists,
        active_detection_allowlists=active_detection_allowlists,
        detection_runs=detection_runs,
        incidents=incidents,
        open_incidents=open_incidents,
        response_recommendations=response_recommendations,
        approved_response_recommendations=approved_response_recommendations,
        response_executions=response_executions,
        pending_response_executions=pending_response_executions,
        successful_response_executions=successful_response_executions,
        image_scans=image_scans,
        completed_image_scans=completed_image_scans,
        sbom_artifacts=sbom_artifacts,
        vulnerability_reports=vulnerability_reports,
        vulnerability_findings=vulnerability_findings,
        cisa_kev_findings=cisa_kev_findings,
    )


def _response_audit(
    db: Session,
    *,
    incident_id: str,
    event_type: str,
    actor: str,
    details: dict[str, object],
    recommendation_id: str | None = None,
    execution_id: str | None = None,
    created_at: datetime | None = None,
) -> ResponseAuditEvent:
    record = ResponseAuditEvent(
        audit_id=str(uuid4()),
        incident_id=incident_id,
        recommendation_id=recommendation_id,
        execution_id=execution_id,
        event_type=event_type,
        actor=actor,
        details=details,
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(record)
    return record


@app.get(
    "/api/v1/response-policy",
    response_model=dict[str, object],
    tags=["response"],
)
def get_response_policy() -> dict[str, object]:
    return {
        "policy": RESPONSE_POLICY,
        "policy_hash": response_policy_hash(),
        "execution_mode": settings.response_execution_mode,
        "approval_max_age_seconds": settings.response_approval_max_age_seconds,
        "interpretation": (
            "Recommendations are deterministic decision support. No Docker state is changed "
            "until a human presents the separate operator credential and approves an exact "
            "action and target. Disruptive actions are claimable only in live execution mode."
        ),
    }


@app.post(
    "/operator/v1/incidents/{incident_id}/response-recommendations",
    response_model=ResponseRecommendationGenerateOut,
    tags=["operator", "response"],
    dependencies=[Depends(require_operator_token)],
)
def generate_response_recommendations(
    incident_id: str,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    if incident.status not in {"open", "acknowledged"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Closed incidents cannot receive new response recommendations",
        )

    targets: list[str | None] = sorted(set(incident.container_ids)) or [None]
    now = datetime.now(timezone.utc)
    records: list[ResponseRecommendation] = []
    for target in targets:
        document = build_recommendation_document(
            incident_id=incident.incident_id,
            target_container_id=target,
            severity_score=incident.severity_score,
            confidence_score=incident.confidence_score,
            findings=incident.findings,
        )
        key = build_recommendation_key(
            incident_id=incident.incident_id,
            target_container_id=target,
            policy_hash=str(document["policy_hash"]),
        )
        existing = db.scalar(
            select(ResponseRecommendation).where(
                ResponseRecommendation.recommendation_key == key
            )
        )
        if existing is not None:
            records.append(existing)
            continue

        record = ResponseRecommendation(
            recommendation_id=str(uuid4()),
            recommendation_key=key,
            incident_id=incident.incident_id,
            target_container_id=target,
            policy_version=str(document["policy_version"]),
            policy_hash=str(document["policy_hash"]),
            recommended_action=str(document["recommended_action"]),
            allowed_actions=list(document["allowed_actions"]),
            rationale=str(document["rationale"]),
            risk_notes=list(document["risk_notes"]),
            status="proposed",
            created_at=now,
            decided_at=None,
            decided_by=None,
            decision_note=None,
            approved_action=None,
        )
        db.add(record)
        _response_audit(
            db,
            incident_id=incident.incident_id,
            recommendation_id=record.recommendation_id,
            event_type="recommendation_created",
            actor="porygon-policy",
            details={
                "target_container_id": target,
                "recommended_action": record.recommended_action,
                "allowed_actions": record.allowed_actions,
                "policy_version": record.policy_version,
                "policy_hash": record.policy_hash,
            },
            created_at=now,
        )
        records.append(record)

    try:
        db.commit()
        for record in records:
            db.refresh(record)
    except IntegrityError:
        db.rollback()
        records = list(
            db.scalars(
                select(ResponseRecommendation)
                .where(ResponseRecommendation.incident_id == incident.incident_id)
                .order_by(ResponseRecommendation.target_container_id)
            ).all()
        )
    return {"incident_id": incident.incident_id, "recommendations": records}


@app.get(
    "/api/v1/response-recommendations",
    response_model=list[ResponseRecommendationOut],
    tags=["response"],
)
def list_response_recommendations(
    incident_id: str | None = Query(default=None, max_length=36),
    recommendation_status: str | None = Query(default=None, alias="status", max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ResponseRecommendation]:
    statement = select(ResponseRecommendation)
    if incident_id:
        statement = statement.where(ResponseRecommendation.incident_id == incident_id)
    if recommendation_status:
        allowed = {"proposed", "approved", "rejected"}
        if recommendation_status not in allowed:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(allowed)}")
        statement = statement.where(ResponseRecommendation.status == recommendation_status)
    return list(
        db.scalars(statement.order_by(desc(ResponseRecommendation.created_at)).limit(limit)).all()
    )


@app.get(
    "/api/v1/response-recommendations/{recommendation_id}",
    response_model=ResponseRecommendationOut,
    tags=["response"],
)
def get_response_recommendation(
    recommendation_id: str,
    db: Session = Depends(get_db),
) -> ResponseRecommendation:
    record = db.get(ResponseRecommendation, recommendation_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recommendation not found")
    return record


@app.post(
    "/operator/v1/response-recommendations/{recommendation_id}/approve",
    response_model=ResponseExecutionOut,
    tags=["operator", "response"],
    dependencies=[Depends(require_operator_token)],
)
def approve_response_recommendation(
    recommendation_id: str,
    payload: ResponseRecommendationApproveIn,
    db: Session = Depends(get_db),
) -> ResponseExecution:
    record = db.get(ResponseRecommendation, recommendation_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recommendation not found")
    existing_execution = db.scalar(
        select(ResponseExecution).where(
            ResponseExecution.recommendation_id == record.recommendation_id
        )
    )
    if existing_execution is not None:
        if record.approved_action != payload.action_type:
            raise HTTPException(
                status_code=409,
                detail="Recommendation was already approved for a different action",
            )
        return existing_execution

    incident = db.get(Incident, record.incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Incident is unavailable")
    if incident.status not in {"open", "acknowledged"}:
        raise HTTPException(status_code=409, detail="Closed incidents cannot approve response actions")
    if record.status == "rejected":
        raise HTTPException(status_code=409, detail="Rejected recommendations cannot be approved")
    if payload.action_type not in record.allowed_actions:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Requested action is not allowed by the recorded response policy",
        )
    if payload.action_type != "observe_only" and record.target_container_id is None:
        raise HTTPException(status_code=422, detail="Disruptive actions require an exact container target")
    if payload.action_type != "observe_only" and not payload.acknowledge_disruption:
        raise HTTPException(
            status_code=422,
            detail="acknowledge_disruption=true is required for pause or stop",
        )

    now = datetime.now(timezone.utc)
    age_seconds = (now - record.created_at).total_seconds()
    if age_seconds > settings.response_approval_max_age_seconds:
        raise HTTPException(
            status_code=409,
            detail="Recommendation is stale; generate a fresh recommendation before approval",
        )
    record.status = "approved"
    record.decided_at = now
    record.decided_by = payload.actor
    record.decision_note = payload.note
    record.approved_action = payload.action_type
    execution = ResponseExecution(
        execution_id=str(uuid4()),
        recommendation_id=record.recommendation_id,
        incident_id=record.incident_id,
        target_container_id=record.target_container_id,
        action_type=payload.action_type,
        status="pending",
        idempotency_key=build_execution_idempotency_key(
            recommendation_id=record.recommendation_id,
            action_type=payload.action_type,
        ),
        executor_instance_id=None,
        lease_expires_at=None,
        attempt_count=0,
        pre_state={},
        post_state={},
        result={},
        error_code=None,
        error_message=None,
        created_at=now,
        started_at=None,
        completed_at=None,
        rollback_requested_at=None,
        rollback_requested_by=None,
        rollback_note=None,
        rollback_started_at=None,
        rollback_completed_at=None,
    )
    db.add(execution)
    _response_audit(
        db,
        incident_id=record.incident_id,
        recommendation_id=record.recommendation_id,
        execution_id=execution.execution_id,
        event_type="recommendation_approved",
        actor=payload.actor,
        details={
            "approved_action": payload.action_type,
            "target_container_id": record.target_container_id,
            "note": payload.note,
            "acknowledge_disruption": payload.acknowledge_disruption,
        },
        created_at=now,
    )
    db.commit()
    db.refresh(execution)
    return execution


@app.post(
    "/operator/v1/response-recommendations/{recommendation_id}/reject",
    response_model=ResponseRecommendationOut,
    tags=["operator", "response"],
    dependencies=[Depends(require_operator_token)],
)
def reject_response_recommendation(
    recommendation_id: str,
    payload: ResponseRecommendationDecisionIn,
    db: Session = Depends(get_db),
) -> ResponseRecommendation:
    record = db.get(ResponseRecommendation, recommendation_id)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recommendation not found")
    if record.status == "approved":
        raise HTTPException(status_code=409, detail="Approved recommendations cannot be rejected")
    if record.status == "rejected":
        return record
    now = datetime.now(timezone.utc)
    record.status = "rejected"
    record.decided_at = now
    record.decided_by = payload.actor
    record.decision_note = payload.note
    _response_audit(
        db,
        incident_id=record.incident_id,
        recommendation_id=record.recommendation_id,
        event_type="recommendation_rejected",
        actor=payload.actor,
        details={"note": payload.note},
        created_at=now,
    )
    db.commit()
    db.refresh(record)
    return record


def _requeue_expired_response_claims(db: Session, now: datetime) -> None:
    db.execute(
        update(ResponseExecution)
        .where(
            ResponseExecution.status == "claimed",
            ResponseExecution.lease_expires_at.is_not(None),
            ResponseExecution.lease_expires_at < now,
        )
        .values(status="pending", executor_instance_id=None, lease_expires_at=None)
    )
    db.execute(
        update(ResponseExecution)
        .where(
            ResponseExecution.status == "rollback_claimed",
            ResponseExecution.lease_expires_at.is_not(None),
            ResponseExecution.lease_expires_at < now,
        )
        .values(status="rollback_pending", executor_instance_id=None, lease_expires_at=None)
    )


@app.post(
    "/internal/v1/response-executions/claim",
    response_model=ResponseClaimOut,
    tags=["internal", "response"],
    dependencies=[Depends(require_internal_token)],
)
def claim_response_execution(
    payload: ResponseClaimIn,
    db: Session = Depends(get_db),
) -> dict[str, object | None]:
    now = datetime.now(timezone.utc)
    _requeue_expired_response_claims(db, now)
    operation: str | None = None
    record = db.scalar(
        select(ResponseExecution)
        .where(ResponseExecution.status == "rollback_pending")
        .order_by(ResponseExecution.rollback_requested_at, ResponseExecution.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if record is not None:
        operation = "rollback"
        record.status = "rollback_claimed"
        record.rollback_started_at = record.rollback_started_at or now
    else:
        pending_statement = select(ResponseExecution).where(ResponseExecution.status == "pending")
        if settings.response_execution_mode != "live":
            pending_statement = pending_statement.where(
                ResponseExecution.action_type == "observe_only"
            )
        record = db.scalar(
            pending_statement
            .order_by(ResponseExecution.created_at)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if record is not None:
            operation = "execute"
            record.status = "claimed"
            record.started_at = record.started_at or now

    if record is None:
        db.commit()
        return {"execution": None, "operation": None}

    record.executor_instance_id = payload.executor_instance_id
    record.lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    record.attempt_count += 1
    _response_audit(
        db,
        incident_id=record.incident_id,
        recommendation_id=record.recommendation_id,
        execution_id=record.execution_id,
        event_type=f"{operation}_claimed",
        actor=payload.executor_instance_id,
        details={
            "lease_expires_at": record.lease_expires_at.isoformat(),
            "attempt_count": record.attempt_count,
        },
        created_at=now,
    )
    db.commit()
    db.refresh(record)
    return {"execution": record, "operation": operation}


@app.post(
    "/internal/v1/response-executions/{execution_id}/complete",
    response_model=ResponseExecutionOut,
    tags=["internal", "response"],
    dependencies=[Depends(require_internal_token)],
)
def complete_response_execution(
    execution_id: str,
    payload: ResponseExecutionCompleteIn,
    db: Session = Depends(get_db),
) -> ResponseExecution:
    record = db.get(ResponseExecution, execution_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Response execution not found")
    if record.status in {"succeeded", "failed", "rolled_back", "rollback_failed"}:
        return record
    if record.status not in {"claimed", "rollback_claimed"}:
        raise HTTPException(status_code=409, detail="Execution is not currently claimed")
    if record.executor_instance_id != payload.executor_instance_id:
        raise HTTPException(status_code=409, detail="Execution is claimed by another executor")

    now = datetime.now(timezone.utc)
    operation = "rollback" if record.status == "rollback_claimed" else "execute"
    if operation == "execute":
        record.status = "succeeded" if payload.success else "failed"
        record.completed_at = now
    else:
        record.status = "rolled_back" if payload.success else "rollback_failed"
        record.rollback_completed_at = now
    record.pre_state = payload.pre_state
    record.post_state = payload.post_state
    record.result = payload.result
    record.error_code = payload.error_code
    record.error_message = payload.error_message
    record.lease_expires_at = None
    _response_audit(
        db,
        incident_id=record.incident_id,
        recommendation_id=record.recommendation_id,
        execution_id=record.execution_id,
        event_type=f"{operation}_{'succeeded' if payload.success else 'failed'}",
        actor=payload.executor_instance_id,
        details={
            "action_type": record.action_type,
            "target_container_id": record.target_container_id,
            "pre_state": payload.pre_state,
            "post_state": payload.post_state,
            "result": payload.result,
            "error_code": payload.error_code,
            "error_message": payload.error_message,
        },
        created_at=now,
    )
    db.commit()
    db.refresh(record)
    return record


@app.post(
    "/operator/v1/response-executions/{execution_id}/rollback",
    response_model=ResponseExecutionOut,
    tags=["operator", "response"],
    dependencies=[Depends(require_operator_token)],
)
def request_response_rollback(
    execution_id: str,
    payload: ResponseRollbackRequestIn,
    db: Session = Depends(get_db),
) -> ResponseExecution:
    record = db.get(ResponseExecution, execution_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Response execution not found")
    if record.action_type == "observe_only":
        raise HTTPException(status_code=409, detail="observe_only has no rollback operation")
    if record.status in {"rollback_pending", "rollback_claimed", "rolled_back"}:
        return record
    if record.status != "succeeded":
        raise HTTPException(status_code=409, detail="Only successful actions can be rolled back")
    if record.action_type == "stop_container" and not payload.acknowledge_limitations:
        raise HTTPException(
            status_code=422,
            detail="acknowledge_limitations=true is required because start cannot restore in-memory state",
        )
    now = datetime.now(timezone.utc)
    record.status = "rollback_pending"
    record.rollback_requested_at = now
    record.rollback_requested_by = payload.actor
    record.rollback_note = payload.note
    _response_audit(
        db,
        incident_id=record.incident_id,
        recommendation_id=record.recommendation_id,
        execution_id=record.execution_id,
        event_type="rollback_requested",
        actor=payload.actor,
        details={
            "action_type": record.action_type,
            "note": payload.note,
            "acknowledge_limitations": payload.acknowledge_limitations,
        },
        created_at=now,
    )
    db.commit()
    db.refresh(record)
    return record


@app.post(
    "/operator/v1/response-executions/{execution_id}/retry",
    response_model=ResponseExecutionOut,
    tags=["operator", "response"],
    dependencies=[Depends(require_operator_token)],
)
def retry_response_execution(
    execution_id: str,
    payload: ResponseRetryRequestIn,
    db: Session = Depends(get_db),
) -> ResponseExecution:
    record = db.get(ResponseExecution, execution_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Response execution not found")
    if not payload.acknowledge_retry:
        raise HTTPException(status_code=422, detail="acknowledge_retry=true is required")
    if record.status not in {"failed", "rollback_failed"}:
        raise HTTPException(status_code=409, detail="Only failed actions can be retried")
    retryable_codes = {"docker_unavailable", "docker_api_error", "executor_internal_error"}
    if record.error_code not in retryable_codes:
        raise HTTPException(
            status_code=409,
            detail="This failure is not retryable without creating and approving a new recommendation",
        )
    now = datetime.now(timezone.utc)
    previous_status = record.status
    record.status = "pending" if previous_status == "failed" else "rollback_pending"
    record.executor_instance_id = None
    record.lease_expires_at = None
    record.error_code = None
    record.error_message = None
    record.pre_state = {}
    record.post_state = {}
    record.result = {}
    if previous_status == "failed":
        record.started_at = None
        record.completed_at = None
    else:
        record.rollback_started_at = None
        record.rollback_completed_at = None
    _response_audit(
        db,
        incident_id=record.incident_id,
        recommendation_id=record.recommendation_id,
        execution_id=record.execution_id,
        event_type="execution_retry_requested",
        actor=payload.actor,
        details={
            "previous_status": previous_status,
            "next_status": record.status,
            "note": payload.note,
        },
        created_at=now,
    )
    db.commit()
    db.refresh(record)
    return record


@app.get(
    "/api/v1/response-executions",
    response_model=list[ResponseExecutionOut],
    tags=["response"],
)
def list_response_executions(
    incident_id: str | None = Query(default=None, max_length=36),
    execution_status: str | None = Query(default=None, alias="status", max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ResponseExecution]:
    statement = select(ResponseExecution)
    if incident_id:
        statement = statement.where(ResponseExecution.incident_id == incident_id)
    if execution_status:
        allowed = {
            "pending", "claimed", "succeeded", "failed", "rollback_pending",
            "rollback_claimed", "rolled_back", "rollback_failed",
        }
        if execution_status not in allowed:
            raise HTTPException(status_code=422, detail=f"status must be one of {sorted(allowed)}")
        statement = statement.where(ResponseExecution.status == execution_status)
    return list(db.scalars(statement.order_by(desc(ResponseExecution.created_at)).limit(limit)).all())


@app.get(
    "/api/v1/response-executions/{execution_id}",
    response_model=ResponseExecutionOut,
    tags=["response"],
)
def get_response_execution(
    execution_id: str,
    db: Session = Depends(get_db),
) -> ResponseExecution:
    record = db.get(ResponseExecution, execution_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Response execution not found")
    return record


@app.get(
    "/api/v1/incidents/{incident_id}/response-audit",
    response_model=list[ResponseAuditEventOut],
    tags=["incidents", "response"],
)
def get_response_audit(
    incident_id: str,
    db: Session = Depends(get_db),
) -> list[ResponseAuditEvent]:
    if db.get(Incident, incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return list(
        db.scalars(
            select(ResponseAuditEvent)
            .where(ResponseAuditEvent.incident_id == incident_id)
            .order_by(ResponseAuditEvent.created_at, ResponseAuditEvent.audit_id)
        ).all()
    )


@app.get("/api/v1/vulnerability-policy", tags=["vulnerability"])
def vulnerability_policy() -> dict[str, object]:
    return {
        "schema_version": "porygon.vulnerability.v1",
        "scanner": {
            "name": "trivy",
            "pinned_version": "0.72.0",
            "target": "exact local image ID verified against the requested repository digest",
            "sbom_format": "CycloneDX JSON",
        },
        "evidence_stages": [
            "package_present",
            "deployed",
            "runtime_observed",
            "runtime_observed_and_port_published",
        ],
        "claim_boundary": (
            "No stage proves exploitation. EPSS, CISA KEV, process observation, and published ports "
            "are independent prioritization or exposure signals."
        ),
    }


@app.post(
    "/operator/v1/image-scans",
    response_model=ImageScanOut,
    tags=["operator", "vulnerability"],
    dependencies=[Depends(require_operator_token)],
)
def create_image_scan(
    payload: ImageScanCreateIn,
    db: Session = Depends(get_db),
) -> ImageScan:
    statement = select(ImageIdentity).where(
        ImageIdentity.primary_repo_digest == payload.image_digest,
        ImageIdentity.digest_status == "resolved",
    )
    if payload.docker_host_id:
        statement = statement.where(ImageIdentity.docker_host_id == payload.docker_host_id)
    identities = list(db.scalars(statement.order_by(desc(ImageIdentity.last_seen_at))).all())
    if not identities:
        raise HTTPException(
            status_code=404,
            detail="No resolved local image identity matches this exact repository digest",
        )
    distinct_targets = {(row.docker_host_id, row.image_id) for row in identities}
    if len(distinct_targets) > 1 and payload.docker_host_id is None:
        raise HTTPException(
            status_code=409,
            detail="Digest exists on multiple Docker hosts; specify docker_host_id",
        )
    identity = identities[0]
    scan_key = build_scan_key(
        image_digest=payload.image_digest,
        image_id=identity.image_id,
        scanner_name=payload.scanner_name,
        scanner_version=payload.scanner_version,
        scan_reference=payload.scan_reference,
    )
    existing = db.scalar(select(ImageScan).where(ImageScan.scan_key == scan_key))
    if existing is not None:
        return existing
    now = datetime.now(timezone.utc)
    record = ImageScan(
        scan_id=str(uuid4()),
        scan_key=scan_key,
        image_digest=payload.image_digest,
        image_id=identity.image_id,
        docker_host_id=identity.docker_host_id,
        scanner_name=payload.scanner_name,
        scanner_version=payload.scanner_version,
        scan_reference=payload.scan_reference,
        status="queued",
        requested_by=payload.requested_by,
        request_note=payload.note,
        scanner_instance_id=None,
        lease_expires_at=None,
        attempt_count=0,
        created_at=now,
        started_at=None,
        completed_at=None,
        error_code=None,
        error_message=None,
        scanner_metadata={},
        summary={},
    )
    db.add(record)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(select(ImageScan).where(ImageScan.scan_key == scan_key))
        if existing is None:
            raise
        return existing
    db.refresh(record)
    return record


@app.post(
    "/internal/v1/image-scans/claim",
    response_model=ImageScanClaimOut,
    tags=["internal", "vulnerability"],
    dependencies=[Depends(require_internal_token)],
)
def claim_image_scan(
    payload: ImageScanClaimIn,
    db: Session = Depends(get_db),
) -> dict[str, ImageScan | None]:
    now = datetime.now(timezone.utc)
    record = db.scalar(
        select(ImageScan)
        .where(
            ImageScan.scanner_name == payload.scanner_name,
            ImageScan.scanner_version == payload.scanner_version,
            or_(
                ImageScan.status == "queued",
                (ImageScan.status == "claimed") & (ImageScan.lease_expires_at < now),
            ),
        )
        .order_by(ImageScan.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if record is None:
        db.commit()
        return {"scan": None}
    record.status = "claimed"
    record.scanner_instance_id = payload.scanner_instance_id
    record.started_at = record.started_at or now
    record.lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
    record.attempt_count += 1
    db.commit()
    db.refresh(record)
    return {"scan": record}


@app.post(
    "/internal/v1/image-scans/{scan_id}/renew",
    response_model=ImageScanOut,
    tags=["internal", "vulnerability"],
    dependencies=[Depends(require_internal_token)],
)
def renew_image_scan_lease(
    scan_id: str,
    payload: ImageScanRenewIn,
    db: Session = Depends(get_db),
) -> ImageScan:
    record = db.get(ImageScan, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Image scan not found")
    if record.status != "claimed" or record.scanner_instance_id != payload.scanner_instance_id:
        raise HTTPException(status_code=409, detail="Scan is not claimed by this scanner")
    record.lease_expires_at = datetime.now(timezone.utc) + timedelta(seconds=payload.lease_seconds)
    db.commit()
    db.refresh(record)
    return record


def _require_scan_claim(record: ImageScan, scanner_instance_id: str) -> None:
    if record.status == "completed":
        return
    if record.status != "claimed":
        raise HTTPException(status_code=409, detail="Scan is not currently claimed")
    if record.scanner_instance_id != scanner_instance_id:
        raise HTTPException(status_code=409, detail="Scan is claimed by another scanner")


@app.post(
    "/internal/v1/image-scans/{scan_id}/complete",
    response_model=ImageScanOut,
    tags=["internal", "vulnerability"],
    dependencies=[Depends(require_internal_token)],
)
def complete_image_scan(
    scan_id: str,
    payload: ImageScanCompleteIn,
    db: Session = Depends(get_db),
) -> ImageScan:
    record = db.get(ImageScan, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Image scan not found")
    if record.status == "completed":
        return record
    _require_scan_claim(record, payload.scanner_instance_id)

    findings = normalize_trivy_report(payload.trivy_report)
    if len(findings) > settings.vulnerability_max_findings:
        raise HTTPException(status_code=413, detail="Scanner result exceeds vulnerability finding limit")
    sbom_info = sbom_summary(payload.cyclonedx_sbom)
    if sbom_info["bom_format"].lower() != "cyclonedx":
        raise HTTPException(status_code=422, detail="SBOM must be CycloneDX JSON")
    if int(sbom_info["component_count"]) > settings.sbom_max_components:
        raise HTTPException(status_code=413, detail="SBOM component count exceeds configured limit")

    now = datetime.now(timezone.utc)
    intel_payload = {item.cve_id: item for item in payload.vulnerability_intel}
    cve_ids = {str(item["cve_id"]) for item in findings}
    intel_records: dict[str, VulnerabilityIntel] = {}
    for cve_id in sorted(cve_ids):
        source = intel_payload.get(cve_id)
        intel = db.get(VulnerabilityIntel, cve_id)
        if intel is None:
            intel = VulnerabilityIntel(
                cve_id=cve_id,
                epss_score=None,
                epss_percentile=None,
                epss_date=None,
                kev=False,
                kev_date_added=None,
                kev_due_date=None,
                kev_vendor_project=None,
                kev_product=None,
                kev_vulnerability_name=None,
                kev_required_action=None,
                kev_known_ransomware_use=None,
                source_metadata={"coverage": "not_returned"},
                fetched_at=now,
            )
            db.add(intel)
        if source is not None:
            metadata = dict(source.source_metadata)
            previous_fetched_at = intel.fetched_at
            epss_authoritative = bool(metadata.get("epss_fetch_complete", True)) or bool(
                metadata.get("epss_record_returned", False)
            )
            kev_authoritative = bool(metadata.get("kev_fetch_complete", True))
            if epss_authoritative:
                intel.epss_score = source.epss_score
                intel.epss_percentile = source.epss_percentile
                intel.epss_date = source.epss_date
                metadata["epss_value_source"] = "current_fetch"
            else:
                metadata["epss_value_source"] = "retained_previous"
            if kev_authoritative:
                intel.kev = source.kev
                intel.kev_date_added = source.kev_date_added
                intel.kev_due_date = source.kev_due_date
                intel.kev_vendor_project = source.kev_vendor_project
                intel.kev_product = source.kev_product
                intel.kev_vulnerability_name = source.kev_vulnerability_name
                intel.kev_required_action = source.kev_required_action
                intel.kev_known_ransomware_use = source.kev_known_ransomware_use
                metadata["kev_value_source"] = "current_fetch"
            else:
                metadata["kev_value_source"] = "retained_previous"
            if not epss_authoritative or not kev_authoritative:
                metadata["retained_from_fetched_at"] = previous_fetched_at.isoformat()
            intel.source_metadata = metadata
            intel.fetched_at = now
        intel_records[cve_id] = intel
    db.flush()

    snapshots = [
        row.current_snapshot
        for row in db.scalars(
            select(ContainerIdentity).where(ContainerIdentity.image_digest == record.image_digest)
        ).all()
    ]
    process_rows = list(
        db.scalars(
            select(ProcessExecEvent)
            .where(ProcessExecEvent.image_digest == record.image_digest)
            .order_by(desc(ProcessExecEvent.occurred_at))
            .limit(settings.vulnerability_runtime_event_limit)
        ).all()
    )
    process_documents = [
        {"executable": row.executable, "process_name": row.process_name}
        for row in process_rows
    ]

    artifact_summary = sbom_info
    artifact = SbomArtifact(
        artifact_id=str(uuid4()),
        scan_id=record.scan_id,
        image_digest=record.image_digest,
        format="cyclonedx-json",
        spec_version=str(sbom_info["spec_version"]),
        component_count=int(sbom_info["component_count"]),
        document_sha256=sha256_document(payload.cyclonedx_sbom),
        summary=artifact_summary,
        document=payload.cyclonedx_sbom,
        created_at=now,
    )
    db.add(artifact)
    report_artifact = VulnerabilityReportArtifact(
        artifact_id=str(uuid4()),
        scan_id=record.scan_id,
        image_digest=record.image_digest,
        format="trivy-json",
        schema_version=(
            int(payload.trivy_report["SchemaVersion"])
            if isinstance(payload.trivy_report.get("SchemaVersion"), int)
            else None
        ),
        finding_count=len(findings),
        document_sha256=sha256_document(payload.trivy_report),
        summary=summarize_findings(findings),
        document=payload.trivy_report,
        created_at=now,
    )
    db.add(report_artifact)

    kev_count = 0
    epss_count = 0
    for item in findings:
        intel = intel_records[str(item["cve_id"])]
        if intel.kev:
            kev_count += 1
        if intel.epss_score is not None:
            epss_count += 1
        intel_snapshot = {
            "cve_id": intel.cve_id,
            "epss_score": intel.epss_score,
            "epss_percentile": intel.epss_percentile,
            "epss_date": intel.epss_date,
            "kev": intel.kev,
            "kev_date_added": intel.kev_date_added,
            "kev_due_date": intel.kev_due_date,
            "kev_vendor_project": intel.kev_vendor_project,
            "kev_product": intel.kev_product,
            "kev_vulnerability_name": intel.kev_vulnerability_name,
            "kev_required_action": intel.kev_required_action,
            "kev_known_ransomware_use": intel.kev_known_ransomware_use,
            "source_metadata": intel.source_metadata,
            "fetched_at": intel.fetched_at.isoformat(),
        }
        exposure = assess_exposure(
            finding=item,
            container_snapshots=snapshots,
            process_events=process_documents,
            intel=intel_snapshot,
        )
        db.add(
            VulnerabilityFinding(
                finding_id=str(uuid4()),
                scan_id=record.scan_id,
                image_digest=record.image_digest,
                cve_id=str(item["cve_id"]),
                target=str(item["target"]),
                class_name=str(item["class_name"]),
                package_type=str(item["package_type"]),
                package_name=str(item["package_name"]),
                package_path=item["package_path"],
                installed_version=str(item["installed_version"]),
                fixed_version=item["fixed_version"],
                status=item["status"],
                severity=str(item["severity"]),
                severity_source=item["severity_source"],
                cvss_score=item["cvss_score"],
                cvss_vector=item["cvss_vector"],
                cvss_source=item["cvss_source"],
                title=item["title"],
                description=item["description"],
                primary_url=item["primary_url"],
                references=item["references"],
                data_source=item["data_source"],
                evidence_stage=str(exposure["evidence_stage"]),
                exploit_status="not_established",
                exposure_evidence=exposure["evidence"],
                intel_snapshot=intel_snapshot,
                limitations=exposure["limitations"],
                created_at=now,
            )
        )

    record.status = "completed"
    record.completed_at = now
    record.lease_expires_at = None
    record.error_code = None
    record.error_message = None
    record.scanner_metadata = payload.scanner_metadata
    record.summary = {
        **summarize_findings(findings),
        "sbom": artifact_summary,
        "intel": {
            "cve_count": len(cve_ids),
            "epss_covered_findings": epss_count,
            "kev_findings": kev_count,
        },
        "runtime_context": {
            "containers_observed": len(snapshots),
            "process_events_considered": len(process_rows),
        },
        "claim_boundary": "Package matches and enrichment do not establish exploitation.",
    }
    db.commit()
    db.refresh(record)
    return record


@app.post(
    "/internal/v1/image-scans/{scan_id}/fail",
    response_model=ImageScanOut,
    tags=["internal", "vulnerability"],
    dependencies=[Depends(require_internal_token)],
)
def fail_image_scan(
    scan_id: str,
    payload: ImageScanFailIn,
    db: Session = Depends(get_db),
) -> ImageScan:
    record = db.get(ImageScan, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Image scan not found")
    if record.status in {"completed", "failed"}:
        return record
    _require_scan_claim(record, payload.scanner_instance_id)
    record.status = "failed"
    record.completed_at = datetime.now(timezone.utc)
    record.lease_expires_at = None
    record.error_code = payload.error_code
    record.error_message = payload.error_message
    record.scanner_metadata = payload.scanner_metadata
    db.commit()
    db.refresh(record)
    return record


@app.get("/api/v1/image-scans", response_model=list[ImageScanOut], tags=["vulnerability"])
def list_image_scans(
    image_digest: str | None = Query(default=None, max_length=255),
    scan_status: str | None = Query(default=None, alias="status", max_length=32),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[ImageScan]:
    statement = select(ImageScan)
    if image_digest:
        statement = statement.where(ImageScan.image_digest == image_digest)
    if scan_status:
        if scan_status not in {"queued", "claimed", "completed", "failed"}:
            raise HTTPException(status_code=422, detail="Invalid scan status")
        statement = statement.where(ImageScan.status == scan_status)
    return list(db.scalars(statement.order_by(desc(ImageScan.created_at)).limit(limit)).all())


@app.get("/api/v1/image-scans/{scan_id}", response_model=ImageScanDetailOut, tags=["vulnerability"])
def get_image_scan(scan_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    scan = db.get(ImageScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Image scan not found")
    sbom = db.scalar(select(SbomArtifact).where(SbomArtifact.scan_id == scan_id))
    report = db.scalar(
        select(VulnerabilityReportArtifact).where(VulnerabilityReportArtifact.scan_id == scan_id)
    )
    findings = list(
        db.scalars(
            select(VulnerabilityFinding)
            .where(VulnerabilityFinding.scan_id == scan_id)
            .order_by(desc(VulnerabilityFinding.cvss_score), VulnerabilityFinding.cve_id)
        ).all()
    )
    cve_ids = {row.cve_id for row in findings}
    intel = list(
        db.scalars(
            select(VulnerabilityIntel)
            .where(VulnerabilityIntel.cve_id.in_(cve_ids))
            .order_by(desc(VulnerabilityIntel.kev), desc(VulnerabilityIntel.epss_score))
        ).all()
    ) if cve_ids else []
    return {
        "scan": scan,
        "sbom": sbom,
        "report": report,
        "vulnerabilities": findings,
        "intel": intel,
    }


@app.get(
    "/api/v1/image-scans/{scan_id}/report",
    response_model=VulnerabilityReportArtifactOut,
    tags=["vulnerability"],
)
def get_image_scan_report(
    scan_id: str, db: Session = Depends(get_db)
) -> VulnerabilityReportArtifact:
    scan = db.get(ImageScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Image scan not found")
    artifact = db.scalar(
        select(VulnerabilityReportArtifact).where(VulnerabilityReportArtifact.scan_id == scan_id)
    )
    if artifact is None:
        raise HTTPException(status_code=404, detail="Vulnerability report is not available for this scan")
    return artifact


@app.get(
    "/api/v1/image-scans/{scan_id}/sbom",
    response_model=SbomArtifactOut,
    tags=["vulnerability"],
)
def get_image_scan_sbom(scan_id: str, db: Session = Depends(get_db)) -> SbomArtifact:
    scan = db.get(ImageScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Image scan not found")
    artifact = db.scalar(select(SbomArtifact).where(SbomArtifact.scan_id == scan_id))
    if artifact is None:
        raise HTTPException(status_code=404, detail="SBOM is not available for this scan")
    return artifact


@app.get(
    "/api/v1/vulnerabilities",
    response_model=list[VulnerabilityFindingOut],
    tags=["vulnerability"],
)
def list_vulnerabilities(
    image_digest: str | None = Query(default=None, max_length=255),
    cve_id: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    kev_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> list[VulnerabilityFinding]:
    statement = select(VulnerabilityFinding)
    if kev_only:
        statement = statement.join(
            VulnerabilityIntel, VulnerabilityIntel.cve_id == VulnerabilityFinding.cve_id
        ).where(VulnerabilityIntel.kev.is_(True))
    if image_digest:
        statement = statement.where(VulnerabilityFinding.image_digest == image_digest)
    if cve_id:
        statement = statement.where(VulnerabilityFinding.cve_id == cve_id.upper())
    if severity:
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        if severity.upper() not in allowed:
            raise HTTPException(status_code=422, detail=f"severity must be one of {sorted(allowed)}")
        statement = statement.where(VulnerabilityFinding.severity == severity.upper())
    return list(
        db.scalars(
            statement.order_by(desc(VulnerabilityFinding.cvss_score), VulnerabilityFinding.cve_id).limit(limit)
        ).all()
    )


@app.get("/api/v1/vulnerability-intel/{cve_id}", response_model=VulnerabilityIntelOut, tags=["vulnerability"])
def get_vulnerability_intel(cve_id: str, db: Session = Depends(get_db)) -> VulnerabilityIntel:
    record = db.get(VulnerabilityIntel, cve_id.upper())
    if record is None:
        raise HTTPException(status_code=404, detail="Vulnerability intelligence not found")
    return record
