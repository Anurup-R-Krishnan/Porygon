"""Retention: prune raw runtime and process-execution evidence past a cutoff.

Behaviour profiles store their aggregated features and training manifest at
build time (backend/src/porygon_api/models.py: BehaviorProfile.features,
training_manifest); they do not hold live foreign keys into the raw event
tables. Deleting old rows from process_exec_events / runtime_events therefore
never invalidates an already-built profile, an already-computed anomaly
score, or an already-recorded detection. Retention only removes raw evidence
that is old enough that no in-flight fit/calibration/confirmatory window
could still need it.

This module is deliberately pure with respect to session control: callers
own the transaction (commit or rollback), so a caller can run this inside a
dry-run session, a scheduled job, or an API request.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from porygon_api.models import ProcessExecEvent, RuntimeEvent


@dataclass(frozen=True)
class RetentionPlan:
    cutoff: datetime
    process_exec_events_eligible: int
    runtime_events_eligible: int


@dataclass(frozen=True)
class RetentionResult:
    cutoff: datetime
    process_exec_events_deleted: int
    runtime_events_deleted: int
    dry_run: bool


def _cutoff(retention_days: int, *, now: datetime | None = None) -> datetime:
    if retention_days < 1:
        raise ValueError("retention_days must be at least 1")
    reference = now or datetime.now(timezone.utc)
    return reference - timedelta(days=retention_days)


def plan_retention(db: Session, *, retention_days: int, now: datetime | None = None) -> RetentionPlan:
    """Report how many rows are eligible for deletion, without deleting anything."""
    cutoff = _cutoff(retention_days, now=now)
    process_count = db.scalar(
        select(func.count()).select_from(ProcessExecEvent).where(ProcessExecEvent.occurred_at < cutoff)
    ) or 0
    runtime_count = db.scalar(
        select(func.count()).select_from(RuntimeEvent).where(RuntimeEvent.occurred_at < cutoff)
    ) or 0
    return RetentionPlan(
        cutoff=cutoff,
        process_exec_events_eligible=process_count,
        runtime_events_eligible=runtime_count,
    )


def apply_retention(
    db: Session,
    *,
    retention_days: int,
    max_delete_batch: int,
    dry_run: bool,
    now: datetime | None = None,
) -> RetentionResult:
    """Delete raw evidence older than the cutoff, one bounded batch at a time.

    A single call deletes at most max_delete_batch rows per table so a large
    backlog cannot hold a long-running transaction or an unbounded lock. Call
    repeatedly (e.g. from a scheduled job) until the counts reach zero.
    """
    cutoff = _cutoff(retention_days, now=now)

    if dry_run:
        plan = plan_retention(db, retention_days=retention_days, now=now)
        return RetentionResult(
            cutoff=cutoff,
            process_exec_events_deleted=min(plan.process_exec_events_eligible, max_delete_batch),
            runtime_events_deleted=min(plan.runtime_events_eligible, max_delete_batch),
            dry_run=True,
        )

    process_ids = db.scalars(
        select(ProcessExecEvent.event_id)
        .where(ProcessExecEvent.occurred_at < cutoff)
        .order_by(ProcessExecEvent.occurred_at)
        .limit(max_delete_batch)
    ).all()
    process_deleted = 0
    if process_ids:
        process_deleted = db.query(ProcessExecEvent).filter(ProcessExecEvent.event_id.in_(process_ids)).delete(
            synchronize_session=False
        )

    runtime_ids = db.scalars(
        select(RuntimeEvent.event_id)
        .where(RuntimeEvent.occurred_at < cutoff)
        .order_by(RuntimeEvent.occurred_at)
        .limit(max_delete_batch)
    ).all()
    runtime_deleted = 0
    if runtime_ids:
        runtime_deleted = db.query(RuntimeEvent).filter(RuntimeEvent.event_id.in_(runtime_ids)).delete(
            synchronize_session=False
        )

    return RetentionResult(
        cutoff=cutoff,
        process_exec_events_deleted=process_deleted,
        runtime_events_deleted=runtime_deleted,
        dry_run=False,
    )
