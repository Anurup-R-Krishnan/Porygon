from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request, status

from porygon_collector.config import get_settings
from porygon_collector.docker_source import DockerEventSource
from porygon_collector.spool import OutboxStore
from porygon_collector.state import CollectorState

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("porygon.collector")


def _iso(value: object) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


async def heartbeat_loop(state: CollectorState, store: OutboxStore) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/heartbeats"
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(5.0, connect=3.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            snapshot = state.snapshot()
            queue_depth = await asyncio.to_thread(store.count)
            state.set(queue_depth=queue_depth)
            observed_at = datetime.now(timezone.utc)
            collector_healthy = bool(
                snapshot["docker_connected"] and snapshot["event_stream_connected"]
            )
            payload = {
                "service_name": settings.service_name,
                "instance_id": settings.collector_instance_id,
                "status": "healthy" if collector_healthy else "degraded",
                "observed_at": observed_at.isoformat(),
                "metadata": {
                    "version": settings.version,
                    "environment": settings.environment,
                    "phase": "3-process-telemetry",
                    "runtime_event_source": "docker-engine-events",
                    "docker_host_id": snapshot["effective_docker_host_id"],
                    "docker_connected": snapshot["docker_connected"],
                    "event_stream_connected": snapshot["event_stream_connected"],
                    "queue_depth": queue_depth,
                    "events_enqueued": snapshot["events_enqueued"],
                    "events_delivered": snapshot["events_delivered"],
                    "duplicates_ignored": snapshot["duplicate_events_ignored"],
                },
            }
            try:
                response = await client.post(endpoint, headers=headers, json=payload)
                response.raise_for_status()
                state.set(
                    backend_last_success_at=datetime.now(timezone.utc),
                    backend_last_error=None,
                    backend_consecutive_failures=0,
                )
            except (httpx.HTTPError, ValueError) as exc:
                current = state.snapshot()
                state.set(
                    backend_last_error=f"{exc.__class__.__name__}: {exc}",
                    backend_consecutive_failures=int(current["backend_consecutive_failures"]) + 1,
                )
                logger.warning(
                    "Heartbeat failed (consecutive_failures=%s): %s",
                    int(current["backend_consecutive_failures"]) + 1,
                    exc.__class__.__name__,
                )
            await asyncio.sleep(settings.heartbeat_interval_seconds)


async def delivery_loop(state: CollectorState, store: OutboxStore) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/events/batch"
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(15.0, connect=3.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            events = await asyncio.to_thread(store.fetch_due, settings.delivery_batch_size)
            if not events:
                queue_depth = await asyncio.to_thread(store.count)
                state.set(queue_depth=queue_depth)
                await asyncio.sleep(settings.delivery_poll_seconds)
                continue

            event_ids = [str(event["event_id"]) for event in events]
            try:
                response = await client.post(endpoint, headers=headers, json={"events": events})
                response.raise_for_status()
                result = response.json()
                if int(result.get("received", -1)) != len(events):
                    raise ValueError("Backend response did not acknowledge the full event batch")

                await asyncio.to_thread(store.acknowledge, event_ids)
                queue_depth = await asyncio.to_thread(store.count)
                state.set(
                    delivery_last_success_at=datetime.now(timezone.utc),
                    delivery_last_error=None,
                    queue_depth=queue_depth,
                )
                state.increment(events_delivered=len(events))
            except (httpx.HTTPError, ValueError) as exc:
                error = f"{exc.__class__.__name__}: {exc}"
                await asyncio.to_thread(
                    store.mark_failed,
                    event_ids,
                    error,
                    settings.delivery_retry_max_seconds,
                )
                state.set(delivery_last_error=error, queue_depth=await asyncio.to_thread(store.count))
                logger.warning("Event delivery failed for %s events: %s", len(events), error)
                await asyncio.sleep(settings.delivery_poll_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state = CollectorState(started_at=datetime.now(timezone.utc))
    store = OutboxStore(settings.spool_path, settings.spool_max_events)
    state.set(queue_depth=store.count())
    source = DockerEventSource(settings, state, store)

    app.state.collector = state
    app.state.store = store
    app.state.docker_source = source

    source.start()
    heartbeat_task = asyncio.create_task(heartbeat_loop(state, store), name="porygon-heartbeat")
    delivery_task = asyncio.create_task(delivery_loop(state, store), name="porygon-delivery")
    try:
        yield
    finally:
        for task in (heartbeat_task, delivery_task):
            task.cancel()
        for task in (heartbeat_task, delivery_task):
            with suppress(asyncio.CancelledError):
                await task
        source.stop()


app = FastAPI(
    title="Porygon Collector",
    version=settings.version,
    description=(
        "Docker event collector retained in the Phase 3 stack for immutable image identity, "
        "and durable at-least-once delivery with exactly-once database storage."
    ),
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
def health_live() -> dict[str, str]:
    return {"status": "ok", "service": "collector", "version": settings.version}


@app.get("/health/ready", tags=["health"])
def health_ready(request: Request) -> dict[str, object]:
    state: CollectorState = request.app.state.collector
    snapshot = state.snapshot()

    if snapshot["backend_last_success_at"] is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No successful backend heartbeat yet",
        )
    age_seconds = (
        datetime.now(timezone.utc) - snapshot["backend_last_success_at"]
    ).total_seconds()
    if age_seconds > settings.heartbeat_interval_seconds * 3:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend heartbeat is stale",
        )
    if not snapshot["docker_connected"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker Engine is unavailable",
        )
    if not snapshot["event_stream_connected"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker event stream is disconnected",
        )

    return {
        "status": "ok",
        "service": "collector",
        "docker_host_id": snapshot["effective_docker_host_id"],
        "queue_depth": snapshot["queue_depth"],
        "last_event_at": _iso(snapshot["last_event_at"]),
        "last_delivery_at": _iso(snapshot["delivery_last_success_at"]),
    }


@app.get("/status", tags=["system"])
def collector_status(request: Request) -> dict[str, object]:
    state: CollectorState = request.app.state.collector
    snapshot = state.snapshot()
    return {
        "service": settings.service_name,
        "instance_id": settings.collector_instance_id,
        "phase": "3-process-telemetry",
        "event_source": "docker-engine-events",
        "docker_host_id": snapshot["effective_docker_host_id"],
        "docker_connected": snapshot["docker_connected"],
        "event_stream_connected": snapshot["event_stream_connected"],
        "docker_last_success_at": _iso(snapshot["docker_last_success_at"]),
        "docker_last_error": snapshot["docker_last_error"],
        "backend_last_success_at": _iso(snapshot["backend_last_success_at"]),
        "backend_last_error": snapshot["backend_last_error"],
        "delivery_last_success_at": _iso(snapshot["delivery_last_success_at"]),
        "delivery_last_error": snapshot["delivery_last_error"],
        "last_event_at": _iso(snapshot["last_event_at"]),
        "queue_depth": snapshot["queue_depth"],
        "events_enqueued": snapshot["events_enqueued"],
        "events_delivered": snapshot["events_delivered"],
        "duplicate_events_ignored": snapshot["duplicate_events_ignored"],
        "spool_overflow_count": snapshot["spool_overflow_count"],
    }
