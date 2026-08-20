from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, HTTPException, Request, status

from porygon_telemetry.config import get_settings
from porygon_telemetry.file_source import FalcoFileSource
from porygon_telemetry.spool import TelemetryStore
from porygon_telemetry.state import TelemetryState

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("porygon.telemetry")


def _iso(value: object) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


def _heartbeat_is_fresh(
    value: object,
    interval_seconds: float,
    *,
    now: datetime | None = None,
) -> bool:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return False
    current = now or datetime.now(timezone.utc)
    age_seconds = (current - value.astimezone(timezone.utc)).total_seconds()
    return age_seconds <= interval_seconds * 3


def _not_ready(condition: str, message: str) -> None:
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"condition": condition, "message": message},
    )


async def heartbeat_loop(state: TelemetryState, store: TelemetryStore) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/heartbeats"
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(5.0, connect=3.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            snapshot = state.snapshot()
            queue_depth = await asyncio.to_thread(store.count)
            state.set(queue_depth=queue_depth)
            healthy = bool(snapshot["source_running"] and snapshot["source_file_available"])
            payload = {
                "service_name": settings.service_name,
                "instance_id": settings.telemetry_instance_id,
                "status": "healthy" if healthy else "degraded",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "version": settings.version,
                    "environment": settings.environment,
                    "phase": "3-process-telemetry",
                    "runtime_event_source": "falco-modern-ebpf",
                    "falco_log_path": settings.falco_log_path,
                    "source_running": snapshot["source_running"],
                    "source_file_available": snapshot["source_file_available"],
                    "source_offset": snapshot["source_offset"],
                    "queue_depth": queue_depth,
                    "events_enqueued": snapshot["events_enqueued"],
                    "events_delivered": snapshot["events_delivered"],
                    "duplicates_ignored": snapshot["duplicates_ignored"],
                    "malformed_lines": snapshot["malformed_lines"],
                    "dead_letters": await asyncio.to_thread(store.dead_letter_count),
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
                    "Telemetry heartbeat failed (consecutive_failures=%s): %s",
                    int(current["backend_consecutive_failures"]) + 1,
                    exc.__class__.__name__,
                )
            await asyncio.sleep(settings.heartbeat_interval_seconds)


async def delivery_loop(state: TelemetryState, store: TelemetryStore) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/process-events/batch"
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(15.0, connect=3.0)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            events = await asyncio.to_thread(store.fetch_due, settings.delivery_batch_size)
            if not events:
                state.set(queue_depth=await asyncio.to_thread(store.count))
                await asyncio.sleep(settings.delivery_poll_seconds)
                continue

            event_ids = [str(event["event_id"]) for event in events]
            try:
                response = await client.post(endpoint, headers=headers, json={"events": events})
                response.raise_for_status()
                result = response.json()
                if int(result.get("received", -1)) != len(events):
                    raise ValueError("Backend did not acknowledge the complete process-event batch")

                await asyncio.to_thread(store.acknowledge, event_ids)
                state.set(
                    delivery_last_success_at=datetime.now(timezone.utc),
                    delivery_last_error=None,
                    queue_depth=await asyncio.to_thread(store.count),
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
                logger.warning("Process-event delivery failed for %s events: %s", len(events), error)
                await asyncio.sleep(settings.delivery_poll_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    state = TelemetryState(started_at=datetime.now(timezone.utc))
    store = TelemetryStore(settings.spool_path, settings.spool_max_events)
    state.set(queue_depth=store.count())
    source = FalcoFileSource(settings, state, store)

    app.state.telemetry = state
    app.state.store = store
    app.state.source = source

    source.start()
    heartbeat_task = asyncio.create_task(heartbeat_loop(state, store), name="telemetry-heartbeat")
    delivery_task = asyncio.create_task(delivery_loop(state, store), name="telemetry-delivery")
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
    title="Porygon Process Telemetry Adapter",
    version=settings.version,
    description=(
        "Tails Falco JSON output, durably spools normalized process executions, "
        "and delivers them to the Porygon control plane."
    ),
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
def health_live() -> dict[str, str]:
    return {"status": "ok", "service": "telemetry", "version": settings.version}


@app.get("/health/ready", tags=["health"])
def health_ready(request: Request) -> dict[str, object]:
    state: TelemetryState = request.app.state.telemetry
    snapshot = state.snapshot()

    if not snapshot["source_running"]:
        _not_ready("falco_source_not_running", "Falco file source is not running")
    if not snapshot["source_file_available"]:
        _not_ready("falco_file_unavailable", "Falco event file is unavailable")
    if snapshot["backend_last_success_at"] is None:
        _not_ready("backend_heartbeat_missing", "No successful backend heartbeat yet")
    if not _heartbeat_is_fresh(
        snapshot["backend_last_success_at"],
        settings.heartbeat_interval_seconds,
    ):
        _not_ready("backend_heartbeat_stale", "Backend heartbeat is stale")
    return {
        "status": "ok",
        "service": "telemetry",
        "source_file_available": snapshot["source_file_available"],
        "source_offset": snapshot["source_offset"],
        "queue_depth": snapshot["queue_depth"],
        "last_read_at": _iso(snapshot["source_last_read_at"]),
        "last_delivery_at": _iso(snapshot["delivery_last_success_at"]),
    }


@app.get("/status", tags=["system"])
def telemetry_status(request: Request) -> dict[str, object]:
    state: TelemetryState = request.app.state.telemetry
    store: TelemetryStore = request.app.state.store
    snapshot = state.snapshot()
    return {
        **{key: _iso(value) if isinstance(value, datetime) else value for key, value in snapshot.items()},
        "dead_letters": store.dead_letter_count(),
        "falco_log_path": settings.falco_log_path,
    }
