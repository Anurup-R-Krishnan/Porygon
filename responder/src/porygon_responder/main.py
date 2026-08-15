from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, status

from porygon_responder.config import get_settings
from porygon_responder.executor import ActionResult, DockerResponseExecutor

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("porygon.responder")


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def heartbeat_loop(app: FastAPI) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/heartbeats"
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(5.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            state: dict[str, Any] = app.state.responder_state
            payload = {
                "service_name": settings.service_name,
                "instance_id": settings.responder_instance_id,
                "status": "healthy" if state["docker_connected"] else "degraded",
                "observed_at": _now().isoformat(),
                "metadata": {
                    "version": settings.version,
                    "environment": settings.environment,
                    "phase": "7-human-approved-response",
                    "docker_connected": state["docker_connected"],
                    "last_claim_at": state["last_claim_at"],
                    "last_completion_at": state["last_completion_at"],
                    "executions_completed": state["executions_completed"],
                    "executions_failed": state["executions_failed"],
                },
            }
            try:
                response = await client.post(endpoint, headers=headers, json=payload)
                response.raise_for_status()
                state["backend_last_success_at"] = _now()
                state["backend_last_error"] = None
            except httpx.HTTPError as exc:
                state["backend_last_error"] = f"{exc.__class__.__name__}: {exc}"
                logger.warning("Responder heartbeat failed: %s", exc.__class__.__name__)
            await asyncio.sleep(settings.heartbeat_interval_seconds)


async def response_loop(app: FastAPI) -> None:
    base = settings.api_base_url.rstrip("/")
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(15.0, connect=3.0)
    executor: DockerResponseExecutor = app.state.executor
    state: dict[str, Any] = app.state.responder_state

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            try:
                await asyncio.to_thread(executor.client.ping)
                state["docker_connected"] = True
                state["docker_last_error"] = None
            except Exception as exc:  # docker raises several transport-specific exceptions
                state["docker_connected"] = False
                state["docker_last_error"] = f"{exc.__class__.__name__}: {exc}"
                await asyncio.sleep(settings.poll_seconds)
                continue

            try:
                claim = await client.post(
                    f"{base}/internal/v1/response-executions/claim",
                    headers=headers,
                    json={
                        "executor_instance_id": settings.responder_instance_id,
                        "lease_seconds": settings.lease_seconds,
                    },
                )
                claim.raise_for_status()
                document = claim.json()
                execution = document.get("execution")
                operation = document.get("operation")
                if execution is None:
                    await asyncio.sleep(settings.poll_seconds)
                    continue
                state["last_claim_at"] = _now().isoformat()

                try:
                    result = await asyncio.to_thread(
                        executor.execute,
                        action_type=str(execution["action_type"]),
                        target_container_id=execution.get("target_container_id"),
                        operation=str(operation),
                    )
                except Exception as exc:  # keep the worker alive and close the leased attempt
                    logger.exception("Unhandled responder executor failure")
                    result = ActionResult(
                        success=False,
                        pre_state={},
                        post_state={},
                        result={"verification": "not_completed"},
                        error_code="executor_internal_error",
                        error_message=f"{exc.__class__.__name__}: {exc}",
                    )
                completion = await client.post(
                    f"{base}/internal/v1/response-executions/{execution['execution_id']}/complete",
                    headers=headers,
                    json={
                        "executor_instance_id": settings.responder_instance_id,
                        "success": result.success,
                        "pre_state": result.pre_state,
                        "post_state": result.post_state,
                        "result": result.result,
                        "error_code": result.error_code,
                        "error_message": result.error_message,
                    },
                )
                completion.raise_for_status()
                state["last_completion_at"] = _now().isoformat()
                if result.success:
                    state["executions_completed"] += 1
                else:
                    state["executions_failed"] += 1
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                state["backend_last_error"] = f"{exc.__class__.__name__}: {exc}"
                logger.warning("Response processing failed: %s", exc)
                await asyncio.sleep(settings.poll_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    executor = DockerResponseExecutor(
        base_url=settings.docker_base_url,
        timeout_seconds=settings.docker_timeout_seconds,
        stop_timeout_seconds=settings.stop_timeout_seconds,
        protected_label=settings.protected_label,
    )
    app.state.executor = executor
    app.state.responder_state = {
        "started_at": _now(),
        "docker_connected": False,
        "docker_last_error": None,
        "backend_last_success_at": None,
        "backend_last_error": None,
        "last_claim_at": None,
        "last_completion_at": None,
        "executions_completed": 0,
        "executions_failed": 0,
    }
    heartbeat_task = asyncio.create_task(heartbeat_loop(app), name="responder-heartbeat")
    response_task = asyncio.create_task(response_loop(app), name="responder-execution")
    try:
        yield
    finally:
        for task in (heartbeat_task, response_task):
            task.cancel()
        for task in (heartbeat_task, response_task):
            with suppress(asyncio.CancelledError):
                await task
        executor.client.close()


app = FastAPI(
    title="Porygon Responder",
    version=settings.version,
    description="Executes only explicitly approved, typed Docker response actions.",
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
def health_live() -> dict[str, str]:
    return {"status": "ok", "service": "responder", "version": settings.version}


@app.get("/health/ready", tags=["health"])
def health_ready(request: Request) -> dict[str, object]:
    state: dict[str, Any] = request.app.state.responder_state
    if not state["docker_connected"]:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker Engine is unavailable",
        )
    last_backend = state["backend_last_success_at"]
    if last_backend is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No successful backend heartbeat yet",
        )
    age = (_now() - last_backend).total_seconds()
    if age > settings.heartbeat_interval_seconds * 3:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend heartbeat is stale",
        )
    return {
        "status": "ok",
        "service": "responder",
        "docker_connected": True,
        "last_claim_at": state["last_claim_at"],
        "last_completion_at": state["last_completion_at"],
    }


@app.get("/status", tags=["system"])
def responder_status(request: Request) -> dict[str, object]:
    state: dict[str, Any] = request.app.state.responder_state
    return {
        "service": settings.service_name,
        "instance_id": settings.responder_instance_id,
        "phase": "7-human-approved-response",
        **state,
    }
