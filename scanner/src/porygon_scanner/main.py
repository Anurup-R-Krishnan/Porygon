from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request, status

from porygon_scanner.config import get_settings
from porygon_scanner.scanner import ScanError, TrivyScanner

settings = get_settings()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("porygon.scanner")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _heartbeat_is_fresh(
    value: object,
    interval_seconds: float,
    *,
    now: datetime | None = None,
) -> bool:
    if not isinstance(value, datetime) or value.tzinfo is None:
        return False
    current = now or _now()
    age_seconds = (current - value.astimezone(timezone.utc)).total_seconds()
    return age_seconds <= interval_seconds * 3


async def heartbeat_loop(app: FastAPI) -> None:
    endpoint = f"{settings.api_base_url.rstrip('/')}/internal/v1/heartbeats"
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    timeout = httpx.Timeout(5.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            state: dict[str, Any] = app.state.scanner_state
            payload = {
                "service_name": settings.service_name,
                "instance_id": settings.scanner_instance_id,
                "status": "healthy" if state["docker_connected"] else "degraded",
                "observed_at": _now().isoformat(),
                "metadata": {
                    "version": settings.version,
                    "phase": "8-sbom-vulnerability-enrichment",
                    "trivy_version": settings.trivy_version,
                    "docker_connected": state["docker_connected"],
                    "last_claim_at": state["last_claim_at"],
                    "last_completion_at": state["last_completion_at"],
                    "scans_completed": state["scans_completed"],
                    "scans_failed": state["scans_failed"],
                },
            }
            try:
                response = await client.post(endpoint, headers=headers, json=payload)
                response.raise_for_status()
                state["backend_last_success_at"] = _now()
                state["backend_last_error"] = None
            except httpx.HTTPError as exc:
                state["backend_last_error"] = f"{exc.__class__.__name__}: {exc}"
                logger.warning("Scanner heartbeat failed: %s", exc.__class__.__name__)
            await asyncio.sleep(settings.heartbeat_interval_seconds)




async def renew_scan_lease(
    client: httpx.AsyncClient,
    *,
    base: str,
    headers: dict[str, str],
    scan_id: str,
    state: dict[str, Any],
) -> None:
    interval = max(20.0, settings.lease_seconds / 3)
    while True:
        await asyncio.sleep(interval)
        try:
            response = await client.post(
                f"{base}/internal/v1/image-scans/{scan_id}/renew",
                headers=headers,
                json={
                    "scanner_instance_id": settings.scanner_instance_id,
                    "lease_seconds": settings.lease_seconds,
                },
            )
            response.raise_for_status()
            state["last_lease_renewal_at"] = _now().isoformat()
            state["lease_renewal_error"] = None
        except httpx.HTTPError as exc:
            state["lease_renewal_error"] = f"{exc.__class__.__name__}: {exc}"
            logger.warning("Scan lease renewal failed for %s: %s", scan_id, exc.__class__.__name__)

async def scan_loop(app: FastAPI) -> None:
    base = settings.api_base_url.rstrip("/")
    headers = {"X-Porygon-Internal-Token": settings.internal_api_token.get_secret_value()}
    scanner: TrivyScanner = app.state.scanner
    state: dict[str, Any] = app.state.scanner_state
    timeout = httpx.Timeout(settings.trivy_timeout_seconds + 120, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            try:
                await asyncio.to_thread(scanner.client.ping)
                state["docker_connected"] = True
                state["docker_last_error"] = None
            except Exception as exc:
                state["docker_connected"] = False
                state["docker_last_error"] = f"{exc.__class__.__name__}: {exc}"
                await asyncio.sleep(settings.poll_seconds)
                continue

            try:
                response = await client.post(
                    f"{base}/internal/v1/image-scans/claim",
                    headers=headers,
                    json={
                        "scanner_instance_id": settings.scanner_instance_id,
                        "scanner_name": "trivy",
                        "scanner_version": settings.trivy_version,
                        "lease_seconds": settings.lease_seconds,
                    },
                )
                response.raise_for_status()
                scan = response.json().get("scan")
                if scan is None:
                    await asyncio.sleep(settings.poll_seconds)
                    continue
                state["last_claim_at"] = _now().isoformat()
                scan_id = str(scan["scan_id"])
                lease_task = asyncio.create_task(
                    renew_scan_lease(
                        client,
                        base=base,
                        headers=headers,
                        scan_id=scan_id,
                        state=state,
                    ),
                    name=f"scan-lease-{scan_id}",
                )
                try:
                    result = await asyncio.to_thread(
                        scanner.scan,
                        image_id=str(scan["image_id"]),
                        image_digest=str(scan["image_digest"]),
                    )
                    completion = await client.post(
                        f"{base}/internal/v1/image-scans/{scan_id}/complete",
                        headers=headers,
                        json={
                            "scanner_instance_id": settings.scanner_instance_id,
                            "scanner_metadata": result.metadata,
                            "trivy_report": result.report,
                            "cyclonedx_sbom": result.sbom,
                            "vulnerability_intel": result.intel,
                        },
                    )
                    completion.raise_for_status()
                    state["scans_completed"] += 1
                except ScanError as exc:
                    failure = await client.post(
                        f"{base}/internal/v1/image-scans/{scan_id}/fail",
                        headers=headers,
                        json={
                            "scanner_instance_id": settings.scanner_instance_id,
                            "error_code": exc.code,
                            "error_message": str(exc),
                            "scanner_metadata": {"scanner": "trivy", "scanner_version": settings.trivy_version},
                        },
                    )
                    failure.raise_for_status()
                    state["scans_failed"] += 1
                except Exception as exc:
                    logger.exception("Unhandled scanner failure")
                    failure = await client.post(
                        f"{base}/internal/v1/image-scans/{scan_id}/fail",
                        headers=headers,
                        json={
                            "scanner_instance_id": settings.scanner_instance_id,
                            "error_code": "executor_internal_error",
                            "error_message": f"{exc.__class__.__name__}: {exc}",
                            "scanner_metadata": {"scanner": "trivy", "scanner_version": settings.trivy_version},
                        },
                    )
                    failure.raise_for_status()
                    state["scans_failed"] += 1
                finally:
                    lease_task.cancel()
                    with suppress(asyncio.CancelledError):
                        await lease_task
                state["last_completion_at"] = _now().isoformat()
            except httpx.HTTPError as exc:
                state["backend_last_error"] = f"{exc.__class__.__name__}: {exc}"
                logger.warning("Scan queue operation failed: %s", exc)
                await asyncio.sleep(settings.poll_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI):
    scanner = TrivyScanner(
        docker_base_url=settings.docker_base_url,
        docker_timeout_seconds=settings.docker_timeout_seconds,
        trivy_binary=settings.trivy_binary,
        trivy_version=settings.trivy_version,
        cache_dir=settings.trivy_cache_dir,
        timeout_seconds=settings.trivy_timeout_seconds,
        epss_url=settings.epss_url,
        cisa_kev_url=settings.cisa_kev_url,
        intel_timeout_seconds=settings.intel_timeout_seconds,
        intel_batch_size=settings.intel_batch_size,
    )
    app.state.scanner = scanner
    app.state.scanner_state = {
        "docker_connected": False,
        "docker_last_error": None,
        "backend_last_success_at": None,
        "backend_last_error": None,
        "last_claim_at": None,
        "last_completion_at": None,
        "scans_completed": 0,
        "scans_failed": 0,
        "last_lease_renewal_at": None,
        "lease_renewal_error": None,
    }
    heartbeat = asyncio.create_task(heartbeat_loop(app), name="scanner-heartbeat")
    worker = asyncio.create_task(scan_loop(app), name="scanner-worker")
    try:
        yield
    finally:
        for task in (heartbeat, worker):
            task.cancel()
        for task in (heartbeat, worker):
            with suppress(asyncio.CancelledError):
                await task
        scanner.client.close()


app = FastAPI(
    title="Porygon Scanner",
    version=settings.version,
    description="Scans exact local image IDs and enriches package matches without asserting exploitation.",
    lifespan=lifespan,
)


@app.get("/health/live", tags=["health"])
def health_live() -> dict[str, str]:
    return {"status": "ok", "service": "scanner", "version": settings.version}


@app.get("/health/ready", tags=["health"])
def health_ready(request: Request) -> dict[str, object]:
    state = request.app.state.scanner_state
    if not state["docker_connected"]:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Docker Engine is unavailable")
    if state["backend_last_success_at"] is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No successful backend heartbeat yet")
    if not _heartbeat_is_fresh(
        state["backend_last_success_at"],
        settings.heartbeat_interval_seconds,
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Backend heartbeat is stale",
        )
    return {
        "status": "ok",
        "service": "scanner",
        "trivy_version": settings.trivy_version,
        "last_claim_at": state["last_claim_at"],
        "last_completion_at": state["last_completion_at"],
    }


@app.get("/status", tags=["system"])
def scanner_status(request: Request) -> dict[str, object]:
    return dict(request.app.state.scanner_state)
