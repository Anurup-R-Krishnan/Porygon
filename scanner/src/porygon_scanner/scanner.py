from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import docker
import httpx


class ScanError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ScanResult:
    report: dict[str, Any]
    sbom: dict[str, Any]
    intel: list[dict[str, Any]]
    metadata: dict[str, Any]



def file_sha256(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def database_cache_metadata(cache_dir: str) -> list[dict[str, Any]]:
    root = Path(cache_dir)
    records: list[dict[str, Any]] = []
    for directory_name in ("db", "java-db"):
        directory = root / directory_name
        if not directory.is_dir():
            continue
        for path in sorted(candidate for candidate in directory.rglob("*") if candidate.is_file()):
            stat = path.stat()
            records.append(
                {
                    "path": str(path.relative_to(root)),
                    "size_bytes": stat.st_size,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": file_sha256(path),
                }
            )
    return records

def parse_epss(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in document.get("data") or []:
        if not isinstance(item, dict) or not item.get("cve"):
            continue
        try:
            score = float(item["epss"])
            percentile = float(item["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        cve = str(item["cve"]).upper()
        result[cve] = {
            "cve_id": cve,
            "epss_score": score,
            "epss_percentile": percentile,
            "epss_date": str(item.get("date")) if item.get("date") else None,
        }
    return result


def parse_kev(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in document.get("vulnerabilities") or []:
        if not isinstance(item, dict) or not item.get("cveID"):
            continue
        cve = str(item["cveID"]).upper()
        result[cve] = {
            "cve_id": cve,
            "kev": True,
            "kev_date_added": item.get("dateAdded"),
            "kev_due_date": item.get("dueDate"),
            "kev_vendor_project": item.get("vendorProject"),
            "kev_product": item.get("product"),
            "kev_vulnerability_name": item.get("vulnerabilityName"),
            "kev_required_action": item.get("requiredAction"),
            "kev_known_ransomware_use": item.get("knownRansomwareCampaignUse"),
        }
    return result


def extract_cves(report: dict[str, Any]) -> list[str]:
    cves: set[str] = set()
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for item in result.get("Vulnerabilities") or []:
            if isinstance(item, dict) and item.get("VulnerabilityID"):
                cves.add(str(item["VulnerabilityID"]).upper())
    return sorted(cves)


def merge_intel(
    cves: Iterable[str],
    epss: dict[str, dict[str, Any]],
    kev: dict[str, dict[str, Any]],
    *,
    source_metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    for cve in sorted(set(cves)):
        row_metadata = {
            **source_metadata,
            "epss_record_returned": cve in epss,
            "kev_record_returned": cve in kev,
        }
        row: dict[str, Any] = {"cve_id": cve, "kev": False, "source_metadata": row_metadata}
        row.update(epss.get(cve, {}))
        row.update(kev.get(cve, {}))
        rows.append(row)
    return rows


class TrivyScanner:
    def __init__(
        self,
        *,
        docker_base_url: str,
        docker_timeout_seconds: int,
        trivy_binary: str,
        trivy_version: str,
        cache_dir: str,
        timeout_seconds: int,
        epss_url: str,
        cisa_kev_url: str,
        intel_timeout_seconds: int,
        intel_batch_size: int,
    ) -> None:
        self.client = docker.DockerClient(base_url=docker_base_url, timeout=docker_timeout_seconds)
        self.trivy_binary = trivy_binary
        self.trivy_version = trivy_version
        self.cache_dir = cache_dir
        self.timeout_seconds = timeout_seconds
        self.epss_url = epss_url
        self.cisa_kev_url = cisa_kev_url
        self.intel_timeout_seconds = intel_timeout_seconds
        self.intel_batch_size = intel_batch_size

    def verify_image(self, *, image_id: str, image_digest: str) -> dict[str, Any]:
        try:
            image = self.client.images.get(image_id)
        except docker.errors.ImageNotFound as exc:
            raise ScanError("image_not_found", f"Local image {image_id} was not found") from exc
        attrs = image.attrs
        actual_id = str(attrs.get("Id") or image.id)
        repo_digests = [str(value) for value in (attrs.get("RepoDigests") or [])]
        if actual_id != image_id or image_digest not in repo_digests:
            raise ScanError(
                "image_identity_mismatch",
                "The local image ID or repository digest no longer matches the queued scan target",
            )
        return {
            "image_id": actual_id,
            "repo_digests": sorted(repo_digests),
            "repo_tags": sorted(str(value) for value in (attrs.get("RepoTags") or [])),
        }

    def _run_trivy(self, *, image_id: str, output: Path) -> None:
        command = [
            self.trivy_binary,
            "image",
            "--quiet",
            "--cache-dir",
            self.cache_dir,
            "--timeout",
            f"{self.timeout_seconds}s",
            "--format",
            "json",
            "--scanners",
            "vuln",
            "--list-all-pkgs",
            "--output",
            str(output),
            image_id,
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds + 30,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("scanner_timeout", "Trivy exceeded its configured timeout") from exc
        if completed.returncode != 0:
            stderr = completed.stderr[-4000:]
            raise ScanError("scanner_error", f"Trivy failed with exit code {completed.returncode}: {stderr}")

    def _convert_to_cyclonedx(self, *, report: Path, output: Path) -> None:
        command = [
            self.trivy_binary,
            "convert",
            "--format",
            "cyclonedx",
            "--output",
            str(output),
            str(report),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("scanner_timeout", "Trivy report conversion exceeded its timeout") from exc
        if completed.returncode != 0:
            stderr = completed.stderr[-4000:]
            raise ScanError(
                "scanner_error",
                f"Trivy conversion failed with exit code {completed.returncode}: {stderr}",
            )

    def _fetch_intel(self, cves: list[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        epss: dict[str, dict[str, Any]] = {}
        kev: dict[str, dict[str, Any]] = {}
        errors: list[str] = []
        timeout = httpx.Timeout(self.intel_timeout_seconds)
        kev_metadata: dict[str, Any] = {}
        epss_response_hashes: list[str] = []
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            try:
                response = client.get(self.cisa_kev_url)
                response.raise_for_status()
                kev_document = response.json()
                kev = parse_kev(kev_document)
                kev_metadata = {
                    "catalog_version": kev_document.get("catalogVersion"),
                    "date_released": kev_document.get("dateReleased"),
                    "document_sha256": hashlib.sha256(response.content).hexdigest(),
                }
            except (httpx.HTTPError, ValueError) as exc:
                errors.append(f"cisa_kev:{exc.__class__.__name__}")
            for start in range(0, len(cves), self.intel_batch_size):
                batch = cves[start : start + self.intel_batch_size]
                try:
                    response = client.get(self.epss_url, params={"cve": ",".join(batch)})
                    response.raise_for_status()
                    epss_response_hashes.append(hashlib.sha256(response.content).hexdigest())
                    epss.update(parse_epss(response.json()))
                except (httpx.HTTPError, ValueError) as exc:
                    errors.append(f"epss_batch_{start}:{exc.__class__.__name__}")
        metadata = {
            "epss_url": self.epss_url,
            "cisa_kev_url": self.cisa_kev_url,
            "epss_records": len(epss),
            "epss_response_sha256": epss_response_hashes,
            "epss_fetch_complete": not any(error.startswith("epss_batch_") for error in errors),
            "kev_catalog_records": len(kev),
            "kev_catalog": kev_metadata,
            "kev_fetch_complete": not any(error.startswith("cisa_kev:") for error in errors),
            "errors": errors,
            "partial": bool(errors),
        }
        return merge_intel(cves, epss, kev, source_metadata=metadata), metadata

    def scan(self, *, image_id: str, image_digest: str) -> ScanResult:
        identity = self.verify_image(image_id=image_id, image_digest=image_digest)
        with tempfile.TemporaryDirectory(prefix="porygon-scan-") as temporary:
            root = Path(temporary)
            report_path = root / "trivy.json"
            sbom_path = root / "sbom.cdx.json"
            self._run_trivy(image_id=image_id, output=report_path)
            self._convert_to_cyclonedx(report=report_path, output=sbom_path)
            try:
                report = json.loads(report_path.read_text())
                sbom = json.loads(sbom_path.read_text())
            except (OSError, json.JSONDecodeError) as exc:
                raise ScanError("invalid_scanner_output", "Trivy output was not valid JSON") from exc
        cves = extract_cves(report)
        intel, intel_metadata = self._fetch_intel(cves)
        return ScanResult(
            report=report,
            sbom=sbom,
            intel=intel,
            metadata={
                "scanner": "trivy",
                "scanner_version": self.trivy_version,
                "image_identity": identity,
                "cve_count": len(cves),
                "trivy_report_created_at": report.get("CreatedAt"),
                "trivy_report_schema_version": report.get("SchemaVersion"),
                "database_cache_files": database_cache_metadata(self.cache_dir),
                "intelligence": intel_metadata,
            },
        )
