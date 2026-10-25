from datetime import datetime, timezone

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from porygon_api.db import Base
from porygon_api.main import (
    claim_image_scan,
    complete_image_scan,
    create_image_scan,
    renew_image_scan_lease,
)
from porygon_api.models import (
    ImageIdentity,
    SbomArtifact,
    VulnerabilityFinding,
    VulnerabilityIntel,
    VulnerabilityReportArtifact,
)
from porygon_api.schemas import (
    ImageScanClaimIn,
    ImageScanCompleteIn,
    ImageScanCreateIn,
    ImageScanRenewIn,
)


def test_digest_bound_scan_workflow_persists_staged_evidence() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    digest = "alpine@sha256:" + "a" * 64
    image_id = "sha256:" + "b" * 64

    with Session(engine) as db:
        db.add(
            ImageIdentity(
                docker_host_id="host-1",
                image_id=image_id,
                image_ref="alpine:3.19",
                primary_repo_digest=digest,
                repo_digests=[digest],
                repo_tags=["alpine:3.19"],
                os="linux",
                architecture="amd64",
                digest_status="resolved",
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        db.commit()

        scan = create_image_scan(
            ImageScanCreateIn(
                image_digest=digest,
                docker_host_id="host-1",
                requested_by="researcher",
                scan_reference="experiment-1",
            ),
            db,
        )
        duplicate = create_image_scan(
            ImageScanCreateIn(
                image_digest=digest,
                docker_host_id="host-1",
                requested_by="researcher",
                scan_reference="experiment-1",
            ),
            db,
        )
        assert duplicate.scan_id == scan.scan_id

        claimed = claim_image_scan(
            ImageScanClaimIn(
                scanner_instance_id="scanner-1",
                scanner_version="0.72.0",
                lease_seconds=600,
            ),
            db,
        )["scan"]
        assert claimed is not None
        assert claimed.status == "claimed"
        original_lease = claimed.lease_expires_at
        renewed = renew_image_scan_lease(
            scan.scan_id,
            ImageScanRenewIn(scanner_instance_id="scanner-1", lease_seconds=1200),
            db,
        )
        assert renewed.lease_expires_at is not None
        assert original_lease is not None
        assert renewed.lease_expires_at >= original_lease

        completed = complete_image_scan(
            scan.scan_id,
            ImageScanCompleteIn(
                scanner_instance_id="scanner-1",
                scanner_metadata={"scanner": "trivy", "scanner_version": "0.72.0"},
                trivy_report={
                    "Results": [
                        {
                            "Target": "alpine:3.19",
                            "Class": "os-pkgs",
                            "Type": "alpine",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": "CVE-2025-12345",
                                    "PkgName": "busybox",
                                    "InstalledVersion": "1.36.1-r0",
                                    "FixedVersion": "1.36.1-r1",
                                    "Severity": "HIGH",
                                }
                            ],
                        }
                    ]
                },
                cyclonedx_sbom={
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.6",
                    "components": [
                        {
                            "type": "library",
                            "name": "busybox",
                            "version": "1.36.1-r0",
                            "purl": "pkg:apk/alpine/busybox@1.36.1-r0",
                        }
                    ],
                },
                vulnerability_intel=[
                    {
                        "cve_id": "CVE-2025-12345",
                        "epss_score": 0.7,
                        "epss_percentile": 0.95,
                        "epss_date": "2026-07-21",
                        "kev": True,
                    }
                ],
            ),
            db,
        )
        assert completed.status == "completed"
        assert completed.summary["finding_count"] == 1
        assert db.scalar(select(SbomArtifact)).component_count == 1
        report_artifact = db.scalar(select(VulnerabilityReportArtifact))
        assert report_artifact is not None
        assert report_artifact.finding_count == 1
        assert len(report_artifact.document_sha256) == 64
        finding = db.scalar(select(VulnerabilityFinding))
        intel = db.scalar(select(VulnerabilityIntel))
        assert finding.exploit_status == "not_established"
        assert finding.evidence_stage == "package_present"
        assert finding.intel_snapshot["kev"] is True
        assert finding.intel_snapshot["epss_score"] == 0.7
        assert intel.kev is True
        assert intel.epss_score == 0.7


def test_partial_intelligence_fetch_preserves_previous_values() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)
    digest = "alpine@sha256:" + "c" * 64
    image_id = "sha256:" + "d" * 64
    report = {
        "Results": [
            {
                "Target": "alpine:3.19",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-54321",
                        "PkgName": "busybox",
                        "InstalledVersion": "1.36.1-r0",
                        "Severity": "HIGH",
                    }
                ],
            }
        ]
    }
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [{"type": "library", "name": "busybox"}],
    }

    with Session(engine) as db:
        db.add(
            ImageIdentity(
                docker_host_id="host-1",
                image_id=image_id,
                image_ref="alpine:3.19",
                primary_repo_digest=digest,
                repo_digests=[digest],
                repo_tags=["alpine:3.19"],
                os="linux",
                architecture="amd64",
                digest_status="resolved",
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        db.commit()

        first = create_image_scan(
            ImageScanCreateIn(
                image_digest=digest,
                docker_host_id="host-1",
                requested_by="researcher",
                scan_reference="complete-intel",
            ),
            db,
        )
        claim_image_scan(
            ImageScanClaimIn(scanner_instance_id="scanner-1", scanner_version="0.72.0"), db
        )
        complete_image_scan(
            first.scan_id,
            ImageScanCompleteIn(
                scanner_instance_id="scanner-1",
                trivy_report=report,
                cyclonedx_sbom=sbom,
                vulnerability_intel=[
                    {
                        "cve_id": "CVE-2025-54321",
                        "epss_score": 0.8,
                        "epss_percentile": 0.97,
                        "epss_date": "2026-07-21",
                        "kev": True,
                        "source_metadata": {
                            "epss_fetch_complete": True,
                            "epss_record_returned": True,
                            "kev_fetch_complete": True,
                        },
                    }
                ],
            ),
            db,
        )

        second = create_image_scan(
            ImageScanCreateIn(
                image_digest=digest,
                docker_host_id="host-1",
                requested_by="researcher",
                scan_reference="partial-intel",
            ),
            db,
        )
        claim_image_scan(
            ImageScanClaimIn(scanner_instance_id="scanner-1", scanner_version="0.72.0"), db
        )
        complete_image_scan(
            second.scan_id,
            ImageScanCompleteIn(
                scanner_instance_id="scanner-1",
                trivy_report=report,
                cyclonedx_sbom=sbom,
                vulnerability_intel=[
                    {
                        "cve_id": "CVE-2025-54321",
                        "kev": False,
                        "source_metadata": {
                            "partial": True,
                            "epss_fetch_complete": False,
                            "epss_record_returned": False,
                            "kev_fetch_complete": False,
                        },
                    }
                ],
            ),
            db,
        )

        intel = db.get(VulnerabilityIntel, "CVE-2025-54321")
        second_finding = db.scalar(
            select(VulnerabilityFinding).where(VulnerabilityFinding.scan_id == second.scan_id)
        )
        assert intel is not None
        assert intel.epss_score == 0.8
        assert intel.kev is True
        assert intel.source_metadata["epss_value_source"] == "retained_previous"
        assert intel.source_metadata["kev_value_source"] == "retained_previous"
        assert second_finding is not None
        assert second_finding.intel_snapshot["epss_score"] == 0.8
        assert second_finding.intel_snapshot["kev"] is True
