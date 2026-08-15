# Phase 8 Acceptance Criteria

Phase 8 is accepted only when all mandatory criteria pass.

## Static and unit criteria

- [x] Full Phase 1–7 unit suite still passes.
- [x] Scanner parser and enrichment tests pass.
- [x] Backend digest-bound workflow test passes.
- [x] Ruff reports no findings across all services.
- [x] Python modules and command-line scripts compile.
- [x] Shell scripts parse with `bash -n`.
- [x] Compose, Falco YAML, and all `pyproject.toml` files parse.
- [x] OpenAPI includes all Phase 8 routes, including explicit raw-report and SBOM retrieval.
- [x] Alembic renders the migration chain through `0008_phase8`.
- [x] The scanner Dockerfile pins Trivy `0.72.0` and verifies architecture-specific SHA-256.

## Identity and idempotency criteria

- [ ] A live scan can only be queued for a resolved repository digest already known to the Phase 2 identity layer.
- [ ] The queue stores the exact local image ID and Docker host.
- [ ] The scanner refuses an ID/digest mismatch before invoking Trivy.
- [ ] The scanner renews its lease during a long-running scan.
- [ ] Repeating the same digest, image ID, scanner version, schema version, and scan reference returns the existing scan.
- [ ] Changing the scan reference creates a different immutable scan record.

## SBOM criteria

- [ ] Trivy produces CycloneDX JSON for the exact local image ID.
- [ ] The API rejects a non-CycloneDX document.
- [ ] The preserved raw Trivy report and SBOM each include a canonical SHA-256.
- [ ] Trivy database cache files used by the scan are hashed in scanner metadata.
- [ ] Component count and summary are persisted.
- [ ] Configured component and finding limits are enforced.

## Vulnerability criteria

- [ ] Findings preserve package, version, source, severity, CVSS, fix, references, and scan identity.
- [ ] Every finding has `exploit_status = not_established`.
- [ ] Every finding uses one of the four documented evidence stages.
- [ ] Every finding stores a scan-time EPSS/KEV snapshot.
- [ ] A later intel refresh cannot alter the snapshot stored with an old finding.
- [ ] Partial EPSS/KEV failure does not erase previously known latest intelligence.
- [ ] Source endpoint, feed metadata, document hashes, and partial errors are recorded.

## Trust-boundary criteria

- [ ] Only the scanner is added to the egress network.
- [ ] Only the scanner, collector, responder, and Falco have their previously documented Docker/host observation boundaries.
- [ ] The backend does not receive Docker socket access.
- [ ] The scanner receives no operator credential.
- [ ] The scanner runs non-root, drops all capabilities, uses a read-only root filesystem, and exposes no host port.

## Live acceptance command

```bash
./scripts/verify_phase8.sh | tee artifacts/phase8-verification.txt
```

The script uses a disposable Alpine container and does not execute an exploit. It verifies identity registration, scan idempotency, CycloneDX persistence, evidence boundaries, immutable intel snapshots, and distinct experiment references.

Live criteria remain unchecked in the packaged validation report because the packaging environment has no Docker Engine.
