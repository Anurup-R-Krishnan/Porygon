# Phase 8 Architecture: Digest-Bound SBOM and Vulnerability Enrichment

## Objective

Phase 8 adds static image context to Porygon without converting a package/version match into an exploitation claim.

A scan is bound to all of the following:

- exact repository digest (`repository@sha256:...`)
- exact local Docker image ID (`sha256:...`)
- Docker host identity
- scanner name and immutable scanner version
- researcher-controlled scan reference
- vulnerability schema version

The queue key is a canonical SHA-256 hash of those values. Repeating the same request returns the same scan. Changing the image ID, digest, scanner version, or experiment reference creates a new immutable record.

## Service topology

```text
Operator
   |
   | operator token
   v
Porygon API ---- PostgreSQL
   ^                  |
   | internal token   | scan queue, SBOM, findings,
   |                  | latest intel, scan-time snapshots
Scanner service ------+
   |
   +-- Docker socket: verifies and scans the exact local image ID
   +-- egress network: Trivy DB, FIRST EPSS, CISA KEV
```

Only the scanner receives both Docker Engine access and outbound network access. The API receives neither Docker socket access nor general internet access.

## Scanner supply-chain control

The scanner image installs a fixed Trivy `0.72.0` release archive and verifies an architecture-specific SHA-256 checksum during the Docker build. It does not use a floating `latest` tag or install script.

This control is deliberate because compromised Trivy releases and Docker images were published during March 2026. Exact versioning and checksum verification reduce, but do not eliminate, scanner supply-chain risk.

## Scan flow

1. The Phase 2 identity layer observes an image and resolves its repository digest.
2. An operator requests a scan for that exact digest.
3. The API resolves the corresponding exact image ID and Docker host.
4. The scanner claims a leased queue item matching its name and version.
5. The scanner re-inspects Docker and refuses the scan if the ID/digest pair changed.
6. Trivy performs one JSON image scan with the full package list.
7. Trivy converts that preserved JSON report into CycloneDX, ensuring both artifacts come from the same scan.
8. The scanner hashes the Trivy database cache files used by the scan and collects EPSS/CISA KEV context.
9. The API preserves the raw Trivy report and CycloneDX document with canonical hashes, then records bounded runtime context.
10. Every finding stores an immutable scan-time intelligence snapshot.
11. A separate `vulnerability_intel` record retains the latest successfully obtained information for lookup.

## Data model

### `image_scans`

Stores queue state, immutable target identity, scanner version, lease state, attempts, scanner metadata, and result summary.

### `sbom_artifacts`

Stores one CycloneDX JSON document per scan, its component summary, and canonical SHA-256. Scan-detail responses return only SBOM metadata; the full document has a separate explicit endpoint to avoid expanding every routine scan lookup.


### `vulnerability_report_artifacts`

Stores the original Trivy JSON report, its schema version, finding summary, and canonical SHA-256. Routine scan-detail responses return report metadata only; the full document has an explicit endpoint.

### `vulnerability_findings`

Stores normalized package matches and evidence:

- CVE and package identity
- installed and fixed versions
- scanner severity and source
- CVSS score/vector/source when supplied
- references and source metadata
- evidence stage
- `exploit_status = not_established`
- runtime/deployment evidence
- immutable EPSS/KEV snapshot
- explicit limitations

### `vulnerability_intel`

Stores the latest successfully fetched EPSS and CISA KEV data for each CVE. This table is mutable by design. Historical findings do not rely on it because they preserve a scan-time snapshot.

## Evidence stages

The stages are ordered context, not attack verdicts:

1. `package_present`
   - Trivy matched a package/version in the image.
2. `deployed`
   - Porygon has observed at least one container from the digest.
3. `runtime_observed`
   - A recent process name/path heuristically matches the package.
4. `runtime_observed_and_port_published`
   - Runtime observation and a published container port both exist.

No stage proves:

- vulnerable code-path reachability
- exploitability under the running configuration
- attacker intent
- successful exploitation
- compromise

## Runtime relevance limitations

Process-to-package matching is heuristic. Package names do not always equal executable names, libraries can be reached without a same-named process, and recent event limits can omit older behaviour. Port publication is container-level exposure, not CVE-specific network reachability.

## External intelligence reproducibility

The scanner records:

- EPSS endpoint and response hashes
- CISA KEV endpoint
- CISA catalog version/date when present
- CISA document SHA-256
- returned record counts
- partial-fetch errors

EPSS and KEV values change over time. Findings therefore embed the exact scan-time values and source metadata.

## Security boundaries

- Long scans renew their queue lease while Trivy and external enrichment run.
- Docker socket access remains equivalent to a high-privilege host-control boundary even with a read-only bind mount.
- The scanner runs non-root, drops all Linux capabilities, uses a read-only root filesystem, and exposes no host port.
- The scanner is the only service attached to the egress network.
- SBOM and report sizes are bounded before persistence.
- Environment variables are not copied from Docker inspection into Phase 8 records.
- Vulnerability output is treated as untrusted structured input and normalized server-side.
