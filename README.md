# Porygon Phase 8

Porygon is a Docker-first runtime-security research system. The cumulative Phase 1–8 repository now collects Docker and kernel-observed process evidence, builds immutable-digest behaviour profiles, calculates explainable behavioural distance, creates deterministic incidents, supports human-approved response actions, and enriches exact image digests with **SBOM and vulnerability context**.

Phase 8 does not claim that a scanner finding proves exploitation. It stores package matches, deployment/runtime context, EPSS, and CISA KEV as separate evidence dimensions.

## Phase status

“Code implemented” means the capability exists in the repository. It does not
mean that live acceptance or experimental validation has passed. On 2026-08-20,
the corrected static gate, all 91 unit tests, and the complete safe live gate
passed. The live run covered forced collector saturation, backend outages,
exactly-once replay checks, Falco-file-to-PostgreSQL equality, profile lifecycle,
behavioural scoring, and deterministic incident lifecycle through Phase 6.

| Phase | Capability | Code | Static/unit | Live acceptance | Experimental validation |
|---|---|---:|---:|---:|---:|
| 1 | PostgreSQL, FastAPI, migrations, health and service authentication | Present | Local pass | Local pass | Not applicable |
| 2 | Docker events, immutable image identity, durable collection outbox | Present | Local pass | Local pass with forced saturation and exact replay equality | Pending Phase 9 |
| 3 | Falco modern-eBPF process execution telemetry | Present | Local pass | Local pass with outage replay and Falco-file equality | Pending Phase 9 |
| 4 | Versioned digest-bound behavioural profiles | Present | Local pass | Local pass | Pending Phase 9 |
| 5 | Explainable behavioural-distance scoring v1 | Provisional | Local pass | Local pass | Pending calibrated path and Phase 9 |
| 6 | Deterministic findings, correlation, incidents and evidence timelines | Present | Local pass | Local pass | Pending Phase 9 |
| 7 | Human-approved response recommendations and controlled execution | Present; disabled by default | Local pass | Explicit disruptive gate not run | Pending Phase 9 |
| 8 | Digest-bound SBOM, CVE, EPSS, KEV and exposure enrichment | Present | Local pass | Unblocked; acceptance rerun pending | Extension; core experiment pending |
| 9 | Experimental evaluation and paper evidence | Not implemented | Not applicable | Not applicable | Pending |

### Live bootstrap corrections

- A digest-pinned, non-root gateway now publishes only `127.0.0.1:8000` and
  proxies to the backend. The backend remains solely on the isolated internal
  network, and the gateway receives no Porygon or PostgreSQL credentials.
- The Falco 0.44.1 rule now validates with its supported `proc.vpid` field. A
  one-shot, networkless initializer also establishes the shared event-volume
  permissions before Falco and telemetry start.
- Falco, telemetry, and the gateway have explicit health checks. The bootstrap
  smoke test observed zero restarts, zero Falco file-open errors, and persisted
  process-execution events in PostgreSQL.
- The Phase 7 response gate was intentionally skipped because it can pause or
  stop a container and is never part of `make verify`.

On the current CachyOS kernel, Falco reports that several optional TOCTOU
mitigation tracepoints are unavailable while continuing to capture process
executions. Confirmatory experiments will use the planned stock Linux LTS
kernel and will record Falco drop/engine metrics instead of treating container
health as proof of lossless capture.

See [`docs/FINAL_PHASES.md`](docs/FINAL_PHASES.md) for the complete roadmap.

## Phase 8 architecture

```text
                         operator token
Researcher/operator --------------------------+
                                                |
                                                v
Docker Engine <--- scanner service <--- Phase 8 work queue --- Porygon API
     |               |                               |              |
     | exact image   | Trivy 0.72.0                 |              |
     | ID + digest   | CycloneDX + JSON              |              v
     |               | EPSS + CISA KEV               +-------- PostgreSQL
     |               |
     +---------------+
```

Only the scanner has both Docker socket access and outbound internet access. The scanner does not receive the operator token. The backend does not receive Docker socket access.

Host API access goes through a credential-free reverse proxy. The backend,
database, collector, telemetry adapter, responder, and Falco remain on an
isolated internal network; only the proxy joins the separate ingress network.

Full design: [`docs/PHASE8_ARCHITECTURE.md`](docs/PHASE8_ARCHITECTURE.md).

## Exact scan identity

A scan is identified by a canonical SHA-256 over:

```text
repository digest
exact local image ID
Docker host
scanner name and version
vulnerability schema version
researcher scan reference
```

An identical request is idempotent. A changed scanner version, image ID, digest, or experiment reference creates a separate immutable record.

Tags are retained as context only. Porygon does not use a mutable tag as the scan identity.

## Scanner supply-chain control

The scanner Dockerfile pins Trivy `0.72.0` and verifies the downloaded release archive before installation:

| Architecture | Pinned archive SHA-256 |
|---|---|
| amd64 | `bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea` |
| arm64 | `2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467` |

The image does not use a floating `latest` tag or an unverified install script. This is important because malicious Trivy release and Docker artifacts were published during March 2026.

## Stored outputs

Each successful scan stores:

- exact image digest, image ID and Docker host
- exact scanner version and experiment reference
- original CycloneDX JSON SBOM
- preserved raw Trivy JSON vulnerability report
- canonical SBOM and raw-report SHA-256 values
- component counts and ecosystems
- normalized package/CVE findings
- installed and fixed versions
- severity, CVSS and scanner data source
- EPSS score/percentile/date when available
- CISA KEV fields when available
- Trivy vulnerability-database file hashes
- feed endpoints, catalog metadata and response hashes
- deployment and bounded runtime context
- explicit limitations

## Evidence model

Phase 8 uses four evidence stages:

| Stage | Meaning |
|---|---|
| `package_present` | The scanner matched package/version metadata in the image |
| `deployed` | Porygon observed a container using that digest |
| `runtime_observed` | A recent process name/path heuristically matches the package |
| `runtime_observed_and_port_published` | Runtime observation and a published container port both exist |

Every finding is stored with:

```text
exploit_status = not_established
```

A package match, EPSS score, CISA KEV membership, same-named process, or published port does not prove vulnerable-path reachability or compromise.

Detailed wording and limitations: [`docs/VULNERABILITY_EVIDENCE_MODEL_V1.md`](docs/VULNERABILITY_EVIDENCE_MODEL_V1.md).

## Historical reproducibility

`vulnerability_intel` is the latest known lookup for each CVE and may change after a later refresh.

Every `vulnerability_finding` separately stores an immutable scan-time snapshot containing:

- EPSS score, percentile and date
- KEV membership and catalog fields
- source metadata and feed hashes
- fetch timestamp

A later intelligence update therefore cannot silently rewrite the evidence used in an earlier experiment.

## Repository structure

```text
porygon-phase8/
├── compose.yaml
├── backend/
│   ├── alembic/versions/0001...0008
│   ├── src/porygon_api/
│   │   ├── baseline.py
│   │   ├── scoring.py
│   │   ├── detection.py
│   │   ├── response.py
│   │   ├── vulnerability.py
│   │   └── main.py
│   └── tests/
├── collector/
├── gateway/nginx.conf
├── telemetry/
├── responder/
├── scanner/
│   ├── Dockerfile
│   ├── src/porygon_scanner/
│   └── tests/
├── falco/porygon_rules.yaml
├── docs/
├── scripts/
│   ├── porygon_baseline.py
│   ├── porygon_score.py
│   ├── porygon_detect.py
│   ├── porygon_respond.py
│   ├── porygon_scan.py
│   └── verify_phase1.sh ... verify_phase8.sh
└── artifacts/
```

## Requirements

- Linux with `/sys/kernel/btf/vmlinux`
- Docker Engine and Docker Compose v2
- kernel support for Falco modern eBPF
- permission to access the Docker socket
- outbound HTTPS from the scanner for Trivy databases, FIRST EPSS, and CISA KEV
- `curl`, `python3` with PyYAML, `ruff`, `stat`, and `uname`

The scanner's Docker socket access remains a high-privilege host boundary even though the bind mount is marked read-only.

## Configure

```bash
make init
```

This creates the ignored `.env` with separate random PostgreSQL, internal, and
operator credentials and records the Docker socket group without printing the
credentials. Review its non-secret settings before starting the stack. To
configure manually, copy `.env.example`, replace every placeholder, and obtain
the socket group with `stat -c '%g' /var/run/docker.sock`.

Keep response execution safe-disabled unless running the separate controlled
Phase 7 experiment:

```env
PORYGON_RESPONSE_EXECUTION_MODE=disabled
PORYGON_TRIVY_VERSION=0.72.0
```

## Start

```bash
docker compose config --quiet
docker compose up --detach --build --wait
docker compose ps
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

## Queue a scan

Start a container so the Phase 2 identity layer observes its digest:

```bash
docker pull alpine:3.19
docker run -d --name porygon-scan-target alpine:3.19 sh -c 'while :; do sleep 30; done'
docker image inspect alpine:3.19 --format '{{index .RepoDigests 0}}'
```

Export the operator token and queue the exact digest:

```bash
export PORYGON_OPERATOR_API_TOKEN='the-value-from-.env'

./scripts/porygon_scan.py create \
  --image-digest 'alpine@sha256:...' \
  --requested-by 'researcher-name' \
  --scan-reference 'experiment-001' \
  --note 'Approved static enrichment run'
```

Inspect results:

```bash
./scripts/porygon_scan.py scans --status completed
./scripts/porygon_scan.py scan <SCAN_ID>
./scripts/porygon_scan.py sbom <SCAN_ID> > artifacts/scan-sbom.json
./scripts/porygon_scan.py report <SCAN_ID> > artifacts/scan-trivy-report.json
./scripts/porygon_scan.py findings --image-digest 'alpine@sha256:...'
./scripts/porygon_scan.py intel CVE-2025-12345
```

## Verification gates

Run the aggregate non-disruptive release gate:

```bash
make verify
```

It records static/schema checks, all service unit suites, the cumulative safe
Phase 1–6 live path, and the Phase 8 scanner path in
`artifacts/verification-manifest.json`. The Phase 7 response execution is never
part of this aggregate because it can pause or stop a container.

Individual gates are available when diagnosing failures:

```bash
make verify-static
make verify-unit
make verify-live-safe
make verify-scanner-live
```

Run the disruptive response gate only in an isolated lab after changing the
local, ignored `.env` response mode to `live` and reviewing its target:

```bash
make verify-response-live
```

## Verify Phase 8 directly

```bash
./scripts/verify_phase8.sh | tee artifacts/phase8-verification.txt
```

The live script:

1. validates and starts the cumulative stack
2. checks the Phase 8 claim-boundary policy
3. starts a disposable non-exploit Alpine workload
4. waits for immutable digest registration
5. queues an exact digest/image scan
6. proves identical requests are idempotent
7. renews the worker lease during long scans
8. waits for Trivy, EPSS and KEV enrichment
9. validates preserved raw-report, CycloneDX and database hashes
10. verifies immutable scan-time intelligence snapshots and finding stages
11. proves a new experiment reference creates a new scan identity

The script does not execute an exploit or enable Phase 7 disruptive response actions.

## Packaged validation artifact

```text
Backend tests:    51 passed
Collector tests:   5 passed
Telemetry tests:   5 passed
Responder tests:   5 passed
Scanner tests:     3 passed
Total:            69 passed
```

Also validated:

- Ruff
- Python and CLI compilation
- shell syntax
- Compose and Falco YAML
- TOML
- OpenAPI generation
- Alembic migration SQL through `0008_phase8`

These results came from the retained packaging artifact. They are historical
evidence, not a claim that this checkout's live Docker, Trivy, Falco,
persistence, or response gates have passed. Record local results through the
verification commands above. Phase 5 v1 remains provisional until the
calibrated model and frozen Phase 9 protocol replace its engineering weights.

## Phase 8 documentation

- [`docs/PHASE8_ARCHITECTURE.md`](docs/PHASE8_ARCHITECTURE.md)
- [`docs/VULNERABILITY_EVIDENCE_MODEL_V1.md`](docs/VULNERABILITY_EVIDENCE_MODEL_V1.md)
- [`docs/PHASE8_ACCEPTANCE.md`](docs/PHASE8_ACCEPTANCE.md)
- [`docs/AUDIT_REPORT_PHASES_1_7.md`](docs/AUDIT_REPORT_PHASES_1_7.md)
