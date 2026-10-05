# Porygon

A container runtime security and behavioral anomaly detection system for Docker.

Porygon monitors container execution at the kernel level using modern eBPF (via Falco) and correlates process activity with Docker daemon lifecycle events. It builds per-image behavioral baselines, measures execution drift using Jensen-Shannon distance, enforces deterministic detection rules, and supports automated or human-approved container containment.

---

## Features

- **Kernel-Level Telemetry**: Captures process execution events (`execve`/`execveat`) in real time using modern eBPF probes.
- **Digest-Bound Baselines**: Profiles expected process behavior bound to cryptographic image digests (`sha256:...`) rather than mutable image tags.
- **Behavioral Anomaly Scoring**: Calculates runtime drift using Jensen-Shannon divergence to identify unexpected processes and abnormal tool usage.
- **Rule Engine & AI Auditor**: Detects shell escapes, privilege escalation, unknown binaries, and suspicious executions, supplemented by automated incident summaries.
- **Automated / Approved Containment**: Quarantines compromised containers (pause or stop) with configurable human-in-the-loop approval workflows.
- **Vulnerability & SBOM Context**: Scans images with Trivy and enriches findings with EPSS exploit probabilities and CISA KEV exploitation data.
- **Interactive Web Dashboard**: Clean UI for live telemetry streaming, behavioral score visualization, incident review, and response actions.

---

## Services

| Service | Role | Port |
| :--- | :--- | :--- |
| **`backend`** | Core API, scoring engine, detection logic, and incident management | `8000` (via gateway) |
| **`collector`** | Streams Docker daemon lifecycle events (create, start, exec, die) | Internal |
| **`telemetry`** | Ingests and spools kernel process events from Falco | Internal |
| **`responder`** | Executes container containment actions (pause / stop) | Internal |
| **`scanner`** | Runs Trivy vulnerability scans and retrieves EPSS/KEV metadata | Internal |
| **`falco`** | Modern eBPF sensor monitoring system calls | Internal |
| **`postgres`** | Stores events, baselines, incidents, and audit trails | `5432` (Internal) |
| **`gateway`** | Nginx reverse proxy routing external API traffic | `8000` |
| **`dashboard`** | Lightweight web server hosting the dashboard UI | `3000` |

---

## Prerequisites

- **OS**: Linux with eBPF support (kernel 5.8+ recommended)
- **Docker Engine**: 24.0+ with Docker Compose v2
- **Python**: 3.11+
- Appropriate permissions to access `/var/run/docker.sock` and load eBPF probes

---

## Quickstart

### 1. Initialize Configuration
Generate local secrets, database credentials, and Docker socket permissions:
```bash
make init
```

### 2. Start Services
Build and start the container stack:
```bash
make up
```

### 3. Launch the Dashboard
Start the dashboard server:
```bash
python3 scripts/serve_dashboard.py
```

Open **`http://localhost:3000`** in your browser. The backend API is available at **`http://localhost:8000`**.

---

## Useful Commands

```bash
make up          # Build and start all services in the background
make down        # Stop all running services
make logs        # Stream aggregated logs across all containers
make ps          # Check service health status
make test        # Run unit tests
make reset       # Stop services and remove volumes (clean database)
```

---

## Configuration

All configuration is controlled via `.env` (created from `.env.example` during `make init`).

Key settings:
- `PORYGON_RESPONSE_EXECUTION_MODE`: Set to `disabled`, `observe_only`, or `live` (for active containment).
- `PORYGON_LOG_LEVEL`: Logging verbosity (`DEBUG`, `INFO`, `WARNING`).
- `PORYGON_OPERATOR_API_TOKEN`: Secret token used for operator actions in the dashboard and API.
