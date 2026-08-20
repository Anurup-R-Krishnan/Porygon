# Phase 3 Architecture: eBPF Process Telemetry

## Objective

Phase 3 adds process-execution visibility that Docker Engine lifecycle events cannot provide. It records container process executions, preserves Falco evidence, reconstructs parent-child links where the parent was also observed executing, and correlates each process event with the full Docker container identity and immutable repository digest learned in Phase 2.

This phase does **not** perform anomaly scoring, attack classification, file-access monitoring, or network-connection monitoring.

## Components

```text
Linux kernel
    │ modern eBPF syscall telemetry
    ▼
Falco sensor
    │ unbuffered JSON lines
    ▼
porygon_falco_events volume
    │ durable inode + byte cursor
    ▼
Telemetry adapter
    │ normalize → deterministic ID → SQLite outbox
    ▼
Authenticated batch API
    ▼
FastAPI backend
    │ short container-ID resolution + digest enrichment + parent lookup
    ▼
PostgreSQL process_exec_events
```

### Falco sensor

Falco runs as a dedicated trusted sensor with the modern eBPF engine. The custom rule records `execve` and `execveat` activity for container workloads only. It emits JSON to a persistent named volume.

Captured fields include:

- event timestamp, nanosecond timestamp, event number, and event type
- Falco-reported container ID, container name, image repository, and tag
- process PID, PPID, virtual PID, name, executable path, command line, working directory, and terminal
- parent process name, executable, and command line
- user and group IDs and names
- Falco rule metadata, output fields, tags, and complete raw JSON event

Environment variables are intentionally not requested or persisted.

### Telemetry adapter

The adapter is separate from the privileged Falco sensor. It:

1. tails the Falco JSONL file;
2. tracks the file inode and committed byte offset in SQLite;
3. rejects oversized or malformed records into a dead-letter table;
4. ignores events not produced by the Porygon rule;
5. normalizes valid process executions;
6. creates a deterministic SHA-256 event ID;
7. stores normalized events in a durable SQLite outbox;
8. delivers batches to the backend using the internal API token;
9. retries failed deliveries with bounded exponential backoff.

The byte cursor advances only after a line is normalized, ignored deliberately, or recorded as malformed. An outbox insert occurs before the cursor advances, so adapter restarts do not lose accepted events. Deterministic identifiers and the PostgreSQL primary key make replay idempotent.

Malformed lines are retained only as bounded diagnostics. Each dead letter
stores its source inode/offset, timestamp, original byte length and SHA-256,
error class/message, and a short redacted excerpt. Full raw lines are cleared
during schema upgrade and are never written by the current schema. Count,
total excerpt bytes, and retention age are enforced transactionally; durable
inserted/evicted/retained counters are exposed in telemetry status. Dead
letters are not canonical experiment evidence.

### Backend correlation

Falco generally reports a shortened container ID. The backend resolves it against Phase 2 `container_identities` using an exact or prefix match.

Correlation results are explicit:

- `resolved`: exactly one container identity matched;
- `unresolved`: no identity matched;
- `ambiguous`: more than one identity matched.

For a resolved event, the backend adds:

- full container ID;
- Docker host ID;
- current container name;
- image ID;
- mutable image reference;
- immutable repository digest.

No digest is invented when Phase 2 has not resolved one.

### Parent-child linkage

For each process event with a positive PPID, the backend searches earlier process-execution records from the same resolved container and Docker host for the newest event whose PID equals that PPID. When found, its deterministic ID becomes `parent_event_id`.

This produces evidence links between observed executions. It is not a complete lifetime process tree: a parent that started before Falco/Porygon began observing, or a parent that never generated a captured execution event, cannot be linked.

## Data model

The `process_exec_events` table stores normalized columns for querying and preserves both `output_fields` and the complete `raw_event` for reproducibility.

Important indexes cover:

- occurrence time;
- container plus nanosecond time;
- reported container ID;
- image digest;
- process name;
- Docker host plus PID plus time;
- parent event ID;
- correlation status.

## Trust boundaries

### Privileged components

- **Falco sensor:** receives `BPF`, `PERFMON`, `SYS_RESOURCE`, and `SYS_PTRACE`, host `/proc`, host `/etc`, and Docker socket metadata access.
- **Docker collector:** retains Docker socket access from Phase 2.

Either component must be treated as part of Porygon's trusted computing base.

### Unprivileged components

- backend;
- telemetry adapter;
- PostgreSQL network client path.
- credential-free loopback gateway.

The backend and telemetry adapter have no Docker socket mount. The telemetry adapter runs non-root, drops all Linux capabilities, uses a read-only root filesystem, and reads the Falco event volume read-only.

A networkless one-shot initializer gives the Falco event volume its fixed
owner/group and mode before either Falco or telemetry starts. It receives only
the `CHOWN` capability, mounts only that volume, and exits before capture begins.

A `:ro` Docker socket mount does not make Docker API access read-only. Host compromise risk remains if the Falco sensor or Docker collector is compromised.

## Reliability boundaries

Phase 3 protects events at two stages:

1. Falco JSON output persists while the telemetry adapter is unavailable.
2. The adapter's SQLite outbox persists normalized events while the backend is unavailable.

The implementation does not claim lossless kernel-to-userspace capture under every load condition. Falco/eBPF drops, storage exhaustion, host failure, log rotation outside the expected inode workflow, and deletion of Docker identity records remain measurable failure modes for later evaluation.

The Phase 3 acceptance gate therefore compares only the records already
published in Falco's JSON file with the unique process rows stored in
PostgreSQL. Kernel and Falco drop metrics are named as unmeasured boundaries;
they are not inferred from downstream count equality.
