# Phase 2 Acceptance Criteria

Phase 2 is complete only when `./scripts/verify_phase2.sh` passes on the Linux Docker host.

## Required behaviour

1. The collector connects to the local Docker Engine and streams container and network events.
2. Only the collector receives access to the Docker socket. The backend and PostgreSQL services do not mount it.
3. The collector remains a non-root process, drops all Linux capabilities, and uses a read-only root filesystem.
4. Each event receives a deterministic SHA-256 event ID derived from Docker host identity, event type, action, actor, timestamp, scope, and attributes.
5. PostgreSQL enforces event-ID uniqueness, making retries idempotent.
6. The raw Docker event is retained with the normalized record.
7. Container events are enriched with a reduced inspect snapshot that excludes environment variables.
8. Porygon stores the image ID and a matching repository digest from `RepoDigests` when available.
9. Locally built images without a repository digest are marked `unavailable`; Porygon must not fabricate a digest.
10. Container create, start, exec, stop/die, destroy, and network connect/disconnect actions are stored.
11. Events generated while the backend is stopped survive in the collector's persistent SQLite outbox and are delivered after recovery.
12. Replaying an overlap window does not duplicate PostgreSQL rows.
13. Container and image identity tables are updated from observed events.
14. Public read APIs can filter events by type, action, container, host, and digest.
15. Docker action detail is split correctly: `action` remains a bounded category while exec command detail is retained in `command` and the raw event.
16. A full collector spool does not advance the Docker replay cursor past the first event that could not be durably enqueued.

## Verification scenario

The script performs the following controlled test:

1. Starts the Porygon stack.
2. Pulls `alpine:3.20` and records its repository digest.
3. Recreates the collector with a temporary 100-event spool limit.
4. Stops the backend to create an ingestion outage.
5. Creates and starts a uniquely identified, labeled Alpine probe container.
6. Executes 40 uniquely identified commands inside it, forcing more than 100 Docker events.
7. Connects and disconnects a test network.
8. Stops and removes the container.
9. Counts the canary's container and network events independently from Docker's event history.
10. Confirms the outbox reaches exactly 100 rows and the overflow counter increases.
11. Restarts the backend and waits for cursor replay and delivery.
12. Requires the Docker-boundary count to equal the unique PostgreSQL canary count.
13. Restarts the collector and requires zero PostgreSQL row growth after replay.
14. Restores the normal collector spool setting, including on failure.
15. Saves evidence under `artifacts/`.

## Evidence generated

- `artifacts/phase2-capture-integrity.json`
- `artifacts/local/phase2-<run-id>/probe-events.json`
- `artifacts/local/phase2-<run-id>/probe-summary.json`
- `artifacts/local/phase2-<run-id>/images.json`
- `artifacts/local/phase2-<run-id>/containers.json`
- `artifacts/local/phase2-<run-id>/services.txt`
- `artifacts/local/phase2-<run-id>/images.txt`

The capture-integrity document keeps separate counts for Docker API events,
rows retained at saturation, overflow attempts, PostgreSQL insertions, and
row growth after replay. It also names boundaries this gate does not measure.
Detailed host-specific evidence stays under the ignored `artifacts/local/`
tree because raw events and inventory can contain sensitive operational data.

## Explicit limitation

Docker only retains the last 256 daemon events for historical retrieval. The SQLite outbox protects events after the collector has received them, but it cannot recover arbitrary events lost while the collector itself is disconnected long enough for Docker's event history to roll over. This must be treated as a measured limitation in the paper, not described as perfect lossless collection.

This gate measures from Docker's published event API onward. It does not
measure loss inside the Docker daemon before publication, host failure, or any
kernel/Falco boundary.
