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

## Verification scenario

The script performs the following controlled test:

1. Starts the Porygon stack.
2. Pulls `alpine:3.20` and records its repository digest.
3. Stops the backend to create an ingestion outage.
4. Creates and starts a labeled Alpine probe container.
5. Executes a command inside it.
6. Connects and disconnects a test network.
7. Stops and removes the container.
8. Confirms the collector retained events in SQLite.
9. Restarts the backend and waits for delivery.
10. Confirms all required actions have the expected digest and unique event IDs.
11. Restarts the collector and confirms replay does not increase the probe-event count.
12. Saves evidence under `artifacts/`.

## Evidence generated

- `artifacts/phase2-probe-events.json`
- `artifacts/phase2-probe-summary.json`
- `artifacts/phase2-images.json`
- `artifacts/phase2-containers.json`
- `artifacts/phase2-services.txt`
- `artifacts/phase2-images.txt`

## Explicit limitation

Docker only retains the last 256 daemon events for historical retrieval. The SQLite outbox protects events after the collector has received them, but it cannot recover arbitrary events lost while the collector itself is disconnected long enough for Docker's event history to roll over. This must be treated as a measured limitation in the paper, not described as perfect lossless collection.
