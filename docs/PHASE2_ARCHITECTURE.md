# Phase 2 Architecture

## Data path

```text
Docker Engine
    │  /events + container/image inspect
    ▼
Porygon collector
    ├── normalize event
    ├── resolve Docker daemon ID
    ├── inspect container and image
    ├── select matching RepoDigest
    ├── compute deterministic event ID
    └── commit to persistent SQLite outbox
             │
             │ authenticated event batches
             ▼
FastAPI backend
    ├── ON CONFLICT DO NOTHING for runtime event
    ├── upsert container identity
    ├── upsert image identity
    └── commit PostgreSQL transaction
             │
             ▼
Read APIs and future Phase 3 correlation
```

## Reliability model

The collector uses **at-least-once HTTP delivery**. A batch may be retried when the backend response is lost or the backend is unavailable. PostgreSQL's unique `event_id` constraint converts those retries into **exactly-once stored rows for events the collector received**.

This is intentionally narrower than claiming globally lossless collection. Docker's historical event buffer is finite, so a sufficiently long collector outage can still cause source-side loss.

## Deterministic event identity

The event ID is SHA-256 over canonical JSON containing:

- Docker daemon ID
- event type
- action
- scope
- actor ID
- nanosecond timestamp
- sorted actor attributes

The raw event is not used wholesale because open-schema additions in newer Docker API versions should not silently change identity for the same semantic event.

## Immutable image identity

Porygon records three separate values:

- `image_ref`: the mutable tag or reference configured for the container
- `image_id`: Docker's local content-addressed image ID
- `image_digest`: a repository digest such as `alpine@sha256:...`

The collector chooses a digest whose repository matches the configured image reference. If none match, it uses a deterministic sorted fallback. When `RepoDigests` is empty, `image_digest` stays null and `image_digest_status` becomes `unavailable`.

## Snapshot policy

The reduced container snapshot stores only fields required for later behavioural and security analysis:

- container name and state
- command, entrypoint, user, working directory, and labels
- privileged mode, read-only root filesystem, namespaces, capabilities, security options, and devices
- mounts
- network endpoints
- image metadata

Environment variables are deliberately excluded because they frequently contain passwords, API tokens, and other secrets.

## Trust boundary

The collector's Docker socket access is operationally equivalent to high privilege over the host Docker daemon. The Compose file limits that access to the collector, but a compromised collector could still invoke write-capable Engine API endpoints. The `:ro` bind flag protects the socket file itself from filesystem writes; it does not make Docker API methods read-only.

A later hardening option is a narrowly allowlisted Engine API proxy that permits only ping, info, events, container inspect/list, and image inspect. It is not introduced in Phase 2 because it would add another privileged component that must itself be implemented and tested.
