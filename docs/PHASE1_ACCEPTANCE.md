# Phase 1 Acceptance Criteria

Phase 1 is complete only when all of the following are true:

1. `docker compose config --quiet` succeeds.
2. PostgreSQL, backend, and collector start with one command.
3. Compose waits for PostgreSQL readiness before starting the backend.
4. The backend migration completes before the API starts.
5. `/health/live` works without querying the database.
6. `/health/ready` returns success only when PostgreSQL is reachable.
7. The collector sends an authenticated heartbeat to the backend.
8. The heartbeat is visible through `/api/v1/services`.
9. The heartbeat's `first_seen_at` survives `docker compose down` followed by `docker compose up`.
10. Backend and collector run as non-root users, drop Linux capabilities, use read-only root filesystems, and do not mount the Docker socket.
11. PostgreSQL is not published to the host.
12. `./scripts/verify_phase1.sh` completes successfully.

## Evidence to save

Run:

```bash
./scripts/verify_phase1.sh | tee artifacts/phase1-verification.txt
docker compose images > artifacts/phase1-images.txt
docker compose ps > artifacts/phase1-services.txt
curl -s http://127.0.0.1:8000/api/v1/system/info > artifacts/phase1-system-info.json
curl -s http://127.0.0.1:8000/api/v1/services > artifacts/phase1-services.json
```

Commit the text and JSON evidence, but do not commit `.env` or database contents.
