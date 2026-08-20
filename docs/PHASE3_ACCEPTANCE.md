# Phase 3 Acceptance Criteria

Phase 3 is accepted only when `./scripts/verify_phase3.sh` completes successfully on the target Linux host.

## Host prerequisites

- Docker Engine and Docker Compose v2 are available.
- The host is Linux.
- `/sys/kernel/btf/vmlinux` is readable for the modern eBPF engine.
- The configured Docker socket exists.
- `DOCKER_GID` matches the group owning that socket.
- `.env` contains non-placeholder secrets.

## Required checks

1. `docker compose config --quiet` succeeds.
2. PostgreSQL, backend, Docker collector, telemetry adapter, and Falco start.
3. Falco remains running with the modern eBPF configuration.
4. Backend readiness succeeds.
5. Collector and telemetry adapter run as non-root users.
6. Backend and telemetry adapter do not mount the Docker socket.
7. A controlled Alpine probe is registered with its full container ID and immutable repository digest.
8. A controlled `sh → sh → sleep` execution produces process records containing PID and PPID data.
9. At least one observed child event links to the corresponding stored parent event through `parent_event_id`.
10. Probe process events resolve to the full container ID and immutable image digest.
11. Events written while the telemetry adapter is stopped are replayed from the persistent Falco JSON file.
12. Events normalized while the backend is stopped remain in the telemetry SQLite outbox and are delivered after recovery.
13. Restarting the telemetry adapter does not create duplicate PostgreSQL process events.
14. No malformed Falco JSON records are produced during the controlled acceptance run.
15. Verification evidence is written under `artifacts/`.
16. Telemetry readiness rejects a stopped source, missing Falco file, stale backend heartbeat, and unrecoverable source error while allowing a healthy idle source.
17. Malformed-record diagnostics are redacted, bounded by count/bytes/age, and reported separately from canonical process evidence.
18. Probe records counted in the Falco JSON file equal unique probe rows in PostgreSQL after recovery and replay.

## Expected evidence

The script writes:

- `artifacts/phase3-capture-integrity.json`
- `artifacts/local/phase3-<run-id>/process-events.json`
- `artifacts/local/phase3-<run-id>/process-summary.json`
- `artifacts/local/phase3-<run-id>/system-info.json`
- `artifacts/local/phase3-<run-id>/falco.log`
- `artifacts/local/phase3-<run-id>/services.txt`
- `artifacts/local/phase3-<run-id>/telemetry-status.json`

Capture the console output separately:

```bash
mkdir -p artifacts/local
./scripts/verify_phase3.sh | tee artifacts/local/phase3-verification.txt
```

## Non-acceptance conditions

Phase 3 is not accepted when:

- Falco starts only by using `privileged: true` without documenting the expanded trust boundary;
- process rows lack PID or PPID information;
- shortened Falco container IDs are stored as though they were verified full IDs;
- image tags are treated as immutable identities;
- events disappear during the tested adapter or backend outages;
- replay inserts duplicate event IDs;
- a process parent is claimed without a stored matching parent execution;
- file access, network activity, anomaly detection, or attack detection is claimed without implementing and evaluating it.

## Measurement boundary

The capture-integrity artifact separately records Falco-file probe records,
telemetry outbox rows observed during backend outage, PostgreSQL probe rows,
replay row growth, dead letters, and adapter overflow attempts. Kernel-to-eBPF
loss and Falco userspace drops remain explicitly unmeasured until Falco metrics
are sampled by the Phase 5 experiment harness. Equality from the Falco file to
PostgreSQL must not be described as proof of zero kernel loss.

Detailed Falco and process artifacts remain local and ignored because they can
contain command lines and host-specific identifiers. The minimized integrity
summary is the versioned paper input.
