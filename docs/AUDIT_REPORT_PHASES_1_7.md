# Cumulative Audit Before Phase 8

The Phase 7 archive was used as the cumulative source tree. Phase 8 was added without removing prior migrations, services, APIs, tests, or acceptance scripts.

## Verified before release

| Service | Tests |
|---|---:|
| Backend | 51 |
| Docker collector | 5 |
| Falco telemetry adapter | 5 |
| Response executor | 5 |
| Image scanner | 3 |
| **Total** | **69** |

The backend total includes all tests for Phases 1–8, including the direct digest-bound scan workflow.

Also verified:

- Ruff across five Python services
- Python compilation
- CLI compilation
- shell syntax
- Compose and Falco YAML parsing
- TOML parsing
- OpenAPI generation
- Alembic SQL rendering from `0001_phase1` through `0008_phase8`

## Regression boundaries retained

- PostgreSQL remains the authoritative persistent store.
- Phase 2 collector outbox and event idempotency are unchanged.
- Phase 3 process telemetry remains separate from Docker lifecycle telemetry.
- Phase 4 profiles remain immutable-digest bound and human-approved.
- Phase 5 anomaly scores still mean distance, not maliciousness.
- Phase 6 incidents still separate anomaly, severity, and confidence.
- Phase 7 disruptive actions remain human-approved and safe-disabled by default.

## New Phase 8 boundaries

- Static package presence is never converted to exploitation proof.
- External intelligence is captured as prioritization context.
- Historical findings carry immutable scan-time intel snapshots.
- The scanner is isolated from the operator credential.
- The scanner adds a new privileged Docker boundary and a new egress boundary; both are explicit.

## Live verification status

The packaging environment does not contain the Docker CLI or daemon. No claim is made that the live Trivy, Docker, Falco, restart, response, or persistence acceptance scripts were executed here.

Run `scripts/verify_phase8.sh` on the target Linux host after configuring `.env`.
