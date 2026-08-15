# Phase 4 Acceptance Criteria

Phase 4 is accepted only when `./scripts/verify_phase4.sh` succeeds on the Linux Docker host.

## Required behaviour

1. The complete Phase 3 process-telemetry acceptance test still passes.
2. Alembic creates `behavior_profiles` without modifying source runtime events.
3. A profile build requires an immutable `repository@sha256:...` digest and timezone-aware interval.
4. Training uses only resolved process events and Docker events matching that exact digest and interval.
5. The profile contains schema version, categorical distributions, observed sets, numeric summaries, quality report, and training manifest.
6. The selected-event hash and model hash are deterministic.
7. An identical rebuild is rejected.
8. New profiles begin as drafts.
9. A quality-passing draft can be activated.
10. A quality-failing draft cannot be activated.
11. Activating a newer profile retires the former active profile.
12. PostgreSQL contains at most one active profile for each digest.
13. A retired profile cannot be reactivated.
14. Public read APIs expose profile versions and the active profile without exposing the internal write token.
15. No anomaly or attack verdict is generated in this phase.

## Evidence to retain

- `artifacts/phase4-profile-v1.json`
- `artifacts/phase4-profile-v2.json`
- `artifacts/phase4-profiles.json`
- `artifacts/phase4-active-profile.json`
- `artifacts/phase4-system-info.json`
- `artifacts/phase4-verification.txt`

These are experimental artefacts, not performance results.
