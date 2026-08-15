# Phase 6 Acceptance Criteria

Phase 6 is accepted only when all static checks and the target-host live script pass.

## Static and unit acceptance

- all backend, Docker collector, and telemetry tests pass
- Ruff passes for all Python services
- all Python modules compile
- all shell scripts pass `bash -n`
- Compose, Falco, and project TOML/YAML parse
- OpenAPI exposes every Phase 6 route
- Alembic renders `0001_phase1` through `0006_phase6`
- migration SQL contains the active-allowlist partial unique index and score/ruleset/allowlist uniqueness

## Detection acceptance

- insufficient score evidence produces no incident
- baseline-like evidence produces no incident
- high distance alone remains informational
- unseen process evidence produces deterministic rule matches
- shell-to-tool evidence is correlated within one container and the configured fixed rule window
- anomaly, severity, and confidence remain separately stored
- exact rerun with unchanged rules and allowlists returns the original run

## Allowlist acceptance

- an allowlist requires an existing digest profile, exact digest, exact rule, exact executable, approver, and reason
- expired allowlists are excluded from detection runs
- changing the active allowlist set changes the run key
- matching process findings are moved to `suppressed_matches`
- nonmatching executable evidence remains active
- suppression of a source shell/tool suppresses only the derived correlation containing that source event
- allowlist deactivation is persisted with actor and timestamp

## Incident acceptance

- one detection run creates at most one incident
- timeline sequence numbers are contiguous and unique
- evidence is chronologically ordered
- open incidents can be acknowledged, resolved, or dismissed
- acknowledged incidents can be resolved or dismissed
- terminal incidents reject reopening with HTTP 409
- status changes append timeline evidence

## Cumulative live command

```bash
./scripts/verify_phase6.sh | tee artifacts/phase6-verification.txt
```

Expected final line:

```text
Phase 6 verification complete. Incident severity and confidence are evidence-oriented research signals, not compromise probabilities.
```

## Environment limitation

The live script requires Docker Engine, Compose v2, a compatible Linux eBPF environment, and Falco access. It cannot be replaced by unit tests because actual host process capture, Docker event delivery, digest resolution, outage replay, and persistent restart behaviour are integration properties.
