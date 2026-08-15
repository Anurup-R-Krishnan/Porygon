# Phase 7 Acceptance Criteria

Phase 7 is complete only when both static/unit checks and the live Linux-host acceptance test pass.

## Static and unit criteria

- all Phase 1–6 tests continue to pass
- responder unit tests cover pause, stop, rollback, idempotency, full-ID enforcement and protected-target refusal
- operator and internal credentials are distinct configuration fields
- disruptive execution defaults to disabled
- OpenAPI contains the Phase 7 read, operator and internal worker routes
- Alembic renders migrations `0001` through `0007`
- Ruff, Python compilation, shell parsing, YAML parsing and TOML parsing pass

## Live criteria

`./scripts/verify_phase7.sh` must prove:

1. Phases 1–6 remain operational.
2. An internal service token cannot authorize an operator endpoint.
3. A disposable target is resolved to an immutable repository digest.
4. Controlled process evidence creates an incident for the exact live container.
5. A recommendation is created without changing Docker state.
6. Pause is in the recorded allowed-action set.
7. No response happens before explicit approval.
8. The separate operator credential approves the exact target and action.
9. The responder records successful immediate post-action verification.
10. Repeated identical approval returns the same execution.
11. Rollback unpauses the exact target and verifies it is running.
12. The response audit sequence is chronological and complete.
13. System counters expose response recommendations and executions.

## Required operator action

The live test refuses to run unless:

```env
PORYGON_RESPONSE_EXECUTION_MODE=live
```

The operator must restore `disabled` after the test.

## Non-claims

Passing Phase 7 does not prove:

- that pause or stop is safe for every production workload
- that the incident was malicious
- that a stopped application's state was restored by start
- that point-in-time verification persists indefinitely
- that the shared operator token provides enterprise identity assurance
