# Phase 7 Architecture: Human-Approved Response

## Objective

Phase 7 converts an explainable Phase 6 incident into a controlled response workflow. It does not allow a model, rule, collector, or executor to independently choose and execute arbitrary Docker operations.

## Components

### Backend control plane

The backend owns:

- deterministic recommendation generation
- operator authentication boundary
- approval freshness checks
- allowed-action enforcement
- execution queue and leases
- response state transitions
- audit records
- retry and rollback authorization

The backend does not mount the Docker socket.

### Responder service

The responder owns the minimum Docker-control surface needed for Phase 7:

- inspect exact container
- pause
- unpause
- stop
- start
- verify immediate state

It cannot generate or approve recommendations because it does not receive the operator token.

### PostgreSQL

Phase 7 adds:

- `response_recommendations`
- `response_executions`
- `response_audit_events`

The API exposes no update or delete operation for audit events. Database administrators remain outside this application-level immutability boundary.

## Credential separation

| Credential | Held by | Permitted purpose |
|---|---|---|
| Internal token | backend services, responder | event delivery, work claiming and completion |
| Operator token | backend and human research terminal | generate, approve, reject, rollback and retry response decisions |

A service credential is rejected at operator endpoints even if the caller provides it in the operator header.

## Safe-disabled queue

`PORYGON_RESPONSE_EXECUTION_MODE=disabled` is the default.

The backend still records approvals, but the claim query excludes disruptive pending actions. This supports review and demonstration without silently modifying Docker state. `observe_only` remains executable because it is a no-op. Rollback work is not discarded if the mode changes after a previous live action.

## Recommendation construction

The recommendation key hashes:

```text
incident ID
exact target container ID
policy version
policy hash
```

One recommendation is generated per exact incident container target. Incidents without a target can only receive `observe_only`.

## Approval constraints

An approval is accepted only when:

- the operator token is valid
- the incident is open or acknowledged
- the recommendation was not rejected
- the action appears in the recommendation's recorded allowed set
- a disruptive action has an exact target
- the operator acknowledges disruption
- the recommendation is younger than the configured freshness limit

Repeating the exact approval returns the original execution.

## Execution queue

The responder claims one row using a PostgreSQL row lock with `SKIP LOCKED`. Each claim has a lease. An abandoned claim is returned to its prior queue state after lease expiry.

Execution idempotency is implemented both in storage and at the Docker-operation layer:

- one execution per recommendation
- deterministic execution key
- pausing an already paused container is a successful no-change result
- stopping an already stopped container is a successful no-change result
- unpausing an unpaused container is a successful no-change result
- starting a running container is a successful no-change result

## Exact target protection

The executor resolves the supplied ID through Docker and compares the returned full ID with the requested ID. Prefixes and names are rejected.

Containers labelled:

```text
com.porygon.protected=true
```

are refused. Every service in Porygon's own Compose stack carries this label.

## Verification

The responder records a reduced pre-state and immediate post-state, including:

- exact container ID
- name
- running, paused, restarting and dead flags
- OOM and exit-code state
- restart policy
- labels

Success requires the expected immediate state:

- pause: `paused=true`
- unpause: `paused=false` and `running=true`
- stop: `running=false`
- compensating start: `running=true`

This is point-in-time verification, not a guarantee against later external changes.

## Rollback semantics

`pause_container` has a genuine inverse operation: unpause.

`stop_container` has only a compensating operation: start. It does not restore lost in-memory state, open connections, or transactional context. Operators must explicitly acknowledge this limitation before requesting it.

## Retry semantics

Retries are manual and limited to transient failures:

- `docker_unavailable`
- `docker_api_error`
- `executor_internal_error`

Protected targets, missing targets, invalid requests, and missing containers are not retried under the same recommendation.
