# Phase 6 Architecture: Deterministic Detection and Incidents

## Objective

Phase 6 transforms one immutable Phase 5 score window into a deterministic detection run. It correlates process and Docker evidence, applies exact digest-scoped allowlists, and optionally creates one auditable incident with a chronological evidence timeline.

It does not execute containment.

## Inputs

A detection run accepts one stored `anomaly_score_id`.

The referenced score fixes:

- immutable image digest
- profile ID and version
- observation start and end
- selected evidence hash
- distance algorithm and configuration

The backend then reloads process and Docker events from the same half-open interval.

## Reproducibility identity

```text
run_key = SHA-256(
    anomaly_score_id,
    ruleset_version,
    ruleset_hash,
    allowlist_set_hash
)
```

The active allowlist set contains only unexpired entries for the score's exact image digest. Its hash includes allowlist IDs, matcher hashes, and expiry timestamps.

A ruleset or allowlist change therefore produces a new detection run rather than rewriting historical output.

## Rule evaluation

The v1 path is deterministic and inspectable. It evaluates:

- high behavioural distance as informational context
- unseen shell execution
- novel UID 0 process execution
- unseen dual-use tool execution
- shell-to-tool sequence in one container within 120 seconds
- Docker exec activity as informational context
- privileged container create/start configuration

High distance alone is not incident eligible because Phase 5 thresholds are not validated attack thresholds.

## Allowlist application

An allowlist matcher contains:

```text
exact image digest
exact rule ID
exact executable
optional exact parent executable
```

For a shell-to-tool correlation, suppressing either underlying allowlisted shell or tool event suppresses the derived correlation. The suppressed evidence remains in `detection_runs.result.suppressed_matches` with the approving allowlist ID.

No wildcard digest, wildcard rule, or regular-expression path is accepted in v1.

## Confidence and severity

Severity and confidence are calculated separately.

Severity combines:

- maximum incident-eligible rule impact
- Phase 5 anomaly distance
- bounded corroboration bonus

Confidence combines:

- rule-evidence support
- source-type diversity
- event coverage

Both are bounded to `[0,1]`. Neither is a probability of compromise.

## Incident construction

An incident is created only when at least one unsuppressed incident-eligible rule remains.

The incident records:

- immutable image digest
- source detection run and anomaly score
- anomaly, severity, and confidence values
- full finding documents
- affected container IDs
- first/last evidence timestamps
- lifecycle state and human actor fields

## Evidence timeline

Timeline sequence begins with the immutable Phase 5 score, then includes rule and derived-correlation evidence sorted by:

```text
occurred_at, source_type, source_id
```

Status transitions append evidence documents rather than mutating the original timeline.

## State machine

```text
open -> acknowledged -> resolved
open ----------------> dismissed
acknowledged --------> dismissed
```

Terminal states cannot be reopened through Phase 6.

## Database tables

- `detection_allowlists`
- `detection_runs`
- `incidents`
- `incident_evidence`

PostgreSQL constraints enforce status values, bounded scores, timeline sequence uniqueness, one incident per detection run, and one active identical allowlist matcher.

## Trust boundaries

- detection execution and state changes require the internal token
- read APIs do not receive Docker access
- the scorer and detector only read stored evidence
- allowlists require named human approval metadata
- suppression is visible and hashed into reproducibility identity
- no Docker control action exists in this phase

## Evidence boundary

The current sensor path contains process execution and Docker lifecycle events. It does not contain socket, DNS, or file-open evidence. Phase 6 therefore implements process-based correlation and does not claim outbound-connection detection.
