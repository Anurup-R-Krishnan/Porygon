# Porygon Deterministic Detection Ruleset v1

Ruleset identifier: `porygon.detection.v1`

The API returns the exact rules and a SHA-256 hash at:

```text
GET /api/v1/detection-rules/config
```

## Rules

### POR-DET-001: High behavioural distance

Condition: Phase 5 total score is at least `0.50`.

Purpose: retain the high-distance context in the result and incident timeline.

Incident eligible: **No**. Phase 5 thresholds are provisional.

### POR-DET-002: Previously unseen shell execution

Condition: the executable basename is a known shell and neither the exact executable nor process name exists in the selected digest baseline.

Incident eligible: **Yes**.

Allowlistable: **Yes**, exact digest and executable, optional exact parent executable.

### POR-DET-003: Novel root process

Condition: a process executes with UID 0 while string UID `0` is absent from the baseline observed user set.

Incident eligible: **Yes**.

Allowlistable: **Yes**, exact digest and executable, optional exact parent executable.

### POR-DET-004: Previously unseen dual-use tool

Condition: a downloader, network utility, interpreter, or encoding tool absent from the baseline executes.

Current v1 name set includes:

```text
curl wget nc ncat netcat socat telnet ssh scp
base64 openssl python python3 perl ruby
```

Incident eligible: **Yes**.

Allowlistable: **Yes**, exact digest and executable, optional exact parent executable.

These are dual-use binaries. Their execution is evidence, not proof of an attack.

### POR-DET-005: Shell-to-tool sequence

Condition: an unseen shell is followed by an unseen dual-use tool in the same container within 120 seconds.

Incident eligible: **Yes**.

Directly allowlistable: **No**. An exact approved allowlist for either source event suppresses the derived correlation.

### POR-DET-006: Docker exec activity

Condition: `exec_create`, `exec_start`, or `exec_die` occurs in the score window.

Incident eligible: **No**.

Purpose: distinguish container-control-plane execution from application-start execution.

### POR-DET-007: Privileged container configuration

Condition: a create/start runtime event carries a container snapshot with privileged mode enabled.

Incident eligible: **Yes**.

Allowlistable: **No** in v1. Privileged configuration remains visible and requires incident review.

## Result interpretation

A detection run can have informational findings without an incident. An incident requires at least one unsuppressed incident-eligible rule.

Severity estimates possible impact. Confidence estimates how strongly the available evidence supports the deterministic finding and correlation. Neither is a compromise probability.

## Known limitations

- executable name matching can miss renamed tools
- exact path allowlists can break after image changes, which is intentional because digest changes require reapproval
- process sequences do not prove data transfer or network communication
- 120 seconds is an engineering default pending evaluation
- rule weights are not calibrated probabilities
