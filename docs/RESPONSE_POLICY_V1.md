# Porygon Response Policy v1

Policy identifier: `porygon.response.v1`

## Principle

Porygon recommends the least disruptive action allowed by the recorded evidence policy, while preserving a human's ability to select a less disruptive allowed action. It never executes before explicit approval.

## Action set

### `observe_only`

Records the decision without changing Docker state.

### `pause_container`

Suspends all processes in the exact target container.

Allowed when:

```text
severity >= 0.70
confidence >= 0.55
exact target exists
```

### `stop_container`

Requests a graceful Docker stop using the configured timeout.

Allowed when:

```text
severity >= 0.90
confidence >= 0.75
exact target exists
strong evidence includes POR-DET-005 or POR-DET-007
```

`POR-DET-005` is a correlated unseen shell-to-tool sequence. `POR-DET-007` is privileged-container configuration evidence.

## Policy interpretation

- anomaly distance is not proof of compromise
- deterministic findings are evidence, not proof of intent
- severity estimates possible impact
- confidence estimates evidence support
- neither score is a compromise probability
- business ownership and availability impact must be reviewed by a human

## Disallowed Phase 7 operations

- delete container
- delete image
- delete volume
- kill with an arbitrary signal
- execute a command inside a target
- modify files
- alter host firewall rules
- disconnect arbitrary networks
- perform a response against a container name or short ID
- modify a Porygon-protected container
