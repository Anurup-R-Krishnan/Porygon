# Phase 5 Architecture: Explainable Behavioural Distance

## Goal

Phase 5 compares a completed runtime observation window with a versioned behaviour profile for the same immutable image digest. It stores a reproducible distance record and evidence explanation without claiming that the observation is malicious.

## Data flow

```text
POST /internal/v1/anomaly-scores/compute
                │
                ▼
      validate digest and profile
                │
                ▼
 derive fixed window from profile duration
                │
                ├── reject unfinished window
                ├── reject training overlap
                └── enforce event-count limit
                │
                ▼
 query resolved process events + Docker events
                │
                ▼
 rebuild porygon.behaviour.v1 observation document
                │
                ├── insufficient process evidence
                │          └── persist insufficient_data
                │
                ▼
  calculate categorical distance, novelty,
             and numeric deviation
                │
                ▼
   fuse scores with versioned fixed weights
                │
                ▼
 persist score, components, explanation,
 manifest, config, and observation key
```

## Profile selection

When `profile_id` is omitted, Porygon selects the active profile for the requested digest.

When `profile_id` is supplied, Porygon permits:

- an active quality-passing profile
- a retired quality-passing profile

Retired profiles remain scoreable so historical experiments can be reproduced after a newer profile becomes active.

Porygon rejects:

- profile/digest mismatch
- draft profiles
- quality-failing profiles

## Observation boundaries

The client supplies only `window_start`. The server derives:

```text
window_end = window_start + profile.window_seconds
```

This prevents clients from changing the statistical unit used by a profile.

A window must be complete at request time. It must not overlap the profile's training interval. This keeps training and evaluation evidence separate.

## Evidence extraction

Process events are restricted to:

- exact image digest
- resolved container correlation
- `occurred_at >= window_start`
- `occurred_at < window_end`

Docker runtime events use the same digest and half-open time interval.

Events are ordered deterministically by timestamp and event ID before feature generation.

The existing Phase 4 vectorizer is reused for observations. This guarantees that baseline and observation documents have the same feature semantics and schema identifier.

## Evidence sufficiency

The synchronous path counts events before loading them.

If total selected events exceed `PORYGON_ANOMALY_MAX_EVENTS`, the API returns HTTP 413.

If selected process events are below `PORYGON_ANOMALY_MIN_PROCESS_EVENTS`, Porygon persists:

```text
status      = insufficient_data
score_band  = insufficient_data
total_score = null
```

Docker lifecycle events alone are not treated as enough evidence to score process behaviour.

## Scoring components

### Categorical distance

Base-2 Jensen-Shannon distance is calculated for available categorical distributions.

### Novelty

Porygon calculates the observed mass of tokens not present in the baseline support and records those tokens explicitly.

### Numeric deviation

Observation means are compared with baseline medians using a protected scale derived from baseline spread and configured floors.

### Fusion

The v1 top-level weights are:

```text
categorical distance  0.50
novelty              0.30
numeric deviation    0.20
```

Missing families or components are excluded and remaining weights are renormalized.

## Persistence model

Table: `anomaly_scores`

Important columns:

- `score_id`
- `observation_key`
- `profile_id`
- `image_digest`
- `profile_version`
- `profile_model_hash`
- `algorithm_version`
- `status`
- `score_band`
- `total_score`
- `window_start`, `window_end`, `window_seconds`
- evidence counts
- `components`
- `explanation`
- `observation_manifest`
- `scoring_config`
- `created_at`

Database constraints enforce valid status values, valid bands, positive window length, bounded scores, and unique observation keys.

## Concurrency and idempotency

Before insertion, the backend obtains a PostgreSQL transaction advisory lock derived from the observation key. It then checks for an existing record.

The unique database constraint remains the final protection against races. If a concurrent request wins, the losing request reloads and returns the existing record.

## Trust and security boundaries

- The compute endpoint requires the internal service token.
- Read endpoints expose score evidence but do not execute actions.
- The scorer does not receive Docker socket access.
- Event and window limits reduce synchronous memory exhaustion risk.
- Raw secrets are not part of the Phase 4/5 feature schema.
- A score cannot trigger containment in this phase.

## Research boundaries

Phase 5 does not provide:

- validated thresholds
- attack classification
- confidence probability
- severity
- incident correlation
- automated response

Those concepts must remain separate in later phases.
