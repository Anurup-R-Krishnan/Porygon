# Phase 4 Architecture: Digest-Bound Behaviour Profiles

## Objective

Phase 4 converts explicitly approved Phase 2 and Phase 3 observations into versioned normal-behaviour profiles for one immutable Docker repository digest.

It deliberately does not calculate anomaly scores, classify attacks, update profiles continuously, or learn from unapproved production traffic.

## Data path

```text
approved UTC interval + immutable repository digest
                         │
                         ▼
                profile build API
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
resolved process_exec_events       runtime_events
          │                             │
          └──────────────┬──────────────┘
                         ▼
              deterministic vectorizer
              ├─ categorical frequencies
              ├─ observed-value sets
              ├─ per-window numeric summaries
              ├─ process sequence bigrams
              ├─ quality checks
              └─ reproducibility manifest
                         │
                         ▼
              draft behavior_profile
                         │ explicit activation
                         ▼
             one active profile per digest
```

## Poisoning control

Porygon does not automatically add new runtime data to an active profile. A researcher must specify the exact digest, time interval, approval identity, and quality thresholds. This is a foundational defence against baseline poisoning, but it does not prove the selected interval is benign. Experimental procedure must establish that separately.

## Version and lifecycle rules

- New profiles begin as `draft`.
- A quality-failing draft cannot be activated.
- Activation retires the previous active profile for that digest in the same database transaction.
- A retired profile cannot be reactivated.
- PostgreSQL enforces one active profile per digest with a partial unique index.
- PostgreSQL advisory transaction locks serialize version creation and activation for the same digest.
- Rebuilding an identical profile is rejected using its deterministic model hash.

## Reproducibility

The training manifest records selection criteria, counts, container identities, event-time boundaries, and a SHA-256 hash over sorted event IDs. The model hash covers the digest, feature document, quality report, and manifest. This detects accidental changes to the training selection or vectorizer output.

The manifest hash does not replace retaining the source events and experiment log.

## Feature limitations

Phase 4 v1 represents only evidence Porygon currently captures reliably:

- Docker lifecycle actions
- process names and executable paths
- parent-child process edges
- user IDs
- within-container process bigrams
- event rates and shell/root ratios

File, network, DNS, and privilege-transition features are excluded until corresponding telemetry is implemented and verified.
