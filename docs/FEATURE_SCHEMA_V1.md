# Porygon Behaviour Feature Schema v1

Schema identifier: `porygon.behaviour.v1`

The Phase 4 profile is a deterministic statistical description of an explicitly approved training interval for one immutable repository digest. It is not an attack classifier and it does not assign an anomaly score.

## Identity and training boundary

Every profile records:

- exact repository digest
- UTC training start and end
- fixed window size
- approving researcher and optional approval reference
- counts of selected process events, Docker events, containers, and windows
- SHA-256 hash of the selected event-ID set
- SHA-256 model hash over the complete profile document

Tags and mutable image references are never used as profile identity in the
current v1 implementation. The frozen profile-scope experiment separately
constructs global and mutable-tag comparator arms; that comparison does not
redefine or silently change stored `porygon.behaviour.v1` profiles.

## Categorical distributions

Each map contains relative frequencies whose values sum to 1 when observations exist:

- `process_name`
- `executable`
- `parent_child`
- `user_uid`
- `runtime_action`
- `process_sequence_bigram`

The sequence bigram is built independently per container after ordering process events by timestamp and deterministic event ID. Porygon never creates a sequence edge across two containers.

## Observed sets

The profile stores sorted unique values corresponding to each categorical family. Phase 5 will use these sets to identify previously unseen values without pretending that unseen automatically means malicious.

## Numeric summaries

For every fixed window, Porygon calculates:

- process events per minute
- Docker runtime events per minute
- distinct executable tokens
- root-process ratio
- shell-process ratio

Each feature stores minimum, maximum, mean, median, 95th percentile using nearest rank, and population standard deviation. Empty windows are included because inactivity is part of the approved observation interval.

## Quality report

A draft passes the activation gate only when:

- selected process-event count meets the request's minimum
- nonempty-window count meets the request's minimum
- an immutable repository digest is present

The thresholds are engineering guardrails supplied with the build request. They are not validated scientific constants. Final thresholds must be justified with the project's benign validation experiments.

Plan 004 may introduce a new calibrated model/schema under the frozen research
protocol. It must use independent whole-run fit/calibration assignments and a
new version identifier rather than reinterpreting these v1 fields.

Warnings do not block activation. Version 1 warns when training contains fewer than two containers, no Docker lifecycle events, or no process bigrams.

## Current evidence boundary

Schema v1 uses Docker lifecycle events and Falco process-execution events available through Phase 3. It does not contain file access, socket connection, DNS, or privilege-transition features. Those must only be added after Porygon captures and validates the corresponding telemetry.
