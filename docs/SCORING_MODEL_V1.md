# Porygon Behavioural-Distance Model v1

## 1. Scope

Algorithm identifier:

```text
porygon.distance.v1
```

Feature-schema identifier:

```text
porygon.behaviour.v1
```

The model compares one completed observation window with one versioned behaviour profile bound to an immutable repository digest. It produces a bounded distance and an explanation document. It does not classify an observation as malicious.

## 2. Input constraints

A score request contains:

- exact `repository@sha256:...` identity
- observation `window_start`
- optional explicit profile UUID

The API derives `window_end` from the profile's fixed `window_seconds`.

The request is rejected when:

- no active profile exists and no explicit profile is supplied
- the explicit profile belongs to another digest
- the explicit profile is a draft or failed its quality gate
- the window has not completed
- the window overlaps the profile's training interval
- the event count exceeds `PORYGON_ANOMALY_MAX_EVENTS`

If process-execution evidence is below `PORYGON_ANOMALY_MIN_PROCESS_EVENTS`, Porygon persists an `insufficient_data` result with no numeric score.

## 3. Categorical distance

For each categorical feature family, Porygon calculates the base-2 Jensen-Shannon distance.

Given normalized baseline distribution `P`, observation distribution `Q`, and midpoint:

```text
M = 0.5(P + Q)
```

Jensen-Shannon divergence:

```text
JSD(P, Q) = 0.5 KL(P || M) + 0.5 KL(Q || M)
```

Porygon uses the distance form:

```text
D_JS(P, Q) = sqrt(JSD(P, Q))
```

With base-2 logarithms, the result is bounded in `[0, 1]`.

Feature-family weights:

| Family | Weight |
|---|---:|
| Process name | 0.15 |
| Executable path | 0.25 |
| Parent-child edge | 0.20 |
| User UID | 0.10 |
| Docker runtime action | 0.10 |
| Process sequence bigram | 0.20 |

The weighted categorical component is:

```text
D_cat = Σ effective_weight_i × D_JS(P_i, Q_i)
```

An empty observation family is treated as unavailable, not as maximally anomalous. Available family weights are renormalized to sum to one.

## 4. Novelty component

For each categorical family, novelty is the observed probability mass assigned to tokens absent from the baseline support.

```text
N_i = Σ Q_i(x), for x not in support(P_i)
```

The family novelty scores use the same categorical weights:

```text
N = Σ effective_weight_i × N_i
```

This separates a distribution shift among known tokens from genuinely unseen behaviour.

Examples of novelty evidence include:

- unseen executable path
- unseen parent-child edge
- unseen user ID
- unseen runtime action
- unseen process sequence bigram

Novelty is not automatically malicious. Software upgrades, maintenance commands, or previously unobserved benign paths can produce novelty.

## 5. Numeric deviation

Numeric families:

| Feature | Weight | Minimum scale floor |
|---|---:|---:|
| Process events per minute | 0.25 | 1.00 |
| Runtime events per minute | 0.10 | 1.00 |
| Distinct processes per window | 0.25 | 1.00 |
| Root-process ratio | 0.20 | 0.05 |
| Shell-process ratio | 0.20 | 0.05 |

For each feature, the observation mean is compared with the baseline median.

A robust scale estimate is derived from the baseline median and p95:

```text
robust_sigma = |p95 - median| / 1.6448536269514722
```

The effective scale prevents division by zero and excessive sensitivity in nearly constant baselines:

```text
scale = max(
    baseline_stddev,
    robust_sigma,
    |baseline_median| × 0.10,
    feature_scale_floor
)
```

Absolute standardized deviation:

```text
z = |observation_mean - baseline_median| / scale
```

The v1 deviation score ignores differences below two effective standard deviations and saturates at six:

```text
D_num_i = clamp((z - 2) / (6 - 2), 0, 1)
```

The numeric component is:

```text
D_num = Σ effective_weight_i × D_num_i
```

These constants are versioned engineering choices. They are not claimed to be statistically optimal.

## 6. Score fusion

Top-level weights:

| Component | Weight |
|---|---:|
| Categorical distance | 0.50 |
| Novelty | 0.30 |
| Numeric deviation | 0.20 |

Final score:

```text
S = 0.50 D_cat + 0.30 N + 0.20 D_num
```

If a complete component is unavailable, remaining top-level weights are renormalized. Porygon never silently substitutes a missing component with zero.

The result is rounded deterministically and bounded in `[0, 1]`.

## 7. Provisional score bands

| Range | Label |
|---|---|
| `0.00 ≤ S < 0.25` | `baseline_like` |
| `0.25 ≤ S < 0.50` | `elevated` |
| `0.50 ≤ S < 0.75` | `high` |
| `0.75 ≤ S ≤ 1.00` | `extreme` |

These labels are UI and experiment-grouping aids only. They are not validated attack thresholds and must not be used to report precision or recall before evaluation.

## 8. Explanation output

Every scored record includes:

- total score and band
- component scores
- effective renormalized weights
- per-family Jensen-Shannon distances
- observed and baseline support sizes
- unseen tokens and observed proportions
- per-feature numeric z values and effective scales
- top weighted contributors
- immutable profile version and model hash
- selected-event-set SHA-256
- complete scoring configuration

## 9. Reproducibility and idempotency

The observation key hashes:

- profile UUID
- profile model hash
- window start and end
- selected-event-set SHA-256
- complete scoring configuration

An exact retry returns the existing record. If late-arriving telemetry changes the selected evidence set, it produces a different observation key and therefore a distinct score record. This behavior preserves evidence history rather than silently mutating an earlier result.

## 10. Known limitations

- Weight values are not learned from data.
- Bands are not selected from a validation set yet.
- p95-based scale estimation can be coarse for small baseline window counts.
- Correlated feature families can count related behaviour more than once.
- Process execution and Docker lifecycle evidence cannot describe file or socket activity.
- Novel but benign software updates may produce high distance.
- Baseline poisoning remains possible if the approved training interval is not actually benign.
- No supervised maliciousness probability is produced.

These limitations must be included in the paper and addressed through Phase 9 experiments and ablation studies.
