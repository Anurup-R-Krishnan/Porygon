# Porygon Calibrated Rarity Model v2

Status: **exploratory implementation — not the default API path**

Algorithm identifier: `porygon.rarity.v2`
Component registry: `porygon.rarity.components.v1`
Protocol dependency: `porygon.research.protocol.v1` (review pending)

This document defines the deterministic evidence primitives for the v2 model.
It does not authorize pilot or confirmatory collection, and it does not replace
the version 1 records or scoring semantics. Until the research protocol is
independently reviewed and the provenance/API layers are complete, v2 remains
an offline, testable implementation.

## Components

The fixed registry is:

1. `categorical_shift`
2. `sequence_surprisal`
3. `novelty_mass`
4. `numeric_tail`

Each component is independently eligible or missing. Missing evidence is
reported explicitly; it is never converted to zero evidence. The final
exploratory fusion is an unweighted arithmetic mean of eligible component
rarities. There are no feature, family, severity, or confidence weights.

## Categorical shift

For baseline distribution `p` and observed distribution `q`, both are
normalised over the union of their support and scored with the Hellinger
distance:

`H(p,q) = sqrt(0.5 * sum_i (sqrt(p_i) - sqrt(q_i))^2)`

The result is bounded to `[0, 1]`, symmetric, and zero for identical
distributions. Empty observations are unavailable evidence. A non-empty
observation with no baseline support returns maximum distance and must be
explained as missing/unsupported fit coverage by the caller.

## Sequence surprisal

Within-container transitions are evaluated independently; transitions are never
formed across container boundaries. For source `s`, target `t`, baseline count
`c(s,t)`, row total `C(s)`, support size `K`, and fixed smoothing `alpha=1`:

`P(t|s) = (c(s,t) + alpha) / (C(s) + alpha*K)`

The sequence component is the mean `-log2(P(t|s))` over observed transitions.
Unseen transitions are retained as evidence. Empty observations are unavailable
evidence. Smoothing is a deterministic likelihood convention, not a tuned
attack threshold.

## Novelty mass

Observed categorical values are normalised, then the proportions whose tokens
are absent from the baseline support are summed:

`novelty_mass = sum_{i notin baseline_support} q_i`

The response includes each unseen token and its proportion. Novelty is kept
separate from distribution shift so a caller can distinguish new support from
redistribution among known values.

## Numeric and count tails

For a test statistic `x` and held-out benign calibration values
`x_1 ... x_n`, the finite-sample inclusive upper-tail p-value is:

`p = (1 + count(x_i >= x)) / (n + 1)`

The reported rarity is `1 - p`. Ties use `>=`, and the minimum p-value is
`1/(n+1)`. No z-score tolerance, saturation constant, or pilot-selected cutoff
is used. Empty calibration is `insufficient_data`.

The eventual confirmatory statistic is defined per complete run/block by the
frozen protocol. Window-level ranks may be displayed as descriptive diagnostics
but must not be presented as run-level coverage evidence.

## Fusion and interpretation

Eligible component rarities are averaged in registry order-independent fashion.
The output records the component registry version, eligible components, and
missing components. If none are eligible, the result is `insufficient_data`.

These outputs are behavioural rarity/evidence values. They are not probabilities
of attack, compromise, intent, or causality. A deterministic rule match and a
high rarity value remain separate evidence; neither alone creates an incident
or authorises a response. Response authority belongs to the versioned response
policy and requires explicit evidence, target binding, and human approval.

## Provenance requirements for the next layer

Before v2 can be used for any study result, the implementation must bind every
fit and calibration artifact to the protocol ID, profile scope/context, sorted
whole-run IDs, algorithm version, component registry version, canonical hashes,
and an immutable held-out run-block calibration artifact. Fit, calibration, and
test runs must be disjoint. Drift, unsupported strata, telemetry gaps, and
insufficient calibration must remain visible in the output.
