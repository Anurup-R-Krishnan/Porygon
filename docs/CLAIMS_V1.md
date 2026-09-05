# Porygon Claim Boundaries v1

Status: **review pending**

Protocol: `porygon.research.protocol.v1`

Behaviour profiling is prior art. Falco, eBPF telemetry, immutable image
digests, calibrated rarity methods, deterministic rules, and the compared
statistical components are not Porygon inventions. The proposed contribution
is the falsifiable, reproducible comparison of global, mutable-tag, digest-only,
and digest-plus-context profile scopes under the frozen protocol.

## Claims allowed before confirmatory evaluation

- `CLM-A001`: Porygon is a Docker-first research prototype that records Docker
  lifecycle/exec evidence and Falco process-execution evidence.
- `CLM-A002`: The current implementation can build versioned digest-bound
  profiles, persist explainable distance evidence, apply deterministic rules,
  and retain an auditable incident lifecycle.
- `CLM-A003`: Phase 2 acceptance measured equality from Docker's retained event
  API to PostgreSQL for its bounded canary; Phase 3 measured equality from the
  Falco JSON file to PostgreSQL for its bounded canary. Neither result proves
  zero loss before those measured boundaries.
- `CLM-A004`: Anomaly outputs are rarity/distance evidence and are **not an
  attack probability**. Deterministic matches are evidence, **not proof** of
  compromise. Scanner findings show package matches and are **not proof** of
  exploitation.
- `CLM-A005`: The protocol and comparison are falsifiable because every
  conditional claim below has a failure criterion and versioned output.

These statements describe code and bounded acceptance evidence. They do not
claim detection superiority, calibration, production readiness, or scientific
validation.

## Claims allowed only after named results

Each conditional claim may be used only when every named artifact exists,
passes the protocol validator, and supports the stated direction. Otherwise the
paper must state that the claim was not supported.

| Claim ID | Conditional claim | Required metric IDs | Required Plan 005 output IDs | Failure boundary |
|---|---|---|---|---|
| `CLM-C001` | Digest-plus-context materially reduces benign run-level false-positive rate versus global, mutable-tag, and digest-only scopes. | `MET-FPR-001`, `MET-INSUF-001` | `ART-TBL-001`, `ART-FIG-001`, `ART-MAN-001` | Unsupported unless the frozen paired comparison meets its effect and interval criterion without excessive insufficient profiles. |
| `CLM-C002` | Digest-plus-context preserves controlled-scenario detection while reducing false alarms. | `MET-REC-001`, `MET-FPR-001`, `MET-TFE-001` | `ART-TBL-001`, `ART-FIG-001`, `ART-MAN-001` | Unsupported if recall crosses the frozen non-inferiority margin or timing materially worsens. |
| `CLM-C003` | The calibrated anomaly output has the stated benign coverage on held-out runs. | `MET-CAL-001` | `ART-TBL-003`, `ART-MAN-001` | Unsupported when the simultaneous interval misses the frozen coverage tolerance. |
| `CLM-C004` | Porygon's measured capture path and overhead remain inside the frozen research-host budget. | `MET-LOSS-001`, `MET-OTP-001`, `MET-CPU-001`, `MET-RSS-001`, `MET-DISK-001`, `MET-LAT-001` | `ART-TBL-004`, `ART-MAN-001` | Unsupported if any mandatory loss boundary is absent or a frozen overhead budget is exceeded. |
| `CLM-C005` | The hybrid detector improves the frozen precision/recall trade-off over rules-only and component-only comparators. | `MET-PREC-001`, `MET-REC-001`, `MET-FPR-001` | `ART-TBL-002`, `ART-FIG-001`, `ART-MAN-001` | Unsupported when rules-only or a component-only comparator is equivalent or superior under the frozen comparison. |
| `CLM-C006` | The selected profile method remains usable under the frozen contamination sensitivity test. | `MET-FPR-001`, `MET-REC-001`, `MET-CAL-001` | `ART-TBL-005`, `ART-MAN-001` | Unsupported if labelled fit contamination exceeds the predeclared degradation boundary. |

Precision may be reported only for the disclosed fixed scenario prevalence. It
must not be presented as a deployment prevalence estimate.

## Prohibited claims

- Porygon invented behavioural profiling, eBPF/Falco observation, digest
  identity, conformal or calibrated rarity methods, or deterministic rules.
- A digest fully defines expected runtime behaviour.
- Digest-plus-context is superior before the frozen confirmatory comparison.
- Any anomaly score, rarity value, p-value, severity, or confidence field is an
  attack probability or probability of compromise.
- A deterministic rule match, sequence, shell, root process, or dual-use tool
  is proof that an attack occurred.
- A CVE/package match, EPSS score, KEV membership, process-name match, or open
  port proves reachability, exploitation, or compromise.
- Porygon captures all kernel, Docker, Falco, process, file, DNS, or network
  activity, or has zero event loss.
- The current system observes file access, network flows, socket connections,
  DNS, or dedicated privilege-transition features.
- Results from adjacent/overlapping windows are independent samples.
- Pilot, fit, calibration, failed, excluded, or exploratory runs are
  confirmatory evidence.
- Safe synthetic scenarios are real-malware evaluation or production attack
  detection.
- The single-host study proves multi-host scalability, production readiness,
  prevention efficacy, exploit attribution, or causal security benefit.
- A negative result may be hidden by changing hypotheses, exclusions, profile
  fallback, thresholds, or workload definitions after outcomes are seen.

## Reporting negative results

Negative and null results are publishable outcomes. The paper must explicitly
report when context conditioning does not materially reduce false alarms, when
fragmentation produces too many insufficient profiles, when version drift
breaks calibration, when rules-only matches the hybrid, when capture loss is
unmeasured or excessive, or when overhead exceeds budget. Those outcomes change
the conclusion, not the frozen protocol.

## Revision rule

Any change after freeze requires a new protocol version, timestamp, rationale,
affected question/hypothesis/claim IDs, and an exploratory/confirmatory reset.
The v1 files and artifacts remain immutable and discoverable.
