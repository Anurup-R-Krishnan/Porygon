# Porygon design decisions

Why each major component exists, why the alternatives were rejected, and what
the system cannot do. Every claim here points at the code or document that
backs it, so a reviewer can check rather than trust.

---

## 1. Why image digest as artifact identity?

A Docker **tag is mutable**. `nginx:1.26-alpine` can be repointed to different
bytes tomorrow while every reference in a deployment stays textually identical.
A profile keyed on a tag can therefore be silently applied to a different
program than the one it was fitted on.

A **digest is content-addressed**: `nginx@sha256:1eadbb07…` names exactly one
manifest. Profiles keyed on the digest cannot be transferred to different bytes
by an upstream push.

Implementation: `docs/FEATURE_SCHEMA_V1.md:5-19` binds profiles to an exact
repository digest and explicitly rejects mutable tags as identity. The
experiment runner refuses any reference lacking `@sha256:`
(`experiments/real.py::pull_pinned_image`).

**Rejected**: keying profiles on container name, image name, or tag. All three
are operator-chosen strings with no relationship to the executed bytes.

---

## 2. Why is the digest alone not sufficient?

The digest fixes the *program*. It does not fix the *deployment*. Two
containers from one digest can behave differently because of entrypoint and
command arguments, the configured user, capabilities, privileged and
read-only-rootfs flags, mounts, devices, network mode, published ports,
workload role, and lifecycle stage.

If those differences move the behavioural distribution, a digest-only profile
mixes several behavioural populations into one baseline. That inflates variance,
which raises the false-alarm rate on benign runs and simultaneously hides real
deviations inside a baseline that is too wide.

**This is the project's research question, not its assumption.** The protocol
explicitly refuses to assert that digest-plus-context wins
(`plans/README.md:50`: treating the digest as complete behavioural identity is
"rejected as a claim"). Four arms are compared — global, mutable tag,
digest-only, digest-plus-context — and a negative result is a valid outcome
(`docs/RESEARCH_PROTOCOL_V1.md`, hypotheses `H_0_001`/`H_1_001`).

---

## 3. Why this particular runtime context?

The fingerprint (`docs/PROFILE_SCOPE_EXPERIMENT_V1.md:62-130`, implemented in
`experiments/context.py`) contains only configuration **known before the
workload runs**. That matters: a fingerprint built from runtime output would be
contaminated by the very behaviour it is supposed to condition.

It **excludes** environment values and names, literal argument values,
host-specific mount sources, container IDs and names, image tags, timestamps,
labels, restart counts, PIDs, and every mutable counter. Command arguments are
reduced to a *shape* — executable basename, flag names, and argument classes —
so a secret passed on a command line becomes `flag:<secret> <secret-value>` and
never reaches an artifact.

Two properties are tested directly against the specification's own worked
examples (`experiments/tests/test_context.py`):

- semantically equal documents in different order produce **one** hash;
- changing one security-relevant field produces a **different** hash.

**Trade-off**: more context fields mean finer strata and therefore fewer runs
per stratum. Excessive fragmentation produces `insufficient_profile` results,
which the protocol requires to stay in the denominator rather than being quietly
dropped. Fragmentation is a measured cost of the approach, not a bug to hide.

**Why only *some* fields belong in the identity.** Ephemeral deployment details
must be normalised out or the identity fragments without bound. Network mode is
reduced to its security class (`host` / `none` / `bridge` / `container` /
`user-defined`) rather than the literal network name: an experiment run creates
its own network, so the literal name would give the same deployment a different
identity in every run and no stratum would ever reach its minimum fit count.
Capability names are likewise normalised across Docker's `CAP_` spelling. Both
were found by running the same real deployment twice and comparing — not by
reading the specification.

**A measured caution.** In the first real pilot, `--cap-drop NET_RAW` and
`--tmpfs /scratch` produced three distinct context identities per family but
**byte-identical process-execution behaviour** (nginx 46/46/46 events, Redis
33/33/33, PostgreSQL 166/166/166, identical `(process, executable)` multisets).
Context that does not change *what executes* fragments the population for
nothing under an execve-only feature set. The frozen variant list should favour
changes that alter execution — entrypoint/command shape, configured user, or a
configuration that changes the startup path.

---

## 4. Why these features, and only these?

v1 evidence is limited to Docker lifecycle events and process execution
(`docs/FEATURE_SCHEMA_V1.md:62-64`). The Falco rule captures `execve` and
`execveat` inside containers and nothing else (`falco/porygon_rules.yaml`).

That is a deliberate, narrow, defensible scope. Process execution is the
highest-signal, lowest-volume evidence class for container behaviour: a
container's process table is small and stable, so novel executables and novel
parent/child edges are meaningful. File, socket, and DNS telemetry would
multiply event volume and storage, and would each need their own normalization,
redaction, and calibration.

**Consequence, stated plainly**: any claim about file access, network
destinations, or privilege transitions is out of scope for v1. Adding such a
family changes the feature-schema version and requires fresh fit and
calibration artifacts.

---

## 5. Why the scoring design, and why no arbitrary weights?

The v1 model (`backend/src/porygon_api/scoring.py`) combines Jensen–Shannon
distance and novelty with hand-selected constants — `0.50` categorical, `0.30`
novelty, `0.20` numeric — plus family weights, z-score tolerances, and
saturation constants. Those numbers are reproducible but **not empirically
justified**: nobody can say why 0.50 rather than 0.45. A composite built from
unjustified weights cannot support a scientific claim, and its output is not on
any meaningful scale.

v1 is preserved read-only for compatibility. The current model is
`calibrated_rarity.py`:

| Evidence | Method |
|---|---|
| Categorical shift | Hellinger distance over the union support |
| Sequence | first-order Markov negative-log surprisal, Laplace smoothing α = 1.0 |
| Novelty | explicit unseen observed mass, kept separate from distribution shift |
| Count/numeric | empirical two-sided tail ranks from held-out benign observations |

Fusion is an **unweighted mean of eligible component rarities** over a fixed
four-component registry, and `fuse_component_ranks` accepts no weight argument
at all — the API makes reintroducing a tuned composite impossible by
construction. Missing components are recorded explicitly; when none is
available the result is `insufficient_data`, not a fabricated score.

**Trade-off**: an unweighted mean is certainly not optimal. It is *defensible*,
which matters more here. Learning weights would require labelled attack data,
and fitting on labelled attacks is exactly the leakage the protocol forbids.

---

## 6. Why calibration, and why run-level splits?

A raw distance is uninterpretable — is 0.31 large? Calibration answers that
against held-out benign behaviour.

`run_calibration.py` computes one predeclared block statistic per held-out
benign run (maximum window nonconformity), then a split-conformal p-value:

```text
p = (1 + count(calibration_stat >= test_stat)) / (n_calibration_runs + 1)
rarity = 1 - p
```

The minimum p-value is `1/(n+1)`, so a claim is bounded by the calibration
sample size and cannot be inflated by a small one.

Splits are **by complete run**. Adjacent windows inside one run are strongly
autocorrelated — the same container, the same processes, seconds apart. Treating
them as independent samples inflates the effective sample size and produces
confidence intervals that are far too narrow. `check_split_isolation`
(`experiments/artifacts.py`) fails if any run appears in more than one split,
and a test asserts that this leakage is detected rather than tolerated.

**Assumption, stated**: conformal validity holds under run exchangeability. If
the workload drifts between calibration and test, coverage degrades. That is a
named failure mode in the protocol, not a hidden caveat.

---

## 7. Why anomaly is not maliciousness

Porygon measures **rarity relative to a fitted baseline**. It does not measure
intent.

- Anomalous but benign: maintenance shells, backups, config reloads, debugging,
  log rotation, a legitimate traffic spike. These are collected deliberately as
  *hard negatives* and remain in the false-positive denominator.
- Malicious but not anomalous: living-off-the-land activity using binaries the
  baseline already contains, or low-and-slow behaviour below the window
  threshold.

The two concepts are kept in separate fields: calibrated rarity, deterministic
rule evidence, categorical policy impact, and evidence completeness never
collapse into one number. `docs/CLAIMS_V1.md` lists "rarity is an attack
probability" as a prohibited claim, and no output is ever labelled a
probability of compromise.

---

## 8. Why Falco rather than a custom eBPF sensor or Tetragon?

Falco 0.44.1 with the modern-eBPF driver provides kernel-level syscall capture,
a maintained CO-RE probe, a validated rule language (`falco --validate` runs in
`make verify-static`), and a stable JSONL output contract.

**Rejected — a custom eBPF sensor**: it would consume most of the project's
engineering budget, add a large privileged attack surface, and produce the same
evidence class. `plans/README.md:49` records this rejection explicitly.

**Rejected — Tetragon**: it is a credible alternative that delivers the same
evidence class, but switching sensors now would invalidate every existing test,
acceptance artifact, and capture-integrity measurement for no research gain.
Tetragon remains noted as a future Kubernetes option
(`docs/FINAL_PHASES.md:237`).

**Trade-off**: Falco's userspace drop behaviour under extreme load is not fully
observable from outside, so kernel-to-eBPF loss stays `unmeasured` rather than
being claimed as zero.

---

## 9. Why a Python collector and a Python control plane?

The collector's job is I/O-bound: read the Docker socket, resolve digests,
normalize, deduplicate, and buffer durably. It is not CPU-bound, so a compiled
language buys little. One language across collector, telemetry, responder,
scanner, and backend keeps one normalization implementation, one test toolchain,
and one review surface for a small team.

**Rejected — rewriting the control plane in Java or Go**: `plans/README.md:47`
records this as adding migration risk without improving the research question,
data quality, calibration, or evidence.

Durability does not depend on the language: each sensor owns a bounded SQLite
outbox, and Plan 002 proved the cursor never advances past an event whose
durable enqueue failed.

**Trade-off**: per-event SQLite transactions are a known throughput ceiling.
Batching is deliberately deferred until the experiment harness measures it —
optimizing before measuring is how projects tune the wrong thing.

---

## 10. Why human-approved response only?

Automatic containment on a statistical signal is a denial-of-service vector
against yourself: a benign maintenance window that scores as anomalous could
pause a production container.

Default is `observe_only`. A disruptive action requires an explicitly
allowlisted rule, adequate evidence quality, an exact target binding,
non-stale evidence, and human approval. `PORYGON_RESPONSE_EXECUTION_MODE` stays
`disabled` outside one explicitly disruptive gate that is never part of
`make verify`.

**Rejected**: unlocking pause/stop from a composite score threshold. A number
built from unjustified weights must not gate a destructive action.

---

## 11. What can the detector miss?

- Anything that is not a process execution — file writes, network destinations,
  privilege transitions (§4).
- Living-off-the-land behaviour using binaries already in the baseline.
- Low-and-slow activity spread below the window threshold.
- Behaviour that was present during fitting — including a **poisoned baseline**.
  This is why `SCN-POISON` is a separate labelled experimental arm applied only
  to *copied* fit sets, never to primary artifacts.
- Anything occurring while telemetry is degraded (§12).
- Any container whose context has too few fitted runs: the answer is
  `insufficient_profile`, not a borrowed profile.

---

## 12. What happens when telemetry is lost?

The system must never mistake missing evidence for normal behaviour.

- Sensors keep bounded durable outboxes and do not advance a cursor past a
  failed enqueue (Plan 002).
- Readiness requires a running source, an available Falco file, and a fresh
  backend heartbeat — not merely a live process.
- Malformed lines become bounded, hashed, redacted dead-letter excerpts, never
  silently discarded raw content.
- Evidence completeness is a first-class categorical field
  (`insufficient` / `partial` / `corroborated`) driven by measured source
  availability, so a score computed on degraded telemetry is reported as
  degraded.
- The experiment harness records every boundary it cannot observe as
  `unmeasured` **with a reason**. Zero is never inferred.

---

## 13. Main trade-offs, summarised

| Decision | Gain | Cost |
|---|---|---|
| Process execution only | High signal, low volume, tractable calibration | Blind to file, network, and privilege evidence |
| Digest-plus-context identity | Homogeneous baselines | Fragmentation and `insufficient_profile` results |
| Unweighted rank fusion | No unjustifiable tuned constants | Almost certainly suboptimal accuracy |
| Run-level splits | Honest intervals | Far more runs needed for the same power |
| Conformal calibration | Interpretable, finite-sample bound | Valid only under run exchangeability |
| Human-approved response | No self-inflicted outage | Slower containment |
| Single-host Docker scope | Reproducible, auditable | No cluster-scale evidence |
| Python everywhere | One toolchain, one normalizer | SQLite per-event write ceiling |

---

## 14. Decisions considered and rejected

Recorded in `plans/README.md:45-51` and preserved here so the reasoning is not
re-litigated: rewriting the control plane in Java; adding Redis in v1; custom
eBPF; Kubernetes; LLM-generated summaries; automatic response; treating the
image digest as complete behavioural identity; and reporting anomaly outputs as
attack probabilities.
