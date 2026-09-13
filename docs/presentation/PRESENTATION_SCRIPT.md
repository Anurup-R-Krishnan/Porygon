# Porygon — Presentation Script (25 minutes)

**23CSE498 Project Phase 2, Panel Review 1 — Team 75**

Pace: ~150 wpm (rehearsed delivery). Times cumulative. Weighting is deliberately front-loaded onto the
architecture (Slide 7) and algorithm (Slide 9).

| Presenter | Slides | Window |
|---|---|---|
| Person 2 | Motivation + 1–6 | 0:00 – 6:14 |
| Anurup | 7–11 | 6:14 – 13:14 |
| Person 3 | 12–20 | 13:14 – 19:30 |
| Person 4 | 21–33 | 19:30 – 25:25 |

---

## MOTIVATION (Title slide) — 3:05 *(3:05)*

> At 02:47 a payment service starts returning 502s. The on-call engineer does
> what any of us would do — `docker exec` into the running container to look at
> it. They are authorised: membership in the host `docker` group, which is
> root-equivalent by design.
>
> The image is `nginx:1.26.3-alpine` — minimal, no diagnostic tooling. They run
> `busybox wget` to pull a static binary, which lands in the container's writable
> overlay layer, and start a listener inside its network namespace to test whether
> a downstream service is reachable. They find the bug, get paged elsewhere, and
> the listener stays up.
>
> Nothing in that is malicious. Now count the controls it just passed.
>
> RBAC evaluated one thing: the `exec` API call. A binary allow-or-deny at request
> time, with no model of the `execve` calls that follow. Authorised, allowed.
>
> The image scanner operates on the OCI manifest at build time. That binary
> arrived afterwards, into the ephemeral upper overlay layer — no digest, not part
> of the image, nonexistent when the scan ran. The manifest digest still scans
> clean.
>
> Network policy matches at layer three and four: egress from an approved workload
> to a routable CIDR is indistinguishable from the service's own traffic. And
> signature matching requires prior knowledge of the artifact — a stripped or
> renamed binary has no matching hash.
>
> Four controls, all passing, and not because anyone misconfigured them. Each
> evaluates identity, provenance, or connectivity. None evaluates what the
> container is actually executing.
>
> Now hold that scene and change one variable — the credentials belong to a
> contractor, phished last week. All four controls return exactly the same
> verdict, because the evidence they consume is identical in both cases.
>
> So we stop trying to classify the actor, and measure the deviation instead.
> And the deviation is enumerable — four feature families move at once.
>
> The **executable** support set for this digest is small and stable: the nginx
> master, its workers, and the shell the entrypoint uses at startup. `wget` is
> not a member, and neither is a listener.
>
> The **parent-child edge** distribution contains `nginx → nginx`. It does not
> contain `containerd-shim-runc-v2 → busybox` — because a process the container
> spawns itself is parented by PID 1 or one of its descendants, whereas an
> exec-injected process is parented by the shim. That edge is the structural
> signature of `docker exec` itself.
>
> The **sequence bigram** for that pair has never been observed, and the
> **root-process ratio** for the window departs from its trained distribution.
>
> Each is a count against a distribution measured before the event — not a rule
> written in advance about what `wget` means. On our own runs, deviations of this
> class score between 0.264 and 0.567 against a per-digest baseline.
>
> Porygon asks one question: has this image digest previously exhibited this
> behaviour? Team 75.

## SLIDE 1 — Container, Image, Digest — 0:49 *(3:54)*

> Three definitions the rest of the talk depends on.
>
> A container is a Linux process constrained by two kernel mechanisms:
> namespaces, which virtualise its view of PIDs, mounts and network interfaces,
> and cgroups, which bound CPU and memory. It shares the host kernel, which is
> why one eBPF probe observes every container on the host simultaneously.
>
> An image is an immutable set of content-addressed filesystem layers plus a
> configuration document. Containers instantiate it; the image itself never
> mutates.
>
> A digest is the SHA-256 hash of the manifest — content-addressed, so identical
> bytes yield an identical digest deterministically. A tag is a mutable reference
> and can be repointed at different content. The digest is the immutable
> identity, and the baseline design rests on that distinction.

## SLIDE 2 — Image to Running Container — 0:24 *(4:18)*

> Layers compose the image. Two references resolve to it: a tag, dashed because
> it is mutable, and a digest, solid because it is not.
>
> We bind every baseline to the digest. Binding to a tag would let a re-published
> manifest silently replace the software under a stable name, leaving us scoring
> current behaviour against a profile trained on different code.

## SLIDE 3 — Introduction — 0:23 *(4:42)*

> Four stages. Containers emit `execve` and lifecycle events continuously — no
> application instrumentation, since the kernel and the Docker engine are the
> sources. Porygon trains a per-digest profile, compares live windows against it
> by Jensen-Shannon distance, and attaches structural evidence via a
> deterministic rule engine.
>
> The objective: an image-specific runtime framework that quantifies behavioural
> deviation and emits explainable findings.

## SLIDE 4 — Problem Statement — 0:40 *(5:23)*

> A shared baseline across heterogeneous images produces false positives.
>
> Pool telemetry from several images into one reference distribution. A workload
> whose steady state is a language runtime contributes probability mass that is
> rare in a pool dominated by static web servers. Its most characteristic
> behaviour registers as high divergence — arithmetically correct, operationally
> wrong.
>
> The correction is not a better estimator. It is correct conditioning: score
> each digest against a profile trained on that digest alone. And "that digest"
> must mean the manifest hash, for the mutability reason on Slide 2.
>
> Four pillars follow: baseline scoping, JSD scoring, rule-based evidence,
> controlled evaluation.

## SLIDE 5 — Literature Review — 0:23 *(5:46)*

> Three families in the prior work: classical supervised learning over syscall
> traces — Castanhel, El Khairi; deep and LLM-based scoring — eBPF-Guard, Li,
> DeepContainer; and distributional divergence measures — Bouke, our own family.
>
> All three converge on the same omission: none treats the conditioning of the
> reference distribution as an experimental variable. That is the gap this work
> occupies.

## SLIDE 6 — Related Work in Detail — 0:27 *(6:14)*

> The right-hand column is the operative one. Four of the six report a single
> point estimate of accuracy — no interval estimate, no hypothesis test. Bouke
> applies the same divergence family, but to network flow features rather than
> container process events.
>
> Stated precisely: none of the six controls baseline granularity — pooled, tag,
> digest, digest-and-configuration — as an independent variable under an analysis
> plan fixed prior to data collection.

>>> HANDOFF to Anurup

## SLIDE 7 — System Architecture — 2:08 *(8:22)*

> This is the full data path, and I want to walk it end to end because several of
> the design decisions are load-bearing.
>
> **Phase one, kernel capture.** Falco attaches an eBPF probe and emits one JSONL
> record per `execve` in a monitored container, carrying `proc.exepath`,
> `proc.name`, `proc.pname`, `proc.pexepath`, `proc.cmdline`, `user.uid` and
> `container.id`.
>
> But Falco's container plugin exposes only image repository and tag — it does
> **not** emit the manifest digest. That is precisely why there is a second
> capture service. The collector reads the Docker socket read-only and
> establishes container identity from the engine, including the authoritative
> repo digest. The backend then resolves each process event's digest by joining
> on `container.id` against that identity record, and records an explicit
> `image_digest_status` field. If identity has not been resolved, the event is
> marked unresolved rather than silently attributed to a digest.
>
> That matters because every downstream guarantee is digest-scoped. An event we
> cannot attribute to a manifest hash must not contaminate a profile.
>
> **Phase two, normalisation.** The telemetry adapter parses the Falco stream
> into a uniform schema and writes to a durable on-disk outbox before
> transmission. Delivery to the backend is an authenticated POST on the internal
> network. The outbox means backend restart or backpressure delays ingestion
> rather than dropping it.
>
> **Phase three, behavioural analysis.** The backend is the only component with a
> database connection. It aggregates events into fixed windows, builds versioned
> per-digest profiles, and computes the distance. Every score is persisted with
> the profile version and algorithm version that produced it, so any result is
> reconstructable.
>
> **Phase four, detection and response.** The same window is evaluated
> independently against the deterministic ruleset; matches become findings, and
> incident-eligible matches open incidents surfaced through the gateway.
>
> And the path along the bottom is the containment loop. The responder holds the
> only other Docker socket handle in the system, and it executes nothing without
> an explicit human approval. The loop is closed deliberately, not automatically.

## SLIDE 8 — Services and Network Segregation — 0:42 *(9:04)*

> The same eight components, single responsibility each, and the property I want
> to draw out is the sole-writer rule: the backend is the only process with a
> database connection, which makes consistency one component's invariant rather
> than a distributed coordination problem.
>
> Three networks. Ingress terminates at the gateway. Internal carries inter-service traffic and
> is not routable from outside. Egress is scanner-only outbound, because the
> scanner is the only component requiring external feed access.
>
> These are compose-level topology constraints asserted by our static
> verification gate, not conventions in code. A compromised component is bounded
> by what it can reach at layer three, independent of application logic.

## SLIDE 9 — Algorithm — 1:53 *(10:58)*

> Eight stages, and the constraints on each one are where the correctness lives.
>
> **One, collect.** Every `execve` and every lifecycle transition, continuously.
> Not sampled — a single execution can constitute the entire deviation, so
> probabilistic sampling would make detection probabilistic.
>
> **Two, identify.** Each event is attributed to an exact manifest digest via the
> identity join described on Slide 7. Unattributed events are excluded, not
> guessed.
>
> **Three, build baseline.** A profile is admitted only after passing a quality
> gate: at least three non-empty sixty-second windows and at least twenty process
> events. The window requirement is the important half — twenty events inside a
> single burst describes one moment, not a steady state. The profile is versioned
> and hashed on admission.
>
> **Four, window.** Live events are aggregated into fixed sixty-second windows,
> and a window is scoreable only once it has elapsed. Scoring a partially
> populated window would systematically underestimate event rates, because the
> denominator is fixed while the numerator is still accumulating. The API rejects
> premature scoring explicitly.
>
> **Five, compute distance.** The observed window distribution Q is compared
> against the profile distribution P for that same digest, per feature family.
>
> **Six, aggregate.** The categorical distance, a novelty term, and a numeric
> deviation term combine into a single bounded score.
>
> **Seven, apply rules.** The same window is evaluated against the deterministic
> ruleset. This runs *independently* — the rule engine does not consume the score
> and the score does not consume rule matches. Two evidence paths over identical
> input, which is what allows one to catch what the other structurally cannot.
>
> **Eight, emit.** Score, band, and every matched rule are returned as one
> object. There is no code path that yields a bare scalar without its supporting
> evidence.

## SLIDE 10 — Jensen-Shannon Distance — 1:21 *(12:19)*

> On currency: NeurIPS 2023 extends this divergence family into representation
> space, and a 2026 paper applies it to intrusion detection. To be exact — we
> implement the classical discrete form; the recent work establishes the family is
> active, not that we adopted their method.
>
> P is the profile distribution, Q the observed window. Rather than compare them
> directly, both are compared against their mixture M, the pointwise average.
>
> That construction is not stylistic. Kullback-Leibler requires absolute
> continuity — it diverges when Q assigns zero mass where P has support. Here a
> previously unseen executable is *by definition* a zero-mass point, so the
> unbounded case is our common case. The mixture has support wherever either
> operand does, so the quantity stays finite.
>
> Lin defined this divergence in 1991; unlike KL it is symmetric. But it is not a
> metric — it violates the triangle inequality. Endres and Schindelin proved in
> 2003 that its square root satisfies the metric axioms, which is why the square
> root is in the expression.
>
> And under base-2 logarithms the codomain is exactly the unit interval: zero iff
> P equals Q, one at disjoint support. That boundedness is what makes a single
> fixed threshold commensurable across every image we monitor.

## SLIDE 11 — Scoring Mathematics — 0:54 *(13:14)*

> The distance is one of three terms. The production aggregate is 0.50 times the
> mean categorical distance over six families, plus 0.30 times a novelty term,
> plus 0.20 times the mean numeric deviation over five features.
>
> The numeric term is z-score based, tolerance 2.0 and saturation 6.0: deviation
> under two standard deviations contributes nothing, and the response clamps at
> six so one outlier cannot dominate. Scale floors prevent division by a near-zero
> standard deviation.
>
> On the weighted sum: each term is independently normalised to the unit interval
> first — the distance by construction, the others by clamped scaling. Given
> commensurable components, a convex combination with weights summing to one is
> the standard composite construction: bounded aggregate, each coefficient
> interpretable as that term's maximum contribution. The weights are fixed in
> source and were not fitted to this dataset.

>>> HANDOFF to Person 3

## SLIDE 12 — Running Live *(flash)* — 0:06 *(13:20)*

> That aggregate evaluating on the live system — three unseen tokens for the
> dropper window.

## SLIDE 13 — Data and Reconciliation — 0:42 *(14:03)*

> No public corpus conditions on baseline granularity, so the dataset is
> generated: three digest-pinned images — nginx, redis, postgres.
>
> Three images, three scenarios, two configurations, twelve replicas: 216
> completed trials, 2,160 operations, zero failed.
>
> Then reconciliation. We inject 1,296 canary sequences — known actions with known
> timing — and trace them across three boundaries: 1,289 observed at the sensor,
> 1,289 persisted, zero duplicates, seven unobserved.
>
> We report the seven. An unmeasured loss rate is an unquantified confound;
> publishing it is the difference between asserting the pipeline works and
> demonstrating it.
>
> Nineteen benign trials construct reference profiles; 149 are scored — 53 benign
> and 96 with ground truth.

## SLIDE 14 — Raw Event to Analysis Feature — 0:38 *(14:41)*

> The projection from kernel event to feature space.
>
> From each record: executable path, parent executable, process name, UID,
> runtime action, and container-image identity. These form six categorical
> distributions, weighted — executable 0.25, parent-child edge and sequence
> bigram 0.20 each, process name 0.15, UID and runtime action 0.10.
>
> The edge and bigram families are the discriminative ones, encoding relational
> and sequential structure rather than set membership. An unseen executable is one
> signal; an unseen executable parented by the service entrypoint and followed by
> a second is a strictly stronger one, and only the relational families represent
> that.

## SLIDE 15 — Declaring a Container Abnormal — 0:44 *(15:26)*

> Two independent conditions.
>
> The statistical condition is band membership: baseline-like below 0.25, then
> elevated, high, extreme. The marker at 0.273 is a measured value from the live
> dropper run.
>
> The structural condition is rule matching on process structure.
>
> Escalation is two-tier. A finding requires one match; an incident requires an
> incident-*eligible* match. Rules 001 and 006 are excluded by design — 001 is
> the score restating itself with no structural content, 006 is routine
> operational exec traffic. Either opening incidents unilaterally would make the
> alert stream unusable.
>
> The score quantifies magnitude of deviation. The rules identify structure.
> Neither is a posterior probability of compromise, and we do not present it as
> one.

## SLIDE 16 — Threshold Selection — 1:08 *(16:35)*

> The order of events determines whether this slide is evidence or circularity.
> 0.25 was fixed in the initial commit as a quartile boundary of the unit interval
> and has not changed — a pre-committed parameter, not a fitted one.
>
> At 0.25, against the pilot 216-trial dataset, we measure zero false positives
> across 53 benign trials and complete recall across 96 ground-truthed trials.
> That is the only threshold with a committed analysis artifact behind it. An
> earlier draft of this deck reported a full sweep from 0.10 to 0.50; those
> additional rows had no backing artifact and cannot currently be regenerated
> without a live backend and the original database state, so they have been
> removed rather than re-asserted without evidence.
>
> The dominant row is not the threshold. Even at 0.25, the pooled arm
> misclassifies all 53 benign trials. No threshold value rescues a misconditioned
> baseline.

## SLIDE 17 — Threshold Sweep, Plotted — 0:09 *(16:44)*

> The illustrative sweep shape: recall complete through 0.25 then decaying
> stepwise; false-positive rate non-zero only below 0.25, reaching zero exactly
> where recall is still complete. The two curves never cross — recall stays
> above the false-positive rate throughout. Only the 0.25 point is backed by a
> committed artifact; the rest of the curve is illustrative, not independently
> reproducible from the current repository state.

## SLIDE 18 — Seven Deterministic Rules — 0:56 *(17:41)*

> Deterministic in the strict sense: no model, no stochasticity, reproducible
> from the event log by hand.
>
> 001, distance at or above 0.50, not incident-eligible. 002, a shell absent from
> the digest baseline. 003, a UID 0 execution where UID 0 is absent from the
> baseline — both clauses required, since many workloads run as root throughout.
> 004, any non-shell executable absent from the baseline, irrespective of name.
> 005, an unseen shell followed by an unseen executable within a 120-second
> window — our strongest predicate, because it encodes a temporal chain rather
> than two independent facts. 006, exec activity, informational. 007, privileged
> configuration.
>
> The downstream gate: pause requires severity 0.70 and confidence 0.55; stop
> requires 0.90 and 0.75 **and** a match on 005 or 007 specifically. The most
> destructive action is unreachable on magnitude alone, at any magnitude. It
> requires named structural evidence.

## SLIDE 19 — Response Policy and Containment — 0:37 *(18:19)*

> Three actions and four enforced preconditions.
>
> No action executes without explicit human approval. Disruptive actions require
> an additional acknowledgement. Execution requires live execution mode, disabled
> by default. Protected containers are excluded unconditionally.
>
> These compose serially: rule evidence, thresholds, approval, acknowledgement,
> live mode, non-protected target. Any single failure blocks execution — the
> design assumes the detector may be wrong.
>
> Verified rather than asserted: a real incident at severity 0.74, confidence
> 0.92 was approved for pause. Execution remained `pending` and the container
> continued running, because live mode was disabled. The `docker ps` output is
> the evidence.

## SLIDE 20 — Operator-Defined Custom Rules — 1:11 *(19:30)*

> Seven fixed predicates cannot cover every deployment, so operators compose
> their own over a constrained vocabulary: a tree of leaf conditions on an
> allowlisted field set, five operators and a scope, joined by boolean
> connectives. It is explicitly not an expression language — nothing submitted is
> evaluated as code, and the validator bounds depth and leaf count.
>
> Scope `ancestor` walks the stored `parent_event_id` chain, so a predicate can
> match anywhere in the lineage, not only the triggering event.
>
> They are additive by construction: custom rules never mutate `RULESET_VERSION`
> or `ruleset_hash` — the identity the frozen protocol reproduces against. They
> are hashed separately and folded into the run key alongside it, so operator
> customisation cannot invalidate published results.
>
> Live-verified, and it closes the opening scenario. An operator defined
> `executable equals nc`; a test container executed it. The statistical path scored
> that window 0.169 — baseline-like, below threshold. The score did **not** flag
> it. The custom predicate did, alongside 004 and 006, opening an incident at
> severity 0.73 with process lineage attached.
>
> That asymmetry is the argument for two independent paths.

>>> HANDOFF to Person 4

## SLIDE 21 — SBOM and Advisory Enrichment — 0:38 *(20:08)*

> A distinct question: composition rather than behaviour.
>
> Pinned Trivy emits a CycloneDX SBOM, matched against advisories, then
> cross-referenced against EPSS — predicted exploitation probability — and
> CISA-KEV, confirmed in-the-wild exploitation.
>
> Alpine: fifteen components, zero findings. Postgres: 150 components, 453
> findings, 182 distinct CVEs — more findings than CVEs because one CVE may affect
> multiple packages. 421 carried a live EPSS score; zero were KEV-listed.
>
> Every finding carries `exploit_status = not_established`. Package presence is
> never reported as evidence of exploitation, and a four-stage ladder — present,
> deployed, runtime-observed via eBPF, port-published — bounds the assertable
> claim.

## SLIDE 22 — Reachability Funnel *(flash)* — 0:11 *(20:19)*

> That ladder live: 136 findings present in the scanned image; four reached the
> heuristic runtime-observed stage, a process-name match against kernel
> telemetry — not proof of reachability or exploitation. No aggregate
> noise-reduction rate has been measured.

## SLIDE 23 — Verification and Testing Rigor — 0:36 *(20:55)*

> Layered gates: static analysis and topology invariants, per-service unit tests,
> live-container checks, digest-pinned experiment acceptance — none mocked end to
> end.
>
> The analysis plan was fixed in advance: sample size, primary comparison and
> significance threshold recorded before the pilot run produced output. No
> analysis decision could be conditioned on observed results.
>
> Six defects were found and fixed to obtain the first pilot result,
> including unbounded recursion in our own confidence-interval code. One further
> defect was found live: the approval endpoint referenced an unflushed row and
> violated a foreign key constraint.

## SLIDE 24 — One Deviation, End to End — 0:42 *(21:37)*

> One complete trace. A container baselined on direct invocations only, passing
> the quality gate at four windows and 360 events, then executing a shell invoking
> a download utility — a lineage absent from training.
>
> Score 0.273, elevated. Rules 002, 004 and 005 match: unseen shell, unseen
> executable, and their temporal correlation — 006 also matches, informational
> only. Severity 0.74, confidence 0.92, incident opened.
>
> Both are recomputable from source: severity is 0.65 times 0.90, plus 0.35 times
> 0.273, plus 0.06 — 0.7406. Confidence follows the same form over all four
> matched rules' confidence weights and the three distinct evidence sources
> they carry.
>
> The response engine recommends pause. A human approves with acknowledgement.
> Execution remains pending and the container continues running, because live
> mode is disabled by default.

## SLIDE 25 — Case Study: Cryptominer — 0:25 *(22:03)*

> A functional XMRig binary, executed with no prior knowledge supplied.
>
> Score 0.567 — high band — across four feature families. Rule 004 matches on
> baseline absence, and 001 on distance crossing 0.50. Severity 0.614, confidence
> 0.887, incident opened.
>
> Not detected because we characterise mining behaviour — the string `xmrig` does
> not appear in the ruleset. Detected because this digest had never executed it.

## SLIDE 26 — Case Study: Direct-Exec Tool — 0:18 *(22:21)*

> Constructed to be harder: a resolver utility executed directly, parented by
> `containerd-shim-runc-v2`. No shell exists, so 002 cannot match and 005 has no
> chain to correlate.
>
> Score 0.264, elevated, one eligible match, incident opened. Rule 004 conditions
> on baseline novelty, requiring neither a shell nor list membership.

## SLIDE 27 — Case Study: Deliberate Evasion — 0:48 *(23:10)*

> This one initially defeated us, which is why it is here.
>
> The same utility invoked two ways: directly, and through busybox. Busybox is a
> multicall binary — it dispatches internally on `argv[0]` without `execve`-ing a
> new image, so `proc.name` and `proc.exepath` remain `busybox`. There is no new
> program for the kernel to report, so identity resolution saw only the dispatcher.
>
> Resolved by deriving identity from the second `proc.cmdline` token when the
> executable is a known multicall binary. Both now resolve identically.
>
> The scores match to eleven decimal places. That is determinism, not
> transcription: both windows contribute one unseen token against the same
> profile, so the distributions are structurally identical — and the statistical
> path therefore cannot separate them. Only identity resolution can.

## SLIDE 28 — Detection Coverage — 0:36 *(23:47)*

> Four deviation classes exercised live, two constructed specifically to evade
> the original engine. All four now detected.
>
> The obvious challenge is whether we tuned the detector until our own tests
> passed. We did not: the fix **generalised** the predicate, replacing a fixed
> tool-name list with baseline novelty, and added no names. `xmrig`, `nslookup`
> and `wget` appear nowhere in the ruleset. The only fixed sets remaining are
> shell names and two multicall binaries, neither enumerating a payload.
>
> Adding names to a list would have been overfitting. Removing the list was the
> opposite.

## SLIDES 29–30 — Results *(flash)* — 0:08 *(23:55)*

> The live incident view with severity, confidence, distance and matched rules;
> and the system overview against the raw telemetry stream underlying it.

## SLIDE 31 — Key Findings — 0:35 *(24:31)*

> Exact-image identity is what eliminated false positives, not configuration
> context. Adding runtime configuration on top of digest identity produced no
> measurable change.
>
> The mechanism is explicable, which makes it an informative negative rather than
> a null finding: the configuration delta tested was a dropped Linux capability,
> which does not alter which processes execute. Process-name features cannot
> represent it, by construction.
>
> A follow-on feature scoring the configuration document directly separated every
> tested case — labelled exploratory and explicitly not confirmatory, because it
> did not arise from the pre-registered plan.

## SLIDE 32 — Limitations and Future Work — 0:28 *(24:59)*

> Tested workload and scenario classes only. `proc.cmdline` resolves identity for
> detection but remains outside the scoring feature set. The generalised predicate
> is verified against four live re-runs, not the full 216-trial protocol. And a
> deviation with no process-level signature leaves the rule engine nothing to
> match.
>
> Future work follows: a broader corpus, syscall-argument features, additional
> divergence measures, and — from that null result — a configuration variant that
> does alter process behaviour.

## SLIDE 33 + CLOSE — 0:25 *(25:25)*

> Enrichment activity, for the record.
>
> To close on the opening case: RBAC evaluated a request, the scanner a manifest,
> the firewall a flow, the signature engine a hash. None evaluated runtime process
> behaviour. That is the observable this work quantifies — per digest, on a
> bounded metric, with structural evidence attached and human approval required
> before any action.
>
> Thank you. We will take questions.
