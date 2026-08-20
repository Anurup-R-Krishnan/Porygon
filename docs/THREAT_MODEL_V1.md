# Porygon Threat Model v1

Status: **review pending**

Protocol: `porygon.research.protocol.v1`

Frozen scope date: 2026-08-20

## Purpose and system boundary

Porygon is evaluated as a single-host Docker runtime-behaviour research
system. It observes Docker control-plane events and Falco process-execution
events, persists evidence, builds explicitly approved profiles, and produces
research signals for human review. It is not evaluated as a multi-host
production prevention platform.

Artifact identity is represented by an immutable repository digest. It
identifies an image artifact, but does not, by
itself, identify the complete behaviour expected from every deployment of that
artifact. The experiment separately compares global, mutable-tag, digest-only,
and digest-plus-context behavioural profile scopes.

## Assets

- integrity and completeness of raw and normalized runtime evidence;
- exact image, container, run, profile, score, ruleset, and protocol identity;
- separation of fit, calibration, pilot, and confirmatory runs;
- operator credentials and PostgreSQL credentials;
- availability and bounded storage of collector and telemetry outboxes;
- incident, allowlist, response-approval, scan, and audit histories;
- reproducible experiment manifests, ground truth, metrics, tables, and plots;
- the Docker host and workloads being observed.

## Trusted computing base

The study trusts the Linux kernel, Docker Engine, container runtime, Falco and
its selected driver, the Porygon service images, PostgreSQL, the experiment
orchestrator, the host clock, and the operator who freezes ground truth before
analysis. These are dependencies, not claims of formal verification.

The gateway, backend, database, and analysis code are trusted to preserve
identities and enforce protocol rules. The collector and responder are trusted
with Docker control-plane authority. Falco is trusted to report the events it
observes honestly. Plan 005 measures loss at available boundaries instead of
assuming these components are lossless.

## Privileged trust boundaries

The Docker socket is equivalent to high privilege over the host. Only the
collector, scanner, and responder receive it, for distinct purposes. A
read-only bind mount does not make Docker API access read-only.

- The collector can inspect Docker state and read the event stream.
- The scanner can inspect exact images and run the pinned scanner workflow; it
  also has outbound network access for explicitly recorded feeds.
- The responder can pause, unpause, stop, or start only an exact approved
  container under the response policy. Disruptive mode remains disabled during
  the primary experiment.
- The backend and telemetry adapter receive neither Docker socket nor kernel
  privilege.
- Falco has the kernel access needed by its modern eBPF driver and writes to a
  dedicated shared event volume.

Compromise of a Docker-socket service may become host compromise. The paper
must report this boundary even when containers run as non-root.

## Attacker and disturbance capabilities

The controlled scenarios model an actor or operator who can execute processes
inside an already running study container, invoke a shell or dual-use utility,
change workload intensity, or exploit an intentionally varied deployment
context. The study also models benign administrators performing maintenance,
reload, backup, debug, log-rotation, and traffic-spike actions.

The study considers these failure or manipulation modes:

- low-and-slow or bursty activity intended to evade fixed windows;
- baseline poisoning when disallowed activity appears in approved fit runs;
- mutable-tag drift between two recorded runs;
- a profile from the wrong workload, digest, or deployment context;
- collector, telemetry, backend, or database outage and replay;
- spool saturation, storage pressure, event duplication, and delayed delivery;
- process renaming and multicall binaries such as BusyBox;
- version drift and contexts with insufficient independent training runs.

The primary evaluation does not assume the actor can compromise the host
kernel, Docker daemon, Falco, Porygon control plane, PostgreSQL, experiment
manifest, or ground-truth clock. Those attacks would invalidate the trusted
measurement apparatus and are reported as out of model.

## Baseline-poisoning controls

Training is never automatic or continuous. Every fit interval is approved and
bound to a complete run manifest. Fit runs use deterministic benign generators
and are assigned before their events are inspected. Known attack simulations,
hard-negative test actions, pilot runs, calibration runs, and confirmatory test
runs cannot enter fit data. A run rejected for contamination remains recorded;
it is not silently replaced after results are known.

The poisoning experiment deliberately injects labelled contamination into a
copy of the fit set. It does not alter the clean primary profiles. Any proposed
poisoning defence is an ablation or later protocol revision, not an unrecorded
cleanup step.

## Telemetry and blind spots

Version 1 evidence includes Docker lifecycle/exec events and Falco-observed
process execution. It does not observe file contents or general file access,
network flows, socket connections, DNS, syscall arguments beyond the selected
Falco output, in-process behaviour, memory-only execution, encrypted payloads,
or privilege transitions as dedicated feature families.

Count equality from Docker's event API or Falco's JSON file to PostgreSQL proves
only the measured downstream segment. It does not prove that Docker published
every control-plane event, that the kernel emitted every event to eBPF, or that
Falco userspace dropped none. Plan 005 must sample the available Falco engine
metrics and retain each unmeasured boundary explicitly.

Command lines can contain secrets. Detailed raw events remain local and access
controlled; versioned summaries minimize them. Dead letters retain hashes,
lengths, coordinates, and sanitized bounded excerpts rather than full records.
The context fingerprint excludes environment values, host mount sources,
container identifiers, names, timestamps, and literal argument values.

## Safety and ethics boundary

All scenarios run on disposable, locally owned containers and synthetic data.
No real malware, persistence, credential theft, destructive payload, public
target, third-party service, or unauthorized network destination is used.
Dual-use commands operate only on fixture data or discard their output. The
primary experiment never enables automated disruptive response. A separate
response acceptance run requires explicit operator approval and an exact
disposable target.

The experiment must stop if isolation, ground truth, host ownership, or event
identity cannot be established. Negative results, insufficient profiles, loss,
and failed runs are retained rather than concealed.

## Residual risk and non-goals

Porygon does not claim tamper-proof telemetry, complete attack detection,
production hardening, multi-tenant isolation, malware analysis, exploit
confirmation, causal attribution, or zero event loss. A container escaping to
the host, a compromised measurement component, and adversarial manipulation of
the kernel or clock are outside the primary empirical claim.

## Required review

Before status changes to **frozen**, one human security reviewer and one human
methodology reviewer must record name, date, decision, and notes in
`RESEARCH_PROTOCOL_V1.md`. Reviewers must not inspect confirmatory outcomes;
none may be collected while this document remains review pending.
