# Porygon Adversarial Scenario Stress Test v1

Status: informational, self-review (not a frozen protocol document)

Purpose: enumerate concrete attacker behaviours and classify each as
detected, detected-but-untested, or structurally invisible to the current
implementation, cross-referenced against the real code
(`backend/src/porygon_api/detection.py`, `backend/src/porygon_api/scoring.py`,
`falco/porygon_rules.yaml`) rather than the aspirational README description.
This exists to stop the project from overselling detection coverage it does
not have, and to give an honest answer to "how would this actually be useful
in real life."

## What Porygon observes, precisely

- Docker lifecycle/control-plane events (create, start, stop, exec, network,
  privileged flag) via the collector.
- Falco-reported process `execve`/`execveat` events: pid/ppid, executable
  path, process name, raw `command_line` string, uid/gid, cwd, tty, parent
  context. Falco captures the raw command line, but the anomaly scorer's
  `process_name` categorical feature ignores its contents beyond the binary
  name/basename — argument values are not a distance feature in v1.
- It does **not** observe: file contents, general file access, network flows,
  socket connections, DNS, syscall arguments beyond the Falco output line,
  in-process behaviour, memory-only execution, encrypted payloads, or
  privilege-transition events as a dedicated feature family. This is stated
  in `THREAT_MODEL_V1.md` and confirmed here directly against the collector
  and telemetry source (no network-facing telemetry code exists anywhere in
  `collector/` or `telemetry/`).

## Detection surface, precisely

Seven deterministic rules (`POR-DET-001..007`) plus a JS-distance anomaly
score. All 7 rules and their exact firing conditions are read directly out of
`backend/src/porygon_api/detection.py`:

| Rule | Fires on |
|---|---|
| POR-DET-001 | Anomaly score ≥ 0.50 |
| POR-DET-002 | A shell name not present in the selected baseline executes |
| POR-DET-003 | A UID-0 process executes and UID 0 was absent from baseline |
| POR-DET-004 | A dual-use tool (curl/wget/nc/python/openssl/etc., fixed list) not present in baseline executes |
| POR-DET-005 | An unseen shell is followed by an unseen dual-use tool within 120s |
| POR-DET-006 | Any `docker exec` occurred |
| POR-DET-007 | Container reports `--privileged` |

Every rule keys off **process/executable-name identity against a fixed
baseline set**, or a lifecycle flag. None of them inspect command-line
argument content, destination addresses, file paths touched, or network
behaviour.

## 18 adversarial scenarios

### A. Structurally invisible (network/data-plane, explicitly out of scope)

1. **C2 domain repoint** — an already-baselined `curl` call gets redirected
   to a malicious destination via config or DNS change. No new process, no
   new executable, no argument-content feature. **Invisible.**
2. **Exfiltration over an existing channel** — data leaked over an
   already-open, already-baselined connection (e.g. an abused replication
   channel). **Invisible**, no network/socket telemetry exists.
3. **File-only webshell** — a webshell using only already-baselined
   interpreters (e.g. `python3`) to read/write files, spawning no new
   process. **Invisible**, no file-access telemetry exists.
4. **DNS tunnelling** from an already-baselined process. **Invisible.**
5. **Fileless/in-memory execution** (reflective loading, no new binary on
   disk, no new process). **Invisible** — explicitly listed as a non-goal in
   `THREAT_MODEL_V1.md`.
6. **Payload smuggled inside a normal-looking already-baselined HTTPS
   request.** **Invisible.**

### B. Depends on exact process-identity granularity

7. **In-place binary replacement** — attacker overwrites `/usr/bin/curl`
   with a static reverse-shell binary but keeps the same path/name.
   `_basename`/`_event_executable` key off name/path string, not a content
   hash. **Likely invisible** unless the replacement changes the executable
   path or is a multicall binary Porygon already special-cases (busybox/
   toybox).
8. **SUID privilege escalation** executed as UID 0 for the first time.
   **Caught by POR-DET-003.**
9. **`/dev/tcp` reverse shell via bash built-in** — no new process is
   spawned (bash is already baselined), and Falco captures `execve`, not
   socket syscalls. **Invisible.**
10. **Real CVE-2019-5736 runc write-escape** — only the harmless simulated
    shape (`SCN-RUNC-ESCAPE-SIM`) has ever been exercised; the real exploit's
    actual process signature is untested. **Caught in simulation only,
    unverified against a real exploit.**

### C. Depends on baseline completeness / untested failure modes

11. **Baseline poisoning during the fit window itself**, before profiles are
    approved. Explicitly modeled and defended against by design (fit-split
    isolation, human-approved fit intervals), but the actual human review
    step that would catch a poisoned fit run has never been exercised or
    tested. **Defended by design, not empirically validated.**
12. **Low-and-slow attack** spread across windows longer than the 120s
    correlation window. Listed as a considered failure mode in
    `THREAT_MODEL_V1.md`. **Acknowledged, never tested.**
13. **Mimicry attack** — an intruder matches the process-sequence bigram
    pattern of a legitimate deploy/backup job. The bigram feature weight
    (0.20, fixed in v1) has never been adversarially evaluated.
    **Untested, plausible evasion.**

### D. Where the design genuinely helps

14. **Backdoored entrypoint script** in a newly deployed image running an
    unexpected shell. **Caught (POR-DET-002)** — the strongest realistic use
    case.
15. **Manual `docker exec` into a running container.** **Caught
    (POR-DET-006)**, though not incident-eligible alone.
16. **Container flipped to `--privileged`** when it never had that flag.
    **Caught (POR-DET-007)**, a genuinely low-false-positive, high-value
    signal.
17. **Supply-chain digest substitution** — a mutable tag silently repoints to
    a different image digest. **This is the one thing digest-based scoping
    structurally catches that tag-based scoping cannot**, independent of the
    anomaly score.
18. **Classic dropper pattern** `sh -c "curl ... | bash"` inside a container
    that has never run a shell or a dual-use tool. **Caught by POR-DET-005**,
    the highest-confidence rule (0.95), and this is a common real
    initial-access/dropper pattern.

## Honest conclusion

Porygon is not, and should not be described as, a general intrusion
detection or runtime-security platform. Categories A and B (10 of 18
scenarios above) show it has no visibility into network-based compromise,
in-memory execution, or careful in-place tampering — which covers a large
share of real-world post-exploitation technique. Category C shows several
protocol-acknowledged failure modes have never actually been tested.

What is real and defensible (category D): Porygon is a **narrow,
digest-identity-aware process-execution anomaly and rule signal for
detecting new/unexpected process behaviour inside an already-running
container** — new shells, new dual-use tools, unexpected privilege
escalation, unexpected privileged-mode reconfiguration, and mutable-tag/
digest substitution. That is a real, useful, defensible niche for a research
prototype (e.g., a defense-in-depth signal layered behind network-level
tools, not a replacement for them), and the paper and README should describe
it as exactly that rather than as a comprehensive security platform.
