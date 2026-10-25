# eBPF Kernel Telemetry & Ingestion Architecture

> **Component:** `porygon-collector`, modern-eBPF driver (Falco)  
> **Schema:** `porygon.behaviour.v1`  
> **Tracepoints Hooked:** `sys_enter_execve`, `sys_exit_execve`, `sys_enter_execveat`, `sys_exit_execveat`

---

## 1. Observability Principles

Porygon leverages Linux eBPF (extended Berkeley Packet Filter) to achieve kernel-level observability with three non-negotiable architectural constraints:

1. **Zero Workload Mutation:** No sidecar injection, no `LD_PRELOAD` tricks, no kernel module compilation, and no modifications to containerized application binaries.
2. **Minimal Kernel Footprint:** Relies on the modern eBPF probe driver utilizing BPF ring buffers rather than legacy perf-event buffers, minimizing context switches and memory overhead.
3. **Provable Ingestion Loss Accounting:** In systems security research, silent telemetry loss leads to false negatives. Porygon treats event loss as a first-class metric, accounting for ring-buffer overruns and pipeline backpressure.

---

## 2. Event Interception & Kernel Tracepoints

Porygon hooks raw kernel tracepoints rather than kprobes to ensure portability and stability across Linux kernel versions:

```
[User Space Process]
        |
        | execve("/bin/sh", ["sh", "-c", "whoami"], ...)
        v
[Kernel System Call Handler]
        |
        +---> tracepoint:syscalls:sys_enter_execve
        |           |
        |           +---> BPF Program: Extracts PPID, UID, GID, Comm, CGroup ID
        |
        | (Process Image Replacement & Execution)
        |
        +---> tracepoint:syscalls:sys_exit_execve
                    |
                    +---> BPF Program: Extracts return code, registers executable path
                          |
                          v
                    [BPF Ring Buffer (Host Memory)]
```

### Tracepoint Selection: Why Execve Only in v1?
As formalized in [`docs/research/threat-model.md`](../research/threat-model.md):
- Per-packet network sniffing or per-syscall tracking (`read`, `write`, `openat`) produces overwhelming telemetry volume (>100,000 events/sec per host), causing severe cache churn and high false-positive rates.
- Container attack workflows (initial access, privilege escalation, defense evasion, command and control) inevitably manifest as **process execution transitions** (e.g., executing `/bin/sh`, invoking `curl`, launching `sudo` or compilers).
- Tracking `execve` and `execveat` captures 100% of distinct binary executions while maintaining sub-1% CPU consumption.

---

## 3. Container Context & Identity Resolution

When an event arrives from the ring buffer, `porygon-collector` resolves the kernel namespace and cgroup identifiers to immutable container metadata:

```
+------------------------------------+
|  eBPF Event (Kernel CGroup v2 ID)  |
+-----------------+------------------+
                  |
                  v
+--------------------------------------------------------------+
|                   porygon-collector                          |
|                                                              |
| 1. Query Docker Engine /proc/self/cgroup or Docker socket    |
| 2. Map cgroup -> Container ID (e.g. 7f93a18b...)             |
| 3. Retrieve immutable image repository digest:               |
|    docker.io/library/nginx@sha256:4b83445e998a...            |
| 4. Extract runtime security permissions:                     |
|    - Privileged mode: bool                                   |
|    - Exposed host ports: [80/tcp, 443/tcp]                   |
|    - Mounted volumes: [/var/log -> /var/log:ro]              |
+------------------------------+-------------------------------+
                               |
                               v
                Normalized Porygon Telemetry Event
```

---

## 4. Telemetry Event Schema (`porygon.behaviour.v1`)

```json
{
  "event_id": "018f6c48-26ab-7b70-87a4-0c33a9b1c701",
  "timestamp": "2026-10-24T15:30:12.451928Z",
  "container_id": "7f93a18b2c45e1a90d817456bc3a918e0018a9",
  "container_name": "web_frontend",
  "image_repo": "nginx",
  "image_tag": "1.25.4-alpine",
  "image_digest": "sha256:4b83445e998a1a3b593798ef3d21c430e719548bb2081a98075f14e7a0487d55",
  "process": {
    "pid": 4821,
    "ppid": 1402,
    "comm": "curl",
    "exe": "/usr/bin/curl",
    "cmdline": "curl -s http://169.254.169.254/latest/meta-data/",
    "uid": 0,
    "gid": 0
  },
  "parent": {
    "pid": 1402,
    "comm": "sh",
    "exe": "/bin/sh",
    "cmdline": "sh -c curl -s http://169.254.169.254/latest/meta-data/"
  },
  "runtime_context": {
    "privileged": false,
    "network_mode": "bridge",
    "read_only_rootfs": false
  }
}
```

---

## 5. Lossless Saturation & Verification Protocol

To mathematically verify that telemetry is not dropped under burst loads, Porygon executes an automated stress gate (`scripts/verify_phase3.sh` and `scripts/verify_all.sh`):

1. **Synthetic Burst Execution:** Generates 5,000 rapid container process executions within a 10-second burst.
2. **Reconciliation Check:** Reconciles the count of executions recorded in container audit logs against the count of persisted events in the PostgreSQL database:
   $$\text{Loss Rate} = \frac{\text{Expected Executions} - \text{Recorded Events}}{\text{Expected Executions}} \times 100\%$$
3. **Pass Criteria:** Loss rate must equal $0.00\%$. Any non-zero drop triggers pipeline failure in the static/unit verification suite.
