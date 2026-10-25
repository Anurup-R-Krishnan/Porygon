# Automated & Human-Gated Containment Architecture

> **Component:** `porygon-responder`, `porygon-dashboard` (Containment Response)  
> **Containment Actions:** `pause_container`, `stop_container`, `observe_only`  
> **Security Model:** Cryptographic Lease Clearance, No Autonomous Destructive Actions

---

## 1. The Containment Dilemma: Safety vs Speed

In container security, fully autonomous remediation presents a severe availability risk:

1. **Self-Inflicted Denial of Service:** A false positive or benign operational spike could trigger an autonomous agent to terminate payment gateways, database leaders, or critical infrastructure.
2. **Forensic Destruction:** Blindly killing a compromised container destroys ephemeral memory, running network sockets, and file handles, erasing the forensic evidence needed for incident response.

To solve this, Porygon introduces a **Dual-Mode Containment Architecture**:
- **Non-Destructive Freezing (`pause_container`):** Freezes CPU cgroups instantly without destroying RAM or sockets.
- **Cryptographic Human Clearance:** Destructive or service-impacting containment actions require human approval authenticated by a time-bound operator token.

---

## 2. Containment Action Taxonomy

```
+-----------------------------------------------------------------------------------------+
|                               PORYGON CONTAINMENT TAXONOMY                              |
+-----------------------------------------------------------------------------------------+
| Action                    | Execution Mechanism       | Memory State  | Reversible? | SLA |
+---------------------------+---------------------------+---------------+-------------+-----+
| pause_container (Default) | cgroup freezer (SIGSTOP)  | Preserved     | Yes         | <1s |
| stop_container            | SIGTERM followed by KILL  | Destroyed     | No          | <5s |
| observe_only              | Elevate telemetry capture | Preserved     | N/A         | 0s  |
+-----------------------------------------------------------------------------------------+
```

### Why `PAUSE` is the Default Containment Primitive
1. **Zero Malware Propagation:** Once a container is paused via the Linux cgroup freezer, zero user-space instructions execute, halting active command-and-control beacons or data exfiltration immediately.
2. **Instant Forensics:** Incident responders can attach `gdb`, inspect `/proc/<pid>/mem`, dump environment secrets, and extract malware binaries from the live filesystem.
3. **Instant Rollback:** If the incident turns out to be a benign maintenance task, the operator clicks **Unpause**, and the service resumes without restarting or losing in-memory sessions.

---

## 3. Cryptographic Clearance Workflow

To prevent compromised backend microservices or rogue API callers from issuing unauthorized containment commands, Porygon gates the Docker daemon socket behind cryptographic leases:

```
[porygon-backend]
       |
       | Detects critical anomaly (Score >= 0.85)
       v
  Generates Containment Recommendation
  Recommendation: PAUSE container 7f93a1...
       |
       v
[porygon-dashboard (Operator View)]
       |
       | Human reviews behavioral diff & TreeSHAP explanation
       | Clicks "AUTHORIZE LEASE"
       v
[Operator Clearance Token Generation]
       |
       | Token = HMAC-SHA256(SecretKey, ContainerID + Action + Nonce + Expiry)
       v
POST /containment/authorize
Headers: { "X-Porygon-Operator-Clearance": "<HMAC_TOKEN>" }
       |
       v
[porygon-responder]
       |
       | 1. Verify HMAC signature against host master key
       | 2. Verify timestamp has not expired (30-second TTL)
       | 3. Verify non-replay (Nonce check in Redis/Memory)
       | 4. Verify target container is not protected (com.porygon.protected=true)
       v
[Docker Socket API: /containers/{id}/pause]
       |
       v
  Container Frozen. Audit Log Recorded.
```

---

## 4. Protected Workload Safeguards

Porygon enforces hardcoded safety filters in `porygon_responder/executor.py`:

```python
# From porygon_responder/executor.py & config.py
# Configured via PROTECTED_LABEL (default: "com.porygon.protected")
value = str(labels.get(self.protected_label, "")).lower()
if value in {"1", "true", "yes"}:
    raise PermissionError("target container is protected by Porygon policy")
```

- Any attempt to target an infrastructure container carrying the Docker label `com.porygon.protected: "true"` (configured on `backend`, `postgres`, `collector`, `telemetry`, etc.) is immediately rejected with `protected_target` error code and logged as an unauthorized action.
