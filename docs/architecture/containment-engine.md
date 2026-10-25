# Automated & Human-Gated Containment Architecture

> **Component:** `porygon-responder`, `porygon-dashboard` (Phase 7)  
> **Containment Actions:** `PAUSE`, `NETWORK_ISOLATE`, `STOP`, `OBSERVE_ONLY`  
> **Security Model:** Cryptographic Lease Clearance, No Autonomous Destructive Actions

---

## 1. The Containment Dilemma: Safety vs Speed

In container security, fully autonomous remediation presents a severe availability risk:

1. **Self-Inflicted Denial of Service:** A false positive or benign operational spike could trigger an autonomous agent to terminate payment gateways, database leaders, or critical infrastructure.
2. **Forensic Destruction:** Blindly killing a compromised container destroys ephemeral memory, running network sockets, and file handles, erasing the forensic evidence needed for incident response.

To solve this, Porygon introduces a **Dual-Mode Containment Architecture**:
- **Non-Destructive Freezing (`PAUSE`):** Freezes CPU cgroups instantly without destroying RAM or sockets.
- **Cryptographic Human Clearance:** Destructive or service-impacting containment actions require human approval authenticated by a time-bound cryptographic token.

---

## 2. Containment Action Taxonomy

```
+-----------------------------------------------------------------------------------+
|                            PORYGON CONTAINMENT TAXONOMY                           |
+-----------------------------------------------------------------------------------+
| Action            | Execution Mechanism       | Memory State  | Reversible? | SLA |
+-------------------+---------------------------+---------------+-------------+-----+
| PAUSE (Default)   | cgroup freezer (SIGSTOP)  | Preserved     | Yes         | <1s |
| NETWORK_ISOLATE   | docker network disconnect | Preserved     | Yes         | <2s |
| STOP              | SIGTERM followed by KILL  | Destroyed     | No          | <5s |
| OBSERVE_ONLY      | Elevate telemetry capture | Preserved     | N/A         | 0s  |
+-----------------------------------------------------------------------------------+
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

Porygon enforces hardcoded safety filters in `porygon-responder`:

```python
# From porygon_responder/safety.py
PROTECTED_CONTAINERS: frozenset[str] = frozenset({
    "porygon-backend",
    "porygon-telemetry",
    "porygon-collector",
    "porygon-responder",
    "porygon-postgres",
    "porygon-dashboard"
})
```

- Any attempt to target a container carrying `com.porygon.protected: "true"` or matching infrastructure service names is rejected with `HTTP 403 Forbidden` and flagged as an adversarial tamper attempt.
