# Porygon Academic Research & Protocol Archive

> **Protocol Identifier:** `porygon.research.protocol.v1`  
> **Status:** `FROZEN` (Pre-registered and reviewed)  
> **Evidence Standard:** Controlled trials, explicit falsification boundaries, pilot vs confirmatory separation.

This directory preserves the complete formal academic package for the Porygon container runtime security research project. In accordance with strict open-science methodologies, protocol documents are versioned, frozen, and protected against post-hoc outcome manipulation.

---

## 1. Directory Structure & Document Map

```
docs/research/
├── README.md                      <-- This document
├── RESEARCH_PROTOCOL_V1.md        <-- Master Frozen Research Protocol (Hypotheses, arms, variables)
├── THREAT_MODEL_V1.md             <-- Formal Threat Model (Attacker capabilities, trust boundaries)
├── CLAIMS_V1.md                   <-- Claim Boundaries (Strict positive & negative claim limits)
├── ADVERSARIAL_SCENARIOS_V1.md    <-- 18 Adversarial Scenarios (Novelty, evasion, stealth tests)
├── PROFILE_SCOPE_EXPERIMENT_V1.md <-- The 4 Profile Arms (Global, Tag, Digest, Context)
├── FEATURE_SCHEMA_V1.md           <-- Behaviour Feature Schema Specification (porygon.behaviour.v1)
├── FEATURE_SCHEMA_CALIBRATED.md   <-- Calibrated Provenance Schema Specification
├── CONFIRMATORY_RESULT_V1.md      <-- Pilot & Confirmatory Results Record
├── DEVIATIONS_V1.md               <-- Protocol Deviations Audit & Non-Destructive Errata
├── LIVE_DEMO_RECORD_V1.md         <-- Real Malware Execution Trials (XMRig & Shell droppers)
├── RELATED_WORK_RECENT.md         <-- Systematic Literature Review (Last 5 Years)
└── FINAL_PHASES.md                <-- Development Roadmap & Engineering Gate Checklist
```

---

## 2. Research Protocol Summary

### The Core Research Question
> *To what extent does binding behavioral baselines to immutable container image digests (`sha256:...`) and host security context reduce false-positive anomaly alerts compared to mutable tags or global host baselines under identical synthetic and realistic workloads?*

### The 4 Experimental Arms
1. **`ARM-GLOBAL`:** A single host-wide behavioral profile shared by all containers.
2. **`ARM-TAG`:** Baselines partitioned by mutable repository tags (`docker.io/library/nginx:latest`).
3. **`ARM-DIGEST`:** Baselines bound strictly to immutable cryptographic image content digests (`docker.io/library/nginx@sha256:...`).
4. **`ARM-CONTEXT`:** Baselines bound to both immutable digest AND runtime security context (capabilities, privileged flag, host mounts).

---

## 3. Scientific Hygiene & Non-Goals

As formalized in [`CLAIMS_V1.md`](CLAIMS_V1.md):
- **Not an attack probability:** Porygon outputs statistical rarity metrics and explainable classification attributions, never an unsubstantiated "probability of compromise."
- **Deterministic rule matches are evidence, not proof:** A matching rule or statistical drift flag is an anomaly indicator prompting investigation or containment, not a courtroom conviction.
- **Negative Result Obligation:** If digest-scoping fails to achieve a statistically significant false-positive reduction ($p < 0.05$) under controlled trials, Porygon protocol requires reporting the negative result without data dredging.
