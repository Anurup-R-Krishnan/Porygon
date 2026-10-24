# Porygon Documentation Portal

Welcome to the **Porygon** documentation repository. Porygon is a provenance-bound container runtime security system combining kernel eBPF observability, digest-bound statistical baseline profiling, explainable machine-learning threat classification, and human-in-the-loop containment.

---

## 📚 Documentation Map

```
docs/
├── architecture/                  # Deep Engineering & System Architecture
│   ├── OVERVIEW.md                # System topology, planes, services, and data flows
│   ├── EBPF_TELEMETRY.md          # Kernel tracepoint capture, ring buffers, zero-drop loss accounting
│   ├── BEHAVIORAL_PROFILING.md    # Digest-bound profiling, rarity formulas, and drift calculation
│   ├── CONTAINMENT_ENGINE.md      # Non-destructive cgroup freezing & cryptographic clearance
│   ├── SBOM_VULNERABILITY.md      # Syft/Grype digest binding & dynamic runtime CVE reachability
│   └── ML_THREAT_CLASSIFIER.md    # Pure-Python Tree Ensemble (Random Forest) & TreeSHAP attributions
│
├── research/                      # Academic Pre-Registration & Scientific Protocol
│   ├── README.md                  # Academic package overview and study design
│   ├── RESEARCH_PROTOCOL_V1.md    # Master frozen research protocol (hypotheses, variables)
│   ├── THREAT_MODEL_V1.md         # Assets, trust boundaries, attacker capabilities
│   ├── CLAIMS_V1.md               # Strict positive and negative claims boundaries
│   ├── ADVERSARIAL_SCENARIOS_V1.md# 18 concrete attacker behaviours and evasion tests
│   ├── PROFILE_SCOPE_EXPERIMENT.md# The 4 experimental arms (Global, Tag, Digest, Context)
│   ├── CONFIRMATORY_RESULT_V1.md  # Pilot and confirmatory measured trial records
│   ├── DEVIATIONS_V1.md           # Protocol deviations log and non-destructive errata
│   ├── LIVE_DEMO_RECORD_V1.md     # Real malware execution trials (XMRig & Shell droppers)
│   ├── RELATED_WORK_RECENT.md     # Systematic literature survey (last 5 years)
│   └── FINAL_PHASES.md            # Comprehensive development roadmap (Phases 1–8)
│
├── review/                        # Academic Review & Evaluation Records
│   ├── REVIEW_PACKAGE.md          # Evaluation instructions for independent reviewers
│   ├── methodology-review.json    # Formal methodology sign-off record
│   └── security-review.json       # Formal security and threat model sign-off record
│
└── presentation/                  # Defense, Viva & Review Presentations
    ├── README.md                  # Compilation guide and slide notes
    ├── porygon_review_v3.tex      # Canonical LaTeX Beamer presentation deck
    ├── porygon_review_v3.pdf      # Compiled presentation slides
    ├── PRESENTATION_SCRIPT.md     # Spoken talk script and slide commentary
    ├── ref.bib                    # Comprehensive BibTeX citations
    └── screenshots/               # High-resolution UI captures of incidents & simulator
```

---

## 🚀 Quick Navigation

- **Want to understand how the system works end-to-end?**  
  Read [`docs/architecture/OVERVIEW.md`](architecture/OVERVIEW.md).
- **Want to see how eBPF telemetry is captured without dropping packets?**  
  Read [`docs/architecture/EBPF_TELEMETRY.md`](architecture/EBPF_TELEMETRY.md).
- **Want to understand the explainable ML model and TreeSHAP values?**  
  Read [`docs/architecture/ML_THREAT_CLASSIFIER.md`](architecture/ML_THREAT_CLASSIFIER.md).
- **Evaluating the academic research or reviewing for publication/viva?**  
  Start with [`docs/research/README.md`](research/README.md) and [`docs/research/RESEARCH_PROTOCOL_V1.md`](research/RESEARCH_PROTOCOL_V1.md).
- **Preparing for the project defense presentation?**  
  Check [`docs/presentation/README.md`](presentation/README.md) and [`docs/presentation/PRESENTATION_SCRIPT.md`](presentation/PRESENTATION_SCRIPT.md).
