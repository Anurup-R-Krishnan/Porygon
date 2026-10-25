# Porygon Documentation Portal

Welcome to the **Porygon** documentation repository. Porygon is a provenance-bound container runtime security system combining kernel eBPF observability, digest-bound statistical baseline profiling, explainable machine-learning threat classification, and human-in-the-loop containment.

---

## 📚 Documentation Map

```
docs/
├── architecture/                  # Deep Engineering & System Architecture
│   ├── system-overview.md         # System topology, planes, services, and data flows
│   ├── ebpf-telemetry.md          # Kernel tracepoint capture, ring buffers, zero-drop loss accounting
│   ├── behavioral-profiling.md    # Digest-bound profiling, rarity formulas, and drift calculation
│   ├── containment-engine.md      # Non-destructive cgroup freezing & cryptographic clearance
│   ├── sbom-vulnerability.md      # Trivy digest binding & dynamic runtime CVE reachability
│   └── ml-threat-classifier.md    # Pure-Python Tree Ensemble (Random Forest) & TreeSHAP attributions
│
├── research/                      # Academic Pre-Registration & Scientific Protocol
│   ├── README.md                  # Academic package overview and study design
│   ├── research-protocol.md       # Master frozen research protocol (hypotheses, variables)
│   ├── threat-model.md            # Assets, trust boundaries, attacker capabilities
│   ├── claims-boundaries.md       # Strict positive and negative claims boundaries
│   ├── profile-scope-experiment.md# The 4 experimental arms (Global, Tag, Digest, Context)
│   ├── adversarial-scenarios.md   # 18 concrete attacker behaviours and evasion tests
│   ├── empirical-results.md       # Pilot and confirmatory measured trial records
│   ├── protocol-deviations.md     # Protocol deviations log and non-destructive errata
│   ├── live-malware-trials.md     # Real malware execution trials (XMRig & Shell droppers)
│   ├── related-work.md            # Systematic literature survey (last 5 years)
│   ├── development-roadmap.md     # Comprehensive development roadmap and milestones
│   └── schemas/                   # Event & provenance schema specifications
│       ├── behavior-schema.md
│       └── calibrated-rarity-schema.md
│
├── review/                        # Academic Review & Evaluation Records
│   ├── review-package.md          # Evaluation instructions for independent reviewers
│   ├── methodology-review.json    # Formal methodology sign-off record
│   └── security-review.json       # Formal security and threat model sign-off record
│
└── presentation/                  # Defense, Viva & Review Presentations
    ├── README.md                  # Compilation guide and slide notes
    ├── porygon_review_v3.tex      # Canonical LaTeX Beamer presentation deck
    ├── porygon_review_v3.pdf      # Compiled presentation slides
    ├── presentation-script.md     # Spoken talk script and slide commentary
    ├── ref.bib                    # Comprehensive BibTeX citations
    └── screenshots/               # High-resolution UI captures of incidents & simulator
```

---

## 🚀 Quick Navigation

- **Looking for the hands-on interactive walkthrough?**  
  Read [`EXPLAINER.md`](../EXPLAINER.md).
- **Want to understand how the system works end-to-end?**  
  Read [`docs/architecture/system-overview.md`](architecture/system-overview.md).
- **Want to see how eBPF telemetry is captured without dropping packets?**  
  Read [`docs/architecture/ebpf-telemetry.md`](architecture/ebpf-telemetry.md).
- **Want to understand the explainable ML model and TreeSHAP values?**  
  Read [`docs/architecture/ml-threat-classifier.md`](architecture/ml-threat-classifier.md).
- **Evaluating the academic research or reviewing for publication/viva?**  
  Start with [`docs/research/README.md`](research/README.md) and [`docs/research/research-protocol.md`](research/research-protocol.md).
- **Preparing for the project defense presentation?**  
  Check [`docs/presentation/README.md`](presentation/README.md) and [`docs/presentation/presentation-script.md`](presentation/presentation-script.md).
