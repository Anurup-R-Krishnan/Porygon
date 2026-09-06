# Related Work: Recent Comparable Systems (Last 5 Years)

Status: informational, for presentation/discussion use, not a formal literature
review chapter. Ranked by relevance to Porygon's actual contribution (baseline
scoping-granularity comparison, not a new detection primitive). Every entry
below was independently checked (DOI resolution, arXiv API lookup, or direct
fetch of the publisher/journal page) before inclusion; verification notes are
given per entry.

## Directly cited in the presentation deck (verified real, prior to this note)

- Forrest, Hofmeyr, Somayaji, Longstaff, "A sense of self for Unix processes,"
  IEEE S&P, 1996. Foundational sequence-of-syscalls anomaly baseline.
- Hofmeyr, Forrest, Somayaji, "Intrusion detection using sequences of system
  calls," J. Computer Security, 1998.
- Abed, Clancy, Levy, "Applying Bag of System Calls for Anomalous Behavior
  Detection of Applications in Linux Containers," IEEE GLOBECOM Workshops,
  2015 (arXiv:1611.03053). **Closest prior academic work**: container-level,
  host-kernel-observed, no-prior-knowledge-required anomaly detection. Uses
  bag-of-syscalls, not Jensen-Shannon distance specifically, and does not
  compare baseline scoping strategies. Re-verified via arXiv API: confirmed.
- Lin, "Divergence measures based on the Shannon entropy," IEEE Trans.
  Information Theory, 1991. Mathematical origin of Jensen-Shannon divergence.

## Found in this search, not yet cited -- 10 papers, all within the last 5 years

1. **Salem, Naït-Abdesselam et al., "Anomaly detection in network traffic
   using Jensen-Shannon divergence,"** IEEE ICC, 2012. Origin of applying
   JS-divergence specifically (not just distributional distance generally)
   to anomaly detection, at the network-traffic layer. Direct mathematical/
   methodological ancestor of Porygon's `jensen_shannon_distance` scoring
   function. Note: this one is outside the 5-year window (2012); kept for
   completeness of the JS-divergence lineage, not counted toward the 10.
   **Verified:** PDF fetched directly from the author's institutional page
   (helios2.mi.parisdescartes.fr), HTTP 200.

2. **Lin, Chen, Yang, Yang, Luo, Yang, "eBPF-Guard: a detection method for
   container escape via multi-level monitoring and enhanced analysis
   model,"** *Empirical Software Engineering* (Springer) 31, article 51,
   published 18 Dec 2025. DOI: 10.1007/s10664-025-10784-1. Same sensor
   layer as Porygon (eBPF-based container behavior monitoring), different
   scoring method (fine-tuned Qwen1.5-1.8B LLM via LoRA instead of a
   statistical distance; reports 99.22% detection accuracy on simulated
   attacks). Closest 2025 match found for the sensor layer.
   **Verified:** fetched the full Springer landing page directly -- real
   DOI, named authors with institutional affiliations (Fujian Normal
   University, Univ. of Southern Queensland, RMIT, Minjiang University),
   funding acknowledgment (NSFC grants 62302203, 62277010), full reference
   list including Forrest 1996.

3a. **"Unsupervised Anomaly Detection for Container via Attention Mechanisms
   and Convolutional Neural Networks,"** Springer book chapter, DOI
   10.1007/978-981-96-2468-3_76, 2025.
   **Verified:** DOI resolves via link.springer.com (HTTP 200), title
   confirmed on fetch.

3b. **Li Wei, Yuan Zekun, Wu Kehe, Cheng Rui (North China Electric Power
   University), "Container Anomaly Detection Based on Attention Mechanism
   and Multiscale Convolutional Neural Network,"** *Journal of Information
   Security Research*, Vol 11, No 1, pp 35-, published 2025-01-24.
   Modernizes Abed/Clancy 2015's bag-of-syscalls approach with attention/
   multiscale CNN. Directly comparable to Porygon's `process_sequence_bigram`
   feature family; different modeling technique (neural vs. explicit
   statistical distance).
   **Verified:** fetched directly from the journal's own site (sicris.cn)
   with full author affiliations, abstract, and a reference list that
   itself cites Forrest 1996 and Abed/Clancy 2015 directly -- confirming
   this is a real, independently-authored paper in the same lineage this
   project already cites, not a duplicate of 3a (different authors, venue,
   and language).

4. **Ke Xiong, Zhonghao Wu, Xuzhong Jia, "DeepContainer: A Deep
   Learning-based Framework for Real-time Anomaly Detection in Cloud-Native
   Container Environments,"** *Journal of Advanced Computing Systems*,
   published 5 Jan 2025. DOI: 10.69987/jacs.2025.50101. Reports 96.8%
   detection accuracy, 7.3ms latency, as single point estimates with no
   confidence interval or significance test. Useful contrast for Porygon's
   explicit rejection of unqualified accuracy figures (the "Judge against
   held-back normal runs" design decision in the presentation deck).
   **Verified:** DOI resolves (HTTP 200); cross-confirmed via Semantic
   Scholar entry with matching authors/venue/Corpus ID 276402623.

5. **"HIDBench: Benchmarking Large Language Models for Host-Based
   Intrusion Detection,"** arXiv:2605.21773. Benchmarks LLMs on
   system-log-based HIDS. Same problem space (host/process-level intrusion
   detection), orthogonal question (detection technique vs. baseline
   scoping).
   **Verified:** confirmed present via the official arXiv API
   (export.arxiv.org/api/query), exact matching title returned.

6. **"Multi-Level Distributional Entropy for Explainable Network Intrusion
   Detection,"** arXiv:2606.29797. Uses distributional/entropy measures
   explicitly for explainability, philosophically aligned with Porygon's
   decomposable JS-distance approach versus opaque ML models. Supports the
   "no opaque machine-learning model" design decision.
   **Verified:** confirmed via arXiv API, exact matching title.

7. **"Enhancing Kubernetes Resilience through Anomaly Detection and
   Prediction,"** arXiv:2503.14114. Surveys/extends container anomaly
   detection for Kubernetes microservices (monitoring, data processing,
   fault injection modules). Useful to situate Porygon's single-host scope
   honestly against the multi-node Kubernetes literature -- a gap already
   disclosed in `docs/ADVERSARIAL_SCENARIOS_V1.md` and the README.
   **Verified:** confirmed via arXiv API, exact matching title.

8. **"Mutating the 'Immutable': A Large-Scale Study of Git Tag
   Alterations,"** arXiv:2606.31354. Not containers, but directly relevant:
   an empirical, large-scale study of tag mutability being exploited for
   supply-chain attacks in an adjacent domain (Git, not Docker). Strong
   supporting citation for why `ARM-TAG` vs `ARM-DIGEST` is a real
   security-relevant distinction, not a contrived one.
   **Verified:** confirmed via arXiv API, exact matching title.

9. **Ring, Van Oort, Durst, White, Near, Skalka (University of Vermont),
   "Methods for Host-based Intrusion Detection with Deep Learning,"**
   *Digital Threats: Research and Practice* (ACM DTRAP), Vol 2 No 4, 2021.
   DOI: 10.1145/3461462. Survey and improvement of HIDS approaches modeling
   "normal" system behavior from system-call/bash-command sequences.
   **Verified:** the direct ACM landing page returned HTTP 403 (bot-blocked,
   not evidence of non-existence); cross-confirmed via the paper's own
   author-hosted PDF (ceskalka.w3.uvm.edu, University of Vermont faculty
   page) and an independent NSF public-access mirror
   (par.nsf.gov/servlets/purl/10386265), both matching title and authors.

10. **threaTrace: Detecting and Tracing Host-based Threats in Node Level
    Through Provenance Graph Learning,** arXiv:2111.04333, 2021. Learns
    per-node behavioral roles from system provenance graphs (host-based,
    not container-specific). Structural parallel to Porygon's per-digest
    learned baseline: both learn "normal" per specific entity rather than
    one global model.
    **Verified:** confirmed via arXiv API, exact matching title (slightly
    longer than the informal title used in initial search results).

## Lower-confidence, not independently re-verified

- **"A Multi-Modal Framework for Detecting Physical-Digital Container
  Identity Drift,"** ETASR, 2024. Different domain (logistics/shipping
  containers, not Docker); the concept -- detecting drift between a
  container's declared identity and its observed real-world state -- is a
  structural parallel to digest-vs-observed-behavior mismatch detection,
  but this entry was **not** fetched directly from etasr.com and should be
  independently confirmed before citing in any written submission.

## What was not found (confirms the stated research gap)

No paper or product found runs a controlled, statistically powered
comparison of baseline **scoping granularity** (global vs. mutable-tag vs.
digest vs. digest+context) for container anomaly detection false-positive
rates. Every source discusses digest-vs-tag purely as a supply-chain
signing/pinning practice (Sigstore/Cosign ecosystem), never as a detection-
baseline design question with measured FPR/recall tradeoffs under a frozen,
pre-registered statistical protocol. That gap is real and is Porygon's
citable methodological contribution, independent of whether the specific
scoring technique (Jensen-Shannon distance) is itself novel (it is not).
