# Related Work: Recent Comparable Systems (Last 5 Years)

Status: informational, for presentation/discussion use, not a formal literature
review chapter. Ranked by relevance to Porygon's actual contribution (baseline
scoping-granularity comparison, not a new detection primitive). Every entry
below was independently checked (DOI resolution, arXiv API lookup, or direct
fetch of the publisher/journal page) before inclusion; verification notes are
given per entry.

## Directly cited in the presentation deck (verified real)

Correction, 2026-09-13: an earlier revision of this document (2026-09-07)
dropped Forrest/Hofmeyr/Somayaji/Longstaff 1996, Hofmeyr/Forrest/Somayaji
1998, Abed/Clancy/Levy 2015, Lin 1991, and Salem/Naït-Abdesselam 2012 from
the slide bibliography, on the theory that the deck enforced a 10-year
(preferably 5-year) citation window. That rule was invented after the fact
and is not how citation works: a primary source is cited for being the true
origin of a result, regardless of publication age -- the same way Shannon
1948 is still the citation for entropy. Two of the five are reinstated as
acknowledged foundational prior art:

- **Lin, J., "Divergence Measures Based on the Shannon Entropy," IEEE
  Transactions on Information Theory, 1991.** The paper that defines
  Jensen-Shannon divergence itself -- the exact distance measure Porygon's
  scorer implements. Cited in `porygon_review_v3.tex` (`\bibitem{lin1991}`)
  regardless of age, alongside a 2026 security application of the same
  distance family (Bouke et al., below) to show the family remains active,
  not to replace the primary source.
- **Forrest, Hofmeyr, Somayaji, Longstaff, "A Sense of Self for Unix
  Processes," IEEE Symposium on Security and Privacy, 1996.** The
  foundational paper establishing host-based anomaly detection from
  sequences of system calls -- the methodological ancestor of every syscall/
  process-behaviour anomaly detector cited below, including Porygon's. Cited
  as acknowledged prior art regardless of age, for the same reason as Lin
  1991: it is the true origin of the approach this whole literature (and
  this project) builds on.

Hofmeyr/Forrest/Somayaji 1998, Abed/Clancy/Levy 2015, and
Salem/Naït-Abdesselam 2012 remain superseded in the deck's bibliography by
closer, more recent prior work on the same specific problem (Castanhel et al.
2021, El Khairi et al. 2022, below) -- that substitution is legitimate
recency-driven refinement, not the invented citation-window rule. Both
`ref.bib` and the presentation decks have been reconciled against this
correction; see `docs/presentation/README.md` for which deck is current.

- Castanhel, Heinrich, Ceschin, Maziero, "Taking a Peek: An Evaluation of
  Anomaly Detection Using System Calls for Containers," IEEE ISCC, 2021.
  **Closest prior academic work** (replaces Abed/Clancy/Levy 2015 in this
  role): container-level, kernel-observed, system-call anomaly detection
  with no prior workload knowledge required. Uses ML classifiers over
  syscall features, not Jensen-Shannon distance; no baseline-scoping
  comparison. **Verified:** IEEE Xplore ISCC 2021 conference program PDF and
  independent Google Scholar author pages (Heinrich, Maziero, Ceschin) all
  confirm title/authors/venue.
- El Khairi, Caselli, Knierim, Peter, Continella, "Contextualizing System
  Calls in Containers for Anomaly-Based Intrusion Detection," ACM Cloud
  Computing Security Workshop (CCSW), 2022. Container-specific HIDS modeling
  normal syscall context via a graph structure; no baseline-scoping
  comparison. **Verified:** ACM DL landing page (DOI 10.1145/3560810.3564266),
  cross-confirmed via the lead author's own publication page and a public
  GitHub artifact repo (github.com/Asbatel/ContainerHIDS).
- Fournier, Afchain, Baubeau, "Runtime Security Monitoring with eBPF," 17th
  SSTIC Symposium, 2021. Foundational description of eBPF-based runtime
  security tooling (Porygon's sensor layer). **Verified:** Semantic Scholar
  entry and the paper's own SSTIC-hosted PDF, both matching title/authors/
  venue/year. Note: an earlier draft of the deck misattributed this paper's
  authors as "Ledoux, Rousseau" -- corrected to the verified author list
  (Fournier, Afchain, Baubeau) on 2026-09-07.
- Bouke, Sayeed, Heng, Abdullah et al., "Multi-Level Distributional Entropy
  for Explainable Network Intrusion Detection," arXiv:2606.29797, 2026.
  Applies Jensen-Shannon divergence (cross-directional JSD as one of three
  entropy levels) to network-flow intrusion detection -- current security
  application of the same distance family Porygon's scorer uses.
  **Verified:** confirmed directly on the arXiv abstract page
  (arxiv.org/abs/2606.29797).

## Found in this search, all within the last 5 years (items 3, 4, 8 already cited in the deck)

1. **Lin, Chen, Yang, Yang, Luo, Yang, "eBPF-Guard: a detection method for
   container escape via multi-level monitoring and enhanced analysis
   model,"** *Empirical Software Engineering* (Springer) 31, article 51,
   published 18 Dec 2025. DOI: 10.1007/s10664-025-10784-1. Same sensor
   layer as Porygon (eBPF-based container behavior monitoring), different
   scoring method (fine-tuned Qwen1.5-1.8B LLM via LoRA instead of a
   statistical distance; reports 99.22% detection accuracy on simulated
   attacks). Closest 2025 match found for the sensor layer. Already cited
   in the deck as `lin2026`.
   **Verified:** fetched the full Springer landing page directly -- real
   DOI, named authors with institutional affiliations (Fujian Normal
   University, Univ. of Southern Queensland, RMIT, Minjiang University),
   funding acknowledgment (NSFC grants 62302203, 62277010).

2. **"Unsupervised Anomaly Detection for Container via Attention Mechanisms
   and Convolutional Neural Networks,"** Springer book chapter, DOI
   10.1007/978-981-96-2468-3_76, 2025.
   **Verified:** DOI resolves via link.springer.com (HTTP 200), title
   confirmed on fetch.

3. **Li Wei, Yuan Zekun, Wu Kehe, Cheng Rui (North China Electric Power
   University), "Container Anomaly Detection Based on Attention Mechanism
   and Multiscale Convolutional Neural Network,"** *Journal of Information
   Security Research*, Vol 11, No 1, pp 35-, published 2025-01-24.
   Modernizes the older bag-of-syscalls line of work with attention/
   multiscale CNN. Directly comparable to Porygon's `process_sequence_bigram`
   feature family; different modeling technique (neural vs. explicit
   statistical distance). Already cited in the deck as `li2025`.
   **Verified:** fetched directly from the journal's own site (sicris.cn)
   with full author affiliations and abstract, confirming this is a real,
   independently-authored paper (not a duplicate of item 2 above --
   different authors, venue, and language).

4. **Ke Xiong, Zhonghao Wu, Xuzhong Jia, "DeepContainer: A Deep
   Learning-based Framework for Real-time Anomaly Detection in Cloud-Native
   Container Environments,"** *Journal of Advanced Computing Systems*,
   published 5 Jan 2025. DOI: 10.69987/jacs.2025.50101. Reports 96.8%
   detection accuracy, 7.3ms latency, as single point estimates with no
   confidence interval or significance test. Useful contrast for Porygon's
   explicit rejection of unqualified accuracy figures (the "Judge against
   held-back normal runs" design decision in the presentation deck). Already
   cited in the deck as `xiong2025`.
   **Verified:** DOI resolves (HTTP 200); cross-confirmed via Semantic
   Scholar entry with matching authors/venue/Corpus ID 276402623.

5. **"HIDBench: Benchmarking Large Language Models for Host-Based
   Intrusion Detection,"** arXiv:2605.21773. Benchmarks LLMs on
   system-log-based HIDS. Same problem space (host/process-level intrusion
   detection), orthogonal question (detection technique vs. baseline
   scoping).
   **Verified:** confirmed present via the official arXiv API
   (export.arxiv.org/api/query), exact matching title returned.

6. **"Enhancing Kubernetes Resilience through Anomaly Detection and
   Prediction,"** arXiv:2503.14114. Surveys/extends container anomaly
   detection for Kubernetes microservices (monitoring, data processing,
   fault injection modules). Useful to situate Porygon's single-host scope
   honestly against the multi-node Kubernetes literature -- a gap already
   disclosed in `docs/ADVERSARIAL_SCENARIOS_V1.md` and the README.
   **Verified:** confirmed via arXiv API, exact matching title.

7. **"Mutating the 'Immutable': A Large-Scale Study of Git Tag
   Alterations,"** arXiv:2606.31354. Not containers, but directly relevant:
   an empirical, large-scale study of tag mutability being exploited for
   supply-chain attacks in an adjacent domain (Git, not Docker). Strong
   supporting citation for why `ARM-TAG` vs `ARM-DIGEST` is a real
   security-relevant distinction, not a contrived one.
   **Verified:** confirmed via arXiv API, exact matching title.

8. **Ring, Van Oort, Durst, White, Near, Skalka (University of Vermont),
   "Methods for Host-based Intrusion Detection with Deep Learning,"**
   *Digital Threats: Research and Practice* (ACM DTRAP), Vol 2 No 4, 2021.
   DOI: 10.1145/3461462. Survey and improvement of HIDS approaches modeling
   "normal" system behavior from system-call/bash-command sequences. Already
   cited in the deck as `ring2021`.
   **Verified:** the direct ACM landing page returned HTTP 403 (bot-blocked,
   not evidence of non-existence); cross-confirmed via the paper's own
   author-hosted PDF (ceskalka.w3.uvm.edu, University of Vermont faculty
   page) and an independent NSF public-access mirror
   (par.nsf.gov/servlets/purl/10386265), both matching title and authors.

9. **threaTrace: Detecting and Tracing Host-based Threats in Node Level
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
