# Porygon Project Guidelines & Operating Principles

This document serves as the permanent, authoritative rulebook and operational standard for engineering, auditing, refactoring, and maintaining the **Porygon** container runtime security research platform.

All contributors and AI pairing assistants must adhere strictly to every rule defined below.

---

## 1. Git, Authorship & Commit Standards

### 1.1 Committer & Author Identity
* **Mandatory Author:** All commits must be authored strictly under:
  ```
  Name:  Anurup R Krishnan
  Email: anuruprkrishnan@gmail.com
  ```
* Verify with `git config user.name` and `git config user.email` before creating any commit.

### 1.2 Prohibited Attribution Footers
* **NEVER** add `Co-authored-by:` lines, `Generated with Claude Code`, `Antigravity`, or any AI tool trailers to commit messages or pull requests.
* Commit messages must appear as genuine, human-authored engineering contributions.

### 1.3 Commit Message Style
* Ask for explicit user approval before every new commit or push. Preparing changes does not authorize publication.
* Use descriptive branch names without the `codex/` prefix.
* Keep every commit message under 15 words.
* Keep commit messages concise, lowercase, and directly descriptive of the action taken (e.g., `replace phase field with capability across services and scripts`, `standardize test fixtures and falco rule tags`).
* Avoid vague, ceremonial, or verbose commit messages.

### 1.4 Multi-Repository & Branch Synchronization
* The project exists across two local directories:
  * Primary working workspace: `/home/anuruprkris/Project/final_yeat_work`
  * Mirror/Git upstream repository: `/home/anuruprkris/Project/Porygon`
* When changes are finalized and tested in `final_yeat_work`, mirror them to `Porygon` on a dedicated branch (e.g., `final-work`), ask for approval before committing with the mandatory author identity and pushing to GitHub remote `origin` (`https://github.com/Anurup-R-Krishnan/Porygon.git`).

---

## 2. File & Directory Integrity (Strict No-Touch Rules)

### 2.1 Academic Presentations & Slides (Strict No-Touch Rule)
* **NEVER** modify, delete, or untrack LaTeX presentation decks (`docs/presentation/*.tex`) or generated PDFs (`docs/presentation/*.pdf`).
* **NEVER** remove or alter the university academic course title:
  ```latex
  \textbf{23CSE498 -- Project Phase 2 (Panel Review 1)} \quad | \quad \textbf{Team Number: 75}
  ```
* These presentation files represent immutable academic defense artifacts.

### 2.2 Research Protocols & Scientific Reproducibility
* Preserve all 12 academic protocol files under `docs/research/` with a master index.
* Core theoretical files—including `threat-model-claims.md` and `threat-model-claims-v1.md`—must remain intact for theoretical consistency and verification by `scripts/check_research_protocol.py`.
* All documentation files must use lowercase, kebab-case naming (e.g., `adversarial-scenarios.md`, `anomaly-detection-protocol.md`). Never introduce erratic mixtures of uppercase acronyms (`PROTOCOL_V1.md`) and lowercase filenames.

### 2.3 README Quality ("No-Slop" Policy)
* Never overwrite the primary [`README.md`](file:///home/anuruprkris/Project/final_yeat_work/README.md) with generic, AI-generated marketing text or superficial summaries.
* Maintain the real architecture diagrams, setup commands, Docker compose workflows, and environment variable references.
* Append new documentation indices cleanly after the configuration section.

---

## 3. Microservice Architecture & Terminology Standards

### 3.1 Phase Milestone Purge vs. Capability Standard
* **Do NOT** use legacy milestone numbers (`phase1`, `phase2`, `phase3`, `phase4`, `phase5`, `phase6`, `phase7`, `phase8`) in active application code, microservice healthchecks, API schemas, or verification scripts.
* Standardize service capability metadata across all microservices using the `capability` field:
  | Service | Capability Identifier | Primary Role |
  | :--- | :--- | :--- |
  | **`telemetry`** | `process-telemetry` | Kernel eBPF exec event ingestion & normalization via Falco |
  | **`collector`** | `event-ingestion` | Docker Engine lifecycle streaming & container inspection |
  | **`responder`** | `containment-response` | Policy-driven container containment (`pause`, `stop`) |
  | **`scanner`** | `vulnerability-enrichment` | Trivy CVE scanning, EPSS & CISA KEV threat intel enrichment |
* The term "Phase" is strictly reserved for the university course title (`23CSE498 Project Phase 2`).

### 3.2 Database Migrations (Alembic) Safety
* Alembic revision script names (e.g., `0001_phase1`, `0004_phase4`) in `backend/alembic/versions/` represent historical migration identifiers.
* **Never** rename or tamper with existing migration revision IDs or down-revision chains, as doing so breaks database schema evolution.
* Always verify migration integrity with dry-runs:
  ```bash
  alembic upgrade head --dry-run
  ```

### 3.3 Prohibition of Arbitrary Version Suffixes (`v1`, `v2`, `0.0.1`, `v1.0.0`)
* **Prohibited Ad-Hoc Version Tagging:** Do **NOT** introduce or append arbitrary, premature, or ad-hoc version suffixes (e.g., `v1`, `v2`, `0.0.1`, `v1.0.0`, `v0.8.0`) to filenames, documentation files, directories, UI headers, schemas, or script names.
* **Canonical & Purpose-Driven Naming:**
  * Use descriptive, canonical, and functional identifiers instead of proliferating version-stamped duplicates (e.g., prefer `pilot-dataset` or `adversarial-scenarios.md` over juggling `pilot-v1` vs. `pilot-v1.0.0`).
  * Avoid naming files or test scripts with superficial version appendages (e.g., avoid `PROTOCOL_V1.md`, `test_v2.py`, `script_v1.sh`).
* **UI & Presentation Cleanliness:**
  * Do not clutter UI headers, mastheads, or dashboard footers with artificial release tags like `Vol. I`, `v1.0.0`, or `v0.0.1`. Keep system branding clean, authoritative, and stable.
* **Preservation of Established Historical Protocols:**
  * Pre-existing frozen protocol files verified by automated protocol checkers (such as `threat-model-claims-v1.md` or `protocol-v1/`) remain immutable per Section 2.2, but no *new* arbitrary `v1`/`0.0.1` tags may be introduced across code, docs, or UI.

---

## 4. Codebase Auditing, Tooling & Verification Workflow

### 4.1 Comprehensive Search ("Grep All") Rule
* When investigating, refactoring, or auditing any field, schema, or function name:
  * **Always grep across the entire repository** using ripgrep (`grep_search` / `rg`).
  * Never assume an identifier only exists in one service. Check `backend`, `collector`, `telemetry`, `responder`, `scanner`, `scripts`, `dashboard`, and `artifacts`.
  * Verify both occurrences in source code and assertions in verification test scripts (`scripts/verify_*.sh`).

### 4.2 Mandatory Verification Suite Before Declaring Completion
Before committing any changes or concluding a task, run the full verification battery:
1. **Static Typing & Code Style:**
   ```bash
   make verify-static
   ```
2. **Microservice Unit Tests:**
   ```bash
   pytest backend/tests/
   pytest telemetry/tests/
   pytest collector/tests/
   pytest responder/tests/
   pytest scanner/tests/
   ```
3. **Research Protocol Integrity:**
   ```bash
   python3 scripts/check_research_protocol.py
   ```
4. **Shell Verification Scripts:**
   ```bash
   bash scripts/verify_infrastructure.sh
   bash scripts/verify_event_ingestion.sh
   bash scripts/verify_ebpf_telemetry.sh
   bash scripts/verify_behavior_profiling.sh
   bash scripts/verify_anomaly_scoring.sh
   bash scripts/verify_detection_engine.sh
   bash scripts/verify_containment_response.sh
   ```

### 4.3 Documentation & Code Integrity
* Preserve existing comments, docstrings, and type hints across files.
* Do not delete explanatory notes or scientific citations unless explicitly requested.

---

## 5. Evaluation & Audit Philosophy

### 5.1 Adversarial, Fault-Finding Focus (No Boilerplate)
* When requested to evaluate or audit the project:
  * **Reject boilerplate checklists:** Do not provide generic OWASP Top 10 summaries, superficial praise, or synthetic security scan outputs.
  * **Conduct adversarial evaluations:** Analyze the code from first principles to expose real race conditions, architectural flaws, telemetry blind spots, scoring formula limitations, and operational bottlenecks.
  * **Cite exact code coordinates:** Every fault must cite concrete file paths, line numbers, and execution sequences.

---

## 6. Web Application & Dashboard Guidelines

* **Project Homepage:** Provide a clean, modern landing interface introducing Porygon's container security research architecture, with seamless navigation to the interactive dashboard.
* **Visual Excellence:** Follow modern, high-contrast dark themes with clean typography (Inter / Roboto), subtle micro-animations, structured metrics, and accessible data visualizations.
* **Testing IDs:** Ensure all interactive elements have unique, descriptive IDs for browser automation and automated verification.
* **Clean, Uncluttered Editorial Typography:** Never clutter UI headers, titles, or mastheads with ad-hoc version badges (`v1`, `0.0.1`, `Vol. I`); maintain clean, authoritative publication standards.
