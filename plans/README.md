# Implementation plans

Numbered plans are executed in order. A plan is authoritative for the code it
touches: read it fully, run every gate it names, and honour its STOP conditions
before editing related code.

| # | Plan | Scope | Status |
|---|------|-------|--------|
| 010 | [010-operator-console-hardening.md](010-operator-console-hardening.md) | Remove the unverified third-party supply chain from the operator console; add SRI, CSP, and a real credential boundary | done |
| 020 | [020-console-quality-gates.md](020-console-quality-gates.md) | Bring `dashboard/` inside lint, test, and verification gates | largely done: node:test suite (60 tests) in verify-unit; markup, supply-chain and API-contract gates in verify-static; served by gateway. Monolith split ongoing via src/ modules |
| 030 | [030-clean-clone-reproducibility.md](030-clean-clone-reproducibility.md) | Make `make verify-static` and the presentation decks build from a fresh clone | done; deck-PDF policy awaits owner |
| 040 | [040-console-feature-depth.md](040-console-feature-depth.md) | Polling discipline, accessibility, and operator-workflow depth | 040.1-040.2 done, truthfulness fixes landed; 040.4 open |
| 050 | [050-evidence-capture.md](050-evidence-capture.md) | Reproducible console screenshot capture wired to the deck build inputs | capture tooling done; deck wiring pending |

## Conventions

- Frozen research semantics are out of scope. `docs/RESEARCH_PROTOCOL_V1.md`,
  the scoring/profiling maths in `backend/src/porygon_api/scoring.py`,
  `calibrated_rarity.py`, `calibrated_provenance.py`, and the
  `experiments/` artifact contract are not to be altered by these plans. Any
  change that would move a measured number is a protocol amendment, not a fix.
- Every plan lands as one or more commits that each leave `make verify-static`
  green and the touched service's unit tests passing.
