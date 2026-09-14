# Deviations against RESEARCH_PROTOCOL_V1

This document records findings against the frozen protocol
(`docs/RESEARCH_PROTOCOL_V1.md`) without editing it. Per the protocol's own freeze
rule ("Protocol revision and freeze rule"), any change to the protocol text requires
a new version, rationale, timestamp, affected question/hypothesis/claim IDs, reviewer
decisions, and an explicit reset of exploratory/confirmatory status. A deviation log
is the correct place to record a problem discovered against the frozen text; it is
not a substitute for, and does not perform, a protocol revision.

## D-001: The two recorded reviews are not independent

**Status: open. Confirmatory data collection remains prohibited by this finding.**

The protocol's "Human review record" table and machine-readable manifest record two
approvals:

| Role | Reviewer | Date | Decision |
|---|---|---|---|
| Security reviewer | Anurup R Krishnan | 2026-09-05 | approved |
| Methodology reviewer | Anurup R Krishnan | 2026-09-05 | approved |

Both `docs/review/security-review.json` and `docs/review/methodology-review.json`
name the same person (`reviewer_name: "Anurup R Krishnan"`) as both the security
reviewer and the methodology reviewer. That person is also the study author.

The protocol requires **independent** human review before confirmatory execution
may begin ("Plan 004 and Plan 005 must not begin confirmatory execution until both
required human reviews approve this document and status becomes `frozen`", read
together with the two distinct reviewer roles the review record table defines and
the per-role checklists each reviewer is asked to attest against). A single person
reviewing their own study design under two hats is a self-review, not an independent
review: it does not provide the check the protocol's two-reviewer structure exists
to provide (an author cannot be expected to catch their own blind spots by re-reading
their own reasoning under a different job title).

This is a deviation from the protocol's intent, not from its literal text — the
protocol does not spell out an algorithm for "independence" for `review_gate.py` to
have originally enforced, and the tool as it stood before this fix only checked that
a decision file existed, said `"approved"`, and had a non-placeholder name and date.
Both existing review files satisfy that literal, narrower check, which is how the
protocol manifest's `protocol_status` came to read `"frozen"` and the review record
table came to show two "approved" rows against the same name.

### Remediation applied (this change)

`scripts/review_gate.py` now enforces independence programmatically rather than
relying on a human to notice the same name appears twice:

- `reviewer_independence()` normalizes both recorded reviewer names (case-fold,
  strip punctuation, collapse whitespace) and fails independence when they match,
  when either name is blank or the unfilled placeholder, or when either review sets
  the new optional `self_review: true` field.
- `gate_state()` (`status` subcommand) now computes `confirmatory_permitted` as
  `protocol_status == "frozen" AND both reviews are clean approvals (via
  approval_problems()) AND reviewer_independence().independent`, and exposes the
  named `approval_problems` per role plus the independence result and reason, so a
  caller sees exactly why confirmatory collection is or is not permitted rather than
  only a boolean.
- `cmd_apply()` refuses (non-zero exit, explicit stderr message) to record a new
  approval that is not independent, so this specific failure mode cannot recur going
  forward.

Because the protocol document's manifest literally says `"protocol_status":
"frozen"` already (from the prior, insufficiently-independent apply), and this fix
deliberately does not edit that document, `docs/RESEARCH_PROTOCOL_V1.md` continues to
read "frozen" on its face. The corrected `review_gate.py status` is the authority on
whether confirmatory collection is actually permitted, and — as of this deviation
being recorded — it reports `confirmatory_permitted: false`, with
`independence.independent: false` and
`independence.reason` naming the same-reviewer collision, against the current
contents of `docs/review/security-review.json` and
`docs/review/methodology-review.json`.

### What resolves this deviation

A genuinely independent security reviewer and methodology reviewer — two different
people, neither of whom is the study author, each completing their own checklist
against the current protocol digest — recording fresh decisions in
`docs/review/security-review.json` and `docs/review/methodology-review.json` (via
`python3 scripts/review_gate.py prepare` regenerating the templates, which now also
capture `reviewer_contact` and an explicit `self_review` flag for future
attestation). Once both files name distinct, non-placeholder reviewers with clean
checklists against the current protocol digest, `reviewer_independence()` and
`confirmatory_permitted` will correctly flip to `true` and this deviation can be
marked resolved — it is intentionally written to *stay* meaningful (and start
passing) once that real review happens, per `experiments/tests/test_review_gate.py`.

## Non-deviations

No other deviation from the frozen protocol's stated requirements has been found in
the scope of this review-gate change. This document does not evaluate the
substantive methodology or security checklist answers recorded in the two review
files (whether the self-reviewer's technical findings are correct) — only the
structural fact that the two roles were not filled by different people.
