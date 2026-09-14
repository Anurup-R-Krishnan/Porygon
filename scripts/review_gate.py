#!/usr/bin/env python3
"""Prepare, inspect and consume the independent review of the research protocol.

The protocol requires one security reviewer and one methodology reviewer to approve
the study design before confirmatory results may be collected. That decision belongs
to people, so this tool does not make it. It automates everything around it:

    prepare   build the package the two reviewers need, with role checklists and the
              current validation evidence, plus a decision file for each to fill in
    status    report exactly what the gate is waiting for, machine-readable
    apply     consume completed decision files and, only if both are genuine
              approvals, move the protocol to frozen and re-validate it

`apply` refuses to write an approval that a reviewer did not record. It never invents
a name, a date, or a decision.

Usage:
    python3 scripts/review_gate.py prepare
    python3 scripts/review_gate.py status [--json]
    python3 scripts/review_gate.py apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/RESEARCH_PROTOCOL_V1.md"
REVIEW_DIR = ROOT / "docs/review"
ROLES = ("security", "methodology")

CHECKLISTS: dict[str, list[str]] = {
    "security": [
        "Container privilege: every experiment container is disposable, memory and PID capped, published on loopback only, and removed by exact name plus label match.",
        "Docker socket exposure: which services hold it, read-only or read-write, and why each needs it.",
        "Scenario safety: the controlled scenarios execute only inert, fixture-only commands inside disposable containers. No malware, no external target, no destructive host action.",
        "Secret minimisation: command arguments are reduced to a shape before storage; the artifact writer refuses to persist a secret-like value and names only the location when it does.",
        "Containment authority: response stays observe-only by default and no disruptive action is reachable without explicit human approval.",
        "Blast radius: confirm cleanup cannot touch a resource outside the current trial, and that the refusal paths are tested rather than assumed.",
        "Data retention: confirm the capture scope and retention settings keep only what the study needs.",
    ],
    "methodology": [
        "Independent unit: the unit of analysis is a complete workload run, never an observation window inside a run.",
        "Split isolation: fit, calibration and test assignment is by whole run, computed from the run identifier before execution, and leakage fails validation rather than warning.",
        "Hypotheses and failure criteria: the null and alternative hypotheses, the effect size, and the conditions under which the result is reported as negative, are all fixed before collection.",
        "Estimands and multiplicity: the primary contrasts, the family-wise correction, and the interval method are stated and match the analysis code.",
        "Calibration validity: the conformal procedure's exchangeability assumption is stated, and drift is surfaced rather than absorbed.",
        "Context variants: each runtime-context variant is classified as a positive or negative control from measured evidence, not assumed.",
        "Claim boundaries: no output is described as a probability of attack, and deterministic rule matches are evidence rather than proof.",
        "Sample size: the recorded counts per cell support the stated power, or the limitation is reported instead of a superiority claim.",
    ],
}


# ---------------------------------------------------------------------------
# Protocol reading
# ---------------------------------------------------------------------------


def read_protocol() -> str:
    return PROTOCOL.read_text(encoding="utf-8")


def manifest_of(text: str) -> dict:
    match = re.search(r"```json protocol-manifest\n(.*?)```", text, re.DOTALL)
    if not match:
        raise SystemExit("the protocol has no machine-readable manifest block")
    return json.loads(match.group(1))


def protocol_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def decision_path(role: str) -> Path:
    return REVIEW_DIR / f"{role}-review.json"


def load_decision(role: str) -> dict | None:
    path = decision_path(role)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{path} is not valid JSON: {error}")


PLACEHOLDER_NAME = "REPLACE WITH YOUR NAME"
PLACEHOLDER_DATE = "YYYY-MM-DD"
_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _parseable_iso_date(value: object) -> bool:
    """True only for a real, parseable YYYY-MM-DD date — the literal placeholder fails."""
    if not isinstance(value, str) or not _ISO_DATE_RE.match(value):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def normalize_reviewer_name(name: object) -> str:
    """Case-fold, strip punctuation, and collapse whitespace for name comparison."""
    if not isinstance(name, str):
        return ""
    lowered = name.strip().lower()
    no_punct = re.sub(r"[^\w\s]", "", lowered, flags=re.UNICODE)
    return re.sub(r"\s+", " ", no_punct).strip()


def approval_problems(decision: dict | None, role: str) -> list[str]:
    """Every reason `decision` does not count as a genuine, current approval for `role`.

    An empty list means the decision is a clean approval. This intentionally returns
    named problems instead of a bool so callers (CLI output, tests, the gate state)
    can say exactly what is wrong rather than just "no".
    """
    if not isinstance(decision, dict):
        return ["no decision file recorded"]

    problems: list[str] = []

    if decision.get("decision") != "approved":
        problems.append(f"decision is {decision.get('decision', 'absent')!r}, not 'approved'")

    name = decision.get("reviewer_name")
    if not isinstance(name, str) or name.strip() in ("", PLACEHOLDER_NAME):
        problems.append("reviewer_name is empty or still the placeholder")

    raw_date = decision.get("date")
    if raw_date == PLACEHOLDER_DATE:
        problems.append("date is still the literal placeholder 'YYYY-MM-DD'")
    elif not _parseable_iso_date(raw_date):
        problems.append("date is not a real parseable YYYY-MM-DD date")

    required = set(CHECKLISTS.get(role, []))
    checklist = decision.get("checklist")
    if not isinstance(checklist, dict):
        problems.append("checklist is missing or is not an object")
        checklist = {}
    actual = set(checklist.keys())
    missing = required - actual
    extra = actual - required
    if missing:
        problems.append(f"checklist is missing required item(s): {sorted(missing)}")
    if extra:
        problems.append(f"checklist has unexpected item(s) not in the {role} checklist: {sorted(extra)}")
    for item in sorted(actual & required):
        value = checklist.get(item)
        if not isinstance(value, str) or value.strip() == "" or value.strip().lower() == "unreviewed":
            problems.append(f"checklist item is unreviewed or empty: {item!r}")

    reviewed_digest = decision.get("protocol_sha256_reviewed")
    if not reviewed_digest or not isinstance(reviewed_digest, str):
        problems.append("protocol_sha256_reviewed is missing")
    else:
        # `apply` itself rewrites the protocol text (status line, review table,
        # manifest reviewer/frozen_at_utc fields) the moment it freezes it, so the
        # live document's digest necessarily differs from what was reviewed *the
        # instant it is frozen* -- that is the freeze transition succeeding, not a
        # stale review. Only compare against the live digest while the protocol is
        # still in the pre-freeze state the reviewer actually looked at; `apply`
        # itself already enforces this exact match before it ever freezes anything.
        text = read_protocol()
        if manifest_of(text).get("protocol_status") != "frozen":
            current_digest = protocol_digest(text)
            if reviewed_digest != current_digest:
                problems.append(
                    "protocol_sha256_reviewed does not match the current protocol "
                    "document (the review was recorded against a different version "
                    "of the text)"
                )

    return problems


def decision_is_approval(decision: dict | None, role: str) -> bool:
    """Backward-compatible bool view of `approval_problems`."""
    return not approval_problems(decision, role)


def reviewer_independence(decisions: dict[str, dict | None]) -> dict:
    """Whether the recorded reviews come from genuinely different people.

    Fails independence if either name is blank/placeholder, either record sets
    `self_review: true` (an optional, opt-in field — absent/false does not fail this
    check), or the normalized names collide.
    """
    names: dict[str, str | None] = {}
    reasons: list[str] = []
    normalized: dict[str, str] = {}

    for role in ROLES:
        decision = decisions.get(role)
        raw_name = decision.get("reviewer_name") if isinstance(decision, dict) else None
        names[role] = raw_name if isinstance(raw_name, str) else None
        norm = normalize_reviewer_name(raw_name)
        normalized[role] = norm
        if not norm or norm == normalize_reviewer_name(PLACEHOLDER_NAME):
            reasons.append(f"{role} reviewer_name is blank or a placeholder")
        if isinstance(decision, dict) and decision.get("self_review") is True:
            reasons.append(f"{role} review is flagged self_review")

    role_a, role_b = ROLES[0], ROLES[1]
    if normalized[role_a] and normalized[role_b] and normalized[role_a] == normalized[role_b]:
        reasons.append(
            f"{role_a} and {role_b} reviews name the same reviewer "
            f"({names[role_a]!r})"
        )

    independent = not reasons
    reason = "; ".join(reasons) if reasons else "reviewers are distinct and neither is a self-review"
    return {"independent": independent, "reason": reason, "names": names}


# ---------------------------------------------------------------------------
# prepare
# ---------------------------------------------------------------------------


def _evidence_summary() -> dict:
    """Collect the objective facts a reviewer needs, without interpreting them."""
    def run(*args: str) -> str:
        try:
            return subprocess.run(args, capture_output=True, text=True, cwd=ROOT,
                                  timeout=120).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "unavailable"

    runs_dir = ROOT / "artifacts/experiments/local"
    trials = sorted(runs_dir.glob("*/trials/*.json")) if runs_dir.is_dir() else []
    completed = failed = 0
    for path in trials:
        try:
            status = json.loads(path.read_text(encoding="utf-8")).get("status")
        except (OSError, json.JSONDecodeError):
            continue
        completed += status == "completed"
        failed += status == "failed"
    return {
        "git_commit": run("git", "rev-parse", "HEAD"),
        "git_dirty": bool(run("git", "status", "--porcelain")),
        "protocol_sha256": protocol_digest(read_protocol()),
        "trial_records": len(trials),
        "trials_completed": completed,
        "trials_failed": failed,
        "structural_check": run("python3", "scripts/check_research_protocol.py").splitlines()[:2],
    }


def cmd_prepare() -> int:
    text = read_protocol()
    manifest = manifest_of(text)
    REVIEW_DIR.mkdir(parents=True, exist_ok=True)
    evidence = _evidence_summary()

    for role in ROLES:
        path = decision_path(role)
        if path.is_file():
            print(f"kept existing {path.relative_to(ROOT)}")
            continue
        path.write_text(json.dumps({
            "role": role,
            "protocol_id": manifest.get("protocol_id"),
            "protocol_sha256_reviewed": evidence["protocol_sha256"],
            "reviewer_name": "REPLACE WITH YOUR NAME",
            "reviewer_contact": "REPLACE WITH YOUR EMAIL OR OTHER CONTACT",
            "self_review": False,
            "date": "YYYY-MM-DD",
            "decision": "pending",
            "decision_options": ["approved", "changes_requested", "rejected"],
            "checklist": {item: "unreviewed" for item in CHECKLISTS[role]},
            "notes": "",
        }, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")

    lines = [
        "# Independent review package",
        "",
        "This package is generated. Regenerate it with "
        "`python3 scripts/review_gate.py prepare`.",
        "",
        "The study design requires two independent reviews before confirmatory results",
        "may be collected. Everything else in the pipeline is automated; this is the one",
        "step that is deliberately a human decision.",
        "",
        "'Independent' is enforced, not just requested: the security and methodology",
        "reviewers must be different people. `apply` compares normalized reviewer names",
        "and the `self_review` flag, and refuses to freeze the protocol if both reviews",
        "trace back to the same person.",
        "",
        "## What the reviewer is approving",
        "",
        f"- Protocol: `{PROTOCOL.relative_to(ROOT)}`",
        f"- Protocol SHA-256: `{evidence['protocol_sha256']}`",
        f"- Repository commit: `{evidence['git_commit']}`"
        + ("  (working tree has uncommitted changes)" if evidence["git_dirty"] else ""),
        "",
        "A decision applies to the exact protocol bytes above. If the protocol changes",
        "afterwards, the review is re-run against the new digest.",
        "",
        "## Evidence available to the reviewer",
        "",
        f"- Trial records collected: {evidence['trial_records']} "
        f"({evidence['trials_completed']} completed, {evidence['trials_failed']} failed)",
        "- Structural validation of the protocol:",
    ]
    lines += [f"  - `{line}`" for line in evidence["structural_check"]]
    lines += [
        "",
        "Supporting documents:",
        "",
        "- `docs/THREAT_MODEL_V1.md` — assets, trust boundaries, attacker capabilities",
        "- `docs/CLAIMS_V1.md` — what may and may not be claimed",
        "- `docs/PROFILE_SCOPE_EXPERIMENT_V1.md` — profile arms and the context identity",
        "- `docs/design-decisions.md` — why each decision was taken and what it costs",
        "- `docs/execution-status.md` — measured state of every module",
        "- `docs/final-verification-report.md` — gate results and measured findings",
        "",
    ]
    for role in ROLES:
        lines += [f"## {role.capitalize()} reviewer checklist", ""]
        lines += [f"{index}. {item}" for index, item in enumerate(CHECKLISTS[role], 1)]
        lines += [
            "",
            f"Record the decision in `docs/review/{role}-review.json`: set `reviewer_name`,",
            "`reviewer_contact`, `date`, `decision`, and mark each checklist entry `ok` or",
            "describe the concern. Set `self_review: true` only if you are also the study",
            "author or are otherwise reviewing your own design decisions.",
            "",
        ]
    lines += [
        "## Applying the decisions",
        "",
        "```bash",
        "python3 scripts/review_gate.py status",
        "python3 scripts/review_gate.py apply",
        "```",
        "",
        "`apply` moves the protocol to frozen only when both files record a genuine",
        "approval with a reviewer name and a date, both reviews name genuinely different",
        "people, and neither is marked `self_review`. It then re-runs structural",
        "validation. A decision of `changes_requested` or `rejected` leaves the protocol",
        "unchanged, and so does a pair of reviews that are not independent.",
        "",
    ]
    package = REVIEW_DIR / "REVIEW_PACKAGE.md"
    package.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {package.relative_to(ROOT)}")
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def gate_state() -> dict:
    text = read_protocol()
    manifest = manifest_of(text)
    decisions = {role: load_decision(role) for role in ROLES}
    problems = {role: approval_problems(decisions[role], role) for role in ROLES}
    approvals = {role: not problems[role] for role in ROLES}
    independence = reviewer_independence(decisions)
    confirmatory_permitted = (
        manifest.get("protocol_status") == "frozen"
        and all(approvals.values())
        and independence["independent"]
    )
    waiting_on = [role for role in ROLES if not approvals[role]]
    if independence["independent"] is False and not waiting_on:
        # both individual reviews are otherwise clean approvals, but they are not
        # independent of each other -- surface that as the blocker.
        waiting_on = list(ROLES)
    return {
        "protocol_status": manifest.get("protocol_status"),
        "protocol_sha256": protocol_digest(text),
        "package_prepared": (REVIEW_DIR / "REVIEW_PACKAGE.md").is_file(),
        "decisions": {
            role: (decisions[role] or {}).get("decision", "absent") for role in ROLES
        },
        "approved": approvals,
        "approval_problems": problems,
        "independence": independence,
        "ready_to_freeze": (
            all(approvals.values())
            and independence["independent"]
            and manifest.get("protocol_status") != "frozen"
        ),
        "confirmatory_permitted": confirmatory_permitted,
        "waiting_on": waiting_on,
    }


def cmd_status(as_json: bool) -> int:
    state = gate_state()
    if as_json:
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    print(f"protocol status      : {state['protocol_status']}")
    print(f"review package built : {state['package_prepared']}")
    for role in ROLES:
        print(f"{role + ' decision':21}: {state['decisions'][role]}"
              f"{'  (approved)' if state['approved'][role] else ''}")
        for problem in state["approval_problems"][role]:
            print(f"  - {problem}")
    print(f"reviewer independence: {state['independence']['independent']} "
          f"({state['independence']['reason']})")
    print(f"confirmatory allowed : {state['confirmatory_permitted']}")
    if state["waiting_on"]:
        print(f"waiting on           : {', '.join(state['waiting_on'])}")
    return 0


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------


def cmd_apply() -> int:
    text = read_protocol()
    manifest = manifest_of(text)
    if manifest.get("protocol_status") == "frozen":
        print("protocol is already frozen; nothing to apply")
        return 0

    decisions = {}
    for role in ROLES:
        decision = load_decision(role)
        if decision is None:
            raise SystemExit(
                f"missing {decision_path(role).relative_to(ROOT)}; "
                "run `python3 scripts/review_gate.py prepare` first"
            )
        problems = approval_problems(decision, role)
        if problems:
            print(f"[blocked] {role} review is not a valid approval; "
                  "the protocol stays as it is:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            return 2
        decisions[role] = decision

    independence = reviewer_independence(decisions)
    if not independence["independent"]:
        print(f"[blocked] the two reviews are not independent ({independence['reason']}); "
              "the protocol stays as it is", file=sys.stderr)
        return 2

    today = date.today().isoformat()
    updated = text.replace(
        "Status: **REVIEW PENDING — CONFIRMATORY COLLECTION PROHIBITED**",
        "Status: **FROZEN — CONFIRMATORY COLLECTION PERMITTED**",
    ).replace("Document version: `1.0.0-review-pending`", "Document version: `1.0.0-frozen`")

    for role, label in (("security", "Security reviewer"), ("methodology", "Methodology reviewer")):
        decision = decisions[role]
        pattern = re.compile(rf"^\| {label} \| \*\*pending\*\* \| — \| pending \|", re.MULTILINE)
        replacement = (f"| {label} | **{decision['reviewer_name']}** | "
                       f"{decision['date']} | approved |")
        updated, count = pattern.subn(replacement, updated)
        if count != 1:
            raise SystemExit(f"could not locate the {label} row in the review record table")

    manifest["protocol_status"] = "frozen"
    manifest["reviewers"] = [
        {"role": role, "status": "approved",
         "name": decisions[role]["reviewer_name"], "date": decisions[role]["date"]}
        for role in ROLES
    ]
    manifest["frozen_at_utc"] = datetime.now(timezone.utc).isoformat()
    updated = re.sub(
        r"```json protocol-manifest\n.*?```",
        "```json protocol-manifest\n" + json.dumps(manifest, indent=2) + "\n```",
        updated, flags=re.DOTALL,
    )

    PROTOCOL.write_text(updated, encoding="utf-8")
    print(f"protocol frozen on {today} with both approvals recorded")

    check = subprocess.run(["python3", "scripts/check_research_protocol.py"],
                           cwd=ROOT, capture_output=True, text=True, timeout=300)
    print(check.stdout.strip())
    if check.returncode != 0:
        print(check.stderr.strip(), file=sys.stderr)
        print("[blocked] the frozen protocol failed structural validation; reverting",
              file=sys.stderr)
        PROTOCOL.write_text(text, encoding="utf-8")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("prepare", help="build the reviewer package and decision files")
    status = sub.add_parser("status", help="report what the gate is waiting for")
    status.add_argument("--json", action="store_true")
    sub.add_parser("apply", help="consume completed decisions and freeze the protocol")
    args = parser.parse_args()
    if args.command == "prepare":
        return cmd_prepare()
    if args.command == "status":
        return cmd_status(args.json)
    return cmd_apply()


if __name__ == "__main__":
    raise SystemExit(main())
