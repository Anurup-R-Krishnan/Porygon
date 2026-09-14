"""Tests for scripts/review_gate.py.

Covers the independent-review enforcement added on top of the original
"is there a decision file that says approved" check: named approval problems,
reviewer independence (same-reviewer detection, placeholders, self_review),
checklist exactness, protocol digest staleness, and that `apply` refuses to
record a non-independent approval. One test asserts against the *actual*
current `docs/review/*.json` files, which as of this change both name the
same reviewer and are therefore correctly not independent.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "review_gate.py"
spec = importlib.util.spec_from_file_location("review_gate", SCRIPT_PATH)
review_gate = importlib.util.module_from_spec(spec)
sys.modules["review_gate"] = review_gate
spec.loader.exec_module(review_gate)


CURRENT_DIGEST = review_gate.protocol_digest(review_gate.read_protocol())


def _valid_checklist(role: str) -> dict:
    return {item: "pass - reviewed and confirmed" for item in review_gate.CHECKLISTS[role]}


def _valid_decision(role: str, *, name: str = "Alice Example", when: str = "2026-09-10") -> dict:
    return {
        "role": role,
        "protocol_sha256_reviewed": CURRENT_DIGEST,
        "reviewer_name": name,
        "date": when,
        "decision": "approved",
        "checklist": _valid_checklist(role),
        "notes": "",
    }


# ---------------------------------------------------------------------------
# approval_problems: individual field checks
# ---------------------------------------------------------------------------


def test_clean_decision_has_no_problems():
    decision = _valid_decision("security")
    assert review_gate.approval_problems(decision, "security") == []
    assert review_gate.decision_is_approval(decision, "security") is True


def test_literal_placeholder_date_is_rejected():
    decision = _valid_decision("security")
    decision["date"] = "YYYY-MM-DD"
    problems = review_gate.approval_problems(decision, "security")
    assert any("placeholder" in p and "date" in p for p in problems)
    assert review_gate.decision_is_approval(decision, "security") is False


def test_non_iso_date_is_rejected_even_if_not_the_literal_placeholder():
    decision = _valid_decision("security")
    decision["date"] = "09/10/2026"
    problems = review_gate.approval_problems(decision, "security")
    assert any("date" in p for p in problems)


def test_placeholder_reviewer_name_is_rejected():
    decision = _valid_decision("security")
    decision["reviewer_name"] = "REPLACE WITH YOUR NAME"
    problems = review_gate.approval_problems(decision, "security")
    assert any("reviewer_name" in p for p in problems)


def test_decision_not_approved_is_rejected():
    decision = _valid_decision("security")
    decision["decision"] = "changes_requested"
    problems = review_gate.approval_problems(decision, "security")
    assert any("not 'approved'" in p for p in problems)


def test_unreviewed_checklist_value_blocks_approval():
    decision = _valid_decision("methodology")
    first_item = next(iter(decision["checklist"]))
    decision["checklist"][first_item] = "unreviewed"
    problems = review_gate.approval_problems(decision, "methodology")
    assert any("unreviewed" in p for p in problems)
    assert review_gate.decision_is_approval(decision, "methodology") is False


def test_blank_and_whitespace_checklist_values_block_approval():
    decision = _valid_decision("methodology")
    items = list(decision["checklist"])
    decision["checklist"][items[0]] = ""
    decision["checklist"][items[1]] = "   "
    problems = review_gate.approval_problems(decision, "methodology")
    assert sum("unreviewed or empty" in p for p in problems) == 2


def test_checklist_missing_a_required_item_blocks_approval():
    decision = _valid_decision("security")
    items = list(decision["checklist"])
    del decision["checklist"][items[0]]
    problems = review_gate.approval_problems(decision, "security")
    assert any("missing required item" in p for p in problems)


def test_checklist_with_an_extra_unexpected_item_blocks_approval():
    decision = _valid_decision("security")
    decision["checklist"]["some new item nobody agreed to review"] = "pass"
    problems = review_gate.approval_problems(decision, "security")
    assert any("unexpected item" in p for p in problems)


def test_stale_protocol_digest_blocks_approval(tmp_path, monkeypatch):
    # The real repo protocol is already frozen, and `apply` itself rewrites the
    # text at freeze time (see the "frozen protocol never re-validates its own
    # digest" test below for why that specific state is deliberately exempt).
    # A stale digest must still block approval while the protocol is still in
    # its pre-freeze, review-pending state -- exercise that with a synthetic
    # not-yet-frozen protocol.
    protocol_text = _synthetic_protocol("review_pending")
    protocol_path = tmp_path / "PROTOCOL.md"
    protocol_path.write_text(protocol_text, encoding="utf-8")
    monkeypatch.setattr(review_gate, "PROTOCOL", protocol_path)

    decision = _valid_decision("security")
    decision["protocol_sha256_reviewed"] = "0" * 64
    problems = review_gate.approval_problems(decision, "security")
    assert any("does not match the current protocol document" in p for p in problems)


def test_missing_protocol_digest_blocks_approval(tmp_path, monkeypatch):
    protocol_text = _synthetic_protocol("review_pending")
    protocol_path = tmp_path / "PROTOCOL.md"
    protocol_path.write_text(protocol_text, encoding="utf-8")
    monkeypatch.setattr(review_gate, "PROTOCOL", protocol_path)

    decision = _valid_decision("security")
    del decision["protocol_sha256_reviewed"]
    problems = review_gate.approval_problems(decision, "security")
    assert any("protocol_sha256_reviewed is missing" in p for p in problems)


def test_frozen_protocol_does_not_re_litigate_its_own_freeze_induced_digest_change(tmp_path, monkeypatch):
    """`apply` rewrites the protocol text (status line, review table, manifest
    reviewer/frozen_at_utc fields) the instant it freezes it, so the live
    document's digest necessarily differs from what was reviewed the moment the
    freeze succeeds. If `approval_problems` compared the live digest against the
    reviewed digest unconditionally, EVERY successful freeze -- including a
    genuinely independent, correctly-executed one -- would permanently and
    incorrectly report a stale-digest problem forever after. Once frozen, a
    non-matching digest must not, by itself, block approval.
    """
    protocol_text = _synthetic_protocol("frozen")
    protocol_path = tmp_path / "PROTOCOL.md"
    protocol_path.write_text(protocol_text, encoding="utf-8")
    monkeypatch.setattr(review_gate, "PROTOCOL", protocol_path)

    decision = _valid_decision("security")
    decision["protocol_sha256_reviewed"] = "0" * 64  # would mismatch if checked
    problems = review_gate.approval_problems(decision, "security")
    assert not any("does not match the current protocol document" in p for p in problems)


def test_missing_decision_file_is_a_problem():
    assert review_gate.approval_problems(None, "security") == ["no decision file recorded"]


# ---------------------------------------------------------------------------
# reviewer_independence
# ---------------------------------------------------------------------------


def test_same_reviewer_both_roles_is_not_independent():
    decisions = {
        "security": _valid_decision("security", name="Anurup R Krishnan"),
        "methodology": _valid_decision("methodology", name="Anurup R Krishnan"),
    }
    result = review_gate.reviewer_independence(decisions)
    assert result["independent"] is False
    assert "same reviewer" in result["reason"]


def test_same_name_with_different_case_and_punctuation_is_still_not_independent():
    decisions = {
        "security": _valid_decision("security", name="  Anurup R. Krishnan  "),
        "methodology": _valid_decision("methodology", name="ANURUP R KRISHNAN"),
    }
    result = review_gate.reviewer_independence(decisions)
    assert result["independent"] is False


def test_distinct_named_reviewers_are_independent():
    decisions = {
        "security": _valid_decision("security", name="Alice Example"),
        "methodology": _valid_decision("methodology", name="Bob Sample"),
    }
    result = review_gate.reviewer_independence(decisions)
    assert result["independent"] is True
    assert result["names"] == {"security": "Alice Example", "methodology": "Bob Sample"}


def test_self_review_flag_blocks_independence_even_with_distinct_names():
    security = _valid_decision("security", name="Alice Example")
    security["self_review"] = True
    methodology = _valid_decision("methodology", name="Bob Sample")
    result = review_gate.reviewer_independence({"security": security, "methodology": methodology})
    assert result["independent"] is False
    assert "self_review" in result["reason"]


def test_self_review_absent_or_false_does_not_block_independence():
    security = _valid_decision("security", name="Alice Example")
    methodology = _valid_decision("methodology", name="Bob Sample")
    methodology["self_review"] = False
    result = review_gate.reviewer_independence({"security": security, "methodology": methodology})
    assert result["independent"] is True


def test_blank_reviewer_name_blocks_independence():
    security = _valid_decision("security", name="")
    methodology = _valid_decision("methodology", name="Bob Sample")
    result = review_gate.reviewer_independence({"security": security, "methodology": methodology})
    assert result["independent"] is False


# ---------------------------------------------------------------------------
# gate_state / confirmatory_permitted assembly
# ---------------------------------------------------------------------------


def test_gate_state_exposes_approval_problems_and_independence(tmp_path, monkeypatch):
    protocol_text = _synthetic_protocol("frozen")
    protocol_path = tmp_path / "PROTOCOL.md"
    protocol_path.write_text(protocol_text, encoding="utf-8")
    review_dir = tmp_path / "review"
    review_dir.mkdir()
    monkeypatch.setattr(review_gate, "PROTOCOL", protocol_path)
    monkeypatch.setattr(review_gate, "REVIEW_DIR", review_dir)

    digest = review_gate.protocol_digest(protocol_text)

    def same_name_decision(role: str) -> dict:
        return {**_valid_decision(role, name="Same Person"), "protocol_sha256_reviewed": digest}

    (review_dir / "security-review.json").write_text(json.dumps(same_name_decision("security")), encoding="utf-8")
    (review_dir / "methodology-review.json").write_text(json.dumps(same_name_decision("methodology")), encoding="utf-8")

    state = review_gate.gate_state()

    assert state["approval_problems"] == {"security": [], "methodology": []}
    assert state["independence"]["independent"] is False
    assert state["confirmatory_permitted"] is False  # frozen status alone is not enough


def _synthetic_protocol(protocol_status: str) -> str:
    manifest = {"protocol_id": "test.protocol.v1", "protocol_status": protocol_status}
    return (
        "# Test Protocol\n\n"
        "Status: **REVIEW PENDING — CONFIRMATORY COLLECTION PROHIBITED**\n\n"
        "Document version: `1.0.0-review-pending`\n\n"
        "## Human review record\n\n"
        "| Role | Reviewer | Date | Decision | Notes |\n"
        "|---|---|---|---|---|\n"
        "| Security reviewer | **pending** | — | pending | |\n"
        "| Methodology reviewer | **pending** | — | pending | |\n\n"
        "## Machine-readable traceability manifest\n\n"
        "```json protocol-manifest\n" + json.dumps(manifest, indent=2) + "\n```\n"
    )


# ---------------------------------------------------------------------------
# cmd_apply: refuses non-independent approvals
# ---------------------------------------------------------------------------


def test_apply_refuses_non_independent_approvals(tmp_path, monkeypatch, capsys):
    protocol_text = _synthetic_protocol("review_pending")
    protocol_path = tmp_path / "PROTOCOL.md"
    protocol_path.write_text(protocol_text, encoding="utf-8")
    review_dir = tmp_path / "review"
    review_dir.mkdir()
    monkeypatch.setattr(review_gate, "PROTOCOL", protocol_path)
    monkeypatch.setattr(review_gate, "REVIEW_DIR", review_dir)

    digest = review_gate.protocol_digest(protocol_text)
    for role in review_gate.ROLES:
        decision = _valid_decision(role, name="Same Person")
        decision["protocol_sha256_reviewed"] = digest
        (review_dir / f"{role}-review.json").write_text(json.dumps(decision), encoding="utf-8")

    exit_code = review_gate.cmd_apply()

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "not independent" in captured.err
    # the protocol must be left untouched -- apply must refuse before writing
    assert protocol_path.read_text(encoding="utf-8") == protocol_text


def test_apply_succeeds_with_genuinely_independent_approvals(tmp_path, monkeypatch, capsys):
    protocol_text = _synthetic_protocol("review_pending")
    protocol_path = tmp_path / "PROTOCOL.md"
    protocol_path.write_text(protocol_text, encoding="utf-8")
    review_dir = tmp_path / "review"
    review_dir.mkdir()
    monkeypatch.setattr(review_gate, "PROTOCOL", protocol_path)
    monkeypatch.setattr(review_gate, "REVIEW_DIR", review_dir)
    # avoid depending on scripts/check_research_protocol.py against a synthetic doc
    monkeypatch.setattr(
        review_gate.subprocess, "run",
        lambda *a, **k: type("R", (), {"returncode": 0, "stdout": "ok", "stderr": ""})(),
    )

    digest = review_gate.protocol_digest(protocol_text)
    names = {"security": "Alice Example", "methodology": "Bob Sample"}
    for role in review_gate.ROLES:
        decision = _valid_decision(role, name=names[role])
        decision["protocol_sha256_reviewed"] = digest
        (review_dir / f"{role}-review.json").write_text(json.dumps(decision), encoding="utf-8")

    exit_code = review_gate.cmd_apply()

    assert exit_code == 0
    updated = protocol_path.read_text(encoding="utf-8")
    assert '"protocol_status": "frozen"' in updated
    assert "Alice Example" in updated
    assert "Bob Sample" in updated

    # A genuinely independent, successful freeze must make confirmatory
    # collection permitted -- not perpetually blocked by the digest change that
    # `apply` itself just made while writing the freeze.
    state = review_gate.gate_state()
    assert state["confirmatory_permitted"] is True
    assert state["independence"]["independent"] is True


# ---------------------------------------------------------------------------
# Against the real, current docs/review/*.json files
# ---------------------------------------------------------------------------


def test_current_review_files_are_not_independent():
    """As of this change, both docs/review/*.json name the same reviewer and the
    same person is the study author. This must report independent: False. Once a
    genuinely independent pair of reviewers replaces these files, this test starts
    passing (independent: True) without needing to change -- it stays meaningful
    rather than being a snapshot of a bug.
    """
    security = review_gate.load_decision("security")
    methodology = review_gate.load_decision("methodology")
    assert security is not None, "docs/review/security-review.json must exist"
    assert methodology is not None, "docs/review/methodology-review.json must exist"

    result = review_gate.reviewer_independence({"security": security, "methodology": methodology})

    if result["independent"]:
        # a real independent review has replaced the placeholders -- nothing to assert
        return
    assert result["independent"] is False
    assert security.get("reviewer_name") == methodology.get("reviewer_name")


def test_current_gate_state_reports_confirmatory_not_permitted_for_same_reviewer():
    """End-to-end sanity check against the real repository files: `status` must not
    report confirmatory collection as permitted while both reviews share a reviewer.
    """
    security = review_gate.load_decision("security")
    methodology = review_gate.load_decision("methodology")
    independence = review_gate.reviewer_independence({"security": security, "methodology": methodology})
    if independence["independent"]:
        pytest.skip("a genuinely independent review is now in place")
    state = review_gate.gate_state()
    assert state["confirmatory_permitted"] is False
    assert state["independence"]["independent"] is False
