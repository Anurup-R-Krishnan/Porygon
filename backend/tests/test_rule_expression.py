from __future__ import annotations

import pytest

from porygon_api.detection import validate_custom_condition
from porygon_api.rule_expression import (
    ExpressionError,
    parse_expression,
    render_expression,
)

ROUND_TRIP_CASES = [
    'executable == "nc"',
    'executable != "sh"',
    'executable == "nc" and parent_executable in ["sh", "bash"]',
    'ancestor.executable == "sh" and executable == "wget"',
    'command_line contains "curl" or command_line contains "wget"',
    'executable == "nc" and (user_uid == 0 or ancestor.process_name == "sh")',
    'executable not in ["sh", "bash", "dash"]',
    "privileged == true",
    "user_uid == 0",
]


@pytest.mark.parametrize("expression", ROUND_TRIP_CASES)
def test_expression_round_trips_through_condition_tree(expression: str) -> None:
    tree = parse_expression(expression)
    rendered = render_expression(tree)
    assert parse_expression(rendered) == tree


def test_comparison_operators_map_to_condition_vocabulary() -> None:
    assert parse_expression('executable == "nc"') == {
        "field": "executable",
        "op": "equals",
        "value": "nc",
        "scope": "event",
    }
    assert parse_expression('executable != "nc"')["op"] == "not_equals"
    assert parse_expression('executable in ["nc"]')["op"] == "in"
    assert parse_expression('executable not in ["nc"]')["op"] == "not_in"
    assert parse_expression('command_line contains "nc"')["op"] == "contains"


def test_ancestor_prefix_sets_scope() -> None:
    assert parse_expression('ancestor.executable == "sh"')["scope"] == "ancestor"
    assert parse_expression('executable == "sh"')["scope"] == "event"


def test_and_binds_tighter_than_or() -> None:
    tree = parse_expression('executable == "a" or executable == "b" and user_uid == 0')
    assert set(tree) == {"any"}
    assert set(tree["any"][1]) == {"all"}


def test_parentheses_override_precedence() -> None:
    tree = parse_expression('(executable == "a" or executable == "b") and user_uid == 0')
    assert set(tree) == {"all"}
    assert set(tree["all"][0]) == {"any"}


def test_repeated_operators_flatten_instead_of_nesting() -> None:
    tree = parse_expression('executable == "a" and executable == "b" and executable == "c"')
    assert len(tree["all"]) == 3


def test_not_negates_the_following_term() -> None:
    assert parse_expression("not user_uid == 0") == {
        "not": {"field": "user_uid", "op": "equals", "value": 0, "scope": "event"}
    }


def test_values_parse_by_type() -> None:
    assert parse_expression("user_uid == 0")["value"] == 0
    assert parse_expression("privileged == true")["value"] is True
    assert parse_expression("privileged == false")["value"] is False
    assert parse_expression('executable == "with \\"quotes\\""')["value"] == 'with "quotes"'
    assert parse_expression('executable in ["a", "b"]')["value"] == ["a", "b"]


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "   ",
        "executable",
        'executable == ',
        'executable "nc"',
        '== "nc"',
        'executable == "nc" and',
        '(executable == "nc"',
        'executable == "nc")',
        'proc.executable == "nc"',
        'executable ~= "nc"',
        'executable == "nc" extra',
        "executable == [1, 2",
        "executable == @",
    ],
)
def test_malformed_expressions_are_rejected(expression: str) -> None:
    with pytest.raises(ExpressionError):
        parse_expression(expression)


def test_expression_length_is_capped() -> None:
    with pytest.raises(ExpressionError):
        parse_expression('executable == "nc" and ' * 200 + 'executable == "nc"')


def test_deeply_nested_parentheses_raise_a_clean_expression_error() -> None:
    # Well under MAX_EXPRESSION_LENGTH (2000 chars), but nested far past MAX_PARSE_DEPTH:
    # this used to blow Python's recursion limit and raise a bare RecursionError instead
    # of the domain ExpressionError callers expect.
    nested = "(" * 400 + 'executable == "nc"' + ")" * 400
    assert len(nested) < 2000
    with pytest.raises(ExpressionError):
        parse_expression(nested)


def test_deeply_nested_not_chain_raises_a_clean_expression_error() -> None:
    nested = "not " * 400 + "user_uid == 0"
    assert len(nested) < 2000
    with pytest.raises(ExpressionError):
        parse_expression(nested)


def test_parsed_expressions_still_pass_the_condition_validator() -> None:
    tree = parse_expression('executable == "nc" and ancestor.parent_executable in ["sh", "bash"]')
    validate_custom_condition(tree, target="process")


def test_expression_cannot_bypass_the_field_allowlist() -> None:
    # The parser accepts any identifier as a field name; the shared validator is what
    # rejects anything outside the audited vocabulary, for text and tree input alike.
    tree = parse_expression('__import__ == "os"')
    with pytest.raises(ValueError):
        validate_custom_condition(tree, target="process")


def test_expression_cannot_bypass_ancestor_scope_restriction() -> None:
    tree = parse_expression("ancestor.privileged == true")
    with pytest.raises(ValueError):
        validate_custom_condition(tree, target="runtime")


def test_expression_cannot_bypass_depth_limit() -> None:
    tree = parse_expression("not " * 8 + "user_uid == 0")
    with pytest.raises(ValueError):
        validate_custom_condition(tree, target="process")


def test_render_rejects_unknown_operator() -> None:
    with pytest.raises(ExpressionError):
        render_expression({"field": "executable", "op": "regex_match", "value": "nc"})
