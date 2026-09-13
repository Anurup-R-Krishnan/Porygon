"""Text front-end for custom detection-rule conditions.

Operators can express a rule either as the structured condition tree the detection
engine evaluates, or as a textual expression like::

    executable == "nc" and ancestor.parent_executable in ["sh", "bash"]

This module only translates between those two representations. It never evaluates
anything: `parse_expression` produces exactly the same condition-tree shape that
`detection.validate_custom_condition` already audits, so the text form inherits the
existing field/operator allowlist and depth limits rather than widening them.
"""

from __future__ import annotations

import re
from typing import Any

_KEYWORDS = {"and", "or", "not", "in", "contains", "true", "false"}

_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<string>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')
    | (?P<number>-?\d+(?:\.\d+)?)
    | (?P<op>==|!=)
    | (?P<lparen>\()
    | (?P<rparen>\))
    | (?P<lbracket>\[)
    | (?P<rbracket>\])
    | (?P<comma>,)
    | (?P<dot>\.)
    | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)

_COMPARISON_OPS = {
    "==": "equals",
    "!=": "not_equals",
    "in": "in",
    "not in": "not_in",
    "contains": "contains",
}

_OP_TO_TEXT = {value: key for key, value in _COMPARISON_OPS.items()}

MAX_EXPRESSION_LENGTH = 2000

# Bounds the parser's own recursive-descent stack depth, independent of
# MAX_EXPRESSION_LENGTH: a deeply parenthesized or negated expression can stay well
# under the character cap while still nesting deeply enough to raise a Python
# RecursionError, which is a RuntimeError subclass that would otherwise escape past
# callers that only catch ValueError/ExpressionError.
MAX_PARSE_DEPTH = 32


class ExpressionError(ValueError):
    """Raised when an expression cannot be parsed."""


class _Token:
    __slots__ = ("kind", "value", "position")

    def __init__(self, kind: str, value: str, position: int) -> None:
        self.kind = kind
        self.value = value
        self.position = position

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"_Token({self.kind!r}, {self.value!r}, {self.position})"


def _tokenize(text: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    length = len(text)
    while index < length:
        match = _TOKEN_RE.match(text, index)
        if match is None:
            raise ExpressionError(f"unexpected character {text[index]!r} at position {index}")
        index = match.end()
        kind = match.lastgroup
        if kind == "ws":
            continue
        value = match.group()
        if kind == "ident" and value.lower() in _KEYWORDS:
            kind = value.lower()
        tokens.append(_Token(str(kind), value, match.start()))
    return tokens


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self._tokens = tokens
        self._index = 0
        self._depth = 0

    def _recurse(self, method: Any) -> Any:
        """Call a recursive-descent method with the shared depth counter enforced.

        Only call sites that genuinely re-enter the grammar (parenthesized groups,
        chained 'not', nested list values) should route through here: and/or chains are
        iterative (a while loop), not recursive, so they never touch this counter.
        """
        self._depth += 1
        if self._depth > MAX_PARSE_DEPTH:
            raise ExpressionError(f"expression nesting exceeds the maximum depth of {MAX_PARSE_DEPTH}")
        try:
            return method()
        finally:
            self._depth -= 1

    def _peek(self) -> _Token | None:
        return self._tokens[self._index] if self._index < len(self._tokens) else None

    def _next(self) -> _Token:
        token = self._peek()
        if token is None:
            raise ExpressionError("unexpected end of expression")
        self._index += 1
        return token

    def _expect(self, kind: str) -> _Token:
        token = self._next()
        if token.kind != kind:
            raise ExpressionError(f"expected {kind!r} but found {token.value!r} at position {token.position}")
        return token

    def parse(self) -> dict[str, Any]:
        if not self._tokens:
            raise ExpressionError("expression is empty")
        node = self._parse_or()
        trailing = self._peek()
        if trailing is not None:
            raise ExpressionError(f"unexpected {trailing.value!r} at position {trailing.position}")
        return node

    def _parse_or(self) -> dict[str, Any]:
        branches = [self._parse_and()]
        while (token := self._peek()) is not None and token.kind == "or":
            self._next()
            branches.append(self._parse_and())
        return branches[0] if len(branches) == 1 else {"any": branches}

    def _parse_and(self) -> dict[str, Any]:
        branches = [self._parse_not()]
        while (token := self._peek()) is not None and token.kind == "and":
            self._next()
            branches.append(self._parse_not())
        return branches[0] if len(branches) == 1 else {"all": branches}

    def _parse_not(self) -> dict[str, Any]:
        token = self._peek()
        if token is not None and token.kind == "not":
            self._next()
            return {"not": self._recurse(self._parse_not)}
        return self._parse_primary()

    def _parse_primary(self) -> dict[str, Any]:
        token = self._peek()
        if token is None:
            raise ExpressionError("unexpected end of expression")
        if token.kind == "lparen":
            self._next()
            node = self._recurse(self._parse_or)
            self._expect("rparen")
            return node
        return self._parse_comparison()

    def _parse_comparison(self) -> dict[str, Any]:
        token = self._next()
        if token.kind != "ident":
            raise ExpressionError(f"expected a field name but found {token.value!r} at position {token.position}")

        scope = "event"
        field = token.value
        if (following := self._peek()) is not None and following.kind == "dot":
            if field != "ancestor":
                raise ExpressionError(
                    f"unknown field prefix {field!r} at position {token.position}; only 'ancestor.' is supported"
                )
            self._next()
            scope = "ancestor"
            field_token = self._next()
            if field_token.kind != "ident":
                raise ExpressionError(
                    f"expected a field name after 'ancestor.' but found {field_token.value!r} "
                    f"at position {field_token.position}"
                )
            field = field_token.value

        operator_token = self._next()
        if operator_token.kind == "not":
            self._expect("in")
            operator = "not_in"
        elif operator_token.kind in {"in", "contains"}:
            operator = _COMPARISON_OPS[operator_token.kind]
        elif operator_token.kind == "op":
            operator = _COMPARISON_OPS[operator_token.value]
        else:
            raise ExpressionError(
                f"expected a comparison operator after {field!r} but found {operator_token.value!r} "
                f"at position {operator_token.position}"
            )

        return {"field": field, "op": operator, "value": self._parse_value(), "scope": scope}

    def _parse_value(self) -> Any:
        token = self._next()
        if token.kind == "string":
            return _decode_string(token.value)
        if token.kind == "number":
            return float(token.value) if "." in token.value else int(token.value)
        if token.kind in {"true", "false"}:
            return token.kind == "true"
        if token.kind == "lbracket":
            values: list[Any] = []
            if (following := self._peek()) is not None and following.kind == "rbracket":
                self._next()
                return values
            while True:
                values.append(self._recurse(self._parse_value))
                separator = self._next()
                if separator.kind == "rbracket":
                    return values
                if separator.kind != "comma":
                    raise ExpressionError(
                        f"expected ',' or ']' in list but found {separator.value!r} at position {separator.position}"
                    )
        raise ExpressionError(f"expected a value but found {token.value!r} at position {token.position}")


def _decode_string(raw: str) -> str:
    body = raw[1:-1]
    return re.sub(r"\\(.)", lambda match: match.group(1), body)


def _encode_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def parse_expression(text: str) -> dict[str, Any]:
    """Compile a textual rule expression into a condition tree.

    The result still has to pass `detection.validate_custom_condition`, which owns the
    field/operator vocabulary and the depth and size limits.
    """
    if not isinstance(text, str) or not text.strip():
        raise ExpressionError("expression is empty")
    if len(text) > MAX_EXPRESSION_LENGTH:
        raise ExpressionError(f"expression exceeds {MAX_EXPRESSION_LENGTH} characters")
    try:
        return _Parser(_tokenize(text)).parse()
    except RecursionError as exc:
        # Backstop only: MAX_PARSE_DEPTH should already reject anything deep enough to
        # reach here. RecursionError is a RuntimeError subclass, not a ValueError, so
        # without this it would slip past callers that only catch ExpressionError.
        raise ExpressionError("expression is nested too deeply to parse") from exc


def render_expression(condition: Any) -> str:
    """Render a condition tree back into its canonical textual form."""
    return _render(condition, parent=None)


def _render(condition: Any, *, parent: str | None) -> str:
    if not isinstance(condition, dict):
        raise ExpressionError("condition node must be an object")

    for key, joiner in (("all", " and "), ("any", " or ")):
        if key in condition:
            rendered = joiner.join(_render(child, parent=key) for child in condition[key])
            # 'and' binds tighter than 'or', so only an 'or' nested under 'and' needs
            # parentheses to survive a parse/render round trip.
            return f"({rendered})" if key == "any" and parent == "all" else rendered

    if "not" in condition:
        inner = condition["not"]
        rendered = _render(inner, parent="not")
        needs_parens = isinstance(inner, dict) and any(key in inner for key in ("all", "any"))
        return f"not ({rendered})" if needs_parens else f"not {rendered}"

    field = condition.get("field")
    operator = condition.get("op")
    if field is None or operator not in _OP_TO_TEXT:
        raise ExpressionError("condition leaf is missing a field or has an unknown operator")
    prefix = "ancestor." if condition.get("scope") == "ancestor" else ""
    return f"{prefix}{field} {_OP_TO_TEXT[operator]} {_render_value(condition.get('value'))}"


def _render_value(value: Any) -> str:
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_render_value(item) for item in value) + "]"
    raise ExpressionError(f"cannot render value of type {type(value).__name__}")
