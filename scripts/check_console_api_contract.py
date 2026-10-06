#!/usr/bin/env python3
"""Assert every request the operator console makes has a backend route.

The console calls the API from string literals scattered through
dashboard/app.js. Nothing tied those strings to the backend, so renaming or
moving a route left the panel that used it quietly failing -- a 404 surfaced
only as an empty card. Moving the AI auditor from /api/ to /operator/ was
exactly that kind of change. This reads the backend's OpenAPI schema and every
fetch()/_apiFetch() call site in the console, and fails on any (method, path)
the backend does not serve.

Run by `verify_all.sh static` after it builds the backend:
    python3 scripts/check_console_api_contract.py <openapi.json>
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "dashboard"
CONSOLE_SOURCES = ("app.js", "src")

# Routes the console calls that are deliberately not backend routes.
NOT_BACKEND = {
    # Served by scripts/serve_dashboard.py (the dev proxy) behind
    # PORYGON_DEMO_MODE=1 and the operator token. It shells out to
    # `docker run`, so it must never be a backend or gateway route.
    ("POST", "/api/demo/run-scenario"),
}

# _fetchEvidence is the evidence export's fetch wrapper; its first argument is a
# path like any fetch() call's, so it is checked the same way.
CALL = re.compile(r"\b(?:fetch|_apiFetch|_fetchEvidence)\s*\(")


def _arguments(source: str, start: int) -> str:
    """Return the text between the call's parentheses.

    A small tokenizer rather than a regex: the path is often a template literal
    whose ${...} holds its own parentheses and braces, and the options object
    nests further, so the closing paren cannot be found by pattern alone.

    Contexts form a stack. "code" tracks bracket depth; a template literal's
    ${ pushes a fresh "code" context that ends at its own closing brace.
    """
    contexts: list[list] = [["code", 0]]  # the call's own argument list
    index = start
    while index < len(source):
        char = source[index]
        kind = contexts[-1][0]
        if kind in ("'", '"'):
            if char == "\\":
                index += 2
                continue
            if char == kind:
                contexts.pop()
        elif kind == "`":
            if char == "\\":
                index += 2
                continue
            if char == "`":
                contexts.pop()
            elif source.startswith("${", index):
                contexts.append(["code", 0])
                index += 2
                continue
        else:
            if source.startswith("//", index):
                newline = source.find("\n", index)
                index = len(source) if newline < 0 else newline
                continue
            if source.startswith("/*", index):
                close = source.find("*/", index + 2)
                index = len(source) if close < 0 else close + 2
                continue
            if char in ("'", '"', "`"):
                contexts.append([char, 0])
            elif char in "([{":
                contexts[-1][1] += 1
            elif char in ")]}":
                if contexts[-1][1]:
                    contexts[-1][1] -= 1
                elif len(contexts) == 1 and char == ")":
                    return source[start:index]
                elif len(contexts) > 1 and char == "}":
                    contexts.pop()  # end of a template ${...}
                else:
                    raise ValueError(f"unbalanced {char!r} at offset {index}")
        index += 1
    raise ValueError(f"unterminated call starting at offset {start}")


def _first_literal(arguments: str) -> str | None:
    match = re.match(r"\s*(['\"`])", arguments)
    if not match:
        return None
    quote = match.group(1)
    body_start = match.end()
    depth = 0
    index = body_start
    while index < len(arguments):
        if arguments[index] == "\\":
            index += 2
            continue
        if quote == "`" and arguments.startswith("${", index):
            depth += 1
            index += 2
            continue
        if quote == "`" and depth and arguments[index] == "}":
            depth -= 1
        elif arguments[index] == quote and depth == 0:
            return arguments[body_start:index]
        index += 1
    return None


def normalise(path: str) -> str:
    path = path.split("?", 1)[0]
    path = re.sub(r"\$\{[^}]*\}", "{}", path)  # console template slots
    path = re.sub(r"\{[^}/]+\}", "{}", path)  # OpenAPI parameters
    return path.rstrip("/") or "/"


def console_calls() -> list[tuple[str, str, str, int]]:
    """(method, normalised path, raw path, line) for every literal call site."""
    files: list[Path] = []
    for entry in CONSOLE_SOURCES:
        target = CONSOLE / entry
        files.extend(sorted(target.rglob("*.js")) if target.is_dir() else [target])

    calls: list[tuple[str, str, str, int]] = []
    for path in files:
        source = path.read_text(encoding="utf-8")
        for match in CALL.finditer(source):
            arguments = _arguments(source, match.end())
            raw = _first_literal(arguments)
            if raw is None or not raw.startswith("/"):
                continue  # dynamic URL; not statically checkable
            method_match = re.search(r"\bmethod\s*:\s*['\"](\w+)['\"]", arguments)
            method = method_match.group(1).upper() if method_match else "GET"
            line = source[: match.start()].count("\n") + 1
            calls.append((method, normalise(raw), raw, line))
    return calls


def backend_routes(openapi: dict) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for path, operations in openapi.get("paths", {}).items():
        for method in operations:
            if method.lower() in {"get", "post", "put", "patch", "delete"}:
                routes.add((method.upper(), normalise(path)))
    return routes


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    openapi = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    routes = backend_routes(openapi)
    if len(routes) < 20:
        print(f"console API contract: only {len(routes)} backend routes parsed", file=sys.stderr)
        return 1

    calls = console_calls()
    if len(calls) < 10:
        # Guards the guard: a broken extractor must not pass vacuously.
        print(f"console API contract: only {len(calls)} console calls found", file=sys.stderr)
        return 1

    failures = []
    for method, path, raw, line in calls:
        if (method, path) in NOT_BACKEND or (method, path) in routes:
            continue
        served = sorted(m for m, p in routes if p == path)
        hint = f" (backend serves {', '.join(served)} there)" if served else ""
        failures.append(f"dashboard/app.js:{line} {method} {raw} has no backend route{hint}")

    for failure in failures:
        print(f"console API contract: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(f"console API contract: {len(calls)} console calls all match backend routes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
