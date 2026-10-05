"""Every route that can change state must require a credential.

The API's convention is that /api/ is read-only, /internal/ carries service
writes under X-Porygon-Internal-Token, and /operator/ carries human-authorised
writes under X-Porygon-Operator-Token. Nothing enforced that convention, so a
feature could add an unauthenticated write and every existing test would still
pass. One did: POST /api/v1/ai/audit was merged with no auth dependency while
falling back to a server-side LLM key. These tests make the convention a
property of the app rather than a habit of its authors.
"""
from __future__ import annotations

from collections.abc import Iterator

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from porygon_api.main import app
from porygon_api.security import require_internal_token, require_operator_token

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CREDENTIAL_CHECKS = {
    require_internal_token: "/internal/",
    require_operator_token: "/operator/",
}


def _dependency_calls(dependant: Dependant) -> Iterator[object]:
    for dependency in dependant.dependencies:
        yield dependency.call
        yield from _dependency_calls(dependency)


def _write_routes() -> list[APIRoute]:
    return [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and set(route.methods) - READ_ONLY_METHODS
    ]


def test_there_are_write_routes_to_check() -> None:
    # Guards the guard: if route discovery silently found nothing, every test
    # below would pass vacuously.
    assert len(_write_routes()) >= 5


def test_every_write_route_requires_a_credential() -> None:
    unguarded = [
        f"{sorted(set(route.methods) - READ_ONLY_METHODS)} {route.path}"
        for route in _write_routes()
        if not any(call in CREDENTIAL_CHECKS for call in _dependency_calls(route.dependant))
    ]
    assert not unguarded, f"write routes with no credential check: {unguarded}"


def test_write_routes_sit_under_the_namespace_their_credential_implies() -> None:
    # A route guarded by the operator token but mounted under /api/ would be
    # proxied by the console's dev server and gateway like a public read, and
    # the console's _apiFetch only attaches the operator token for /operator/
    # paths -- so the namespace is load-bearing, not cosmetic.
    misplaced = []
    for route in _write_routes():
        calls = set(_dependency_calls(route.dependant))
        prefixes = [prefix for check, prefix in CREDENTIAL_CHECKS.items() if check in calls]
        if prefixes and not any(route.path.startswith(prefix) for prefix in prefixes):
            misplaced.append(f"{route.path} (expects {' or '.join(prefixes)})")
    assert not misplaced, f"write routes outside their credential namespace: {misplaced}"


def test_api_namespace_is_read_only() -> None:
    writes = [route.path for route in _write_routes() if route.path.startswith("/api/")]
    assert not writes, f"/api/ must be read-only; found writes at {writes}"


def test_ai_audit_requires_the_operator_token() -> None:
    routes = [
        route
        for route in app.routes
        if isinstance(route, APIRoute) and route.path.endswith("/ai/audit")
    ]
    assert len(routes) == 1, [route.path for route in routes]
    (route,) = routes
    assert route.path == "/operator/v1/ai/audit"
    assert require_operator_token in set(_dependency_calls(route.dependant))
