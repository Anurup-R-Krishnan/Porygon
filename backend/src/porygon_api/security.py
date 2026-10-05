from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, status

from porygon_api.config import get_settings


def require_internal_token(
    x_porygon_internal_token: str = Header(..., alias="X-Porygon-Internal-Token"),
) -> None:
    expected = get_settings().internal_api_token.get_secret_value()
    if not secrets.compare_digest(x_porygon_internal_token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token")


def require_operator_token(
    x_porygon_operator_token: str = Header(..., alias="X-Porygon-Operator-Token"),
) -> None:
    expected = get_settings().operator_api_token.get_secret_value()
    if not secrets.compare_digest(x_porygon_operator_token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid operator token")
