from __future__ import annotations

import pytest
from fastapi import HTTPException

from porygon_api import main


def test_calibrated_endpoints_use_descriptive_paths() -> None:
    paths = main.app.openapi()["paths"]

    assert "/internal/calibrated/rarity-models" in paths
    assert "/api/calibrated/rarity-models/{model_id}" in paths
    assert "/internal/calibrated/rarity-scores" in paths
    assert "/api/calibrated/rarity-scores/{score_id}" in paths


def test_calibrated_endpoints_are_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "calibrated_enabled", False)

    with pytest.raises(HTTPException) as error:
        main._require_calibrated_enabled()

    assert error.value.status_code == 404
    assert "protocol review" in str(error.value.detail)
