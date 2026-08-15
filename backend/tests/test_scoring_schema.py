from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from porygon_api.schemas import AnomalyScoreComputeIn


DIGEST = "example/app@sha256:" + "a" * 64


def test_anomaly_score_request_requires_timezone_aware_start() -> None:
    with pytest.raises(ValidationError, match="timezone offset"):
        AnomalyScoreComputeIn(
            image_digest=DIGEST,
            window_start=datetime(2026, 7, 21, 10, 0),
        )


def test_anomaly_score_request_accepts_digest_and_optional_profile() -> None:
    payload = AnomalyScoreComputeIn(
        image_digest=DIGEST,
        window_start=datetime(2026, 7, 21, 10, 0, tzinfo=timezone.utc),
        profile_id="00000000-0000-0000-0000-000000000001",
    )

    assert payload.image_digest == DIGEST
    assert payload.profile_id is not None
