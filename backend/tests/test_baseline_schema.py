from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from porygon_api.schemas import BehaviorProfileBuildIn


def test_baseline_build_request_requires_repository_digest() -> None:
    start = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        BehaviorProfileBuildIn(
            image_digest="sha256:" + "a" * 64,
            training_start=start,
            training_end=start + timedelta(minutes=5),
            approved_by="researcher",
        )


def test_baseline_build_request_requires_ordered_timezone_interval() -> None:
    start = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        BehaviorProfileBuildIn(
            image_digest="example/app@sha256:" + "a" * 64,
            training_start=start,
            training_end=start,
            approved_by="researcher",
        )
