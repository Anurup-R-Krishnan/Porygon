from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from porygon_api.baseline import FEATURE_SCHEMA_VERSION, build_profile_document


@dataclass
class ProcessEvent:
    event_id: str
    occurred_at: datetime
    container_id: str | None
    process_name: str | None
    executable: str | None
    parent_name: str | None
    parent_executable: str | None
    user_uid: int | None


@dataclass
class RuntimeEvent:
    event_id: str
    occurred_at: datetime
    container_id: str | None
    event_type: str
    action: str


def _training_data() -> tuple[datetime, datetime, list[ProcessEvent], list[RuntimeEvent]]:
    start = datetime(2026, 7, 21, 10, 0, tzinfo=timezone.utc)
    end = start + timedelta(minutes=3)
    process_events = [
        ProcessEvent("p1", start + timedelta(seconds=5), "c1", "python", "/usr/bin/python", "sh", "/bin/sh", 1000),
        ProcessEvent("p2", start + timedelta(seconds=20), "c1", "gunicorn", "/usr/bin/gunicorn", "python", "/usr/bin/python", 1000),
        ProcessEvent("p3", start + timedelta(seconds=70), "c2", "python", "/usr/bin/python", "sh", "/bin/sh", 1000),
        ProcessEvent("p4", start + timedelta(seconds=95), "c2", "sh", "/bin/sh", "python", "/usr/bin/python", 0),
    ]
    runtime_events = [
        RuntimeEvent("r1", start + timedelta(seconds=1), "c1", "container", "start"),
        RuntimeEvent("r2", start + timedelta(seconds=61), "c2", "container", "start"),
    ]
    return start, end, process_events, runtime_events


def test_profile_is_deterministic_and_digest_bound() -> None:
    start, end, process_events, runtime_events = _training_data()
    kwargs = dict(
        image_digest="example/app@sha256:" + "a" * 64,
        start_at=start,
        end_at=end,
        window_seconds=60,
        minimum_process_events=4,
        minimum_nonempty_windows=2,
    )

    first = build_profile_document(
        process_events=process_events,
        runtime_events=runtime_events,
        **kwargs,
    )
    second = build_profile_document(
        process_events=list(reversed(process_events)),
        runtime_events=list(reversed(runtime_events)),
        **kwargs,
    )

    assert first == second
    features, quality, manifest, model_hash = first
    assert features["schema_version"] == FEATURE_SCHEMA_VERSION
    assert quality["passed"] is True
    assert manifest["image_digest"] == kwargs["image_digest"]
    assert manifest["window_count"] == 3
    assert manifest["nonempty_window_count"] == 2
    assert manifest["container_count"] == 2
    assert len(model_hash) == 64


def test_distributions_and_numeric_windows_are_well_formed() -> None:
    start, end, process_events, runtime_events = _training_data()
    features, _, _, _ = build_profile_document(
        image_digest="example/app@sha256:" + "b" * 64,
        start_at=start,
        end_at=end,
        window_seconds=60,
        process_events=process_events,
        runtime_events=runtime_events,
        minimum_process_events=1,
        minimum_nonempty_windows=1,
    )

    distributions = features["categorical_distributions"]
    for distribution in distributions.values():
        if distribution:
            assert abs(sum(distribution.values()) - 1.0) < 1e-9

    numeric = features["numeric_summaries"]
    assert numeric["process_events_per_minute"]["mean"] == pytest.approx(4 / 3)
    assert numeric["root_process_ratio"]["max"] == 0.5
    assert numeric["shell_process_ratio"]["max"] == 0.5
    assert "/usr/bin/python -> /usr/bin/gunicorn" in distributions["process_sequence_bigram"]


def test_quality_gate_fails_without_enough_approved_training_data() -> None:
    start, end, process_events, runtime_events = _training_data()
    _, quality, manifest, _ = build_profile_document(
        image_digest="example/app@sha256:" + "c" * 64,
        start_at=start,
        end_at=end,
        window_seconds=60,
        process_events=process_events[:1],
        runtime_events=runtime_events[:1],
        minimum_process_events=10,
        minimum_nonempty_windows=3,
    )

    assert quality["passed"] is False
    assert quality["checks"]["minimum_process_events"]["passed"] is False
    assert quality["checks"]["minimum_nonempty_windows"]["passed"] is False
    assert manifest["process_event_count"] == 1
