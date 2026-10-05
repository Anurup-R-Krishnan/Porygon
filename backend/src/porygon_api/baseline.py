from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable, Protocol

FEATURE_SCHEMA_VERSION = "porygon.behaviour.v1"
_SHELL_NAMES = {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}
_UNKNOWN = "<unknown>"


class ProcessEventLike(Protocol):
    event_id: str
    occurred_at: datetime
    container_id: str | None
    process_name: str | None
    executable: str | None
    parent_name: str | None
    parent_executable: str | None
    user_uid: int | None


class RuntimeEventLike(Protocol):
    event_id: str
    occurred_at: datetime
    container_id: str | None
    event_type: str
    action: str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _normalise(counter: Counter[str]) -> dict[str, float]:
    total = sum(counter.values())
    if total <= 0:
        return {}
    return {key: round(counter[key] / total, 12) for key in sorted(counter)}


def _token(value: str | None) -> str:
    rendered = (value or "").strip()
    return rendered if rendered else _UNKNOWN


def _process_token(event: ProcessEventLike) -> str:
    return _token(event.executable or event.process_name)


def _parent_token(event: ProcessEventLike) -> str:
    return _token(event.parent_executable or event.parent_name)


def _nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return float(ordered[rank - 1])


def _summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"min": 0.0, "max": 0.0, "mean": 0.0, "median": 0.0, "p95": 0.0, "stddev": 0.0}
    return {
        "min": round(float(min(values)), 12),
        "max": round(float(max(values)), 12),
        "mean": round(float(statistics.fmean(values)), 12),
        "median": round(float(statistics.median(values)), 12),
        "p95": round(_nearest_rank(values, 0.95), 12),
        "stddev": round(float(statistics.pstdev(values)), 12),
    }


def _window_index(occurred_at: datetime, start_at: datetime, window_seconds: int) -> int:
    offset = (occurred_at - start_at).total_seconds()
    return max(0, int(offset // window_seconds))


def _event_set_hash(process_events: Iterable[ProcessEventLike], runtime_events: Iterable[RuntimeEventLike]) -> str:
    identities = [f"process:{event.event_id}" for event in process_events]
    identities.extend(f"runtime:{event.event_id}" for event in runtime_events)
    return hashlib.sha256("\n".join(sorted(identities)).encode("utf-8")).hexdigest()


def build_profile_document(
    *,
    image_digest: str,
    start_at: datetime,
    end_at: datetime,
    window_seconds: int,
    process_events: list[ProcessEventLike],
    runtime_events: list[RuntimeEventLike],
    minimum_process_events: int,
    minimum_nonempty_windows: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], str]:
    """Build a deterministic digest-bound behavioural profile.

    The function deliberately performs no anomaly scoring. It converts an explicitly
    approved training interval into distributions, observed sets, per-window numeric
    summaries, a quality report, and a reproducibility manifest.
    """

    duration_seconds = (end_at - start_at).total_seconds()
    if duration_seconds <= 0:
        raise ValueError("end_at must be after start_at")
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    window_count = max(1, math.ceil(duration_seconds / window_seconds))
    process_windows: list[list[ProcessEventLike]] = [[] for _ in range(window_count)]
    runtime_windows: list[list[RuntimeEventLike]] = [[] for _ in range(window_count)]

    process_name_counts: Counter[str] = Counter()
    executable_counts: Counter[str] = Counter()
    parent_child_counts: Counter[str] = Counter()
    uid_counts: Counter[str] = Counter()
    runtime_action_counts: Counter[str] = Counter()
    sequence_bigram_counts: Counter[str] = Counter()
    processes_by_container: dict[str, list[ProcessEventLike]] = defaultdict(list)

    container_ids: set[str] = set()
    process_times: list[datetime] = []
    runtime_times: list[datetime] = []

    for event in process_events:
        index = min(_window_index(event.occurred_at, start_at, window_seconds), window_count - 1)
        process_windows[index].append(event)
        process_name_counts[_token(event.process_name)] += 1
        executable_counts[_process_token(event)] += 1
        parent_child_counts[f"{_parent_token(event)} -> {_process_token(event)}"] += 1
        uid_counts[str(event.user_uid) if event.user_uid is not None else _UNKNOWN] += 1
        process_times.append(event.occurred_at)
        if event.container_id:
            container_ids.add(event.container_id)
            processes_by_container[event.container_id].append(event)

    for event in runtime_events:
        index = min(_window_index(event.occurred_at, start_at, window_seconds), window_count - 1)
        runtime_windows[index].append(event)
        runtime_action_counts[f"{event.event_type}:{event.action}"] += 1
        runtime_times.append(event.occurred_at)
        if event.container_id:
            container_ids.add(event.container_id)

    for events in processes_by_container.values():
        ordered = sorted(events, key=lambda item: (item.occurred_at, item.event_id))
        tokens = [_process_token(item) for item in ordered]
        for left, right in zip(tokens, tokens[1:]):
            sequence_bigram_counts[f"{left} -> {right}"] += 1

    process_rate: list[float] = []
    runtime_rate: list[float] = []
    distinct_processes: list[float] = []
    root_ratios: list[float] = []
    shell_ratios: list[float] = []
    nonempty_windows = 0
    minutes_per_window = window_seconds / 60.0

    for proc_window, runtime_window in zip(process_windows, runtime_windows):
        if proc_window or runtime_window:
            nonempty_windows += 1
        process_rate.append(len(proc_window) / minutes_per_window)
        runtime_rate.append(len(runtime_window) / minutes_per_window)
        distinct_processes.append(float(len({_process_token(event) for event in proc_window})))
        if proc_window:
            root_ratios.append(sum(event.user_uid == 0 for event in proc_window) / len(proc_window))
            shell_ratios.append(
                sum(
                    (event.process_name or "").lower() in _SHELL_NAMES
                    or _process_token(event).rsplit("/", 1)[-1].lower() in _SHELL_NAMES
                    for event in proc_window
                )
                / len(proc_window)
            )
        else:
            root_ratios.append(0.0)
            shell_ratios.append(0.0)

    features = {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "categorical_distributions": {
            "process_name": _normalise(process_name_counts),
            "executable": _normalise(executable_counts),
            "parent_child": _normalise(parent_child_counts),
            "user_uid": _normalise(uid_counts),
            "runtime_action": _normalise(runtime_action_counts),
            "process_sequence_bigram": _normalise(sequence_bigram_counts),
        },
        "observed_sets": {
            "process_names": sorted(process_name_counts),
            "executables": sorted(executable_counts),
            "parent_child_edges": sorted(parent_child_counts),
            "user_uids": sorted(uid_counts),
            "runtime_actions": sorted(runtime_action_counts),
            "process_sequence_bigrams": sorted(sequence_bigram_counts),
        },
        "numeric_summaries": {
            "process_events_per_minute": _summary(process_rate),
            "runtime_events_per_minute": _summary(runtime_rate),
            "distinct_processes_per_window": _summary(distinct_processes),
            "root_process_ratio": _summary(root_ratios),
            "shell_process_ratio": _summary(shell_ratios),
        },
    }

    checks = {
        "minimum_process_events": {
            "required": minimum_process_events,
            "actual": len(process_events),
            "passed": len(process_events) >= minimum_process_events,
        },
        "minimum_nonempty_windows": {
            "required": minimum_nonempty_windows,
            "actual": nonempty_windows,
            "passed": nonempty_windows >= minimum_nonempty_windows,
        },
        "immutable_image_digest": {
            "required": True,
            "actual": bool(image_digest),
            "passed": bool(image_digest),
        },
    }
    warnings: list[str] = []
    if len(container_ids) < 2:
        warnings.append("Training data contains fewer than two distinct containers; host-specific behaviour may be overrepresented.")
    if not runtime_events:
        warnings.append("No Docker lifecycle events were present in the approved interval.")
    if len(sequence_bigram_counts) == 0:
        warnings.append("No process-sequence bigrams were observed; sequence modelling will have no baseline support.")

    quality = {
        "passed": all(check["passed"] for check in checks.values()),
        "checks": checks,
        "warnings": warnings,
    }

    manifest = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "image_digest": image_digest,
        "training_start": start_at.isoformat(),
        "training_end": end_at.isoformat(),
        "duration_seconds": round(duration_seconds, 6),
        "window_seconds": window_seconds,
        "window_count": window_count,
        "nonempty_window_count": nonempty_windows,
        "process_event_count": len(process_events),
        "runtime_event_count": len(runtime_events),
        "container_count": len(container_ids),
        "container_ids": sorted(container_ids),
        "first_process_event_at": min(process_times).isoformat() if process_times else None,
        "last_process_event_at": max(process_times).isoformat() if process_times else None,
        "first_runtime_event_at": min(runtime_times).isoformat() if runtime_times else None,
        "last_runtime_event_at": max(runtime_times).isoformat() if runtime_times else None,
        "selected_event_ids_sha256": _event_set_hash(process_events, runtime_events),
    }

    model_hash = _sha256_json(
        {
            "image_digest": image_digest,
            "features": features,
            "quality": quality,
            "manifest": manifest,
        }
    )
    return features, quality, manifest, model_hash
