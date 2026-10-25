from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from porygon_api.baseline import FEATURE_SCHEMA_VERSION
from porygon_api.main import (
    app,
    classify_events,
    classify_features,
    get_ml_model_info,
)
from porygon_api.ml_classifier import (
    CLASSES,
    FEATURE_NAMES,
    MODEL_VERSION,
    default_classifier,
    extract_features_from_document,
    extract_features_from_events,
)
from porygon_api.schemas import (
    MLClassifyEventsIn,
    MLClassifyFeaturesIn,
)


def _make_dummy_features() -> dict[str, Any]:
    return {
        "schema_version": FEATURE_SCHEMA_VERSION,
        "categorical_distributions": {
            "process_name": {"python": 0.8, "gunicorn": 0.2},
            "executable": {"/usr/bin/python": 0.8, "/usr/bin/gunicorn": 0.2},
            "parent_child": {"systemd -> /usr/bin/python": 1.0},
            "user_uid": {"1000": 1.0},
            "runtime_action": {"container:start": 1.0},
            "process_sequence_bigram": {"/usr/bin/python -> /usr/bin/gunicorn": 1.0},
        },
        "observed_sets": {},
        "numeric_summaries": {
            "process_events_per_minute": {"mean": 10.0, "median": 10.0},
            "distinct_processes_per_window": {"mean": 2.0, "median": 2.0},
            "root_process_ratio": {"mean": 0.0, "median": 0.0},
            "shell_process_ratio": {"mean": 0.0, "median": 0.0},
        },
    }


def test_model_metadata() -> None:
    assert len(CLASSES) == 5
    assert "benign" in CLASSES
    assert "shell_escape" in CLASSES
    assert "reconnaissance" in CLASSES
    assert "suspicious_tooling" in CLASSES
    assert "privilege_escalation" in CLASSES
    assert len(FEATURE_NAMES) == 12
    assert "shell_ratio" in FEATURE_NAMES
    assert "parent_shim_ratio" in FEATURE_NAMES


def test_extract_features_empty_events() -> None:
    features = extract_features_from_events([])
    assert features["shell_ratio"] == 0.0
    assert features["event_count"] == 0.0
    assert len(features) == len(FEATURE_NAMES)


def test_extract_features_from_events() -> None:
    events = [
        {
            "process_name": "sh",
            "executable": "/bin/sh",
            "parent_name": "containerd-shim-runc-v2",
            "user_uid": 0,
        },
        {
            "process_name": "curl",
            "executable": "/usr/bin/curl",
            "parent_name": "sh",
            "user_uid": 0,
        },
    ]
    fvec = extract_features_from_events(events, drift_score=0.75)
    assert fvec["shell_ratio"] == 0.5
    assert fvec["tooling_ratio"] == 0.5
    assert fvec["root_ratio"] == 1.0
    assert fvec["parent_shim_ratio"] == 0.5
    assert fvec["jensen_shannon_drift"] == 0.75
    assert fvec["event_count"] == 2.0


def test_extract_features_from_document() -> None:
    doc = _make_dummy_features()
    fvec = extract_features_from_document(doc, drift_score=0.05)
    assert fvec["shell_ratio"] == 0.0
    assert fvec["root_ratio"] == 0.0
    assert fvec["distinct_proc_count"] == 2.0
    assert fvec["jensen_shannon_drift"] == 0.05


def test_classify_benign_workload() -> None:
    events = [
        {"process_name": "python3", "executable": "/usr/bin/python3", "user_uid": 1000},
        {"process_name": "gunicorn", "executable": "/usr/local/bin/gunicorn", "user_uid": 1000},
        {"process_name": "python3", "executable": "/usr/bin/python3", "user_uid": 1000},
    ]
    result = default_classifier.predict_events(events, drift_score=0.02)
    assert result.predicted_class == "benign"
    assert result.risk_level in ("clean", "low")
    assert result.confidence > 0.70
    assert "BENIGN" in result.summary.upper() or "benign" in result.summary.lower()


def test_classify_shell_escape() -> None:
    events = [
        {
            "process_name": "sh",
            "executable": "/bin/sh",
            "parent_name": "containerd-shim",
            "user_uid": 0,
        },
        {
            "process_name": "bash",
            "executable": "/bin/bash",
            "parent_name": "sh",
            "user_uid": 0,
        },
    ]
    result = default_classifier.predict_events(events, drift_score=0.85)
    assert result.predicted_class == "shell_escape"
    assert result.risk_level in ("high", "critical")
    assert result.confidence > 0.40
    contrib_features = [c.feature for c in result.top_contributing_features]
    assert "shell_ratio" in contrib_features


def test_classify_reconnaissance() -> None:
    events = [
        {"process_name": "whoami", "executable": "/usr/bin/whoami", "user_uid": 0},
        {"process_name": "id", "executable": "/usr/bin/id", "user_uid": 0},
        {"process_name": "uname", "executable": "/bin/uname", "user_uid": 0},
        {"process_name": "ps", "executable": "/bin/ps", "user_uid": 0},
        {"process_name": "netstat", "executable": "/bin/netstat", "user_uid": 0},
    ]
    result = default_classifier.predict_events(events, drift_score=0.65)
    assert result.predicted_class == "reconnaissance"
    assert result.risk_level in ("medium", "high")
    assert result.class_probabilities["reconnaissance"] > 0.40


def test_classify_suspicious_tooling() -> None:
    events = [
        {"process_name": "curl", "executable": "/usr/bin/curl", "user_uid": 1000},
        {"process_name": "wget", "executable": "/usr/bin/wget", "user_uid": 1000},
        {"process_name": "nc", "executable": "/bin/nc", "user_uid": 1000},
    ]
    result = default_classifier.predict_events(events, drift_score=0.70)
    assert result.predicted_class == "suspicious_tooling"
    assert result.risk_level in ("high", "critical")
    assert result.class_probabilities["suspicious_tooling"] > 0.40


def test_classify_privilege_escalation() -> None:
    events = [
        {"process_name": "sudo", "executable": "/usr/bin/sudo", "user_uid": 0},
        {"process_name": "su", "executable": "/bin/su", "user_uid": 0},
        {"process_name": "chmod", "executable": "/bin/chmod", "user_uid": 0},
    ]
    result = default_classifier.predict_events(events, drift_score=0.75)
    assert result.predicted_class == "privilege_escalation"
    assert result.risk_level in ("high", "critical")
    assert result.class_probabilities["privilege_escalation"] > 0.40


def test_feature_attribution_structure() -> None:
    events = [
        {"process_name": "bash", "executable": "/bin/bash", "user_uid": 0, "parent_name": "runc"},
        {"process_name": "whoami", "executable": "/usr/bin/whoami", "user_uid": 0},
    ]
    result = default_classifier.predict_events(events, drift_score=0.60)
    assert len(result.top_contributing_features) > 0
    top = result.top_contributing_features[0]
    assert top.feature in FEATURE_NAMES
    assert top.direction in ("increases_threat", "decreases_threat", "neutral")
    assert len(top.explanation) > 0


def test_ml_routes_are_exposed_in_openapi() -> None:
    paths = app.openapi()["paths"]
    assert "/api/v1/ml/model-info" in paths
    assert "/api/v1/ml/classify" in paths
    assert "/api/v1/ml/classify-container/{container_id}" in paths
    assert "/api/v1/ml/classify-features" in paths


def test_api_model_info_endpoint() -> None:
    info = get_ml_model_info()
    assert info.model_version == MODEL_VERSION
    assert len(info.classes) == 5
    assert len(info.features) == 12
    assert info.num_trees > 0
    assert "TreeSHAP" in info.explainability_method


def test_api_classify_events_endpoint() -> None:
    payload = MLClassifyEventsIn(
        events=[
            {"process_name": "sh", "executable": "/bin/sh", "user_uid": 0, "parent_name": "containerd-shim"},
            {"process_name": "bash", "executable": "/bin/bash", "user_uid": 0},
        ],
        drift_score=0.82,
    )
    mock_db = MagicMock()
    data = classify_events(payload=payload, db=mock_db)
    assert data.predicted_class == "shell_escape"
    assert data.confidence > 0.0
    assert "shell_escape" in data.class_probabilities
    assert len(data.top_contributing_features) > 0


def test_api_classify_features_endpoint() -> None:
    payload = MLClassifyFeaturesIn(
        observation_features=_make_dummy_features(),
        drift_score=0.02,
    )
    data = classify_features(payload=payload)
    assert data.predicted_class == "benign"
    assert data.risk_level in ("clean", "low")
