from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from porygon_api import main
from porygon_api.db import Base
from porygon_api.main import (
    CALIBRATED_ALGORITHM_ID,
    COMPONENT_REGISTRY_ID,
    PROTOCOL_ID,
    create_calibrated_model,
    create_calibrated_score,
)
from porygon_api.schemas import CalibratedModelCreateIn, CalibratedScoreCreateIn


@pytest.fixture(autouse=True)
def _enable_calibrated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.settings, "calibrated_enabled", True)


def _model(db: Session, *, profile_context_hash: str):
    calibration_run_ids = [f"run-cal-{i:03d}" for i in range(10)]
    return create_calibrated_model(
        CalibratedModelCreateIn(
            protocol_id=PROTOCOL_ID,
            profile_scope_id="ARM-CONTEXT",
            profile_context_hash=profile_context_hash,
            algorithm_id=CALIBRATED_ALGORITHM_ID,
            component_registry_id=COMPONENT_REGISTRY_ID,
            fit_run_ids=[f"run-fit-{i:03d}" for i in range(5)],
            calibration_run_ids=calibration_run_ids,
            calibration_block_statistics={run_id: float(i) for i, run_id in enumerate(calibration_run_ids)},
        ),
        db,
    )


def test_matching_context_hash_is_scored_normally() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    context_hash = "a" * 64

    with Session(engine) as db:
        model = _model(db, profile_context_hash=context_hash)

        score = create_calibrated_score(
            CalibratedScoreCreateIn(
                model_id=model.model_id,
                test_run_id="run-test-001",
                evidence_set_hash="e" * 64,
                test_context_hash=context_hash,
                test_statistic=3.0,
            ),
            db,
        )

        assert score.status == "scored"
        assert score.p_value is not None
        assert score.test_context_hash == context_hash


def test_mismatched_context_hash_is_reported_as_drift_not_silently_scored() -> None:
    """A test run whose declared identity differs from the model's training identity
    breaks the exchangeability assumption. It must be surfaced as drift_detected,
    never silently scored against a calibration set it was never drawn from."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    trained_context_hash = "a" * 64
    drifted_context_hash = "b" * 64

    with Session(engine) as db:
        model = _model(db, profile_context_hash=trained_context_hash)

        score = create_calibrated_score(
            CalibratedScoreCreateIn(
                model_id=model.model_id,
                test_run_id="run-test-002",
                evidence_set_hash="f" * 64,
                test_context_hash=drifted_context_hash,
                test_statistic=3.0,
            ),
            db,
        )

        assert score.status == "drift_detected"
        assert score.p_value is None
        assert score.rarity is None
        assert score.test_context_hash == drifted_context_hash
        assert score.explanation["reason"] == "test_context_hash does not match model.profile_context_hash"
        assert score.explanation["profile_context_hash"] == trained_context_hash


def test_omitted_context_hash_is_scored_without_a_drift_claim() -> None:
    """Callers that do not declare a test_context_hash get the pre-existing
    behaviour: scored normally. Drift can only be detected when it is declared."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as db:
        model = _model(db, profile_context_hash="a" * 64)

        score = create_calibrated_score(
            CalibratedScoreCreateIn(
                model_id=model.model_id,
                test_run_id="run-test-003",
                evidence_set_hash="c" * 64,
                test_statistic=3.0,
            ),
            db,
        )

        assert score.status == "scored"
        assert score.test_context_hash is None
