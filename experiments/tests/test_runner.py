from __future__ import annotations

from experiments.run import replay, run_smoke, validate


def test_smoke_run_validates_and_replays(tmp_path) -> None:
    run_dir = run_smoke(tmp_path / "run")
    validate(run_dir)
    replay(run_dir)
    assert (run_dir / "run.json").is_file()
    assert (run_dir / "artifact-manifest.json").is_file()

