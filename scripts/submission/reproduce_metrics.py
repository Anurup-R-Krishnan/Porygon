"""Reproduce the recorded metrics offline from bundled JSON outputs."""

import argparse
import json
from pathlib import Path


def reproduce(source: Path) -> dict:
    def read(name):
        return json.loads((source / name).read_text())

    integrity = read("ebpf-capture-integrity.json")
    normal = read("scoring-normal-score.json")
    novel = read("scoring-novel-score.json")
    detection = read("detection-novel-detection.json")["run"]
    execution = read("containment-execution.json")
    rollback = read("containment-rolled-back-execution.json")
    return {
        "schema_version": "porygon.demo.metrics.v1",
        "capture_run_id": integrity["run_id"],
        "observed_falco_records": integrity["boundaries"][
            "falco_file_probe_records_observed"
        ],
        "persisted_process_records": integrity["boundaries"][
            "postgres_probe_rows_after_recovery"
        ],
        "additional_rows_after_replay": integrity["boundaries"][
            "postgres_row_growth_after_replay"
        ],
        "baseline_score": normal["total_score"],
        "novel_score": novel["total_score"],
        "score_window_seconds": novel["window_seconds"],
        "incident_created": detection["incident_created"],
        "matched_findings": detection["matches_count"],
        "containment_status": execution["status"],
        "paused_after_action": execution["post_state"]["paused"],
        "rollback_status": rollback["status"],
        "running_after_rollback": rollback["post_state"]["running"],
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path, default=Path(__file__).parent / "sample-outputs"
    )
    parser.add_argument("--expected", type=Path)
    args = parser.parse_args()
    result = reproduce(args.input)
    if args.expected and result != json.loads(args.expected.read_text()):
        raise SystemExit("Recorded metrics do not match sample outputs")
    print(json.dumps(result, indent=2))
