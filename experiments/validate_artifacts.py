from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    # Imported here because the package is only importable after the sys.path insert above.
    from experiments.artifacts import ArtifactError
    from experiments.run import validate

    if len(sys.argv) != 2:
        print("usage: python3 experiments/validate_artifacts.py RUN_DIR", file=sys.stderr)
        return 2
    try:
        validate(Path(sys.argv[1]))
    except ArtifactError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(f"[PASS] validated experiment artifacts: {sys.argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

