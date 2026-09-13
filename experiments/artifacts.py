from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


class ArtifactError(ValueError):
    """Raised when an experiment artifact violates the provenance contract."""


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _walk_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    """Yield (json path, string) pairs so a rejection can name the location, not the value."""
    if isinstance(value, dict):
        return [
            pair
            for key, item in value.items()
            for pair in [(f"{path}.{key}", str(key)), *_walk_strings(item, f"{path}.{key}")]
        ]
    if isinstance(value, list):
        return [pair for index, item in enumerate(value) for pair in _walk_strings(item, f"{path}[{index}]")]
    if isinstance(value, str):
        return [(path, value)]
    return []


# Redaction placeholders mandated by docs/PROFILE_SCOPE_EXPERIMENT_V1.md. They prove a
# secret was removed, so they must not be mistaken for the secret itself.
REDACTION_PLACEHOLDERS = frozenset({"flag:<secret>", "<secret-value>"})


def reject_secrets(value: Any) -> None:
    secret_markers = ("password", "token", "secret", "credential", "api_key", "private_key")
    for path, text in _walk_strings(value):
        if text in REDACTION_PLACEHOLDERS:
            continue
        lowered = text.lower()
        marker = next((item for item in secret_markers if item in lowered), None)
        if marker:
            # The path and the matched marker are reported; the value itself never is.
            raise ArtifactError(
                f"secret-like value is not permitted in experiment artifacts "
                f"(matched {marker!r} at {path})"
            )


def atomic_write_json(path: Path, value: Any) -> str:
    reject_secrets(value)
    return atomic_write_bytes(path, (canonical_json(value) + "\n").encode("utf-8"))


def atomic_write_bytes(path: Path, encoded: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_bytes()
        if existing != encoded:
            raise ArtifactError(f"completed artifact cannot be overwritten: {path}")
        return sha256_bytes(existing)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    return sha256_bytes(encoded)


def _versioned_pattern(stem: str, suffix: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(stem)}(?:\.v(\d+))?{re.escape(suffix)}$")


def _artifact_version(path: Path, pattern: "re.Pattern[str]") -> int:
    match = pattern.match(path.name)
    return int(match.group(1)) if match and match.group(1) else 1


def versioned_artifact_paths(directory: Path, stem: str, suffix: str = ".json") -> list[Path]:
    """Every existing version of a versioned artifact, oldest first.

    The bare `<stem><suffix>` is the implicit first version; `<stem>.vN<suffix>` (N >= 2)
    are later versions written by `write_versioned_json` when the content legitimately
    changed after the first version was already completed.
    """
    if not directory.is_dir():
        return []
    pattern = _versioned_pattern(stem, suffix)
    found = [path for path in directory.glob(f"{stem}*{suffix}") if path.is_file() and pattern.match(path.name)]
    return sorted(found, key=lambda path: _artifact_version(path, pattern))


def write_versioned_json(directory: Path, stem: str, value: Any, suffix: str = ".json") -> Path:
    """Write a JSON artifact that must never be silently changed once completed.

    `atomic_write_bytes` already refuses to overwrite a completed artifact whose content
    differs -- that guard is the whole point of the provenance contract. Calling code must
    not route around it by unlinking the file first (that defeats the guard entirely,
    letting anyone silently rewrite a "completed" artifact, including its evidence-class
    labels, in place).

    So: if nothing with this name exists yet, it is written as `<stem><suffix>`. If the
    latest existing version has byte-identical content, this is a no-op (an idempotent
    resume writing the same thing again). If the latest version's content differs -- e.g.
    a later pipeline stage legitimately has more to say than the run did when it first
    completed -- the existing file is left exactly as it is and the new content is written
    to the next `<stem>.vN<suffix>` instead, so every completed version stays exactly as
    originally written and the full history is auditable.
    """
    pattern = _versioned_pattern(stem, suffix)
    existing = versioned_artifact_paths(directory, stem, suffix)
    if existing:
        latest = existing[-1]
        if load_json(latest) == value:
            return latest
        target = directory / f"{stem}.v{_artifact_version(latest, pattern) + 1}{suffix}"
    else:
        target = directory / f"{stem}{suffix}"
    atomic_write_json(target, value)
    return target


def load_json(path: Path) -> Any:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError(f"invalid JSON artifact: {path}") from exc
    reject_secrets(value)
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reconcile_boundaries(events: list[dict[str, Any]], boundaries: list[str]) -> dict[str, Any]:
    """Reconcile sequence-numbered canaries without treating unknown boundaries as zero."""
    if not boundaries:
        raise ArtifactError("at least one observable boundary is required")
    expected = {int(event["sequence"]) for event in events}
    result: dict[str, Any] = {"generated": len(expected), "boundaries": {}}
    for boundary in boundaries:
        observed = {
            int(event["sequence"])
            for event in events
            if boundary in event.get("observed_at", [])
        }
        missing = sorted(expected - observed)
        result["boundaries"][boundary] = {
            "observed": len(observed),
            "missing": len(missing),
            "missing_sequences": missing,
            "loss_fraction": (len(missing) / len(expected)) if expected else None,
            "status": "measured",
        }
    return result


SPLITS = ("fit", "calibration", "pilot", "test")


def assign_split(run_id: str, splits: tuple[str, ...] = ("fit", "calibration", "test")) -> str:
    """Deterministically assign a whole run to one split from its run ID alone.

    Assignment is by complete run, never by window, and is computed before execution so
    that no result can influence it.
    """
    digest = hashlib.sha256(run_id.encode("utf-8")).digest()
    return splits[int.from_bytes(digest[:8], "big") % len(splits)]


def check_split_isolation(records: list[dict[str, Any]]) -> None:
    """Reject any run that appears in more than one split.

    Windows inherit their run's split, so a run in two splits is leakage no matter how
    the windows were cut.
    """
    seen: dict[str, str] = {}
    for record in records:
        run_id = record.get("run_id")
        split = record.get("split")
        if run_id is None or split is None:
            raise ArtifactError("split isolation requires both run_id and split on every record")
        if split not in SPLITS:
            raise ArtifactError(f"unknown split: {split}")
        if seen.setdefault(run_id, split) != split:
            raise ArtifactError(
                f"split leakage: run {run_id} appears in both {seen[run_id]} and {split}"
            )
