"""Actual runtime-environment fingerprint, captured once at pilot run-start.

`experiments/context.py` fingerprints only the *container spec* an experiment asked
for (entrypoint, capabilities, mounts, ...). Nothing else records what the run
actually executed against: kernel version, the Falco ruleset that was active,
the digests of the service images that were running, the scoring-config version,
or the exact code state. Without that, a claim like "this run reproduces that run
at a larger n" cannot be checked against code/environment drift between the two
runs -- it can only be asserted.

Every probe here degrades to `{"status": "unavailable", "reason": "..."}` rather
than raising or silently returning an empty/zero value when the underlying
resource (Docker, a running container, an expected file) isn't reachable from
wherever this happens to run. This matches the honest-degradation convention
already used by `experiments/real.py` (`{"status": "unmeasured", "reason": ...}`
for a boundary that can't be reconciled) and `experiments/context.py`/`artifacts.py`
(`MISSING` sentinels, `reconcile_boundaries` never treating an unknown boundary as
zero loss). A probe that quietly returned `{}` or `0` on failure would be
indistinguishable from a probe that measured an actually-empty result, which is
exactly the kind of silent gap this module exists to close.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from experiments.artifacts import sha256_file, sha256_json

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "porygon.run-environment.v1"

FALCO_DIR = ROOT / "falco"
COMPOSE_PATH = ROOT / "compose.yaml"
BACKEND_SRC = ROOT / "backend/src/porygon_api"
EXPERIMENTS_DIR = ROOT / "experiments"

SERVICE_NAMES = ("backend", "collector", "telemetry", "responder", "scanner", "gateway", "postgres")
SCORING_FILES = ("scoring.py", "calibrated_rarity.py", "detection.py", "rule_expression.py")
COMPOSE_PROJECT_DEFAULT = "porygon"
DOCKER_TIMEOUT = 30


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _run(args: list[str], timeout: int = DOCKER_TIMEOUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


# --------------------------------------------------------------------------
# Git state -- same probes `experiments/run.py` already uses (kept local to avoid
# a circular import: `run.py` calls into this module at pilot run-start).
# --------------------------------------------------------------------------


def _git_sha() -> str:
    try:
        completed = _run(["git", "rev-parse", "HEAD"], timeout=30)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _git_dirty() -> bool:
    try:
        completed = _run(["git", "status", "--porcelain"], timeout=30)
    except (OSError, subprocess.SubprocessError):
        return True
    if completed.returncode != 0:
        return True
    return bool(completed.stdout.strip())


# --------------------------------------------------------------------------
# Kernel fingerprint
# --------------------------------------------------------------------------


def kernel_fingerprint() -> dict[str, Any]:
    """`uname -r`, BTF availability, and cgroup version -- never raises."""
    try:
        release = platform.release()
    except Exception as error:  # pragma: no cover - platform.release() essentially never raises
        return _unavailable(f"platform.release() failed: {type(error).__name__}: {error}")
    if not release:
        return _unavailable("platform.release() returned no value")
    try:
        btf_present = Path("/sys/kernel/btf/vmlinux").exists()
        cgroup_v2 = Path("/sys/fs/cgroup/cgroup.controllers").exists()
    except OSError as error:
        return _unavailable(f"could not probe /sys: {error}")
    return {
        "status": "measured",
        "kernel_release": release,
        "btf_present": btf_present,
        "cgroup_version": "v2" if cgroup_v2 else "v1",
    }


# --------------------------------------------------------------------------
# compose.yaml -- a narrow line-oriented scan, not a YAML parser. experiments/ is
# stdlib-only and the file's service blocks are flat enough (2-space service key,
# 4-space-indented body) that this is reliable for the one field read here.
# --------------------------------------------------------------------------


def _compose_service_image(service: str) -> str | None:
    try:
        lines = COMPOSE_PATH.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    in_service = False
    for line in lines:
        if line.startswith(f"  {service}:"):
            in_service = True
            continue
        if not in_service:
            continue
        if line.strip() and not line.startswith((" " * 4, "\t")):
            break  # dedented back to a sibling top-level key: this service block ended
        stripped = line.strip()
        if stripped.startswith("image:"):
            return stripped.split(":", 1)[1].strip()
    return None


def _hash_directory(directory: Path) -> dict[str, Any]:
    if not directory.is_dir():
        return _unavailable(f"{directory} does not exist")
    try:
        files = sorted(path for path in directory.rglob("*") if path.is_file())
    except OSError as error:
        return _unavailable(f"could not list {directory}: {error}")
    if not files:
        return _unavailable(f"{directory} contains no files")
    digest = hashlib.sha256()
    per_file: dict[str, str] = {}
    try:
        for path in files:
            rel = str(path.relative_to(directory))
            file_hash = sha256_file(path)
            per_file[rel] = file_hash
            digest.update(rel.encode("utf-8"))
            digest.update(file_hash.encode("utf-8"))
    except OSError as error:
        return _unavailable(f"could not hash a file under {directory}: {error}")
    return {"status": "measured", "combined_sha256": digest.hexdigest(), "files": per_file}


def falco_ruleset_fingerprint() -> dict[str, Any]:
    """Combined sha256 of every file under `falco/`, plus the Falco image reference.

    The image reference is read from `compose.yaml` (digest-pinned there per the
    repository's image-pinning convention), which is available whether or not the
    stack is up. If it isn't found there, a running container named `falco` is
    tried as a fallback; either miss degrades to "unavailable" rather than failing.
    """
    ruleset = _hash_directory(FALCO_DIR)
    reference = _compose_service_image("falco")
    if reference is not None:
        image: dict[str, Any] = {"status": "measured", "reference": reference, "source": "compose.yaml"}
    else:
        inspected = _docker_image_inspect_by_container("falco")
        if inspected is None:
            image = _unavailable("no falco image reference in compose.yaml and no running falco container")
        else:
            image = {
                "status": "measured",
                "reference": inspected.get("Image", ""),
                "source": "docker inspect (running container)",
            }
    return {"ruleset": ruleset, "image": image}


def _docker_image_inspect_by_container(container: str) -> dict[str, Any] | None:
    """`.Config` of a running container inspect -- `.Config.Image` is the reference
    the container was created from. Container inspect has no `RepoDigests`; that
    field only exists on an image inspect, which `service_image_fingerprint` covers.
    """
    try:
        completed = _run(["docker", "inspect", container])
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    if not parsed:
        return None
    return parsed[0].get("Config") or {}


# --------------------------------------------------------------------------
# Service image digests
# --------------------------------------------------------------------------


def _docker_image_inspect(reference: str) -> dict[str, Any] | None:
    try:
        completed = _run(["docker", "image", "inspect", reference])
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    try:
        parsed = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return parsed[0] if parsed else None


def service_image_fingerprint() -> dict[str, Any]:
    """Per-service `docker inspect` identity; one missing service never fails the rest.

    `postgres` and `gateway` pull an explicitly pinned external reference recorded
    in compose.yaml. `backend`/`collector`/`telemetry`/`responder`/`scanner` are
    built locally with no explicit `image:` in compose.yaml, so they fall back to
    Compose's default build-tag convention (`<project>-<service>:latest`).
    """
    result: dict[str, Any] = {}
    for service in SERVICE_NAMES:
        pinned = _compose_service_image(service)
        candidates = [pinned] if pinned else [f"{COMPOSE_PROJECT_DEFAULT}-{service}:latest"]
        entry: dict[str, Any] | None = None
        for reference in candidates:
            inspected = _docker_image_inspect(reference)
            if inspected is not None:
                entry = {
                    "status": "measured",
                    "reference": reference,
                    "image_id": inspected.get("Id"),
                    "repo_digests": inspected.get("RepoDigests") or [],
                }
                break
        if entry is None:
            entry = _unavailable(
                "docker is unreachable or no local image matched: " + ", ".join(candidates)
            )
        result[service] = entry
    return result


# --------------------------------------------------------------------------
# Scoring-config fingerprint
# --------------------------------------------------------------------------


def _import_scoring_module() -> Any:
    backend_src = str(ROOT / "backend/src")
    inserted = backend_src not in sys.path
    if inserted:
        sys.path.insert(0, backend_src)
    try:
        sys.modules.pop("porygon_api.scoring", None)
        return importlib.import_module("porygon_api.scoring")
    finally:
        if inserted:
            sys.path.remove(backend_src)


def _scoring_config_constant() -> dict[str, Any]:
    path = BACKEND_SRC / "scoring.py"
    if not path.is_file():
        return _unavailable(f"{path} does not exist")
    try:
        module = _import_scoring_module()
        config = module.SCORING_CONFIG
    except Exception as error:
        return _unavailable(f"scoring.py could not be imported: {type(error).__name__}: {error}")
    try:
        return {"status": "measured", "sha256": sha256_json(config)}
    except TypeError as error:
        return _unavailable(f"SCORING_CONFIG is not JSON-serialisable: {error}")


def scoring_config_fingerprint() -> dict[str, Any]:
    files: dict[str, Any] = {}
    for name in SCORING_FILES:
        path = BACKEND_SRC / name
        if not path.is_file():
            files[name] = _unavailable(f"{path} does not exist")
            continue
        try:
            files[name] = {"status": "measured", "sha256": sha256_file(path)}
        except OSError as error:
            files[name] = _unavailable(f"could not hash {path}: {error}")
    return {"files": files, "config_constant": _scoring_config_constant()}


# --------------------------------------------------------------------------
# Code fingerprint
# --------------------------------------------------------------------------


def code_fingerprint() -> dict[str, Any]:
    if not EXPERIMENTS_DIR.is_dir():
        experiments_py = _unavailable(f"{EXPERIMENTS_DIR} does not exist")
    else:
        try:
            files = sorted(path for path in EXPERIMENTS_DIR.rglob("*.py") if path.is_file())
            digest = hashlib.sha256()
            for path in files:
                rel = str(path.relative_to(EXPERIMENTS_DIR))
                digest.update(rel.encode("utf-8"))
                digest.update(sha256_file(path).encode("utf-8"))
        except OSError as error:
            experiments_py = _unavailable(f"could not hash experiments/*.py: {error}")
        else:
            experiments_py = {
                "status": "measured",
                "combined_sha256": digest.hexdigest(),
                "file_count": len(files),
            }
    return {"git_sha": _git_sha(), "git_dirty": _git_dirty(), "experiments_py": experiments_py}


# --------------------------------------------------------------------------
# Whole document
# --------------------------------------------------------------------------


def run_environment() -> dict[str, Any]:
    """Combine every fingerprint into one immutable, captured-at-run-start document."""
    return {
        "schema_version": SCHEMA_VERSION,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "kernel": kernel_fingerprint(),
        "falco_ruleset": falco_ruleset_fingerprint(),
        "service_images": service_image_fingerprint(),
        "scoring_config": scoring_config_fingerprint(),
        "code": code_fingerprint(),
    }


def environment_hash(doc: dict[str, Any]) -> str:
    """Stable sha256 over the canonical form of the document.

    `sha256_json` (via `canonical_json`) already sorts every dict's keys
    recursively, so two documents with the same logical content but different
    key order hash identically -- no separate canonicalisation step is needed.
    """
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("run-environment document must declare " + SCHEMA_VERSION)
    return sha256_json(doc)


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------


def _is_probe_result(node: Any) -> bool:
    return isinstance(node, dict) and "status" in node


def _diff(a: Any, b: Any, path: str, out: list[str]) -> None:
    if _is_probe_result(a) or _is_probe_result(b):
        status_a = a.get("status") if isinstance(a, dict) else None
        status_b = b.get("status") if isinstance(b, dict) else None
        if status_a == "unavailable" or status_b == "unavailable":
            # A probe that failed to capture on either side is never reported as a
            # difference -- that would flag two runs as non-comparable on a field
            # neither run actually measured, which is a false signal, not a real one.
            return
        if not isinstance(a, dict) or not isinstance(b, dict):
            if a != b:
                out.append(f"{path} differs: {a!r} vs {b!r}")
            return
        for key in sorted((set(a) | set(b)) - {"status", "reason"}):
            _diff(a.get(key), b.get(key), f"{path}.{key}" if path else key, out)
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            _diff(a.get(key), b.get(key), f"{path}.{key}" if path else key, out)
        return
    if a != b:
        out.append(f"{path} differs: {a!r} vs {b!r}")


def compare_environments(a: dict[str, Any], b: dict[str, Any]) -> list[str]:
    """Human-readable descriptions of every field that differs between two documents.

    This is what turns "these two runs are comparable" from an assertion into
    something checkable: it names the field and both values, and it never reports
    a difference on a field that either side simply couldn't capture.
    """
    out: list[str] = []
    _diff(a, b, "", out)
    return out
