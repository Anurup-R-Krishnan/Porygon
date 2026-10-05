#!/usr/bin/env python3
"""Validate the frozen Porygon research protocol and traceability graph."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "docs" / "RESEARCH_PROTOCOL_V1.md"
THREAT_PATH = ROOT / "docs" / "THREAT_MODEL_V1.md"
CLAIMS_PATH = ROOT / "docs" / "CLAIMS_V1.md"
SCOPE_PATH = ROOT / "docs" / "PROFILE_SCOPE_EXPERIMENT_V1.md"
FINAL_PHASES_PATH = ROOT / "docs" / "FINAL_PHASES.md"
FEATURE_SCHEMA_PATH = ROOT / "docs" / "FEATURE_SCHEMA_V1.md"

REQUIRED_ARMS = {"ARM-GLOBAL", "ARM-TAG", "ARM-DIGEST", "ARM-CONTEXT"}
REQUIRED_DETECTORS = {
    "DET-RULES",
    "DET-NOVELTY",
    "DET-FREQUENCY",
    "DET-SEQUENCE",
    "DET-CALIBRATED",
    "DET-HYBRID",
}
REQUIRED_ABLATIONS = {
    "ABL-NO-SEQUENCE",
    "ABL-NO-NOVELTY",
    "ABL-NO-DISTRIBUTION",
    "ABL-NO-NUMERIC",
    "ABL-NO-CONTEXT",
    "ABL-FALLBACK",
}
EXPECTED_OUTPUT_PREFIX = "artifacts/experiments/protocol-v1/"
ID_PATTERNS = {
    "questions": r"RQ-\d{3}",
    "hypotheses": r"H_[01]_\d{3}",
    "experiments": r"EXP-\d{3}",
    "metrics": r"MET-[A-Z]+-\d{3}",
    "outputs": r"ART-(?:MAN|TBL|FIG|DES)-\d{3}",
    "conditional_claims": r"CLM-C\d{3}",
    "workloads": r"WL-[A-Z0-9-]+",
    "scenarios": r"SCN-[A-Z0-9-]+",
}
SET_LIKE_CONTEXT_FIELDS = {"devices", "ports", "mounts"}
FORBIDDEN_CONTEXT_KEYS = {
    "environment",
    "environment_names",
    "environment_values",
    "mount_source",
    "source",
    "container_id",
    "container_name",
    "timestamp",
    "labels",
    "restart_count",
    "pid",
}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def _extract_json_fence(text: str, label: str) -> Any:
    pattern = rf"```json[ \t]+{re.escape(label)}\n(.*?)\n```"
    matches = re.findall(pattern, text, flags=re.DOTALL)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one JSON fence labelled {label!r}, found {len(matches)}")
    return json.loads(matches[0])


def _collect_ids(items: Any, label: str, errors: list[str]) -> set[str]:
    if not isinstance(items, list):
        errors.append(f"{label} must be a list")
        return set()
    values: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            errors.append(f"{label}[{index}] is missing a non-empty id")
            continue
        values.append(item["id"])
    duplicates = sorted({value for value in values if values.count(value) > 1})
    if duplicates:
        errors.append(f"{label} contains duplicate IDs: {', '.join(duplicates)}")
    pattern = ID_PATTERNS.get(label)
    invalid = sorted(value for value in values if pattern and re.fullmatch(pattern, value) is None)
    if invalid:
        errors.append(f"{label} contains malformed IDs: {', '.join(invalid)}")
    return set(values)


def _check_refs(
    item: dict[str, Any],
    field: str,
    allowed: set[str],
    owner: str,
    errors: list[str],
    *,
    required: bool = True,
) -> None:
    refs = item.get(field)
    if not isinstance(refs, list) or (required and not refs):
        errors.append(f"{owner} requires a non-empty {field} list")
        return
    unknown = sorted(set(refs) - allowed)
    if unknown:
        errors.append(f"{owner} has unknown {field}: {', '.join(unknown)}")


def validate_manifest(manifest: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["protocol manifest must be a JSON object"]

    if manifest.get("schema_version") != "porygon.research-protocol-manifest.v1":
        errors.append("unexpected or missing protocol manifest schema_version")
    if manifest.get("protocol_id") != "porygon.research.protocol.v1":
        errors.append("unexpected or missing protocol_id")
    if manifest.get("protocol_status") not in {"review_pending", "frozen"}:
        errors.append("protocol_status must be review_pending or frozen")
    if manifest.get("independent_unit") != "complete_workload_run":
        errors.append("independent_unit must be complete_workload_run")

    split_policy = str(manifest.get("split_policy", "")).lower()
    if "whole-run" not in split_policy or "window crosses" not in split_policy:
        errors.append("split_policy must prohibit whole-run/window leakage")
    if "window-level assignment" in split_policy or "windows may cross" in split_policy:
        errors.append("split_policy permits window-level split leakage")

    safety = str(manifest.get("safety_boundary", "")).lower()
    for phrase in ("disposable local containers", "no real malware", "no public targets"):
        if phrase not in safety:
            errors.append(f"safety_boundary is missing {phrase!r}")

    if set(manifest.get("arms", [])) != REQUIRED_ARMS:
        errors.append("profile arms do not exactly match the four frozen primary arms")
    if set(manifest.get("detectors", [])) != REQUIRED_DETECTORS:
        errors.append("detector comparisons do not exactly match the frozen set")
    if set(manifest.get("ablations", [])) != REQUIRED_ABLATIONS:
        errors.append("ablations do not exactly match the frozen set")

    questions = manifest.get("questions", [])
    hypotheses = manifest.get("hypotheses", [])
    experiments = manifest.get("experiments", [])
    metrics = manifest.get("metrics", [])
    outputs = manifest.get("outputs", [])
    claims = manifest.get("conditional_claims", [])
    workloads = manifest.get("workloads", [])
    scenarios = manifest.get("scenarios", [])

    question_ids = _collect_ids(questions, "questions", errors)
    hypothesis_ids = _collect_ids(hypotheses, "hypotheses", errors)
    experiment_ids = _collect_ids(experiments, "experiments", errors)
    metric_ids = _collect_ids(metrics, "metrics", errors)
    output_ids = _collect_ids(outputs, "outputs", errors)
    claim_ids = _collect_ids(claims, "conditional_claims", errors)
    workload_ids = _collect_ids(workloads, "workloads", errors)
    scenario_ids = _collect_ids(scenarios, "scenarios", errors)

    if len(workload_ids) < 3:
        errors.append("at least three workload families are required")
    for workload in workloads if isinstance(workloads, list) else []:
        versions = workload.get("versions", []) if isinstance(workload, dict) else []
        modes = workload.get("modes", []) if isinstance(workload, dict) else []
        if len(versions) < 2:
            errors.append(f"{workload.get('id', '<unknown>')} requires at least two versions")
        if len(modes) < 2:
            errors.append(f"{workload.get('id', '<unknown>')} requires multiple benign modes")

    for scenario in scenarios if isinstance(scenarios, list) else []:
        if not isinstance(scenario, dict) or scenario.get("safe") is not True:
            errors.append(f"{scenario.get('id', '<unknown>')} is not explicitly safe")
        if not scenario.get("ground_truth"):
            errors.append(f"{scenario.get('id', '<unknown>')} lacks ground truth")

    for hypothesis in hypotheses if isinstance(hypotheses, list) else []:
        if not isinstance(hypothesis, dict):
            continue
        owner = str(hypothesis.get("id", "<hypothesis>"))
        if hypothesis.get("kind") not in {"null", "alternative"}:
            errors.append(f"{owner} kind must be null or alternative")
        _check_refs(hypothesis, "question_ids", question_ids, owner, errors)
        _check_refs(hypothesis, "experiment_ids", experiment_ids, owner, errors)
        _check_refs(hypothesis, "metric_ids", metric_ids, owner, errors)
        _check_refs(hypothesis, "output_ids", output_ids, owner, errors)
        if not str(hypothesis.get("failure_criterion", "")).strip():
            errors.append(f"{owner} lacks a failure criterion")

    for question_id in sorted(question_ids):
        kinds = {
            item.get("kind")
            for item in hypotheses
            if isinstance(item, dict) and question_id in item.get("question_ids", [])
        }
        if "null" not in kinds:
            errors.append(f"{question_id} has no linked null hypothesis")
        if "alternative" not in kinds:
            errors.append(f"{question_id} has no linked alternative hypothesis")

    for experiment in experiments if isinstance(experiments, list) else []:
        if not isinstance(experiment, dict):
            continue
        owner = str(experiment.get("id", "<experiment>"))
        _check_refs(experiment, "question_ids", question_ids, owner, errors)
        _check_refs(experiment, "hypothesis_ids", hypothesis_ids, owner, errors)
        _check_refs(experiment, "workload_ids", workload_ids, owner, errors)
        _check_refs(experiment, "scenario_ids", scenario_ids, owner, errors)
        _check_refs(experiment, "metric_ids", metric_ids, owner, errors)
        _check_refs(experiment, "output_ids", output_ids, owner, errors)
        if "whole-run" not in str(experiment.get("split", "")).lower() and "copied fit sets" not in str(
            experiment.get("split", "")
        ).lower():
            errors.append(f"{owner} does not state a whole-run or isolated copied-fit split")
        if not str(experiment.get("failure_criterion", "")).strip():
            errors.append(f"{owner} lacks a failure criterion")

    for metric in metrics if isinstance(metrics, list) else []:
        if not isinstance(metric, dict):
            continue
        owner = str(metric.get("id", "<metric>"))
        if not str(metric.get("unit", "")).strip() or not str(metric.get("estimand", "")).strip():
            errors.append(f"{owner} requires unit and estimand")

    output_paths: list[str] = []
    for output in outputs if isinstance(outputs, list) else []:
        if not isinstance(output, dict):
            continue
        path = str(output.get("path", ""))
        output_paths.append(path)
        if not path.startswith(EXPECTED_OUTPUT_PREFIX):
            errors.append(f"{output.get('id', '<output>')} path is outside the versioned artifact root")
    if len(output_paths) != len(set(output_paths)):
        errors.append("outputs contain duplicate artifact paths")

    for claim in claims if isinstance(claims, list) else []:
        if not isinstance(claim, dict):
            continue
        owner = str(claim.get("id", "<claim>"))
        _check_refs(claim, "metric_ids", metric_ids, owner, errors)
        _check_refs(claim, "output_ids", output_ids, owner, errors)

    referenced_metrics = {
        ref
        for collection in (hypotheses, experiments, claims)
        for item in collection
        if isinstance(item, dict)
        for ref in item.get("metric_ids", [])
    }
    referenced_outputs = {
        ref
        for collection in (hypotheses, experiments, claims)
        for item in collection
        if isinstance(item, dict)
        for ref in item.get("output_ids", [])
    }
    if metric_ids - referenced_metrics:
        errors.append(f"unlinked metrics: {', '.join(sorted(metric_ids - referenced_metrics))}")
    if output_ids - referenced_outputs:
        errors.append(f"unlinked outputs: {', '.join(sorted(output_ids - referenced_outputs))}")

    reviewers = manifest.get("reviewers")
    if not isinstance(reviewers, list):
        errors.append("reviewers must be a list")
    else:
        roles = {item.get("role") for item in reviewers if isinstance(item, dict)}
        if roles != {"security", "methodology"}:
            errors.append("reviewers must include exactly security and methodology roles")
        if manifest.get("protocol_status") == "frozen":
            for reviewer in reviewers:
                if not isinstance(reviewer, dict) or reviewer.get("status") != "approved":
                    errors.append("frozen protocol requires both reviewer approvals")
                    continue
                if not reviewer.get("name") or not reviewer.get("date"):
                    errors.append("approved reviewers require name and date")

    if not claim_ids:
        errors.append("at least one conditional claim is required")
    return errors


def _normalize_text(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _canonical_context(value: Any, *, field: str | None = None) -> Any:
    if isinstance(value, dict):
        normalized = {str(key): _canonical_context(item, field=str(key)) for key, item in value.items()}
        capabilities = normalized.get("capabilities")
        if isinstance(capabilities, dict):
            for key in ("add", "drop"):
                if isinstance(capabilities.get(key), list):
                    capabilities[key] = sorted(capabilities[key])
        return normalized
    if isinstance(value, list):
        normalized_items = [_canonical_context(item) for item in value]
        if field in SET_LIKE_CONTEXT_FIELDS:
            return sorted(normalized_items, key=_canonical_json)
        return normalized_items
    if isinstance(value, str):
        return _normalize_text(value)
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _context_hash(value: Any) -> str:
    canonical = _canonical_json(_canonical_context(value))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _find_forbidden_context_keys(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_CONTEXT_KEYS:
                errors.append(f"forbidden context key {path}.{key}")
            errors.extend(_find_forbidden_context_keys(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            errors.extend(_find_forbidden_context_keys(item, f"{path}[{index}]"))
    return errors


def validate_documents(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    protocol = _read(PROTOCOL_PATH)
    threat = _read(THREAT_PATH)
    claims = _read(CLAIMS_PATH)
    scope = _read(SCOPE_PATH)
    final_phases = _read(FINAL_PHASES_PATH)
    feature_schema = _read(FEATURE_SCHEMA_PATH)

    required_files = {
        PROTOCOL_PATH: protocol,
        THREAT_PATH: threat,
        CLAIMS_PATH: claims,
        SCOPE_PATH: scope,
    }
    for path, text in required_files.items():
        if not text:
            errors.append(f"missing or empty required document: {path.relative_to(ROOT)}")

    for term in ("global", "mutable tag", "digest-only", "digest-plus-context", "H_0", "H_1", "run-level"):
        if term.lower() not in protocol.lower():
            errors.append(f"research protocol is missing required concept {term!r}")

    for term in (
        "assets",
        "trusted computing base",
        "docker socket",
        "baseline-poisoning",
        "blind spots",
        "single-host",
        "safety and ethics",
        "artifact identity",
        "behavioural profile scope",
    ):
        if term not in threat.lower():
            errors.append(f"threat model is missing required concept {term!r}")

    claim_patterns = {
        "not an attack probability": r"not\s+an\s+attack probability",
        "not proof": r"not\s+proof",
        "prior art": r"prior art",
        "falsifiable": r"falsif",
        "scanner finding boundary": r"scanner findings?.*not proof.*exploitation",
    }
    plain_claims = claims.replace("**", "")
    for label, pattern in claim_patterns.items():
        if not re.search(pattern, plain_claims, flags=re.IGNORECASE | re.DOTALL):
            errors.append(f"claims document is missing {label!r} wording")

    documented_claim_ids = set(re.findall(r"`(CLM-C\d{3})`", claims))
    manifest_claim_ids = {item["id"] for item in manifest.get("conditional_claims", [])}
    if documented_claim_ids != manifest_claim_ids:
        errors.append("conditional claim IDs differ between claims document and protocol manifest")

    for name in ("RESEARCH_PROTOCOL_V1.md", "THREAT_MODEL_V1.md", "CLAIMS_V1.md", "PROFILE_SCOPE_EXPERIMENT_V1.md"):
        if name not in final_phases:
            errors.append(f"FINAL_PHASES.md does not link {name}")
    if "current v1 implementation" not in feature_schema.lower() or "profile-scope experiment" not in feature_schema.lower():
        errors.append("FEATURE_SCHEMA_V1.md does not distinguish current implementation from experiment arms")

    try:
        equivalent_a = _extract_json_fence(scope, "context-example-equivalent-a")
        equivalent_b = _extract_json_fence(scope, "context-example-equivalent-b")
        security_change = _extract_json_fence(scope, "context-example-security-change")
    except (ValueError, json.JSONDecodeError) as exc:
        errors.append(f"context examples are invalid: {exc}")
    else:
        for document in (equivalent_a, equivalent_b, security_change):
            errors.extend(_find_forbidden_context_keys(document))
            if document.get("schema_version") != "porygon.runtime-context.v1":
                errors.append("context example has the wrong schema_version")
        if _context_hash(equivalent_a) != _context_hash(equivalent_b):
            errors.append("semantically reordered context examples do not produce one hash")
        if _context_hash(equivalent_a) == _context_hash(security_change):
            errors.append("security-relevant context change did not change the hash")

    return errors


def run_negative_self_tests(manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []

    cases: list[tuple[str, Any, str]] = []

    missing_id = copy.deepcopy(manifest)
    missing_id["metrics"][0].pop("id", None)
    cases.append(("missing ID", missing_id, "missing a non-empty id"))

    malformed_id = copy.deepcopy(manifest)
    malformed_id["questions"][0]["id"] = "question one"
    cases.append(("malformed ID", malformed_id, "malformed IDs"))

    duplicate_id = copy.deepcopy(manifest)
    duplicate_id["questions"].append(copy.deepcopy(duplicate_id["questions"][0]))
    cases.append(("duplicate ID", duplicate_id, "duplicate IDs"))

    unlinked_claim = copy.deepcopy(manifest)
    unlinked_claim["conditional_claims"][0]["output_ids"] = ["ART-DOES-NOT-EXIST"]
    cases.append(("unlinked claim", unlinked_claim, "unknown output_ids"))

    absent_null = copy.deepcopy(manifest)
    absent_null["hypotheses"] = [
        item
        for item in absent_null["hypotheses"]
        if not (item["kind"] == "null" and "RQ-001" in item["question_ids"])
    ]
    cases.append(("absent null hypothesis", absent_null, "has no linked null hypothesis"))

    window_leakage = copy.deepcopy(manifest)
    window_leakage["split_policy"] = "window-level assignment allowed; windows may cross splits"
    cases.append(("window leakage", window_leakage, "window-level split leakage"))

    missing_safety = copy.deepcopy(manifest)
    missing_safety["safety_boundary"] = ""
    cases.append(("missing safety boundary", missing_safety, "safety_boundary is missing"))

    for label, fixture, expected in cases:
        errors = validate_manifest(fixture)
        if not any(expected in error for error in errors):
            failures.append(f"self-test {label!r} did not detect {expected!r}")
    return failures


def main() -> int:
    protocol_text = _read(PROTOCOL_PATH)
    try:
        manifest = _extract_json_fence(protocol_text, "protocol-manifest")
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"[FAIL] protocol manifest is invalid: {exc}", file=sys.stderr)
        return 1

    errors = validate_manifest(manifest)
    errors.extend(validate_documents(manifest))
    errors.extend(run_negative_self_tests(manifest))
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1

    reviewer_status = ", ".join(
        f"{item['role']}={item['status']}" for item in manifest["reviewers"]
    )
    print(
        "[PASS] protocol schema, unique IDs, traceability, claims, split leakage, "
        "safety boundary, context canonicalization, and negative validator fixtures"
    )
    print(f"[INFO] protocol status={manifest['protocol_status']}; reviewers: {reviewer_status}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
