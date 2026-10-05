"""ART-DES-001: the pre-confirmatory sample-size lock.

RESEARCH_PROTOCOL_V1.md's "Deterministic assignment and seeds" section
specifies this exactly: enumerate candidate per-cell counts from a minimum
through 120, pick the smallest count whose exact binomial power calculation
reaches 80% power for the frozen 25% relative-FPR-reduction / 5-percentage-
point recall-margin material effect, using the upper 95% binomial bound on
the pilot discordant-pair rate as the nuisance parameter. The maximum across
co-primary contrasts becomes the locked per-cell count.

Ordering matters and is enforced by the protocol text, not just convention:
"The versioned sample-size lock records inputs... before confirmatory
execution. Once one confirmatory run starts, v1 counts and criteria cannot
change." A lock computed after confirmatory data already exists cannot serve
as that document — it would not have constrained the collection it claims to
govern. This module is therefore built to be run BEFORE the next real
confirmatory collection round, using only pilot-split discordant-pair data,
and its output is refused if run against a dataset that already contains
confirmatory-eligible test-split evidence for the same contrasts (see
`assert_no_confirmatory_contamination`).
"""
from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import math
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from experiments.analysis import exact_mcnemar_p
from experiments.artifacts import load_json, sha256_file, write_versioned_json
from experiments.scope import SCOPES, compare_scopes

ROOT = Path(__file__).resolve().parents[1]
# Kept as separate module-level names (rather than recomputed from ROOT inline)
# so a test can redirect where pilot evidence is discovered/scanned for
# contamination and where the lock is written by default, without also having
# to fake up a whole scripts/review_gate.py at a temporary ROOT -- ROOT itself
# always points at this real repository.
LOCAL_ARTIFACTS_DIR = ROOT / "artifacts" / "experiments" / "local"
DEFAULT_LOCK_DIR = ROOT / "artifacts" / "experiments" / "protocol-v1" / "design"

MIN_CANDIDATE_COUNT = 5
MAX_CANDIDATE_COUNT = 120
TARGET_POWER = 0.80
MATERIAL_RELATIVE_FPR_REDUCTION = 0.25
MATERIAL_RECALL_MARGIN_PP = 0.05
FPR_FAMILY_ALPHA = 0.05 / 3  # three primary FPR contrasts, conservative planning alpha
RECALL_ALPHA = 0.05  # one-sided for the co-primary recall gate


def _binom_sf_ge(k: int, n: int, p: float) -> float:
    if k > n:
        return 0.0
    if k <= 0:
        return 1.0
    return min(1.0, sum(math.comb(n, i) * (p**i) * ((1 - p) ** (n - i)) for i in range(k, n + 1)))


def upper_95_binomial_bound(successes: int, trials: int) -> float:
    """Upper 95% Clopper-Pearson bound on a proportion, used as the nuisance
    discordant-pair probability. 0.5 (maximum variance, most conservative) is
    used when the bound is undefined, matching the protocol text exactly."""
    if trials == 0:
        return 0.5
    from experiments.analysis import clopper_pearson_interval

    return clopper_pearson_interval(successes, trials, confidence=0.90).upper  # 90% two-sided = 95% one-sided upper


@dataclass(frozen=True)
class PowerEnumerationResult:
    contrast_id: str
    nuisance_discordant_p: float
    required_count: int | None  # None if no count through MAX_CANDIDATE_COUNT reaches target power
    achieved_power: float | None
    alpha: float


def enumerate_fpr_power(
    contrast_id: str,
    *,
    baseline_fpr: float,
    nuisance_discordant_p: float,
    alpha: float = FPR_FAMILY_ALPHA,
    material_relative_reduction: float = MATERIAL_RELATIVE_FPR_REDUCTION,
    target_power: float = TARGET_POWER,
) -> PowerEnumerationResult:
    """Exact binomial power enumeration for one paired FPR contrast.

    Models the McNemar test's power at a given per-cell run count n. Under
    the alternative, the coarser arm has false-positive rate baseline_fpr and
    the finer-scope arm has baseline_fpr * (1 - material_relative_reduction);
    treating the two arms' positive calls on the same run as approximately
    independent Bernoulli outcomes, the probability a discordant pair favours
    the coarser arm (the direction the material effect predicts) is

        p_effect = p_a * (1 - p_b) / (p_a * (1 - p_b) + (1 - p_a) * p_b)

    where p_a = baseline_fpr, p_b = baseline_fpr * (1 - material_relative_reduction).
    This requires an actual pilot-estimated baseline_fpr; without one, "a 25%
    relative reduction" has no absolute meaning and any power number would be
    an artifact of an arbitrary placeholder, not a real planning estimate.
    Discordant pairs are modelled as Binomial(n * nuisance_discordant_p,
    p_effect); power is P(reject H0) under that alternative, using the same
    exact two-sided test as experiments.analysis.exact_mcnemar_p.
    """
    if not (0.0 < baseline_fpr < 1.0):
        raise ValueError("baseline_fpr must be a real pilot-estimated proportion strictly between 0 and 1")
    target_fpr = baseline_fpr * (1 - material_relative_reduction)
    p_effect = (baseline_fpr * (1 - target_fpr)) / (
        baseline_fpr * (1 - target_fpr) + (1 - baseline_fpr) * target_fpr
    )
    for n in range(MIN_CANDIDATE_COUNT, MAX_CANDIDATE_COUNT + 1):
        n_discordant = max(1, round(n * nuisance_discordant_p))
        # Power = P(exact two-sided McNemar rejects | discordant pairs ~ Binomial(n_discordant, p_effect))
        power = 0.0
        for b10 in range(0, n_discordant + 1):
            b01 = n_discordant - b10
            prob = math.comb(n_discordant, b10) * (p_effect**b10) * ((1 - p_effect) ** b01)
            larger = max(b10, b01)
            p_value = min(1.0, 2 * _binom_sf_ge(larger, n_discordant, 0.5))
            if p_value < alpha:
                power += prob
        if power >= target_power:
            return PowerEnumerationResult(
                contrast_id=contrast_id, nuisance_discordant_p=nuisance_discordant_p,
                required_count=n, achieved_power=power, alpha=alpha,
            )
    return PowerEnumerationResult(
        contrast_id=contrast_id, nuisance_discordant_p=nuisance_discordant_p,
        required_count=None, achieved_power=None, alpha=alpha,
    )


def enumerate_recall_power(
    contrast_id: str,
    *,
    reference_recall: float,
    alpha: float = RECALL_ALPHA,
    margin_pp: float = MATERIAL_RECALL_MARGIN_PP,
    target_power: float = TARGET_POWER,
) -> PowerEnumerationResult:
    """Exact binomial power enumeration for the co-primary recall
    non-inferiority gate: power to conclude observed recall is within
    margin_pp of reference_recall, one-sided, at count n."""
    for n in range(MIN_CANDIDATE_COUNT, MAX_CANDIDATE_COUNT + 1):
        # Under the alternative (true recall == reference_recall, i.e. no
        # real degradation), power is the probability the exact one-sided
        # lower confidence bound clears (reference_recall - margin_pp).
        power = 0.0
        for successes in range(0, n + 1):
            prob = math.comb(n, successes) * (reference_recall**successes) * ((1 - reference_recall) ** (n - successes))
            from experiments.analysis import clopper_pearson_interval

            ci = clopper_pearson_interval(successes, n, confidence=1 - 2 * alpha)
            if ci.lower >= reference_recall - margin_pp:
                power += prob
        if power >= target_power:
            return PowerEnumerationResult(
                contrast_id=contrast_id, nuisance_discordant_p=reference_recall,
                required_count=n, achieved_power=power, alpha=alpha,
            )
    return PowerEnumerationResult(
        contrast_id=contrast_id, nuisance_discordant_p=reference_recall,
        required_count=None, achieved_power=None, alpha=alpha,
    )


@dataclass(frozen=True)
class SampleSizeLock:
    schema_version: str
    contrasts: list[PowerEnumerationResult]
    locked_per_cell_count: int | None
    feasibility_failure: bool
    note: str


def assert_no_confirmatory_contamination(evidence_classes: Sequence[str]) -> None:
    """Refuse to build a sample-size lock if any confirmatory-eligible run
    already exists for this protocol.

    evidence_classes is the list of `evidence_class` values recorded on every
    prior study-manifest.json (see experiments/study.py: manifest["evidence_class"]).
    A lock built after confirmatory data already exists could not have
    constrained the collection it claims to govern; the protocol text
    requires the lock before confirmatory execution, not after.
    """
    if "confirmatory" in evidence_classes:
        raise ValueError(
            "cannot build a fresh ART-DES-001 sample-size lock: confirmatory-eligible "
            "data already exists for this protocol. A lock computed now would not have "
            "constrained the collection it claims to govern (RESEARCH_PROTOCOL_V1.md: "
            "'the versioned sample-size lock records inputs... before confirmatory "
            "execution. Once one confirmatory run starts, v1 counts and criteria cannot "
            "change.'). This lock may only be used to plan a genuinely new confirmatory "
            "round under a revised protocol version, never to retroactively justify data "
            "already collected."
        )


def build_sample_size_lock(
    pilot_discordant_pairs: dict[str, tuple[int, int]],
    pilot_baseline_fpr: dict[str, float],
    reference_recall: float,
) -> SampleSizeLock:
    """Build ART-DES-001 from pilot-split discordant-pair counts only.

    pilot_discordant_pairs maps each of the three primary FPR contrast IDs to
    (successes, trials) for the discordant-pair rate observed in the pilot
    split, exactly as the protocol specifies. pilot_baseline_fpr maps the
    same contrast IDs to the coarser arm's observed pilot-split FPR, needed
    to give "25% relative reduction" an absolute meaning. Never pass test-split or
    confirmatory-split data here: doing so would make this a post-hoc
    justification rather than a pre-registered lock, which the protocol
    explicitly prohibits by requiring the lock before confirmatory execution.
    """
    results: list[PowerEnumerationResult] = []
    for contrast_id, (successes, trials) in pilot_discordant_pairs.items():
        nuisance = upper_95_binomial_bound(successes, trials)
        results.append(enumerate_fpr_power(
            contrast_id, baseline_fpr=pilot_baseline_fpr[contrast_id], nuisance_discordant_p=nuisance,
        ))
    results.append(enumerate_recall_power("recall_non_inferiority", reference_recall=reference_recall))

    feasible = [r for r in results if r.required_count is not None]
    if len(feasible) < len(results):
        return SampleSizeLock(
            schema_version="porygon.sample-size-lock.v1",
            contrasts=results,
            locked_per_cell_count=None,
            feasibility_failure=True,
            note=(
                "At least one contrast did not reach 80% power through the maximum "
                f"candidate count ({MAX_CANDIDATE_COUNT}); per the protocol, confirmatory "
                "collection stops here for a feasibility decision and protocol revision, "
                "rather than proceeding with an underpowered count."
            ),
        )

    locked = max(r.required_count for r in results)
    return SampleSizeLock(
        schema_version="porygon.sample-size-lock.v1",
        contrasts=results,
        locked_per_cell_count=locked,
        feasibility_failure=False,
        note=(
            f"Locked per-cell count is {locked}, the maximum across all co-primary "
            "contrasts' required counts. This value only governs confirmatory "
            "collection that has not yet started; per the protocol, it cannot be "
            "applied retroactively to justify data already collected."
        ),
    )


# ---------------------------------------------------------------------------
# Real-evidence estimation, serialization, and the ART-DES-001 artifact writer.
#
# Everything above this point is pure arithmetic over caller-supplied numbers.
# Everything below reads real pilot-run evidence off disk (experiments/scope.py's
# compare_scopes, which itself needs a reachable backend to fetch per-container
# process-event distributions), converts the resulting dataclasses to JSON, and
# writes the versioned, immutable ART-DES-001 artifact the protocol requires.
# ---------------------------------------------------------------------------

# The three primary co-primary FPR contrasts. arm_a is always ARM-CONTEXT (the
# finer-scope arm); arm_b is the coarser comparator whose pilot-split baseline
# FPR seeds enumerate_fpr_power's "25% relative reduction". Contrast IDs and
# arm pairing match experiments/analyze_scope_run.py's own contrast_pairs list
# exactly -- this must never silently drift from that module's naming.
PRIMARY_CONTRASTS: tuple[tuple[str, str, str], ...] = (
    ("CONTEXT_vs_ARM-GLOBAL", "ARM-CONTEXT", "ARM-GLOBAL"),
    ("CONTEXT_vs_ARM-TAG", "ARM-CONTEXT", "ARM-TAG"),
    ("CONTEXT_vs_ARM-DIGEST", "ARM-CONTEXT", "ARM-DIGEST"),
)


def _load_review_gate():
    """Import scripts/review_gate.py by file path.

    scripts/ has no __init__.py and is not an importable package; this is the
    exact loading pattern experiments/tests/test_review_gate.py already uses,
    reused here so the lock's reviewer_approvals and protocol digest can never
    disagree with what that module itself computes.
    """
    path = ROOT / "scripts" / "review_gate.py"
    spec = importlib.util.spec_from_file_location("review_gate", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _benign_positive_map(scope_result: dict, scope: str) -> dict[str, bool]:
    """trial_id -> positive, restricted to benign (non-scenario) test-split
    trials with a present reference key, for one scope in one run's
    compare_scopes() result. Matches exactly the filter
    experiments/analyze_scope_run.py:analyze() applies before pairing arms."""
    return {
        row["trial_id"]: row["positive"]
        for row in scope_result["scopes"][scope]["trials"]
        if row["reference_key_present"] and not row["is_scenario"]
    }


def _reject_degenerate_baseline_fpr(contrast_id: str, baseline_fpr: float, source: str) -> None:
    """Refuse a coarser-arm baseline FPR that is constant (0.0 or 1.0) across
    the given pilot evidence.

    A comparator that never varies makes every discordant pair point the same
    way by construction (see experiments/analyze_scope_run.py:
    detect_degenerate_contrast) and cannot honestly seed "a 25% relative
    reduction" with any real meaning. enumerate_fpr_power refuses the same
    condition, but only once build_sample_size_lock is actually called with
    this value; this input-estimation stage must refuse it immediately,
    naming the degenerate contrast and its source, rather than deferring to a
    less legible failure downstream or silently proceeding.
    """
    if not (0.0 < baseline_fpr < 1.0):
        raise ValueError(
            f"{contrast_id}: the coarser-arm baseline FPR observed across {source} is "
            f"degenerate ({baseline_fpr!r}) -- constant across every pilot run given. "
            "This carries zero statistical information and cannot honestly seed "
            "ART-DES-001's sample-size calculation; refusing rather than silently "
            "substituting a placeholder or proceeding with a result that would be an "
            "artifact of construction, not a real measured effect."
        )


def estimate_pilot_inputs(run_dirs: list[Path], base_url: str) -> dict:
    """Estimate build_sample_size_lock's real inputs from real pilot-run
    evidence.

    For each of PRIMARY_CONTRASTS, pools across every given pilot run
    directory: the observed discordant-pair count (via
    experiments.analysis.exact_mcnemar_p over paired benign test-split calls)
    and the coarser arm's baseline FPR (raw false_positives/benign_runs from
    experiments.scope.compare_scopes). Also computes reference_recall pooled
    from the ARM-GLOBAL arm's scenario (attack-like) trials.

    Raises ValueError, and refuses to proceed, if any contrast's pooled
    baseline FPR is 0.0 or 1.0 -- a degenerate, constant comparator across
    every pilot run given (see _reject_degenerate_baseline_fpr). Given this
    codebase's actual committed pilot data, calling this against
    artifacts/experiments/local/study-confirmatory-200-20260906t071234Z is
    expected to raise: that run's ARM-GLOBAL comparator called every benign
    trial positive (100% FPR), a real, already-documented degeneracy
    (docs/CONFIRMATORY_RESULT_V1.md), not a bug in this function.

    Never pass a run directory whose evidence_class is confirmatory here --
    that is enforced downstream in write_sample_size_lock, not this function,
    which only estimates numbers from whatever run directories it is given.
    """
    if not run_dirs:
        raise ValueError("estimate_pilot_inputs requires at least one pilot run directory")

    fpr_successes = {contrast_id: 0 for contrast_id, _, _ in PRIMARY_CONTRASTS}
    fpr_trials = {contrast_id: 0 for contrast_id, _, _ in PRIMARY_CONTRASTS}
    discordant_successes = {contrast_id: 0 for contrast_id, _, _ in PRIMARY_CONTRASTS}
    discordant_trials = {contrast_id: 0 for contrast_id, _, _ in PRIMARY_CONTRASTS}
    contributing_trial_ids: dict[str, list[str]] = {contrast_id: [] for contrast_id, _, _ in PRIMARY_CONTRASTS}
    global_true_positives = 0
    global_scenario_n = 0
    source_runs: list[str] = []

    for raw_run_dir in run_dirs:
        run_dir = Path(raw_run_dir)
        source_runs.append(run_dir.name)
        scope_result = compare_scopes(base_url, run_dir)

        global_true_positives += scope_result["scopes"]["ARM-GLOBAL"]["true_positives"]
        global_scenario_n += scope_result["scopes"]["ARM-GLOBAL"]["scenario_runs"]

        positive_by_scope = {scope: _benign_positive_map(scope_result, scope) for scope in SCOPES}

        for contrast_id, arm_a, arm_b in PRIMARY_CONTRASTS:
            fpr_successes[contrast_id] += scope_result["scopes"][arm_b]["false_positives"]
            fpr_trials[contrast_id] += scope_result["scopes"][arm_b]["benign_runs"]

            a_map, b_map = positive_by_scope[arm_a], positive_by_scope[arm_b]
            common = sorted(set(a_map) & set(b_map))
            if not common:
                continue
            mcnemar = exact_mcnemar_p(
                contrast_id=contrast_id,
                arm_a_positive=[a_map[t] for t in common],
                arm_b_positive=[b_map[t] for t in common],
            )
            discordant_successes[contrast_id] += mcnemar.discordant_a_only + mcnemar.discordant_b_only
            discordant_trials[contrast_id] += mcnemar.n_pairs
            contributing_trial_ids[contrast_id].extend(common)

    contrasts: dict[str, dict] = {}
    for contrast_id, _, arm_b in PRIMARY_CONTRASTS:
        trials = fpr_trials[contrast_id]
        if trials == 0:
            raise ValueError(
                f"{contrast_id}: no benign test-split trials with a present reference key "
                f"were found under {arm_b} across {source_runs}; cannot estimate a baseline FPR"
            )
        baseline_fpr = fpr_successes[contrast_id] / trials
        _reject_degenerate_baseline_fpr(contrast_id, baseline_fpr, source=str(source_runs))
        contrasts[contrast_id] = {
            "discordant_successes": discordant_successes[contrast_id],
            "discordant_trials": discordant_trials[contrast_id],
            "baseline_fpr": baseline_fpr,
            "baseline_fpr_successes": fpr_successes[contrast_id],
            "baseline_fpr_trials": trials,
            "contributing_trial_ids": contributing_trial_ids[contrast_id],
        }

    if global_scenario_n == 0:
        raise ValueError(
            f"no ARM-GLOBAL scenario (attack-like) trials with a present reference key were "
            f"found across {source_runs}; cannot estimate reference_recall"
        )
    reference_recall = global_true_positives / global_scenario_n

    return {
        "schema_version": "porygon.sample-size-lock-inputs.v1",
        "source_run_dirs": source_runs,
        "base_url": base_url,
        "contrasts": contrasts,
        "reference_recall": reference_recall,
        "reference_recall_successes": global_true_positives,
        "reference_recall_trials": global_scenario_n,
    }


def lock_to_dict(lock: SampleSizeLock) -> dict:
    """JSON-safe conversion of a SampleSizeLock, including its nested
    `contrasts: list[PowerEnumerationResult]`.

    dataclasses are not JSON-serializable by default; `dataclasses.asdict`
    already recurses correctly through nested dataclasses and lists (every
    field on both SampleSizeLock and PowerEnumerationResult is already a
    JSON-safe scalar, list, or nested dataclass), so it is reused here rather
    than a hand-rolled walk that could silently drift from the real shape.
    """
    return dataclasses.asdict(lock)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _git_state() -> dict:
    def run(*args: str) -> str:
        try:
            return subprocess.run(
                args, capture_output=True, text=True, cwd=ROOT, timeout=120
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "unavailable"

    return {
        "git_sha": run("git", "rev-parse", "HEAD"),
        "git_dirty": bool(run("git", "status", "--porcelain")),
    }


def _study_manifest_evidence_classes() -> list[str]:
    """evidence_class of every study-manifest*.json under
    LOCAL_ARTIFACTS_DIR/**, the input assert_no_confirmatory_contamination
    requires. Reads the module-level LOCAL_ARTIFACTS_DIR (not a path computed
    inline from ROOT) so a test can monkeypatch it to an isolated tree
    instead of depending on this repository's real committed evidence.
    """
    local_dir = LOCAL_ARTIFACTS_DIR
    manifests = sorted(local_dir.glob("**/study-manifest*.json")) if local_dir.is_dir() else []
    classes: list[str] = []
    for path in manifests:
        try:
            doc = load_json(path)
        except Exception:
            continue
        evidence_class = doc.get("evidence_class") if isinstance(doc, dict) else None
        if evidence_class is not None:
            classes.append(evidence_class)
    return classes


def write_sample_size_lock(
    inputs: dict,
    lock: SampleSizeLock,
    *,
    reviewer_approvals: dict,
    out_dir: Path | None = None,
) -> Path:
    """Write the ART-DES-001 sample-size lock as a versioned, immutable artifact.

    Refuses (via assert_no_confirmatory_contamination) if any study-manifest*.json
    under artifacts/experiments/local/** already records evidence_class
    "confirmatory": the protocol requires this lock before confirmatory
    execution, so a lock built after confirmatory data already exists could
    not have constrained the collection it claims to govern.

    reviewer_approvals is scripts/review_gate.py's gate_state() output (or an
    equivalent dict for testing), taken as-is. reviewer_approval_status is
    "approved" only when reviewer_approvals["confirmatory_permitted"] is
    true; otherwise "pending", with the specific blocking reasons copied in.
    A "pending" lock is still written -- the design work is auditable and
    re-checkable before human review completes, it just cannot yet satisfy
    the confirmatory gate.
    """
    assert_no_confirmatory_contamination(_study_manifest_evidence_classes())

    review_gate = _load_review_gate()
    protocol_sha256 = review_gate.protocol_digest(review_gate.read_protocol())
    enumeration_code_sha256 = sha256_file(Path(__file__).resolve())
    git_state = _git_state()

    confirmatory_permitted = bool(reviewer_approvals.get("confirmatory_permitted"))
    blocking_reasons: list[str] = []
    if confirmatory_permitted:
        reviewer_approval_status = "approved"
    else:
        reviewer_approval_status = "pending"
        for role, problems in (reviewer_approvals.get("approval_problems") or {}).items():
            blocking_reasons.extend(f"{role}: {problem}" for problem in problems)
        independence = reviewer_approvals.get("independence") or {}
        if independence.get("independent") is False:
            blocking_reasons.append(f"independence: {independence.get('reason')}")
        protocol_status = reviewer_approvals.get("protocol_status")
        if protocol_status != "frozen":
            blocking_reasons.append(f"protocol_status is {protocol_status!r}, not 'frozen'")

    doc = {
        "schema_version": "porygon.sample-size-lock.v1",
        "art_id": "ART-DES-001",
        "created_at_utc": _utc_now_iso(),
        "inputs": inputs,
        "enumeration_code_sha256": enumeration_code_sha256,
        "protocol_sha256": protocol_sha256,
        "git_sha": git_state["git_sha"],
        "git_dirty": git_state["git_dirty"],
        "lock": lock_to_dict(lock),
        "reviewer_approvals": reviewer_approvals,
        "reviewer_approval_status": reviewer_approval_status,
        "reviewer_approval_blocking_reasons": blocking_reasons,
    }

    directory = out_dir if out_dir is not None else DEFAULT_LOCK_DIR
    return write_versioned_json(directory, "sample-size-lock", doc)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _discover_pilot_run_dirs() -> list[Path]:
    """Every run directory under artifacts/experiments/local whose run.json
    says kind=="real_container_pilot" and research_eligible is false -- this
    codebase's actual definition of "pilot evidence" (a whole labelled run
    directory, never a within-run split value; see experiments/artifacts.py:
    assign_split, which never assigns a "pilot" split)."""
    local_dir = LOCAL_ARTIFACTS_DIR
    if not local_dir.is_dir():
        return []
    found = []
    for run_dir in sorted(local_dir.iterdir()):
        manifest = run_dir / "run.json"
        if not manifest.is_file():
            continue
        try:
            doc = load_json(manifest)
        except Exception:
            continue
        if doc.get("kind") == "real_container_pilot" and doc.get("research_eligible") is False:
            found.append(run_dir)
    return found


def _cmd_build(args: argparse.Namespace) -> int:
    run_dirs = list(args.run_dir) if args.run_dir else _discover_pilot_run_dirs()
    if not run_dirs:
        print(
            "no pilot run directories found under artifacts/experiments/local "
            "(kind=real_container_pilot, research_eligible=false); pass --run-dir explicitly",
            file=sys.stderr,
        )
        return 2

    try:
        inputs = estimate_pilot_inputs(run_dirs, args.base_url)
    except ValueError as exc:
        print(f"[refused] {exc}", file=sys.stderr)
        return 1

    lock = build_sample_size_lock(
        pilot_discordant_pairs={
            contrast_id: (c["discordant_successes"], c["discordant_trials"])
            for contrast_id, c in inputs["contrasts"].items()
        },
        pilot_baseline_fpr={contrast_id: c["baseline_fpr"] for contrast_id, c in inputs["contrasts"].items()},
        reference_recall=inputs["reference_recall"],
    )

    review_gate = _load_review_gate()
    reviewer_approvals = review_gate.gate_state()

    try:
        path = write_sample_size_lock(
            inputs, lock, reviewer_approvals=reviewer_approvals, out_dir=args.out,
        )
    except ValueError as exc:
        print(f"[refused] {exc}", file=sys.stderr)
        return 1

    print(f"wrote {path}")
    if lock.feasibility_failure:
        print(f"[warning] {lock.note}", file=sys.stderr)
    status = "approved" if reviewer_approvals.get("confirmatory_permitted") else "pending"
    print(f"reviewer_approval_status: {status}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ART-DES-001: estimate pilot inputs and write the sample-size lock."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="estimate pilot inputs and write the ART-DES-001 lock")
    build.add_argument(
        "--run-dir", type=Path, action="append", default=None,
        help="pilot run directory (repeatable); default: auto-discover under artifacts/experiments/local",
    )
    build.add_argument("--base-url", default="http://127.0.0.1:8000")
    build.add_argument(
        "--out", type=Path, default=None,
        help="directory to write the lock under (default: artifacts/experiments/protocol-v1/design)",
    )
    args = parser.parse_args(argv)
    if args.command == "build":
        return _cmd_build(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
