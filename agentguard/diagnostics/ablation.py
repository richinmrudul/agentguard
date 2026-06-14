import shutil
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from agentguard.checks.registry import (
    CheckRegistration,
    instantiate_checks,
    normalize_check_selection,
    registered_checks,
)
from agentguard.diagnostics.mutations import (
    DEFAULT_CATALOG_PATH,
    MutationDefinition,
    MutationResult,
    _evaluate_mutation,
    _prepare_workspace,
    _rate,
    _runtime_failure,
    _select_mutations,
    load_mutation_catalog,
)
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.benchmarks.registry import normalize_registry_values
from agentguard.config.loader import load_config
from agentguard.provenance.manifest import (
    agentguard_identity,
    host_identity,
    sha256_file,
)


ABLATION_SCHEMA = "agentguard.policy-ablation"
ABLATION_SCHEMA_VERSION = 1
DEFAULT_OUTPUT_DIR = Path(".agentguard/diagnostics/ablation")


@dataclass(frozen=True)
class AblationCondition:
    id: str
    disabled_check_identifier: Optional[str]
    disabled_check: Optional[str]


@dataclass(frozen=True)
class AblationTrialResult:
    condition_id: str
    disabled_check: Optional[str]
    mutation_id: str
    mutation_class: str
    trial_index: int
    mutation: MutationResult


@dataclass(frozen=True)
class CheckContribution:
    check: str
    direct_expected_detection_opportunities: int
    detections_uniquely_attributable: int
    detections_redundantly_covered: int
    unique_mutation_coverage: list[str]
    redundant_mutation_coverage: list[str]
    contribution_percentage: Optional[float]


@dataclass(frozen=True)
class CheckOverlap:
    checks: list[str]
    matrix: dict[str, dict[str, int]]
    mutation_detection_sets: dict[str, list[str]]
    exactly_one_check: list[str]
    multiple_checks: list[str]
    no_checks: list[str]


@dataclass(frozen=True)
class AblationConditionSummary:
    condition_id: str
    disabled_check: Optional[str]
    unsafe_mutations_evaluated: int
    escaped_unsafe_mutations: list[str]
    expected_detections_lost: int
    detection_rate_delta_percentage_points: float
    safe_fixture_pass_rate_delta_percentage_points: float
    policy_failures_removed: int
    score_delta: float
    newly_passing_unsafe_mutations: list[str]
    unchanged_unsafe_mutations: list[str]
    controlled_mutation_detection_rate: float
    safe_fixture_pass_rate: float


@dataclass(frozen=True)
class AblationValidity:
    valid: bool
    control_failures: list[str]
    missed_required_detections: list[str]
    forbidden_safe_detections: list[str]
    runtime_failures: list[str]


@dataclass(frozen=True)
class PolicyAblationResult:
    study_id: str
    schema: str
    schema_version: int
    created_at: str
    catalog_path: Path
    catalog_sha256: str
    selected_mutation_ids: list[str]
    studied_checks: list[str]
    trials: int
    workers: int
    control_validity: AblationValidity
    control_metrics: dict[str, object]
    conditions: list[AblationConditionSummary]
    check_contributions: Optional[list[CheckContribution]]
    overlap: Optional[CheckOverlap]
    unstable_mutations: list[str]
    failures: list[dict[str, object]]
    raw_trial_summaries: list[AblationTrialResult]
    duration_seconds: float
    environment: dict[str, object]
    limitations: list[str]
    json_report_path: Path
    markdown_report_path: Path

    @property
    def has_study_failures(self) -> bool:
        return (
            not self.control_validity.valid
            or bool(self.unstable_mutations)
            or bool(self.failures)
        )


def _study_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"policy-ablation-{timestamp}-{uuid4().hex[:8]}"


def _default_studied_checks(
    selected: list[MutationDefinition],
) -> list[CheckRegistration]:
    represented = {
        check
        for mutation in selected
        for check in mutation.expectation.expected_detections
    }
    return [
        registration
        for registration in registered_checks()
        if registration.policy_check and registration.name in represented
    ]


def _conditions(
    selected_checks: list[CheckRegistration],
) -> list[AblationCondition]:
    return [
        AblationCondition("control", None, None),
        *[
            AblationCondition(
                f"without-{registration.identifier}",
                registration.identifier,
                registration.name,
            )
            for registration in selected_checks
        ],
    ]


def _run_trial(
    task: tuple[AblationCondition, MutationDefinition, int, Path],
) -> AblationTrialResult:
    condition, mutation, trial_index, workspace_root = task
    started = time.perf_counter()
    try:
        repo_dir = _prepare_workspace(mutation, workspace_root)
        result = _evaluate_mutation(
            mutation,
            repo_dir,
            load_config(mutation.config),
            strict=False,
            checks=instantiate_checks(
                disabled_identifiers=(
                    [condition.disabled_check_identifier]
                    if condition.disabled_check_identifier
                    else []
                )
            ),
        )
    except Exception as error:
        result = _runtime_failure(
            mutation,
            error,
            time.perf_counter() - started,
        )
    return AblationTrialResult(
        condition_id=condition.id,
        disabled_check=condition.disabled_check,
        mutation_id=mutation.id,
        mutation_class=mutation.mutation_class,
        trial_index=trial_index,
        mutation=result,
    )


def _signature(trial: AblationTrialResult) -> tuple[object, ...]:
    result = trial.mutation
    return (
        tuple(result.observed_detections),
        tuple(result.missed_detections),
        tuple(result.forbidden_detections),
        result.result,
        result.score,
        result.runtime_error,
    )


def _representative_trials(
    trials: list[AblationTrialResult],
) -> dict[tuple[str, str], AblationTrialResult]:
    return {
        (trial.condition_id, trial.mutation_id): trial
        for trial in trials
        if trial.trial_index == 0
    }


def _unstable_mutations(trials: list[AblationTrialResult]) -> list[str]:
    groups: dict[tuple[str, str], set[tuple[object, ...]]] = {}
    for trial in trials:
        groups.setdefault(
            (trial.condition_id, trial.mutation_id),
            set(),
        ).add(_signature(trial))
    return [
        f"{condition_id}:{mutation_id}"
        for (condition_id, mutation_id), signatures in groups.items()
        if len(signatures) > 1
    ]


def _control_validity(
    control_trials: list[AblationTrialResult],
) -> AblationValidity:
    missed = [
        f"{trial.mutation_id}[trial {trial.trial_index}]: "
        f"{', '.join(trial.mutation.missed_detections)}"
        for trial in control_trials
        if trial.mutation.missed_detections
    ]
    forbidden = [
        f"{trial.mutation_id}[trial {trial.trial_index}]: "
        f"{', '.join(trial.mutation.forbidden_detections)}"
        for trial in control_trials
        if trial.mutation.mutation_class == "safe"
        and trial.mutation.forbidden_detections
    ]
    runtime = [
        f"{trial.mutation_id}[trial {trial.trial_index}]: "
        f"{trial.mutation.runtime_error}"
        for trial in control_trials
        if trial.mutation.runtime_error
    ]
    failures = [*missed, *forbidden, *runtime]
    return AblationValidity(
        valid=not failures,
        control_failures=failures,
        missed_required_detections=missed,
        forbidden_safe_detections=forbidden,
        runtime_failures=runtime,
    )


def _condition_metrics(results: list[MutationResult]) -> dict[str, object]:
    expected = sum(len(result.expected_detections) for result in results)
    observed = sum(
        len(set(result.expected_detections) & set(result.observed_detections))
        for result in results
    )
    safe = [result for result in results if result.mutation_class == "safe"]
    unsafe = [result for result in results if result.mutation_class == "unsafe"]
    return {
        "unsafe_mutations": len(unsafe),
        "safe_mutations": len(safe),
        "controlled_expected_detections": expected,
        "observed_expected_detections": observed,
        "controlled_mutation_detection_rate": _rate(observed, expected),
        "safe_fixture_pass_rate": _rate(
            sum(not item.observed_detections for item in safe),
            len(safe),
        ),
        "average_score": round(
            sum(item.score for item in results) / len(results),
            2,
        ),
        "policy_failures": sum(
            len(item.observed_detections) for item in results
        ),
    }


def _summarize_condition(
    condition: AblationCondition,
    control: list[MutationResult],
    ablated: list[MutationResult],
) -> AblationConditionSummary:
    control_by_id = {item.id: item for item in control}
    ablated_by_id = {item.id: item for item in ablated}
    control_metrics = _condition_metrics(control)
    ablated_metrics = _condition_metrics(ablated)
    escaped: list[str] = []
    newly_passing: list[str] = []
    unchanged: list[str] = []
    for mutation_id, control_result in control_by_id.items():
        if control_result.mutation_class != "unsafe":
            continue
        ablated_result = ablated_by_id[mutation_id]
        required_under_control = set(control_result.expected_detections) & set(
            control_result.observed_detections
        )
        required_under_ablation = set(ablated_result.expected_detections) & set(
            ablated_result.observed_detections
        )
        if required_under_control and not required_under_ablation:
            escaped.append(mutation_id)
        if control_result.result != "PASS" and ablated_result.result == "PASS":
            newly_passing.append(mutation_id)
        if (
            control_result.observed_detections
            == ablated_result.observed_detections
            and control_result.result == ablated_result.result
            and control_result.score == ablated_result.score
        ):
            unchanged.append(mutation_id)
    expected_lost = sum(
        len(
            (set(control_result.expected_detections)
             & set(control_result.observed_detections))
            - set(ablated_by_id[control_result.id].observed_detections)
        )
        for control_result in control
    )
    return AblationConditionSummary(
        condition_id=condition.id,
        disabled_check=condition.disabled_check,
        unsafe_mutations_evaluated=int(ablated_metrics["unsafe_mutations"]),
        escaped_unsafe_mutations=escaped,
        expected_detections_lost=expected_lost,
        detection_rate_delta_percentage_points=round(
            float(ablated_metrics["controlled_mutation_detection_rate"])
            - float(control_metrics["controlled_mutation_detection_rate"]),
            2,
        ),
        safe_fixture_pass_rate_delta_percentage_points=round(
            float(ablated_metrics["safe_fixture_pass_rate"])
            - float(control_metrics["safe_fixture_pass_rate"]),
            2,
        ),
        policy_failures_removed=(
            int(control_metrics["policy_failures"])
            - int(ablated_metrics["policy_failures"])
        ),
        score_delta=round(
            float(ablated_metrics["average_score"])
            - float(control_metrics["average_score"]),
            2,
        ),
        newly_passing_unsafe_mutations=newly_passing,
        unchanged_unsafe_mutations=unchanged,
        controlled_mutation_detection_rate=float(
            ablated_metrics["controlled_mutation_detection_rate"]
        ),
        safe_fixture_pass_rate=float(
            ablated_metrics["safe_fixture_pass_rate"]
        ),
    )


def _control_detection_sets(
    control: list[MutationResult],
    checks: list[CheckRegistration],
) -> dict[str, set[str]]:
    names = {registration.name for registration in checks}
    return {
        result.id: (
            set(result.expected_detections)
            & set(result.observed_detections)
            & names
        )
        for result in control
        if result.mutation_class == "unsafe"
    }


def _contributions_and_overlap(
    control: list[MutationResult],
    checks: list[CheckRegistration],
) -> tuple[list[CheckContribution], CheckOverlap]:
    detection_sets = _control_detection_sets(control, checks)
    contributions: list[CheckContribution] = []
    for registration in checks:
        direct = sum(
            registration.name in result.expected_detections
            for result in control
            if result.mutation_class == "unsafe"
        )
        unique = [
            mutation_id
            for mutation_id, detected in detection_sets.items()
            if detected == {registration.name}
        ]
        redundant = [
            mutation_id
            for mutation_id, detected in detection_sets.items()
            if registration.name in detected and len(detected) > 1
        ]
        contributions.append(
            CheckContribution(
                check=registration.name,
                direct_expected_detection_opportunities=direct,
                detections_uniquely_attributable=len(unique),
                detections_redundantly_covered=len(redundant),
                unique_mutation_coverage=unique,
                redundant_mutation_coverage=redundant,
                contribution_percentage=(
                    round(len(unique) / direct * 100.0, 2) if direct else None
                ),
            )
        )
    names = [item.name for item in checks]
    matrix = {
        left: {
            right: sum(
                left in detected and right in detected
                for detected in detection_sets.values()
            )
            for right in names
        }
        for left in names
    }
    overlap = CheckOverlap(
        checks=names,
        matrix=matrix,
        mutation_detection_sets={
            mutation_id: [
                name for name in names if name in detected
            ]
            for mutation_id, detected in detection_sets.items()
        },
        exactly_one_check=[
            mutation_id
            for mutation_id, detected in detection_sets.items()
            if len(detected) == 1
        ],
        multiple_checks=[
            mutation_id
            for mutation_id, detected in detection_sets.items()
            if len(detected) > 1
        ],
        no_checks=[
            mutation_id
            for mutation_id, detected in detection_sets.items()
            if not detected
        ],
    )
    return contributions, overlap


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _write_reports(result: PolicyAblationResult) -> None:
    atomic_write_json(
        result.json_report_path,
        asdict(result),
        default=_json_default,
        sort_keys=True,
    )
    valid = "yes" if result.control_validity.valid else "no"
    lines = [
        "# AgentGuard Policy Ablation Study",
        "",
        "## Study Summary",
        "",
        f"- Control valid: {valid}",
        f"- Trials: {result.trials}",
        f"- Workers: {result.workers}",
        f"- Studied checks: {', '.join(result.studied_checks)}",
        f"- Duration: {result.duration_seconds:.6f}s",
        "",
        "## Control Validity",
        "",
    ]
    if result.control_validity.valid:
        lines.append("- The control satisfied all catalog expectations.")
    else:
        lines.extend(
            f"- {failure}" for failure in result.control_validity.control_failures
        )
    lines.extend(
        [
            "",
            "## Detection Metrics",
            "",
            f"- Unsafe mutations: {result.control_metrics['unsafe_mutations']}",
            f"- Safe mutations: {result.control_metrics['safe_mutations']}",
            "- Controlled expected detections: "
            f"{result.control_metrics['controlled_expected_detections']}",
            "- Observed expected detections: "
            f"{result.control_metrics['observed_expected_detections']}",
            "- Controlled mutation detection rate: "
            f"{float(result.control_metrics['controlled_mutation_detection_rate']):.2f}%",
            "- Safe-fixture pass rate: "
            f"{float(result.control_metrics['safe_fixture_pass_rate']):.2f}%",
            "",
            "## Check Contribution",
            "",
        ]
    )
    if result.check_contributions is None:
        lines.append(
            "Headline contribution claims are suppressed because the control is invalid."
        )
    else:
        lines.extend(
            [
                "| Check | Direct Opportunities | Unique | Redundant | Contribution |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for item in result.check_contributions:
            percentage = (
                f"{item.contribution_percentage:.2f}%"
                if item.contribution_percentage is not None
                else "-"
            )
            lines.append(
                f"| {item.check} | "
                f"{item.direct_expected_detection_opportunities} | "
                f"{item.detections_uniquely_attributable} | "
                f"{item.detections_redundantly_covered} | {percentage} |"
            )
    lines.extend(
        [
            "",
            "## Ablation Results",
            "",
            "| Disabled Check | Escaped Mutations | Detection Delta | "
            "Newly Passing Unsafe | Safe Pass Delta | Score Delta |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for condition in result.conditions:
        lines.append(
            f"| {condition.disabled_check or 'None (control)'} | "
            f"{len(condition.escaped_unsafe_mutations)} | "
            f"{condition.detection_rate_delta_percentage_points:+.2f} pp | "
            f"{len(condition.newly_passing_unsafe_mutations)} | "
            f"{condition.safe_fixture_pass_rate_delta_percentage_points:+.2f} pp | "
            f"{condition.score_delta:+.2f} |"
        )
    lines.extend(["", "## Overlap Matrix", ""])
    if result.overlap is None:
        lines.append("Overlap claims are suppressed because the control is invalid.")
    else:
        lines.append("| Check | " + " | ".join(result.overlap.checks) + " |")
        lines.append("|---|" + "---:|" * len(result.overlap.checks))
        for check in result.overlap.checks:
            lines.append(
                f"| {check} | "
                + " | ".join(
                    str(result.overlap.matrix[check][other])
                    for other in result.overlap.checks
                )
                + " |"
            )
    escaped = [
        (condition.disabled_check, mutation_id)
        for condition in result.conditions
        for mutation_id in condition.escaped_unsafe_mutations
    ]
    lines.extend(["", "## Escaped Mutations", ""])
    lines.extend(
        [f"- {check}: {mutation_id}" for check, mutation_id in escaped]
        or ["- None"]
    )
    lines.extend(["", "## Unstable Results", ""])
    lines.extend(
        [f"- {item}" for item in result.unstable_mutations] or ["- None"]
    )
    lines.extend(
        [
            "",
            "## Methodology and Limitations",
            "",
            "- An escaped mutation is unsafe, has a required detection in "
            "control, and has no required policy detection under ablation.",
            "- A newly passing unsafe mutation is PASS under ablation but not "
            "under control.",
            "- Unique contribution means only one studied check supplies a "
            "required control detection for that mutation.",
            "- Redundant coverage means multiple studied checks supply required "
            "control detections for the same mutation.",
        ]
    )
    lines.extend(f"- {item}" for item in result.limitations)
    lines.append("")
    atomic_write_text(result.markdown_report_path, "\n".join(lines))


def run_policy_ablation(
    catalog_path: Path = DEFAULT_CATALOG_PATH,
    *,
    check_values: Optional[list[str]] = None,
    mutation_ids: Optional[list[str]] = None,
    category: Optional[str] = None,
    trials: int = 1,
    workers: int = 1,
    output_dir: Optional[Path] = None,
    force: bool = False,
) -> PolicyAblationResult:
    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        raise ValueError("Ablation trials must be a positive integer.")
    if isinstance(workers, bool) or not isinstance(workers, int) or workers <= 0:
        raise ValueError("Ablation workers must be a positive integer.")
    catalog = load_mutation_catalog(catalog_path)
    selected = _select_mutations(
        catalog,
        normalize_registry_values(mutation_ids),
        category,
    )
    requested_checks = normalize_check_selection(check_values)
    studied_checks = requested_checks or _default_studied_checks(selected)
    if not studied_checks:
        raise ValueError("No policy checks are represented by the selected mutations.")
    conditions = _conditions(studied_checks)
    started = time.perf_counter()
    study_id = _study_id()
    study_dir = (output_dir or DEFAULT_OUTPUT_DIR) / study_id
    if study_dir.exists():
        if not force:
            raise FileExistsError(f"Ablation output already exists: {study_dir}")
        shutil.rmtree(study_dir)
    workspace_root = study_dir / "workspaces"
    tasks = [
        (
            condition,
            mutation,
            trial_index,
            workspace_root / condition.id / mutation.id / f"trial-{trial_index}",
        )
        for condition in conditions
        for mutation in selected
        for trial_index in range(trials)
    ]
    if workers == 1:
        raw = [_run_trial(task) for task in tasks]
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(tasks))) as executor:
            raw = list(executor.map(_run_trial, tasks))
    shutil.rmtree(workspace_root, ignore_errors=True)

    control_trials = [item for item in raw if item.condition_id == "control"]
    validity = _control_validity(control_trials)
    representative = _representative_trials(raw)
    control_results = [
        representative[("control", mutation.id)].mutation
        for mutation in selected
    ]
    summaries = [
        _summarize_condition(
            condition,
            control_results,
            [
                representative[(condition.id, mutation.id)].mutation
                for mutation in selected
            ],
        )
        for condition in conditions
    ]
    failures = [
        {
            "condition_id": trial.condition_id,
            "mutation_id": trial.mutation_id,
            "trial_index": trial.trial_index,
            "error": trial.mutation.runtime_error,
        }
        for trial in raw
        if trial.mutation.runtime_error
    ]
    contributions: Optional[list[CheckContribution]] = None
    overlap: Optional[CheckOverlap] = None
    if validity.valid:
        contributions, overlap = _contributions_and_overlap(
            control_results,
            studied_checks,
        )
    identity = agentguard_identity()
    host = host_identity(docker_relevant=False)
    result = PolicyAblationResult(
        study_id=study_id,
        schema=ABLATION_SCHEMA,
        schema_version=ABLATION_SCHEMA_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        catalog_path=catalog.path,
        catalog_sha256=sha256_file(catalog.path),
        selected_mutation_ids=[item.id for item in selected],
        studied_checks=[item.name for item in studied_checks],
        trials=trials,
        workers=workers,
        control_validity=validity,
        control_metrics=_condition_metrics(control_results),
        conditions=summaries,
        check_contributions=contributions,
        overlap=overlap,
        unstable_mutations=_unstable_mutations(raw),
        failures=failures,
        raw_trial_summaries=raw,
        duration_seconds=round(time.perf_counter() - started, 6),
        environment={
            "agentguard_version": identity.version,
            "agentguard_git_commit": identity.git_commit,
            "agentguard_dirty_worktree": identity.dirty_worktree,
            "python_version": host.python_version,
            "operating_system": host.operating_system,
            "architecture": host.architecture,
        },
        limitations=[
            "Results measure controlled synthetic mutations, not production security effectiveness.",
            "Controlled mutation detection rate is not a real-world false-negative rate.",
            "Safe-fixture pass rate is not a real-world false-positive rate.",
            "No statistical significance is claimed from repeated deterministic trials.",
            "Score is an existing policy severity summary, not a calibrated probability.",
            "Contribution depends on this catalog, its fixtures, and their configured policies.",
        ],
        json_report_path=study_dir / "ablation.json",
        markdown_report_path=study_dir / "ablation.md",
    )
    _write_reports(result)
    return result
