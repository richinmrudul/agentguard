import inspect
import threading
import time
import warnings
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from statistics import stdev
from typing import Any, Callable, Optional
from urllib.parse import quote
from uuid import uuid4

from agentguard.artifact_paths import artifact_directory
from agentguard.config.loader import load_config
from agentguard.core.baseline import BaselineComparison, compare_suite_to_baseline
from agentguard.core.matrix_checkpoint import (
    CheckpointStore,
    MatrixCheckpoint,
    MatrixCheckpointAttempt,
    checkpoint_id,
    load_checkpoint,
    stable_attempt_key,
    upsert_reused_history,
    utc_now_iso as checkpoint_utc_now_iso,
    verify_completed_attempt,
)
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.reliability_baseline import (
    ConfidenceInterval,
    ReliabilityComparison,
    compare_matrix_reliability,
    evaluate_minimum_reliability,
    reliability_combination_key,
    reliability_thresholds,
    wilson_score_interval,
    write_matrix_reliability_baseline,
)
from agentguard.core.result import BenchmarkResult
from agentguard.core.scheduler import run_bounded_schedule
from agentguard.core.suite import (
    SuiteFilters,
    SuiteRunConfig,
    filter_suite_runs,
    format_suite_filters,
    load_suite_config,
)
from agentguard.history.store import (
    DEFAULT_HISTORY_DB_PATH,
    HistoryRecord,
    HistoryStorageError,
    record_history,
    utc_now_iso,
)
from agentguard.guard.filesystem import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    GuardMode,
    validate_guard_configuration,
)
from agentguard.guard.aggregation import (
    GuardAggregateSummary,
    GuardGroupSummary,
    GuardTimingDistribution,
    aggregate_matrix_guard,
)
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.provenance.artifact_paths import artifact_roots, portable_artifact_value
from agentguard.reports.markdown import markdown_table_cell, markdown_text
from agentguard.provenance.manifest import (
    ChildExecution,
    ExecutionManifest,
    agentguard_identity,
    artifact_identity,
    benchmark_identity,
    configuration_identity,
    host_identity,
    policy_identity,
    sha256_file,
    source_identity,
    utc_now_iso as manifest_utc_now_iso,
    write_manifest,
)


@dataclass(frozen=True)
class MatrixGroupSummary:
    runs: int
    attempts: int
    passed: int
    failed: int
    success_rate: float
    average_score: float
    minimum_score: int
    maximum_score: int
    score_standard_deviation: float
    confidence_interval_95: ConfidenceInterval
    combinations_with_any_pass: int
    combinations_with_all_passes: int
    functional_passed: int = 0
    functional_success_rate: float = 0.0
    policy_compliant_passed: int = 0
    policy_compliant_success_rate: float = 0.0
    unsafe_functional_successes: int = 0


@dataclass(frozen=True)
class MatrixReliabilitySummary:
    attempts: int
    passed: int
    failed: int
    success_rate: float
    average_score: float
    minimum_score: int
    maximum_score: int
    score_standard_deviation: float
    confidence_interval_95: ConfidenceInterval
    combinations_with_any_pass: int
    combinations_with_all_passes: int


@dataclass(frozen=True)
class MatrixCombinationSummary:
    task_id: str
    config_path: Path
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    agent: str
    trials: int
    attempts: int
    passed: int
    failed: int
    success_rate: float
    average_score: float
    minimum_score: int
    maximum_score: int
    score_standard_deviation: float
    confidence_interval_95: ConfidenceInterval
    any_pass: bool
    all_passed: bool


@dataclass(frozen=True)
class MatrixRowSummary:
    task_id: str
    config_path: Path
    agent: str
    result: str
    score: int
    failed_checks: list[str]
    warning_checks: list[str]
    json_report_path: Optional[Path]
    markdown_report_path: Optional[Path]
    run_dir: Optional[Path]
    execution_id: Optional[str] = None
    manifest_path: Optional[Path] = None
    benchmark_id: Optional[str] = None
    benchmark_version: Optional[int] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    error: Optional[str] = None
    trial_index: int = 1
    trial_count: int = 1
    functional_passed: bool = False
    task_prompt_source: Optional[str] = None
    task_prompt_sha256: Optional[str] = None
    profile_id: Optional[str] = None
    guard_violations_total: int = 0
    guard_blocked: bool = False
    filesystem_guard_violations: int = 0
    command_guard_violations: int = 0
    time_to_first_violation_ms: Optional[int] = None
    time_to_block_ms: Optional[int] = None
    guard_incident_json_path: Optional[Path] = None
    guard_incident_markdown_path: Optional[Path] = None
    blocking_guard: Optional[str] = None


@dataclass(frozen=True)
class MatrixResult:
    matrix_id: str
    suite_id: str
    description: str
    suite_path: Path
    total_runs: int
    agents: list[str]
    passed: int
    failed: int
    pass_rate: float
    average_score: int
    per_agent: dict[str, MatrixGroupSummary]
    per_category: dict[str, MatrixGroupSummary]
    per_difficulty: dict[str, MatrixGroupSummary]
    runs: list[MatrixRowSummary]
    result_counts: dict[str, int]
    failed_check_counts: dict[str, int]
    json_report_path: Path
    markdown_report_path: Path
    manifest_path: Optional[Path] = None
    requested_workers: int = 1
    effective_workers: int = 1
    execution_mode: str = "serial"
    duration_seconds: float = 0.0
    attempts_planned: int = 0
    attempts_executed: int = 0
    stopped_early: bool = False
    trials: int = 1
    reliability: Optional[MatrixReliabilitySummary] = None
    per_agent_reliability: dict[str, MatrixReliabilitySummary] = field(
        default_factory=dict
    )
    combinations: dict[str, MatrixCombinationSummary] = field(default_factory=dict)
    filters: SuiteFilters = field(default_factory=SuiteFilters)
    baseline_comparison: Optional[BaselineComparison] = None
    reliability_baseline_path: Optional[Path] = None
    reliability_comparison: Optional[ReliabilityComparison] = None
    functional_passed: int = 0
    functional_success_rate: float = 0.0
    policy_compliant_passed: int = 0
    policy_compliant_success_rate: float = 0.0
    unsafe_functional_successes: int = 0
    profile_id: Optional[str] = None
    profile_name: Optional[str] = None
    profile_model: Optional[str] = None
    checkpoint_path: Optional[Path] = None
    checkpoint_id: Optional[str] = None
    resumed_from: Optional[Path] = None
    checkpoint_status: Optional[str] = None
    attempts_reused: int = 0
    attempts_skipped: int = 0
    attempts_executed_this_invocation: int = 0
    failed_attempts_retried: int = 0
    invalidated_attempts: int = 0
    reuse_percentage: float = 0.0
    estimated_recomputation_avoided_seconds: float = 0.0
    compatibility_warnings: list[str] = field(default_factory=list)
    guard_mode: str = GuardMode.OFF.value
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS
    guard_summary: GuardAggregateSummary = field(
        default_factory=GuardAggregateSummary
    )


def normalize_matrix_agents(raw_agents: Optional[list[str]]) -> list[str]:
    if raw_agents is None:
        return []
    agents: list[str] = []
    for raw_agent in raw_agents:
        agent = raw_agent.strip()
        if not agent:
            raise ValueError("Matrix agent values must be non-empty strings.")
        if agent not in agents:
            agents.append(agent)
    return agents


def expand_matrix_runs(
    runs: list[SuiteRunConfig],
    agents: list[str],
) -> list[SuiteRunConfig]:
    if not agents:
        return list(runs)
    return [
        SuiteRunConfig(config_path=run.config_path, agent=agent)
        for run in runs
        for agent in agents
    ]


def expand_matrix_trials(
    runs: list[SuiteRunConfig],
    trials: int,
) -> list[tuple[SuiteRunConfig, int]]:
    if trials <= 0:
        raise ValueError("Matrix trials must be a positive integer.")
    return [
        (run, trial_index)
        for run in runs
        for trial_index in range(1, trials + 1)
    ]


def validate_matrix_workers(workers: int) -> int:
    if isinstance(workers, bool) or not isinstance(workers, int) or workers <= 0:
        raise ValueError("Matrix workers must be a positive integer.")
    return workers


def _matrix_id(suite_id: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"{suite_id}-{timestamp}-{uuid4().hex[:8]}"


def _matrix_dir(matrix_id: str, matrices_root: Path) -> Path:
    return artifact_directory(matrices_root, matrix_id)


def _checkpoint_attempts(
    trial_runs: list[tuple[SuiteRunConfig, int]],
    *,
    suite_sha256: str,
    trials: int,
    profile_id: Optional[str],
    profile_model: Optional[str],
    profile_identity: dict[str, object],
) -> tuple[list[MatrixCheckpointAttempt], list[dict[str, object]]]:
    attempts = []
    benchmarks: dict[str, dict[str, object]] = {}
    for ordinal, (run, trial_index) in enumerate(trial_runs):
        loaded = load_config(run.config_path)
        config_hash = sha256_file(loaded.config_path)
        prompt_hash = None
        if profile_id is not None:
            from agentguard.evaluation.profile import load_task_prompt

            prompt_hash = load_task_prompt(loaded).sha256
        resolved_agent = profile_id or run.agent
        attempts.append(
            MatrixCheckpointAttempt(
                key=stable_attempt_key(
                    suite_sha256=suite_sha256,
                    config=loaded,
                    config_sha256=config_hash,
                    agent=resolved_agent,
                    profile_id=profile_id,
                    profile_model=profile_model,
                    profile_identity=profile_identity,
                    task_prompt_sha256=prompt_hash,
                    trial_index=trial_index,
                ),
                ordinal=ordinal,
                task_id=loaded.task_id,
                config_path=str(loaded.config_path),
                config_sha256=config_hash,
                benchmark_id=loaded.benchmark.id,
                benchmark_version=loaded.benchmark.version,
                agent=resolved_agent,
                profile_id=profile_id,
                profile_model=profile_model,
                task_prompt_sha256=prompt_hash,
                trial_index=trial_index,
                trial_count=trials,
            )
        )
        benchmarks.setdefault(
            str(loaded.config_path),
            {
                "config_path": str(loaded.config_path),
                "config_sha256": config_hash,
                "benchmark_id": loaded.benchmark.id,
                "benchmark_version": loaded.benchmark.version,
            },
        )
    return attempts, list(benchmarks.values())


def _checkpoint_compatibility(
    checkpoint: MatrixCheckpoint,
    current: MatrixCheckpoint,
    *,
    force_resume: bool,
) -> list[str]:
    incompatible = []
    for label, stored, resolved in [
        ("suite identity", checkpoint.suite_id, current.suite_id),
        ("suite path", checkpoint.suite_path, current.suite_path),
        ("suite hash", checkpoint.suite_sha256, current.suite_sha256),
        ("filters", checkpoint.filters, current.filters),
        ("agents", checkpoint.agents, current.agents),
        ("trials", checkpoint.trials, current.trials),
        ("fail-fast setting", checkpoint.fail_fast, current.fail_fast),
        ("guard mode", checkpoint.guard_mode, current.guard_mode),
        (
            "guard polling interval",
            checkpoint.guard_poll_interval_seconds,
            current.guard_poll_interval_seconds,
        ),
        ("benchmarks", checkpoint.benchmarks, current.benchmarks),
        ("profile identity", checkpoint.profile_identity, current.profile_identity),
        (
            "attempt identities",
            [attempt.key for attempt in checkpoint.attempts],
            [attempt.key for attempt in current.attempts],
        ),
    ]:
        if stored != resolved:
            incompatible.append(label)
    if incompatible:
        raise ValueError(
            "Matrix checkpoint is incompatible with the resolved run: "
            + ", ".join(incompatible)
            + "."
        )
    warnings_found = []
    stored_runtime = checkpoint.execution_compatibility
    current_runtime = current.execution_compatibility
    for label in ("agentguard_version", "agentguard_git_commit"):
        if stored_runtime.get(label) != current_runtime.get(label):
            warnings_found.append(
                f"{label} changed from {stored_runtime.get(label)!r} "
                f"to {current_runtime.get(label)!r}"
            )
    if warnings_found and not force_resume:
        raise ValueError(
            "Matrix checkpoint has compatibility warning(s): "
            + "; ".join(warnings_found)
            + ". Use --force-resume to acknowledge these non-artifact warnings."
        )
    return [f"Bypassed with --force-resume: {message}" for message in warnings_found]


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _nonnegative_optional_int(value: object) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _row_from_result(
    result: BenchmarkResult,
    trial_index: int,
    trial_count: int,
) -> MatrixRowSummary:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    warning_checks = [
        check.name
        for check in result.check_results
        if not check.passed and check.severity == "warning"
    ]
    raw_metrics = getattr(result, "guard_metrics", {})
    metrics = raw_metrics if isinstance(raw_metrics, dict) else {}
    filesystem_violations = _nonnegative_int(
        metrics.get("filesystem_guard_violations")
    )
    command_violations = _nonnegative_int(
        metrics.get("command_guard_violations")
    )
    violations_total = _nonnegative_int(metrics.get("guard_violations_total"))
    blocking_guard = None
    if bool(getattr(getattr(result, "guard_summary", None), "terminated_agent", False)):
        blocking_guard = "filesystem"
    elif bool(
        getattr(
            getattr(result, "command_guard_summary", None),
            "terminated_agent",
            False,
        )
    ):
        blocking_guard = "command"
    return MatrixRowSummary(
        task_id=result.task_id,
        config_path=result.config_path,
        agent=result.agent,
        result=result.result,
        score=result.score,
        failed_checks=failed_checks,
        warning_checks=warning_checks,
        json_report_path=result.report_paths.json,
        markdown_report_path=result.report_paths.markdown,
        run_dir=result.run_dir,
        execution_id=getattr(result, "execution_id", None),
        manifest_path=getattr(result.report_paths, "manifest", None),
        benchmark_id=result.benchmark.id,
        benchmark_version=result.benchmark.version,
        category=result.benchmark.category,
        difficulty=result.benchmark.difficulty,
        tags=result.benchmark.tags,
        trial_index=trial_index,
        trial_count=trial_count,
        functional_passed=(
            getattr(
                getattr(result, "test_result", None),
                "exit_code",
                0 if result.result == "PASS" else 1,
            )
            == 0
        ),
        task_prompt_source=getattr(result, "task_prompt_source", None),
        task_prompt_sha256=getattr(result, "task_prompt_sha256", None),
        profile_id=getattr(result, "profile_id", None),
        guard_violations_total=violations_total,
        guard_blocked=bool(metrics.get("guard_blocked", False)) and violations_total > 0,
        filesystem_guard_violations=filesystem_violations,
        command_guard_violations=command_violations,
        time_to_first_violation_ms=_nonnegative_optional_int(
            metrics.get("time_to_first_violation_ms")
        ),
        time_to_block_ms=_nonnegative_optional_int(metrics.get("time_to_block_ms")),
        guard_incident_json_path=getattr(
            result.report_paths,
            "guard_incident_json",
            None,
        ),
        guard_incident_markdown_path=getattr(
            result.report_paths,
            "guard_incident_markdown",
            None,
        ),
        blocking_guard=blocking_guard,
    )


def _error_row(
    run: SuiteRunConfig,
    error: Exception,
    trial_index: int,
    trial_count: int,
) -> MatrixRowSummary:
    config = load_config(run.config_path)
    return MatrixRowSummary(
        task_id=config.task_id,
        config_path=config.config_path,
        agent=run.agent,
        result="FAIL",
        score=0,
        failed_checks=["Agent execution"],
        warning_checks=[],
        json_report_path=None,
        markdown_report_path=None,
        run_dir=None,
        benchmark_id=config.benchmark.id,
        benchmark_version=config.benchmark.version,
        category=config.benchmark.category,
        difficulty=config.benchmark.difficulty,
        tags=config.benchmark.tags,
        error=f"{type(error).__name__}: {error}",
        trial_index=trial_index,
        trial_count=trial_count,
    )


def _run_matrix_row(
    run: SuiteRunConfig,
    trial_index: int,
    trial_count: int,
    matrix_id: str,
    benchmark_runner: Optional[
        Callable[[Path, str, str], BenchmarkResult]
    ] = None,
    guard_mode: GuardMode = GuardMode.OFF,
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> MatrixRowSummary:
    try:
        return _row_from_result(
            _invoke_run_benchmark(
                run,
                matrix_id,
                benchmark_runner,
                guard_mode,
                guard_poll_interval_seconds,
            ),
            trial_index,
            trial_count,
        )
    except ValueError:
        raise
    except Exception as error:
        return _error_row(run, error, trial_index, trial_count)


def _invoke_run_benchmark(
    run: SuiteRunConfig,
    matrix_id: str,
    benchmark_runner: Optional[Callable[[Path, str, str], BenchmarkResult]],
    guard_mode: GuardMode,
    guard_poll_interval_seconds: float,
) -> BenchmarkResult:
    if benchmark_runner is not None:
        return benchmark_runner(run.config_path, run.agent, matrix_id)
    parameters = inspect.signature(run_benchmark).parameters
    accepts_keywords = any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )
    keyword_arguments: dict[str, object] = {}
    if "parent_execution_id" in parameters or accepts_keywords:
        keyword_arguments.update(
            parent_execution_id=matrix_id,
            parent_execution_type="matrix",
        )
    if "guard_mode" in parameters or accepts_keywords:
        keyword_arguments.update(
            guard_mode=guard_mode,
            guard_poll_interval_seconds=guard_poll_interval_seconds,
        )
    return run_benchmark(run.config_path, run.agent, **keyword_arguments)


def _run_serial_attempts(
    trial_runs: list[tuple[SuiteRunConfig, int]],
    trial_count: int,
    fail_fast: bool,
    matrix_id: str,
    benchmark_runner: Optional[
        Callable[[Path, str, str], BenchmarkResult]
    ] = None,
    guard_mode: GuardMode = GuardMode.OFF,
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> tuple[list[MatrixRowSummary], bool]:
    scheduled = run_bounded_schedule(
        trial_runs,
        workers=1,
        fail_fast=fail_fast,
        runner=lambda item: _run_matrix_row(
            item[0],
            item[1],
            trial_count,
            matrix_id,
            benchmark_runner,
            guard_mode,
            guard_poll_interval_seconds,
        ),
        is_failure=lambda row: row.result == "FAIL",
    )
    return scheduled.results, scheduled.stopped_early


def _run_parallel_attempts(
    trial_runs: list[tuple[SuiteRunConfig, int]],
    trial_count: int,
    workers: int,
    fail_fast: bool,
    matrix_id: str,
    benchmark_runner: Optional[
        Callable[[Path, str, str], BenchmarkResult]
    ] = None,
    guard_mode: GuardMode = GuardMode.OFF,
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> tuple[list[MatrixRowSummary], bool]:
    scheduled = run_bounded_schedule(
        trial_runs,
        workers=workers,
        fail_fast=fail_fast,
        runner=lambda item: _run_matrix_row(
            item[0],
            item[1],
            trial_count,
            matrix_id,
            benchmark_runner,
            guard_mode,
            guard_poll_interval_seconds,
        ),
        is_failure=lambda row: row.result == "FAIL",
    )
    return scheduled.results, scheduled.stopped_early


def _group_summary(rows: list[MatrixRowSummary]) -> MatrixGroupSummary:
    passed = sum(1 for row in rows if row.result == "PASS")
    total = len(rows)
    scores = [row.score for row in rows]
    combinations = _combination_summaries(rows)
    functional_passed = sum(row.functional_passed for row in rows)
    unsafe_functional_successes = sum(
        row.functional_passed and row.result != "PASS" for row in rows
    )
    return MatrixGroupSummary(
        runs=total,
        attempts=total,
        passed=passed,
        failed=total - passed,
        success_rate=round((passed / total) * 100, 1),
        average_score=round(sum(scores) / total, 2),
        minimum_score=min(scores),
        maximum_score=max(scores),
        score_standard_deviation=round(stdev(scores), 2) if total > 1 else 0.0,
        confidence_interval_95=wilson_score_interval(passed, total),
        combinations_with_any_pass=sum(
            summary.any_pass for summary in combinations.values()
        ),
        combinations_with_all_passes=sum(
            summary.all_passed for summary in combinations.values()
        ),
        functional_passed=functional_passed,
        functional_success_rate=round((functional_passed / total) * 100, 1),
        policy_compliant_passed=passed,
        policy_compliant_success_rate=round((passed / total) * 100, 1),
        unsafe_functional_successes=unsafe_functional_successes,
    )


def _summaries_by(
    rows: list[MatrixRowSummary],
    field_name: str,
    missing_label: str,
) -> dict[str, MatrixGroupSummary]:
    grouped: dict[str, list[MatrixRowSummary]] = {}
    for row in rows:
        key = getattr(row, field_name) or missing_label
        grouped.setdefault(key, []).append(row)
    return {key: _group_summary(grouped[key]) for key in sorted(grouped)}


def _combination_key(row: MatrixRowSummary) -> str:
    portable_path = str(
        portable_artifact_value(
            row.config_path,
            artifact_roots(repository_root=Path.cwd(), config_path=row.config_path),
        )
    )
    return reliability_combination_key(
        portable_path,
        row.benchmark_id,
        row.benchmark_version,
        row.task_id,
        row.agent,
    )


def _combination_summaries(
    rows: list[MatrixRowSummary],
) -> dict[str, MatrixCombinationSummary]:
    grouped: dict[str, list[MatrixRowSummary]] = {}
    for row in rows:
        grouped.setdefault(_combination_key(row), []).append(row)

    summaries = {}
    for key in sorted(grouped):
        combination_rows = grouped[key]
        scores = [row.score for row in combination_rows]
        passed = sum(row.result == "PASS" for row in combination_rows)
        attempts = len(combination_rows)
        summaries[key] = MatrixCombinationSummary(
            task_id=combination_rows[0].task_id,
            config_path=combination_rows[0].config_path,
            benchmark_id=combination_rows[0].benchmark_id,
            benchmark_version=combination_rows[0].benchmark_version,
            agent=combination_rows[0].agent,
            trials=attempts,
            attempts=attempts,
            passed=passed,
            failed=attempts - passed,
            success_rate=round((passed / attempts) * 100, 1),
            average_score=round(sum(scores) / attempts, 2),
            minimum_score=min(scores),
            maximum_score=max(scores),
            score_standard_deviation=(
                round(stdev(scores), 2) if attempts > 1 else 0.0
            ),
            confidence_interval_95=wilson_score_interval(passed, attempts),
            any_pass=passed > 0,
            all_passed=passed == attempts,
        )
    return summaries


def _reliability_summary(
    rows: list[MatrixRowSummary],
    combinations: dict[str, MatrixCombinationSummary],
) -> MatrixReliabilitySummary:
    scores = [row.score for row in rows]
    attempts = len(rows)
    passed = sum(row.result == "PASS" for row in rows)
    return MatrixReliabilitySummary(
        attempts=attempts,
        passed=passed,
        failed=attempts - passed,
        success_rate=round((passed / attempts) * 100, 1),
        average_score=round(sum(scores) / attempts, 2),
        minimum_score=min(scores),
        maximum_score=max(scores),
        score_standard_deviation=round(stdev(scores), 2) if attempts > 1 else 0.0,
        confidence_interval_95=wilson_score_interval(passed, attempts),
        combinations_with_any_pass=sum(
            summary.any_pass for summary in combinations.values()
        ),
        combinations_with_all_passes=sum(
            summary.all_passed for summary in combinations.values()
        ),
    )


def _reliability_by_agent(
    rows: list[MatrixRowSummary],
    combinations: dict[str, MatrixCombinationSummary],
) -> dict[str, MatrixReliabilitySummary]:
    agents = sorted({row.agent for row in rows})
    return {
        agent: _reliability_summary(
            [row for row in rows if row.agent == agent],
            {
                key: summary
                for key, summary in combinations.items()
                if summary.agent == agent
            },
        )
        for agent in agents
    }


def _format_checks(checks: list[str]) -> str:
    return ", ".join(checks) if checks else "-"


def _write_json_report(result: MatrixResult) -> Path:
    roots = artifact_roots(
        repository_root=Path.cwd(),
        run_root=result.json_report_path.parent,
        config_path=result.suite_path,
    )
    data = portable_artifact_value(result, roots)
    if result.baseline_comparison is None:
        data.pop("baseline_comparison", None)
    if result.reliability_baseline_path is None:
        data.pop("reliability_baseline_path", None)
    if result.reliability_comparison is None:
        data.pop("reliability_comparison", None)
    if not result.filters.has_filters():
        data.pop("filters", None)
    atomic_write_json(result.json_report_path, data, default=_json_default)
    return result.json_report_path


def _summary_table(
    heading: str,
    summaries: dict[str, MatrixGroupSummary],
) -> list[str]:
    lines = [
        f"## {heading}",
        "",
        "| Name | Runs | Passed | Failed | Average Score |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, summary in summaries.items():
        lines.append(
            f"| {name} | {summary.runs} | {summary.passed} | "
            f"{summary.failed} | {summary.average_score} |"
        )
    return lines


def _reliability_lines(summary: MatrixReliabilitySummary) -> list[str]:
    return [
        f"Attempts: {summary.attempts}",
        f"Passed: {summary.passed}",
        f"Failed: {summary.failed}",
        f"Success rate: {summary.success_rate}%",
        f"Average score: {summary.average_score}",
        f"Minimum score: {summary.minimum_score}",
        f"Maximum score: {summary.maximum_score}",
        f"Score standard deviation: {summary.score_standard_deviation}",
        (
            "95% confidence interval: "
            f"{summary.confidence_interval_95.lower_bound}% to "
            f"{summary.confidence_interval_95.upper_bound}%"
        ),
        f"Combinations with any pass: {summary.combinations_with_any_pass}",
        f"Combinations with all passes: {summary.combinations_with_all_passes}",
    ]


def _escape_markdown_table(value: object) -> str:
    return markdown_table_cell(value)


def _guard_timing_line(
    label: str,
    distribution: GuardTimingDistribution,
) -> str:
    if distribution.samples == 0:
        return f"{label}: no samples"
    return (
        f"{label}: {distribution.samples} sample(s), "
        f"min {distribution.minimum_ms} ms, median {distribution.median_ms} ms, "
        f"p95 {distribution.p95_ms} ms, max {distribution.maximum_ms} ms"
    )


def _guard_group_table(
    heading: str,
    groups: dict[str, GuardGroupSummary],
) -> list[str]:
    lines = [
        f"### {heading}",
        "",
        "| Name | Runs | Incidents | Blocked | Audit only | Violations | Filesystem | Command |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, summary in groups.items():
        lines.append(
            f"| {_escape_markdown_table(name)} | {summary.runs} | "
            f"{summary.incident_runs} | {summary.blocked_runs} | "
            f"{summary.audit_only_runs} | {summary.violations_total} | "
            f"{summary.filesystem_violations} | {summary.command_violations} |"
        )
    if not groups:
        lines.append("| - | 0 | 0 | 0 | 0 | 0 | 0 | 0 |")
    return lines


def _incident_link(path: Optional[str], label: str) -> str:
    if path is None:
        return "unavailable"
    return f"[{label}]({quote(path, safe='/._-')})"


def _guard_incident_lines(summary: GuardAggregateSummary) -> list[str]:
    lines = [
        "## Guard Incidents",
        "",
        f"Runs evaluated: {summary.runs_evaluated}",
        f"Incident runs: {summary.incident_runs}",
        f"Blocked runs: {summary.blocked_runs}",
        f"Audit-only runs: {summary.audit_only_runs}",
        f"Total violations: {summary.violations_total}",
        f"Filesystem violations: {summary.filesystem_violations}",
        f"Command violations: {summary.command_violations}",
        _guard_timing_line(
            "Time to first violation",
            summary.time_to_first_violation,
        ),
        _guard_timing_line("Time to block", summary.time_to_block),
        "",
    ]
    if not summary.incidents:
        lines.extend(["No guard incidents were recorded.", ""])
    lines.extend(_guard_group_table("By Agent", summary.by_agent))
    lines.extend(["", *_guard_group_table("By Benchmark", summary.by_benchmark)])
    lines.extend(["", *_guard_group_table("By Category", summary.by_category)])
    lines.extend(
        [
            "",
            "### By Guard Type",
            "",
            "| Guard | Incident runs | Blocked runs | Violations |",
            "|---|---:|---:|---:|",
        ]
    )
    for guard_type, guard_summary in summary.by_guard_type.items():
        lines.append(
            f"| {_escape_markdown_table(guard_type)} | "
            f"{guard_summary.incident_runs} | {guard_summary.blocked_runs} | "
            f"{guard_summary.violations_total} |"
        )
    lines.extend(
        [
            "",
            "### Child Incidents",
            "",
            (
                "| Task / benchmark | Agent | Trial | Status | Violations | "
                "First violation | JSON | Markdown |"
            ),
            "|---|---|---:|---|---:|---:|---|---|",
        ]
    )
    for incident in summary.incidents:
        lines.append(
            f"| {_escape_markdown_table(incident.task_id)} / "
            f"{_escape_markdown_table(incident.benchmark_id)} | "
            f"{_escape_markdown_table(incident.agent)} | {incident.trial_index} | "
            f"{'blocked' if incident.blocked else 'audit only'} | "
            f"{incident.violations_total} | "
            f"{incident.time_to_first_violation_ms if incident.time_to_first_violation_ms is not None else '-'} | "
            f"{_incident_link(incident.incident_json, 'JSON')} | "
            f"{_incident_link(incident.incident_markdown, 'Markdown')} |"
        )
    if not summary.incidents:
        lines.append("| - | - | - | - | 0 | - | unavailable | unavailable |")
    return lines


def _write_markdown_report(result: MatrixResult) -> Path:
    roots = artifact_roots(
        repository_root=Path.cwd(),
        run_root=result.markdown_report_path.parent,
        config_path=result.suite_path,
    )
    lines = [
        "# AgentGuard Matrix Summary",
        "",
        f"Matrix: {markdown_text(result.matrix_id)}",
        f"Suite: {markdown_text(result.suite_id)}",
        f"Suite config: {markdown_text(portable_artifact_value(result.suite_path, roots))}",
        f"Agents: {markdown_text(', '.join(result.agents))}",
        f"Trials per combination: {result.trials}",
        f"Requested workers: {result.requested_workers}",
        f"Effective workers: {result.effective_workers}",
        f"Execution mode: {markdown_text(result.execution_mode)}",
        f"Execution duration: {result.duration_seconds:.3f} seconds",
        f"Attempts planned: {result.attempts_planned}",
        f"Attempts executed: {result.attempts_executed}",
        f"Stopped early: {'yes' if result.stopped_early else 'no'}",
        f"Runs: {result.total_runs}",
        f"Passed: {result.passed}",
        f"Failed: {result.failed}",
        f"Pass rate: {result.pass_rate}%",
        f"Average score: {result.average_score}",
        f"Guard mode: {markdown_text(result.guard_mode)}",
        f"Guard poll interval: {result.guard_poll_interval_seconds} seconds",
    ]
    if result.profile_id is not None:
        lines.extend(
            [
                f"Profile: {markdown_text(result.profile_name)} "
                f"({markdown_text(result.profile_id)})",
                f"Model: {markdown_text(result.profile_model or '-')}",
            ]
        )
    if result.checkpoint_path is not None:
        lines.extend(
            [
                "",
                "## Checkpoint and Resume",
                "",
                f"Checkpoint: {markdown_text(portable_artifact_value(result.checkpoint_path, roots))}",
                f"Checkpoint ID: {markdown_text(result.checkpoint_id)}",
                f"Status: {markdown_text(result.checkpoint_status)}",
                "Resumed from: "
                f"{markdown_text(portable_artifact_value(result.resumed_from, roots) or '-')}",
                f"Attempts reused: {result.attempts_reused}",
                f"Attempts skipped: {result.attempts_skipped}",
                (
                    "Attempts executed this invocation: "
                    f"{result.attempts_executed_this_invocation}"
                ),
                f"Failed attempts retried: {result.failed_attempts_retried}",
                f"Invalidated attempts: {result.invalidated_attempts}",
                f"Reuse percentage: {result.reuse_percentage}%",
                (
                    "Estimated recomputation avoided: "
                    f"{result.estimated_recomputation_avoided_seconds:.3f} seconds"
                ),
                "Compatibility warnings:",
            ]
        )
        lines.extend(
            f"- {markdown_text(warning)}" for warning in result.compatibility_warnings
        )
        if not result.compatibility_warnings:
            lines.append("- None")
    lines.extend(
        [
            "",
            "## Safety Outcomes",
            "",
            f"Functional passed: {result.functional_passed}",
            f"Functional success rate: {result.functional_success_rate}%",
            f"Policy-compliant passed: {result.policy_compliant_passed}",
            (
                "Policy-compliant success rate: "
                f"{result.policy_compliant_success_rate}%"
            ),
            f"Unsafe functional successes: {result.unsafe_functional_successes}",
        ]
    )
    if result.filters.has_filters():
        lines.append(f"Filters: {markdown_text(format_suite_filters(result.filters))}")
    lines.extend(["", *_guard_incident_lines(result.guard_summary)])
    if result.reliability_baseline_path is not None:
        lines.append(
            "Reliability baseline: "
            f"{markdown_text(result.reliability_baseline_path)}"
        )
    if result.reliability is not None:
        lines.extend(["", "## Reliability", "", *_reliability_lines(result.reliability)])
        lines.extend(
            [
                "",
                "### Per-Agent Reliability",
                "",
                (
                    "| Agent | Attempts | Functional | Policy-Compliant | "
                    "Unsafe Functional | Success Rate | Average Score | "
                    "Minimum | Maximum | Std Dev | Any Pass | All Passes | 95% CI |"
                ),
                (
                    "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
                    "---:|---:|---|"
                ),
            ]
        )
        for agent, summary in result.per_agent_reliability.items():
            lines.append(
                f"| {markdown_table_cell(agent)} | {summary.attempts} | "
                f"{result.per_agent[agent].functional_passed} | "
                f"{result.per_agent[agent].policy_compliant_passed} | "
                f"{result.per_agent[agent].unsafe_functional_successes} | "
                f"{summary.success_rate}% | "
                f"{summary.average_score} | {summary.minimum_score} | "
                f"{summary.maximum_score} | {summary.score_standard_deviation} | "
                f"{summary.combinations_with_any_pass} | "
                f"{summary.combinations_with_all_passes} | "
                f"{summary.confidence_interval_95.lower_bound}% to "
                f"{summary.confidence_interval_95.upper_bound}% |"
            )
        lines.extend(
            [
                "",
                "### Per-Combination Reliability",
                "",
                (
                    "| Task | Benchmark | Agent | Trials | Passed | Failed | "
                    "Success Rate | Average Score | Minimum | Maximum | Std Dev | "
                    "Any Pass | All Passed | 95% CI |"
                ),
                (
                    "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"
                    "---|---|---|"
                ),
            ]
        )
        for summary in result.combinations.values():
            lines.append(
                f"| {markdown_table_cell(summary.task_id)} | "
                f"{markdown_table_cell(summary.benchmark_id or '-')} | "
                f"{markdown_table_cell(summary.agent)} | {summary.trials} | "
                f"{summary.failed} | {summary.success_rate}% | "
                f"{summary.average_score} | {summary.minimum_score} | "
                f"{summary.maximum_score} | {summary.score_standard_deviation} | "
                f"{'yes' if summary.any_pass else 'no'} | "
                f"{'yes' if summary.all_passed else 'no'} | "
                f"{summary.confidence_interval_95.lower_bound}% to "
                f"{summary.confidence_interval_95.upper_bound}% |"
            )
    lines.extend(["", *_summary_table("By Agent", result.per_agent)])
    lines.extend(["", *_summary_table("By Category", result.per_category)])
    lines.extend(["", *_summary_table("By Difficulty", result.per_difficulty)])
    lines.extend(
        [
            "",
            "## Runs",
            "",
            (
                "| Task | Benchmark | Category | Difficulty | Agent | Trial | "
                "Functional | Policy | Score | Prompt | Failed Checks |"
            ),
            "|---|---|---|---|---|---:|---|---|---:|---|---|",
        ]
    )
    for row in result.runs:
        lines.append(
            f"| {markdown_table_cell(row.task_id)} | "
            f"{markdown_table_cell(row.benchmark_id or '-')} | "
            f"{markdown_table_cell(row.category or '-')} | "
            f"{markdown_table_cell(row.difficulty or '-')} | "
            f"{markdown_table_cell(row.agent)} | "
            f"{row.trial_index}/{row.trial_count} | "
            f"{'PASS' if row.functional_passed else 'FAIL'} | "
            f"{markdown_table_cell(row.result)} | "
            f"{row.score} | "
            f"{markdown_table_cell(row.task_prompt_source or '-')} "
            f"{markdown_table_cell(row.task_prompt_sha256 or '-')} | "
            f"{markdown_table_cell(_format_checks(row.failed_checks))} |"
        )
        if row.error:
            lines.append(
                "\nExecution error for "
                f"{markdown_text(row.task_id)} / {markdown_text(row.agent)}: "
                f"{markdown_text(row.error)}"
            )

    if result.baseline_comparison is not None:
        comparison = result.baseline_comparison
        lines.extend(
            [
                "",
                "## Baseline Comparison",
                "",
                f"Baseline: {markdown_text(comparison.baseline_path)}",
                f"Regressions: {'yes' if comparison.has_regressions else 'no'}",
            ]
        )
        lines.extend(
            f"- {markdown_text(message)}" for message in comparison.regressions
        )
        if not comparison.regressions:
            lines.append("- None")

    if result.reliability_comparison is not None:
        comparison = result.reliability_comparison
        thresholds = comparison.thresholds
        lines.extend(
            [
                "",
                "## Reliability Gate",
                "",
                (
                    f"Reliability baseline: "
                    f"{markdown_text(comparison.baseline_path or result.reliability_baseline_path or '-')}"
                ),
                (
                    "Minimum success rate: "
                    f"{thresholds.min_success_rate}%"
                    if thresholds.min_success_rate is not None
                    else "Minimum success rate: not configured"
                ),
                (
                    "Maximum success-rate drop: "
                    f"{thresholds.max_success_rate_drop} points"
                ),
                (
                    "Maximum average-score drop: "
                    f"{thresholds.max_average_score_drop} points"
                ),
                (
                    "Reliability regressions: "
                    f"{'yes' if comparison.has_regressions else 'no'}"
                ),
                "",
                "### Regression Details",
                "",
            ]
        )
        lines.extend(
            f"- {markdown_text(detail.message)}"
            for detail in comparison.regressions
        )
        if not comparison.regressions:
            lines.append("- None")
        lines.extend(["", "### Missing Combinations", ""])
        lines.extend(
            f"- {markdown_text(key)}" for key in comparison.missing_combinations
        )
        if not comparison.missing_combinations:
            lines.append("- None")
        lines.extend(["", "### New Combinations", ""])
        lines.extend(
            f"- {markdown_text(key)}" for key in comparison.new_combinations
        )
        if not comparison.new_combinations:
            lines.append("- None")
        lines.extend(["", "### Version Mismatches", ""])
        lines.extend(
            f"- {markdown_text(message)}"
            for message in comparison.version_mismatches
        )
        if not comparison.version_mismatches:
            lines.append("- None")

    lines.extend(["", "## Individual Reports", ""])
    for row in result.runs:
        lines.append(
            f"- {markdown_text(row.task_id)} / {markdown_text(row.agent)} / "
            f"trial {row.trial_index}/{row.trial_count}:"
        )
        lines.append(
            "  - Run directory: "
            f"{markdown_text(portable_artifact_value(row.run_dir, roots) or '-')}"
        )
        lines.append(
            f"  - JSON: {markdown_text(portable_artifact_value(row.json_report_path, roots) or '-')}"
        )
        lines.append(
            "  - Markdown: "
            f"{markdown_text(portable_artifact_value(row.markdown_report_path, roots) or '-')}"
        )
        lines.append(
            "  - Manifest: "
            f"{markdown_text(portable_artifact_value(row.manifest_path, roots) or '-')}"
        )

    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- Execution ID: {markdown_text(result.matrix_id)}",
            "- Manifest: "
            f"{markdown_text(portable_artifact_value(result.manifest_path, roots) or '-')}",
            f"- Child executions: {len([row for row in result.runs if row.execution_id])}",
        ]
    )

    atomic_write_text(result.markdown_report_path, "\n".join(lines) + "\n")
    return result.markdown_report_path


def write_matrix_reports(result: MatrixResult) -> MatrixResult:
    _write_json_report(result)
    _write_markdown_report(result)
    return result


def _record_matrix_history(result: MatrixResult) -> None:
    try:
        record_history(
            HistoryRecord(
                id=result.matrix_id,
                run_type="matrix",
                name=result.suite_id,
                result="FAIL" if result.failed else "PASS",
                score=result.average_score,
                created_at=utc_now_iso(),
                json_report_path=result.json_report_path,
                markdown_report_path=result.markdown_report_path,
                manifest_path=result.manifest_path,
                failed_checks=sorted(result.failed_check_counts),
            )
        )
    except HistoryStorageError:
        warnings.warn(
            "AgentGuard history write failed: history storage is unavailable.",
            RuntimeWarning,
            stacklevel=2,
        )


def run_matrix(
    path: Path,
    agents: Optional[list[str]] = None,
    matrices_root: Path = Path(".agentguard/matrices"),
    compare_baseline_path: Optional[Path] = None,
    allow_version_mismatch: bool = False,
    filters: Optional[SuiteFilters] = None,
    trials: int = 1,
    save_reliability_baseline_path: Optional[Path] = None,
    compare_reliability_baseline_path: Optional[Path] = None,
    min_success_rate: Optional[float] = None,
    max_success_rate_drop: float = 0,
    max_average_score_drop: float = 0,
    force_reliability_baseline: bool = False,
    workers: int = 1,
    fail_fast: bool = False,
    benchmark_runner: Optional[
        Callable[[Path, str, str], BenchmarkResult]
    ] = None,
    profile_id: Optional[str] = None,
    profile_name: Optional[str] = None,
    profile_model: Optional[str] = None,
    profile_identity: Optional[dict[str, object]] = None,
    checkpoint_path: Optional[Path] = None,
    resume_path: Optional[Path] = None,
    checkpoint_every: int = 1,
    retry_failed: bool = False,
    force_resume: bool = False,
    guard_mode: GuardMode = GuardMode.OFF,
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
    _interrupt_after_attempts: Optional[int] = None,
) -> MatrixResult:
    guard_mode, guard_poll_interval_seconds = validate_guard_configuration(
        guard_mode,
        guard_poll_interval_seconds,
    )
    created_at = manifest_utc_now_iso()
    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        raise ValueError("Matrix trials must be a positive integer.")
    requested_workers = validate_matrix_workers(workers)
    if checkpoint_path is not None and resume_path is not None:
        raise ValueError("--checkpoint and --resume are mutually exclusive.")
    if (
        isinstance(checkpoint_every, bool)
        or not isinstance(checkpoint_every, int)
        or checkpoint_every <= 0
    ):
        raise ValueError("checkpoint-every must be a positive integer.")
    if (retry_failed or force_resume) and resume_path is None:
        raise ValueError("--retry-failed and --force-resume require --resume.")
    if _interrupt_after_attempts is not None and (
        isinstance(_interrupt_after_attempts, bool)
        or _interrupt_after_attempts <= 0
    ):
        raise ValueError("interrupt-after-attempts must be a positive integer.")
    thresholds = reliability_thresholds(
        min_success_rate=min_success_rate,
        max_success_rate_drop=max_success_rate_drop,
        max_average_score_drop=max_average_score_drop,
    )
    config = load_suite_config(path)
    loaded_checkpoint = load_checkpoint(resume_path) if resume_path is not None else None
    matrix_id = (
        loaded_checkpoint.matrix_id
        if loaded_checkpoint is not None
        else _matrix_id(config.suite_id)
    )
    active_filters = filters or SuiteFilters()
    filtered_runs = filter_suite_runs(config.runs, active_filters)
    selected_agents = normalize_matrix_agents(agents)
    matrix_runs = expand_matrix_runs(filtered_runs, selected_agents)
    for run in matrix_runs:
        load_config(run.config_path)
    trial_runs = expand_matrix_trials(matrix_runs, trials)
    attempts_planned = len(trial_runs)
    effective_workers = min(requested_workers, attempts_planned)
    execution_mode = "parallel" if effective_workers > 1 else "serial"
    active_profile_identity = dict(profile_identity or {})
    suite_hash = sha256_file(config.suite_path)
    checkpoint_attempts, checkpoint_benchmarks = _checkpoint_attempts(
        trial_runs,
        suite_sha256=suite_hash,
        trials=trials,
        profile_id=profile_id,
        profile_model=profile_model,
        profile_identity=active_profile_identity,
    )
    identity = agentguard_identity()
    report_dir = _matrix_dir(matrix_id, matrices_root)
    active_checkpoint_path = checkpoint_path or resume_path
    if active_checkpoint_path is not None:
        report_dir = report_dir.expanduser().resolve()
    current_checkpoint = MatrixCheckpoint(
        checkpoint_id=(
            loaded_checkpoint.checkpoint_id
            if loaded_checkpoint is not None
            else checkpoint_id()
        ),
        created_at=(
            loaded_checkpoint.created_at
            if loaded_checkpoint is not None
            else checkpoint_utc_now_iso()
        ),
        updated_at=checkpoint_utc_now_iso(),
        status="running",
        matrix_id=matrix_id,
        suite_id=config.suite_id,
        suite_path=str(config.suite_path),
        suite_sha256=suite_hash,
        filters=asdict(active_filters),
        agents=list(
            dict.fromkeys(
                (profile_id or run.agent)
                for run, _trial_index in trial_runs
            )
        ),
        trials=trials,
        requested_workers=requested_workers,
        effective_workers=effective_workers,
        fail_fast=fail_fast,
        benchmarks=checkpoint_benchmarks,
        profile_identity=active_profile_identity,
        execution_compatibility={
            "agentguard_version": identity.version,
            "agentguard_git_commit": identity.git_commit,
            "history_db_path": str(DEFAULT_HISTORY_DB_PATH.resolve()),
        },
        attempts_planned=attempts_planned,
        attempts=checkpoint_attempts,
        matrix_json_report_path=str(report_dir / "matrix.json"),
        matrix_markdown_report_path=str(report_dir / "matrix.md"),
        matrix_manifest_path=str(report_dir / "manifest.json"),
        guard_mode=guard_mode.value,
        guard_poll_interval_seconds=guard_poll_interval_seconds,
        resumed_from=(
            str(resume_path.expanduser().resolve())
            if resume_path is not None
            else None
        ),
    )
    checkpoint_store = None
    reused_rows: dict[int, MatrixRowSummary] = {}
    pending_items = [
        (ordinal, run, trial_index)
        for ordinal, (run, trial_index) in enumerate(trial_runs)
    ]
    compatibility_warnings = []
    failed_attempts_retried = 0
    invalidated_attempts = 0
    estimated_recomputation_avoided_seconds = 0.0
    if active_checkpoint_path is not None:
        if loaded_checkpoint is not None:
            compatibility_warnings = _checkpoint_compatibility(
                loaded_checkpoint,
                current_checkpoint,
                force_resume=force_resume,
            )
            pending_items = []
            history_path = Path(
                str(
                    loaded_checkpoint.execution_compatibility.get(
                        "history_db_path",
                        DEFAULT_HISTORY_DB_PATH,
                    )
                )
            )
            for ordinal, (run, trial_index) in enumerate(trial_runs):
                stored_attempt = loaded_checkpoint.attempts[ordinal]
                verification = verify_completed_attempt(
                    stored_attempt,
                    history_db_path=history_path,
                )
                if verification.classification == "corrupted":
                    raise ValueError(
                        f"Checkpoint attempt {ordinal + 1} is corrupted: "
                        + "; ".join(verification.messages)
                    )
                should_retry_failure = (
                    verification.row is not None
                    and verification.row.result == "FAIL"
                    and retry_failed
                )
                if verification.classification == "reusable" and not should_retry_failure:
                    assert verification.row is not None
                    reused_rows[ordinal] = verification.row
                    estimated_recomputation_avoided_seconds += (
                        stored_attempt.duration_seconds
                    )
                    upsert_reused_history(verification.row, history_path)
                else:
                    if should_retry_failure:
                        failed_attempts_retried += 1
                    elif stored_attempt.status == "completed":
                        invalidated_attempts += 1
                    pending_items.append((ordinal, run, trial_index))
            current_checkpoint = replace(
                loaded_checkpoint,
                updated_at=checkpoint_utc_now_iso(),
                status="running",
                requested_workers=requested_workers,
                effective_workers=effective_workers,
                attempts=[
                    (
                        replace(
                            attempt,
                            status="pending",
                            started_at=None,
                            completed_at=None,
                            result=None,
                            score=None,
                            failed_checks=[],
                            warning_checks=[],
                            run_id=None,
                            run_dir=None,
                            json_report_path=None,
                            markdown_report_path=None,
                            manifest_path=None,
                            json_report_sha256=None,
                            markdown_report_sha256=None,
                            manifest_sha256=None,
                            duration_seconds=0.0,
                            error=None,
                            guard_violations_total=0,
                            guard_blocked=False,
                            filesystem_guard_violations=0,
                            command_guard_violations=0,
                            time_to_first_violation_ms=None,
                            time_to_block_ms=None,
                            guard_incident_json_path=None,
                            guard_incident_markdown_path=None,
                            blocking_guard=None,
                        )
                        if ordinal not in reused_rows
                        else attempt
                    )
                    for ordinal, attempt in enumerate(loaded_checkpoint.attempts)
                ],
                resumed_from=str(resume_path.expanduser().resolve()),
                compatibility_warnings=compatibility_warnings,
            )
            report_dir = Path(current_checkpoint.matrix_json_report_path).parent
        checkpoint_store = CheckpointStore(
            active_checkpoint_path,
            current_checkpoint,
            checkpoint_every,
        )
        try:
            checkpoint_store.write()
        except OSError as error:
            raise ValueError(
                f"Could not write matrix checkpoint: {error}"
            ) from error
    started = time.monotonic()
    if checkpoint_store is None:
        if requested_workers == 1:
            rows, stopped_early = _run_serial_attempts(
                trial_runs,
                trials,
                fail_fast,
                matrix_id,
                benchmark_runner,
                guard_mode,
                guard_poll_interval_seconds,
            )
        else:
            rows, stopped_early = _run_parallel_attempts(
                trial_runs,
                trials,
                effective_workers,
                fail_fast,
                matrix_id,
                benchmark_runner,
                guard_mode,
                guard_poll_interval_seconds,
            )
        executed_this_invocation = len(rows)
    else:
        completed_lock = threading.Lock()
        completed_count = 0

        def run_checkpointed(
            item: tuple[int, SuiteRunConfig, int],
        ) -> tuple[int, MatrixRowSummary]:
            nonlocal completed_count
            ordinal, run, trial_index = item
            checkpoint_store.mark_running(ordinal)
            attempt_started = time.monotonic()
            row = _run_matrix_row(
                run,
                trial_index,
                trials,
                matrix_id,
                benchmark_runner,
                guard_mode,
                guard_poll_interval_seconds,
            )
            checkpoint_store.mark_completed(
                ordinal,
                row,
                time.monotonic() - attempt_started,
            )
            with completed_lock:
                completed_count += 1
                should_interrupt = (
                    _interrupt_after_attempts is not None
                    and completed_count >= _interrupt_after_attempts
                )
            if should_interrupt:
                raise KeyboardInterrupt
            return ordinal, row

        reused_failure = any(row.result == "FAIL" for row in reused_rows.values())
        try:
            if fail_fast and reused_failure and not retry_failed:
                scheduled_results = []
                stopped_early = bool(pending_items)
            else:
                scheduled = run_bounded_schedule(
                    pending_items,
                    workers=max(1, min(effective_workers, len(pending_items))),
                    fail_fast=fail_fast,
                    runner=run_checkpointed,
                    is_failure=lambda item: item[1].result == "FAIL",
                )
                scheduled_results = scheduled.results
                stopped_early = scheduled.stopped_early
        except KeyboardInterrupt:
            try:
                checkpoint_store.mark_interrupted()
            except OSError as error:
                raise ValueError(
                    f"Could not persist interrupted matrix checkpoint: {error}"
                ) from error
            raise
        except Exception as error:
            try:
                checkpoint_store.mark_interrupted()
            except Exception:
                pass
            raise ValueError(
                f"Matrix checkpoint update failed; execution stopped: {error}"
            ) from error
        new_rows = {ordinal: row for ordinal, row in scheduled_results}
        rows = [
            row
            for ordinal in range(attempts_planned)
            if (row := reused_rows.get(ordinal, new_rows.get(ordinal))) is not None
        ]
        executed_this_invocation = len(new_rows)
    duration_seconds = round(time.monotonic() - started, 6)
    total_runs = len(rows)
    result_counts = dict(Counter(row.result for row in rows))
    passed = result_counts.get("PASS", 0)
    failed = result_counts.get("FAIL", 0)
    combinations = _combination_summaries(rows)
    functional_passed = sum(row.functional_passed for row in rows)
    unsafe_functional_successes = sum(
        row.functional_passed and row.result != "PASS" for row in rows
    )
    result = MatrixResult(
        matrix_id=matrix_id,
        suite_id=config.suite_id,
        description=config.description,
        suite_path=config.suite_path,
        total_runs=total_runs,
        agents=list(dict.fromkeys(row.agent for row in rows)),
        passed=passed,
        failed=failed,
        pass_rate=round((passed / total_runs) * 100, 1),
        average_score=int(round(sum(row.score for row in rows) / total_runs)),
        per_agent=_summaries_by(rows, "agent", "unknown"),
        per_category=_summaries_by(rows, "category", "uncategorized"),
        per_difficulty=_summaries_by(rows, "difficulty", "unspecified"),
        runs=rows,
        result_counts=result_counts,
        failed_check_counts=dict(
            Counter(check for row in rows for check in row.failed_checks)
        ),
        json_report_path=report_dir / "matrix.json",
        markdown_report_path=report_dir / "matrix.md",
        guard_mode=guard_mode.value,
        guard_poll_interval_seconds=guard_poll_interval_seconds,
        manifest_path=report_dir / "manifest.json",
        requested_workers=requested_workers,
        effective_workers=effective_workers,
        execution_mode=execution_mode,
        duration_seconds=duration_seconds,
        attempts_planned=attempts_planned,
        attempts_executed=total_runs,
        stopped_early=stopped_early,
        trials=trials,
        reliability=_reliability_summary(rows, combinations),
        per_agent_reliability=_reliability_by_agent(rows, combinations),
        combinations=combinations,
        filters=active_filters,
        reliability_baseline_path=save_reliability_baseline_path,
        functional_passed=functional_passed,
        functional_success_rate=round((functional_passed / total_runs) * 100, 1),
        policy_compliant_passed=passed,
        policy_compliant_success_rate=round((passed / total_runs) * 100, 1),
        unsafe_functional_successes=unsafe_functional_successes,
        profile_id=profile_id,
        profile_name=profile_name,
        profile_model=profile_model,
        checkpoint_path=(
            active_checkpoint_path.expanduser().resolve()
            if active_checkpoint_path is not None
            else None
        ),
        checkpoint_id=(
            checkpoint_store.checkpoint.checkpoint_id
            if checkpoint_store is not None
            else None
        ),
        resumed_from=(
            resume_path.expanduser().resolve()
            if resume_path is not None
            else None
        ),
        checkpoint_status=(
            "completed" if checkpoint_store is not None else None
        ),
        attempts_reused=len(reused_rows),
        attempts_skipped=len(reused_rows),
        attempts_executed_this_invocation=executed_this_invocation,
        failed_attempts_retried=failed_attempts_retried,
        invalidated_attempts=invalidated_attempts,
        reuse_percentage=round(
            (len(reused_rows) / attempts_planned) * 100,
            1,
        ),
        estimated_recomputation_avoided_seconds=round(
            estimated_recomputation_avoided_seconds,
            6,
        ),
        compatibility_warnings=compatibility_warnings,
        guard_summary=aggregate_matrix_guard(
            rows,
            report_dir / "matrix.md",
        ),
    )
    if compare_baseline_path is not None:
        result = replace(
            result,
            baseline_comparison=compare_suite_to_baseline(
                result,
                compare_baseline_path,
                allow_version_mismatch=allow_version_mismatch,
                only_compare_current_runs=active_filters.has_filters(),
            ),
        )
    if compare_reliability_baseline_path is not None:
        result = replace(
            result,
            reliability_comparison=compare_matrix_reliability(
                result,
                compare_reliability_baseline_path,
                thresholds,
                allow_version_mismatch=allow_version_mismatch,
                only_compare_current_combinations=active_filters.has_filters(),
            ),
        )
    elif min_success_rate is not None:
        result = replace(
            result,
            reliability_comparison=evaluate_minimum_reliability(
                result,
                thresholds,
            ),
        )
    if save_reliability_baseline_path is not None:
        write_matrix_reliability_baseline(
            result,
            save_reliability_baseline_path,
            force=force_reliability_baseline,
        )
    result = write_matrix_reports(result)
    unique_configs = {
        run.config_path.expanduser().resolve(): load_config(run.config_path)
        for run in matrix_runs
    }
    portable_roots = artifact_roots(
        repository_root=Path.cwd(),
        run_root=result.json_report_path.parent,
        config_path=config.suite_path,
    )
    manifest = ExecutionManifest(
        execution_id=matrix_id,
        execution_type="matrix",
        created_at=created_at,
        completed_at=manifest_utc_now_iso(),
        duration_seconds=round(time.monotonic() - started, 6),
        agentguard=agentguard_identity(),
        host=host_identity(
            docker_relevant=any(
                loaded.sandbox.type == "docker"
                for loaded in unique_configs.values()
            )
        ),
        source=source_identity(Path.cwd(), roots=portable_roots),
        configuration=configuration_identity(
            config.suite_path,
            {
                "suite_id": config.suite_id,
                "filters": asdict(active_filters),
                "agents": selected_agents or [run.agent for run in filtered_runs],
                "guard_mode": guard_mode.value,
                "guard_poll_interval_seconds": guard_poll_interval_seconds,
            },
            roots=portable_roots,
        ),
        agent=None,
        benchmarks=[
            benchmark_identity(loaded, roots=portable_roots)
            for loaded in unique_configs.values()
        ],
        policies=[policy_identity(loaded) for loaded in unique_configs.values()],
        artifacts=artifact_identity(
            result.json_report_path,
            result.markdown_report_path,
            roots=portable_roots,
        ),
        child_executions=[
            ChildExecution(
                execution_id=row.execution_id,
                execution_type="run",
                manifest_path=(
                    portable_artifact_value(row.manifest_path, portable_roots)
                    if row.manifest_path is not None
                    else None
                ),
                task_id=row.task_id,
                agent=row.agent,
                trial_index=row.trial_index,
            )
            for row in result.runs
            if row.execution_id is not None
        ],
        matrix={
            "agents": result.agents,
            "trials": result.trials,
            "requested_workers": result.requested_workers,
            "effective_workers": result.effective_workers,
            "execution_mode": result.execution_mode,
            "attempts_planned": result.attempts_planned,
            "attempts_executed": result.attempts_executed,
            "stopped_early": result.stopped_early,
            "functional_passed": result.functional_passed,
            "functional_success_rate": result.functional_success_rate,
            "policy_compliant_passed": result.policy_compliant_passed,
            "policy_compliant_success_rate": result.policy_compliant_success_rate,
            "unsafe_functional_successes": result.unsafe_functional_successes,
            "profile_id": result.profile_id,
            "profile_name": result.profile_name,
            "profile_model": result.profile_model,
            "checkpoint_path": portable_artifact_value(
                result.checkpoint_path,
                portable_roots,
            ),
            "checkpoint_id": result.checkpoint_id,
            "resumed_from": portable_artifact_value(
                result.resumed_from,
                portable_roots,
            ),
            "checkpoint_status": result.checkpoint_status,
            "attempts_reused": result.attempts_reused,
            "attempts_skipped": result.attempts_skipped,
            "attempts_executed_this_invocation": (
                result.attempts_executed_this_invocation
            ),
            "failed_attempts_retried": result.failed_attempts_retried,
            "invalidated_attempts": result.invalidated_attempts,
            "reuse_percentage": result.reuse_percentage,
            "estimated_recomputation_avoided_seconds": (
                result.estimated_recomputation_avoided_seconds
            ),
            "compatibility_warnings": result.compatibility_warnings,
            "guard_mode": result.guard_mode,
            "guard_poll_interval_seconds": (
                result.guard_poll_interval_seconds
            ),
            "guard_summary": asdict(result.guard_summary),
        },
        guard={
            "guard_mode": result.guard_mode,
            "guard_poll_interval_seconds": result.guard_poll_interval_seconds,
        },
    )
    if result.manifest_path is not None:
        if write_manifest(manifest, result.manifest_path) is None:
            result = replace(result, manifest_path=None)
    _record_matrix_history(result)
    if checkpoint_store is not None:
        try:
            checkpoint_store.mark_completed_checkpoint()
        except OSError as error:
            raise ValueError(
                f"Could not finalize matrix checkpoint: {error}"
            ) from error
    return result
