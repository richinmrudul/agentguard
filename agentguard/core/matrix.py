import json
import inspect
import time
import warnings
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from statistics import stdev
from typing import Any, Callable, Optional
from uuid import uuid4

from agentguard.config.loader import load_config
from agentguard.core.baseline import BaselineComparison, compare_suite_to_baseline
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
from agentguard.history.store import HistoryRecord, record_history, utc_now_iso
from agentguard.provenance.manifest import (
    ChildExecution,
    ExecutionManifest,
    agentguard_identity,
    artifact_identity,
    benchmark_identity,
    configuration_identity,
    host_identity,
    policy_identity,
    portable_path,
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


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


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
) -> MatrixRowSummary:
    try:
        return _row_from_result(
            _invoke_run_benchmark(run, matrix_id, benchmark_runner),
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
) -> BenchmarkResult:
    if benchmark_runner is not None:
        return benchmark_runner(run.config_path, run.agent, matrix_id)
    parameters = inspect.signature(run_benchmark).parameters
    if "parent_execution_id" not in parameters:
        return run_benchmark(run.config_path, run.agent)
    return run_benchmark(
        run.config_path,
        run.agent,
        parent_execution_id=matrix_id,
        parent_execution_type="matrix",
    )


def _run_serial_attempts(
    trial_runs: list[tuple[SuiteRunConfig, int]],
    trial_count: int,
    fail_fast: bool,
    matrix_id: str,
    benchmark_runner: Optional[
        Callable[[Path, str, str], BenchmarkResult]
    ] = None,
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
    config_path = row.config_path.expanduser().resolve()
    try:
        portable_path = config_path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        portable_path = config_path.as_posix()
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
    result.json_report_path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(result)
    if result.baseline_comparison is None:
        data.pop("baseline_comparison", None)
    if result.reliability_baseline_path is None:
        data.pop("reliability_baseline_path", None)
    if result.reliability_comparison is None:
        data.pop("reliability_comparison", None)
    if not result.filters.has_filters():
        data.pop("filters", None)
    with result.json_report_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, default=_json_default, indent=2)
        file.write("\n")
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


def _write_markdown_report(result: MatrixResult) -> Path:
    result.markdown_report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AgentGuard Matrix Summary",
        "",
        f"Matrix: {result.matrix_id}",
        f"Suite: {result.suite_id}",
        f"Suite config: {result.suite_path}",
        f"Agents: {', '.join(result.agents)}",
        f"Trials per combination: {result.trials}",
        f"Requested workers: {result.requested_workers}",
        f"Effective workers: {result.effective_workers}",
        f"Execution mode: {result.execution_mode}",
        f"Execution duration: {result.duration_seconds:.3f} seconds",
        f"Attempts planned: {result.attempts_planned}",
        f"Attempts executed: {result.attempts_executed}",
        f"Stopped early: {'yes' if result.stopped_early else 'no'}",
        f"Runs: {result.total_runs}",
        f"Passed: {result.passed}",
        f"Failed: {result.failed}",
        f"Pass rate: {result.pass_rate}%",
        f"Average score: {result.average_score}",
    ]
    if result.profile_id is not None:
        lines.extend(
            [
                f"Profile: {result.profile_name} ({result.profile_id})",
                f"Model: {result.profile_model or '-'}",
            ]
        )
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
        lines.append(f"Filters: {format_suite_filters(result.filters)}")
    if result.reliability_baseline_path is not None:
        lines.append(f"Reliability baseline: {result.reliability_baseline_path}")
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
                f"| {agent} | {summary.attempts} | "
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
                f"| {summary.task_id} | {summary.benchmark_id or '-'} | "
                f"{summary.agent} | {summary.trials} | {summary.passed} | "
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
            f"| {row.task_id} | {row.benchmark_id or '-'} | "
            f"{row.category or '-'} | {row.difficulty or '-'} | {row.agent} | "
            f"{row.trial_index}/{row.trial_count} | "
            f"{'PASS' if row.functional_passed else 'FAIL'} | {row.result} | "
            f"{row.score} | "
            f"{row.task_prompt_source or '-'} "
            f"{row.task_prompt_sha256 or '-'} | "
            f"{_format_checks(row.failed_checks)} |"
        )
        if row.error:
            lines.append(f"\nExecution error for {row.task_id} / {row.agent}: {row.error}")

    if result.baseline_comparison is not None:
        comparison = result.baseline_comparison
        lines.extend(
            [
                "",
                "## Baseline Comparison",
                "",
                f"Baseline: {comparison.baseline_path}",
                f"Regressions: {'yes' if comparison.has_regressions else 'no'}",
            ]
        )
        lines.extend(f"- {message}" for message in comparison.regressions)
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
                    f"{comparison.baseline_path or result.reliability_baseline_path or '-'}"
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
        lines.extend(f"- {detail.message}" for detail in comparison.regressions)
        if not comparison.regressions:
            lines.append("- None")
        lines.extend(["", "### Missing Combinations", ""])
        lines.extend(f"- {key}" for key in comparison.missing_combinations)
        if not comparison.missing_combinations:
            lines.append("- None")
        lines.extend(["", "### New Combinations", ""])
        lines.extend(f"- {key}" for key in comparison.new_combinations)
        if not comparison.new_combinations:
            lines.append("- None")
        lines.extend(["", "### Version Mismatches", ""])
        lines.extend(f"- {message}" for message in comparison.version_mismatches)
        if not comparison.version_mismatches:
            lines.append("- None")

    lines.extend(["", "## Individual Reports", ""])
    for row in result.runs:
        lines.append(
            f"- {row.task_id} / {row.agent} / "
            f"trial {row.trial_index}/{row.trial_count}:"
        )
        lines.append(f"  - Run directory: {row.run_dir or '-'}")
        lines.append(f"  - JSON: {row.json_report_path or '-'}")
        lines.append(f"  - Markdown: {row.markdown_report_path or '-'}")
        lines.append(f"  - Manifest: {row.manifest_path or '-'}")

    lines.extend(
        [
            "",
            "## Provenance",
            "",
            f"- Execution ID: {result.matrix_id}",
            f"- Manifest: {result.manifest_path or '-'}",
            f"- Child executions: {len([row for row in result.runs if row.execution_id])}",
        ]
    )

    result.markdown_report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
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
    except Exception as error:
        warnings.warn(
            f"AgentGuard history write failed: {error}",
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
    resolve_suite_config_paths: bool = False,
) -> MatrixResult:
    created_at = manifest_utc_now_iso()
    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        raise ValueError("Matrix trials must be a positive integer.")
    requested_workers = validate_matrix_workers(workers)
    thresholds = reliability_thresholds(
        min_success_rate=min_success_rate,
        max_success_rate_drop=max_success_rate_drop,
        max_average_score_drop=max_average_score_drop,
    )
    config = load_suite_config(
        path,
        resolve_config_paths=resolve_suite_config_paths,
    )
    matrix_id = _matrix_id(config.suite_id)
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
    started = time.monotonic()
    if requested_workers == 1:
        rows, stopped_early = _run_serial_attempts(
            trial_runs,
            trials,
            fail_fast,
            matrix_id,
            benchmark_runner,
        )
    else:
        rows, stopped_early = _run_parallel_attempts(
            trial_runs,
            trials,
            effective_workers,
            fail_fast,
            matrix_id,
            benchmark_runner,
        )
    duration_seconds = round(time.monotonic() - started, 6)
    total_runs = len(rows)
    result_counts = dict(Counter(row.result for row in rows))
    passed = result_counts.get("PASS", 0)
    failed = result_counts.get("FAIL", 0)
    report_dir = matrices_root / matrix_id
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
        source=source_identity(Path.cwd()),
        configuration=configuration_identity(
            config.suite_path,
            {
                "suite_id": config.suite_id,
                "filters": asdict(active_filters),
                "agents": selected_agents or [run.agent for run in filtered_runs],
            },
        ),
        agent=None,
        benchmarks=[
            benchmark_identity(loaded) for loaded in unique_configs.values()
        ],
        policies=[policy_identity(loaded) for loaded in unique_configs.values()],
        artifacts=artifact_identity(
            result.json_report_path,
            result.markdown_report_path,
        ),
        child_executions=[
            ChildExecution(
                execution_id=row.execution_id,
                execution_type="run",
                manifest_path=(
                    portable_path(row.manifest_path)
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
        },
    )
    if result.manifest_path is not None:
        if write_manifest(manifest, result.manifest_path) is None:
            result = replace(result, manifest_path=None)
    _record_matrix_history(result)
    return result
