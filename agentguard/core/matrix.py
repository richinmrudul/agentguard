import json
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agentguard.config.loader import load_config
from agentguard.core.baseline import BaselineComparison, compare_suite_to_baseline
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import BenchmarkResult
from agentguard.core.suite import (
    SuiteFilters,
    SuiteRunConfig,
    filter_suite_runs,
    format_suite_filters,
    load_suite_config,
)


@dataclass(frozen=True)
class MatrixGroupSummary:
    runs: int
    passed: int
    failed: int
    average_score: int


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
    benchmark_id: Optional[str] = None
    benchmark_version: Optional[int] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    error: Optional[str] = None


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
    filters: SuiteFilters = field(default_factory=SuiteFilters)
    baseline_comparison: Optional[BaselineComparison] = None


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


def _matrix_id(suite_id: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"{suite_id}-{timestamp}"


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _row_from_result(result: BenchmarkResult) -> MatrixRowSummary:
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
        benchmark_id=result.benchmark.id,
        benchmark_version=result.benchmark.version,
        category=result.benchmark.category,
        difficulty=result.benchmark.difficulty,
        tags=result.benchmark.tags,
    )


def _error_row(run: SuiteRunConfig, error: Exception) -> MatrixRowSummary:
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
    )


def _run_matrix_row(run: SuiteRunConfig) -> MatrixRowSummary:
    try:
        return _row_from_result(run_benchmark(run.config_path, run.agent))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        return _error_row(run, error)


def _group_summary(rows: list[MatrixRowSummary]) -> MatrixGroupSummary:
    passed = sum(1 for row in rows if row.result == "PASS")
    total = len(rows)
    return MatrixGroupSummary(
        runs=total,
        passed=passed,
        failed=total - passed,
        average_score=int(round(sum(row.score for row in rows) / total)),
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


def _format_checks(checks: list[str]) -> str:
    return ", ".join(checks) if checks else "-"


def _write_json_report(result: MatrixResult) -> Path:
    result.json_report_path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(result)
    if result.baseline_comparison is None:
        data.pop("baseline_comparison", None)
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


def _write_markdown_report(result: MatrixResult) -> Path:
    result.markdown_report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AgentGuard Matrix Summary",
        "",
        f"Matrix: {result.matrix_id}",
        f"Suite: {result.suite_id}",
        f"Suite config: {result.suite_path}",
        f"Agents: {', '.join(result.agents)}",
        f"Runs: {result.total_runs}",
        f"Passed: {result.passed}",
        f"Failed: {result.failed}",
        f"Pass rate: {result.pass_rate}%",
        f"Average score: {result.average_score}",
    ]
    if result.filters.has_filters():
        lines.append(f"Filters: {format_suite_filters(result.filters)}")
    lines.extend(["", *_summary_table("By Agent", result.per_agent)])
    lines.extend(["", *_summary_table("By Category", result.per_category)])
    lines.extend(["", *_summary_table("By Difficulty", result.per_difficulty)])
    lines.extend(
        [
            "",
            "## Runs",
            "",
            (
                "| Task | Benchmark | Category | Difficulty | Agent | Result | "
                "Score | Failed Checks |"
            ),
            "|---|---|---|---|---|---|---:|---|",
        ]
    )
    for row in result.runs:
        lines.append(
            f"| {row.task_id} | {row.benchmark_id or '-'} | "
            f"{row.category or '-'} | {row.difficulty or '-'} | {row.agent} | "
            f"{row.result} | {row.score} | {_format_checks(row.failed_checks)} |"
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

    lines.extend(["", "## Individual Reports", ""])
    for row in result.runs:
        lines.append(f"- {row.task_id} / {row.agent}:")
        lines.append(f"  - JSON: {row.json_report_path or '-'}")
        lines.append(f"  - Markdown: {row.markdown_report_path or '-'}")

    result.markdown_report_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return result.markdown_report_path


def write_matrix_reports(result: MatrixResult) -> MatrixResult:
    _write_json_report(result)
    _write_markdown_report(result)
    return result


def run_matrix(
    path: Path,
    agents: Optional[list[str]] = None,
    matrices_root: Path = Path(".agentguard/matrices"),
    compare_baseline_path: Optional[Path] = None,
    allow_version_mismatch: bool = False,
    filters: Optional[SuiteFilters] = None,
) -> MatrixResult:
    config = load_suite_config(path)
    active_filters = filters or SuiteFilters()
    filtered_runs = filter_suite_runs(config.runs, active_filters)
    selected_agents = normalize_matrix_agents(agents)
    matrix_runs = expand_matrix_runs(filtered_runs, selected_agents)
    rows = [_run_matrix_row(run) for run in matrix_runs]
    total_runs = len(rows)
    result_counts = dict(Counter(row.result for row in rows))
    passed = result_counts.get("PASS", 0)
    failed = result_counts.get("FAIL", 0)
    matrix_id = _matrix_id(config.suite_id)
    report_dir = matrices_root / matrix_id
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
        filters=active_filters,
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
    return write_matrix_reports(result)
