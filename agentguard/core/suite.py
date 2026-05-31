import json
import warnings
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.config.loader import load_config
from agentguard.core.baseline import BaselineComparison, compare_suite_to_baseline
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import BenchmarkResult
from agentguard.history.store import HistoryRecord, record_history, utc_now_iso


@dataclass(frozen=True)
class SuiteRunConfig:
    config_path: Path
    agent: str


@dataclass(frozen=True)
class SuiteConfig:
    suite_id: str
    description: str
    suite_path: Path
    runs: list[SuiteRunConfig]


@dataclass(frozen=True)
class SuiteFilters:
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: list[str] = field(default_factory=list)

    def has_filters(self) -> bool:
        return bool(self.category or self.difficulty or self.tags)


@dataclass(frozen=True)
class SuiteRunSummary:
    task_id: str
    config_path: Path
    agent: str
    result: str
    score: int
    failed_checks: list[str]
    warning_checks: list[str]
    json_report_path: Path
    markdown_report_path: Path
    run_dir: Path
    benchmark_id: Optional[str] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SuiteRunHeadline:
    task_id: str
    agent: str
    result: str
    score: int


@dataclass(frozen=True)
class SuiteResult:
    suite_id: str
    description: str
    suite_path: Path
    total_runs: int
    passed: int
    failed: int
    pass_rate: float
    average_score: int
    best_run: SuiteRunHeadline
    worst_run: SuiteRunHeadline
    failed_check_counts: dict[str, int]
    warning_check_counts: dict[str, int]
    result_counts: dict[str, int]
    runs: list[SuiteRunSummary]
    json_report_path: Path
    markdown_report_path: Path
    filters: SuiteFilters = field(default_factory=SuiteFilters)
    baseline_comparison: Optional[BaselineComparison] = None


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _suite_dir(suite_id: str, suites_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return suites_root / f"{suite_id}-{timestamp}"


def _required_string(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Suite field '{key}' must be a non-empty string.")
    return value


def normalize_filter_tags(raw_tags: Optional[list[str]]) -> list[str]:
    if raw_tags is None:
        return []
    tags: list[str] = []
    for raw_tag in raw_tags:
        for tag in raw_tag.split(","):
            normalized = tag.strip()
            if normalized:
                tags.append(normalized)
    return tags


def suite_filters_from_values(
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> SuiteFilters:
    normalized_category = category.strip() if category is not None else None
    normalized_difficulty = difficulty.strip() if difficulty is not None else None
    if normalized_category == "":
        raise ValueError("Suite filter 'category' must be a non-empty string.")
    if normalized_difficulty == "":
        raise ValueError("Suite filter 'difficulty' must be a non-empty string.")
    return SuiteFilters(
        category=normalized_category,
        difficulty=normalized_difficulty,
        tags=normalize_filter_tags(tags),
    )


def load_suite_config(path: Path) -> SuiteConfig:
    suite_path = path.expanduser().resolve()
    with suite_path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    if not isinstance(data, dict):
        raise ValueError("Suite config must be a YAML mapping.")

    suite_id = _required_string(data, "suite_id")
    description = _required_string(data, "description")
    raw_runs = data.get("runs")
    if not isinstance(raw_runs, list) or not raw_runs:
        raise ValueError("Suite field 'runs' must be a non-empty list.")

    runs = []
    for index, raw_run in enumerate(raw_runs):
        if not isinstance(raw_run, dict):
            raise ValueError(f"Suite run {index} must be a mapping.")
        config = raw_run.get("config")
        agent = raw_run.get("agent")
        if not isinstance(config, str) or not config:
            raise ValueError(f"Suite run {index} field 'config' is required.")
        if not isinstance(agent, str) or not agent:
            raise ValueError(f"Suite run {index} field 'agent' is required.")
        runs.append(SuiteRunConfig(config_path=Path(config), agent=agent))

    return SuiteConfig(
        suite_id=suite_id,
        description=description,
        suite_path=suite_path,
        runs=runs,
    )


def _matches_filters(run: SuiteRunConfig, filters: SuiteFilters) -> bool:
    if not filters.has_filters():
        return True

    metadata = load_config(run.config_path).benchmark
    if filters.category is not None and metadata.category != filters.category:
        return False
    if filters.difficulty is not None and metadata.difficulty != filters.difficulty:
        return False
    if filters.tags and not set(filters.tags).issubset(set(metadata.tags)):
        return False
    return True


def filter_suite_runs(
    runs: list[SuiteRunConfig],
    filters: SuiteFilters,
) -> list[SuiteRunConfig]:
    if not filters.has_filters():
        return runs
    matched = [run for run in runs if _matches_filters(run, filters)]
    if not matched:
        raise ValueError("suite filters matched no runs.")
    return matched


def _run_summary(result: BenchmarkResult) -> SuiteRunSummary:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    warning_checks = [
        check.name
        for check in result.check_results
        if not check.passed and check.severity == "warning"
    ]
    return SuiteRunSummary(
        task_id=result.task_id,
        config_path=result.config_path,
        agent=result.agent,
        result=result.result,
        score=result.score,
        benchmark_id=result.benchmark.id,
        category=result.benchmark.category,
        difficulty=result.benchmark.difficulty,
        tags=result.benchmark.tags,
        failed_checks=failed_checks,
        warning_checks=warning_checks,
        json_report_path=result.report_paths.json,
        markdown_report_path=result.report_paths.markdown,
        run_dir=result.run_dir,
    )


def _format_checks(checks: list[str]) -> str:
    return ", ".join(checks) if checks else "-"


def format_suite_filters(filters: SuiteFilters) -> str:
    parts = []
    if filters.category is not None:
        parts.append(f"category={filters.category}")
    if filters.difficulty is not None:
        parts.append(f"difficulty={filters.difficulty}")
    if filters.tags:
        parts.append(f"tags={','.join(filters.tags)}")
    return ", ".join(parts)


def _run_headline(run: SuiteRunSummary) -> SuiteRunHeadline:
    return SuiteRunHeadline(
        task_id=run.task_id,
        agent=run.agent,
        result=run.result,
        score=run.score,
    )


def _count_checks(runs: list[SuiteRunSummary], field_name: str) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for run in runs:
        counts.update(getattr(run, field_name))
    return dict(counts)


def _format_count_lines(counts: dict[str, int]) -> list[str]:
    if not counts:
        return ["- None"]
    return [
        f"- {name}: {count}"
        for name, count in sorted(counts.items(), key=lambda item: -item[1])
    ]


def _write_json_report(result: SuiteResult) -> Path:
    report_path = result.json_report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(result)
    if result.baseline_comparison is None:
        data.pop("baseline_comparison", None)
    if not result.filters.has_filters():
        data.pop("filters", None)
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(data, file, default=_json_default, indent=2)
        file.write("\n")
    return report_path


def _write_markdown_report(result: SuiteResult) -> Path:
    report_path = result.markdown_report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AgentGuard Suite Summary",
        "",
        "## Summary",
        "",
        f"Suite: {result.suite_id}",
        f"Description: {result.description}",
        f"Suite config: {result.suite_path}",
        f"Runs: {result.total_runs}",
        f"Passed: {result.passed}",
        f"Failed: {result.failed}",
        f"Pass rate: {result.pass_rate}%",
        f"Average score: {result.average_score}",
    ]
    if result.filters.has_filters():
        lines.append(f"Filters: {format_suite_filters(result.filters)}")
    lines.extend([
        "",
        "## Best/Worst Runs",
        "",
        (
            f"Best run: {result.best_run.task_id} / {result.best_run.agent} / "
            f"{result.best_run.result} / {result.best_run.score}"
        ),
        (
            f"Worst run: {result.worst_run.task_id} / {result.worst_run.agent} / "
            f"{result.worst_run.result} / {result.worst_run.score}"
        ),
        "",
        "## Failed Check Counts",
        "",
        *_format_count_lines(result.failed_check_counts),
        "",
        "## Warning Check Counts",
        "",
        *_format_count_lines(result.warning_check_counts),
        "",
        "## Runs",
        "",
        (
            "| Task | Category | Difficulty | Agent | Result | Score | "
            "Failed Checks | Warnings |"
        ),
        "|---|---|---|---|---|---:|---|---|",
    ])
    for run in result.runs:
        lines.append(
            f"| {run.task_id} | {run.category or '-'} | "
            f"{run.difficulty or '-'} | {run.agent} | {run.result} | "
            f"{run.score} | "
            f"{_format_checks(run.failed_checks)} | "
            f"{_format_checks(run.warning_checks)} |"
        )

    if result.baseline_comparison is not None:
        comparison = result.baseline_comparison
        lines.extend(
            [
                "",
                "## Baseline Comparison",
                "",
                f"Baseline: {comparison.baseline_path}",
                f"Regressions: {'yes' if comparison.has_regressions else 'no'}",
                f"Unchanged runs: {comparison.unchanged_count}",
                "",
                "### Regressions",
                "",
            ]
        )
        lines.extend(
            f"- {message}" for message in comparison.regressions
        )
        if not comparison.regressions:
            lines.append("- None")
        lines.extend(["", "### Improvements", ""])
        lines.extend(
            f"- {message}" for message in comparison.improvements
        )
        if not comparison.improvements:
            lines.append("- None")

    lines.extend(["", "## Individual Reports"])
    for run in result.runs:
        lines.append(f"- {run.task_id} / {run.agent}:")
        lines.append(f"  - Run directory: {run.run_dir}")
        lines.append(f"  - JSON: {run.json_report_path}")
        lines.append(f"  - Markdown: {run.markdown_report_path}")

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def write_suite_reports(result: SuiteResult) -> SuiteResult:
    json_path = _write_json_report(result)
    markdown_path = _write_markdown_report(result)
    written = replace(
        result,
        json_report_path=json_path,
        markdown_report_path=markdown_path,
    )
    _record_suite_history(written)
    return written


def _record_suite_history(result: SuiteResult) -> None:
    try:
        record_history(
            HistoryRecord(
                id=result.json_report_path.parent.name,
                run_type="suite",
                name=result.suite_id,
                result="FAIL" if result.failed > 0 else "PASS",
                score=result.average_score,
                created_at=utc_now_iso(),
                json_report_path=result.json_report_path,
                markdown_report_path=result.markdown_report_path,
                failed_checks=sorted(result.failed_check_counts),
            )
        )
    except Exception as error:
        warnings.warn(
            f"AgentGuard history write failed: {error}",
            RuntimeWarning,
            stacklevel=2,
        )


def run_suite(
    path: Path,
    suites_root: Path = Path(".agentguard/suites"),
    compare_baseline_path: Optional[Path] = None,
    filters: Optional[SuiteFilters] = None,
) -> SuiteResult:
    config = load_suite_config(path)
    active_filters = filters or SuiteFilters()
    suite_runs = filter_suite_runs(config.runs, active_filters)
    run_results = [
        run_benchmark(run.config_path, run.agent)
        for run in suite_runs
    ]
    runs = [_run_summary(result) for result in run_results]
    total_runs = len(runs)
    summary_dir = _suite_dir(config.suite_id, suites_root)
    result_counts = dict(Counter(run.result for run in runs))
    passed = result_counts.get("PASS", 0)
    failed = result_counts.get("FAIL", 0)
    average_score = int(round(sum(run.score for run in runs) / total_runs))
    best_run = max(runs, key=lambda run: run.score)
    worst_run = min(runs, key=lambda run: run.score)
    result = SuiteResult(
        suite_id=config.suite_id,
        description=config.description,
        suite_path=config.suite_path,
        total_runs=total_runs,
        passed=passed,
        failed=failed,
        pass_rate=round((passed / total_runs) * 100, 1),
        average_score=average_score,
        best_run=_run_headline(best_run),
        worst_run=_run_headline(worst_run),
        failed_check_counts=_count_checks(runs, "failed_checks"),
        warning_check_counts=_count_checks(runs, "warning_checks"),
        result_counts=result_counts,
        runs=runs,
        json_report_path=summary_dir / "suite.json",
        markdown_report_path=summary_dir / "suite.md",
        filters=active_filters,
    )
    if compare_baseline_path is not None:
        result = replace(
            result,
            baseline_comparison=compare_suite_to_baseline(
                result,
                compare_baseline_path,
            ),
        )
    return write_suite_reports(result)
