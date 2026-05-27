import json
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import BenchmarkResult


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


@dataclass(frozen=True)
class SuiteResult:
    suite_id: str
    description: str
    suite_path: Path
    total_runs: int
    passed: int
    failed: int
    average_score: int
    runs: list[SuiteRunSummary]
    json_report_path: Path
    markdown_report_path: Path


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
        failed_checks=failed_checks,
        warning_checks=warning_checks,
        json_report_path=result.report_paths.json,
        markdown_report_path=result.report_paths.markdown,
        run_dir=result.run_dir,
    )


def _format_checks(checks: list[str]) -> str:
    return ", ".join(checks) if checks else "-"


def _write_json_report(result: SuiteResult) -> Path:
    report_path = result.json_report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(asdict(result), file, default=_json_default, indent=2)
        file.write("\n")
    return report_path


def _write_markdown_report(result: SuiteResult) -> Path:
    report_path = result.markdown_report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AgentGuard Suite Summary",
        "",
        f"Suite: {result.suite_id}",
        f"Description: {result.description}",
        f"Suite config: {result.suite_path}",
        f"Runs: {result.total_runs}",
        f"Passed: {result.passed}",
        f"Failed: {result.failed}",
        f"Average score: {result.average_score}",
        "",
        "| Task | Agent | Result | Score | Failed Checks | Warnings |",
        "|---|---|---|---:|---|---|",
    ]
    for run in result.runs:
        lines.append(
            f"| {run.task_id} | {run.agent} | {run.result} | {run.score} | "
            f"{_format_checks(run.failed_checks)} | "
            f"{_format_checks(run.warning_checks)} |"
        )

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
    return replace(
        result,
        json_report_path=json_path,
        markdown_report_path=markdown_path,
    )


def run_suite(
    path: Path,
    suites_root: Path = Path(".agentguard/suites"),
) -> SuiteResult:
    config = load_suite_config(path)
    run_results = [
        run_benchmark(run.config_path, run.agent)
        for run in config.runs
    ]
    runs = [_run_summary(result) for result in run_results]
    total_runs = len(runs)
    summary_dir = _suite_dir(config.suite_id, suites_root)
    average_score = int(round(sum(run.score for run in runs) / total_runs))
    result = SuiteResult(
        suite_id=config.suite_id,
        description=config.description,
        suite_path=config.suite_path,
        total_runs=total_runs,
        passed=sum(1 for run in runs if run.result == "PASS"),
        failed=sum(1 for run in runs if run.result == "FAIL"),
        average_score=average_score,
        runs=runs,
        json_report_path=summary_dir / "suite.json",
        markdown_report_path=summary_dir / "suite.md",
    )
    return write_suite_reports(result)
