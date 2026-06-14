from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from agentguard.core.orchestrator import run_benchmark
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.core.result import (
    AgentBenchmarkSummary,
    BenchmarkResult,
    BenchmarkSummaryPaths,
    MultiAgentBenchmarkSummary,
)


def parse_agent_list(agents: str) -> list[str]:
    parsed = [agent.strip() for agent in agents.split(",") if agent.strip()]
    if not parsed:
        raise ValueError("At least one agent must be provided with --agents.")
    return parsed


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _agent_summary(result: BenchmarkResult) -> AgentBenchmarkSummary:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    warning_checks = [
        check.name
        for check in result.check_results
        if not check.passed and check.severity == "warning"
    ]
    return AgentBenchmarkSummary(
        agent=result.agent,
        result=result.result,
        score=result.score,
        failed_checks=failed_checks,
        warning_checks=warning_checks,
        json_report_path=result.report_paths.json,
        markdown_report_path=result.report_paths.markdown,
        run_dir=result.run_dir,
    )


def _summary_dir(task_id: str, benchmarks_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return benchmarks_root / f"{task_id}-{timestamp}-{uuid4().hex[:8]}"


def _write_json_report(summary: MultiAgentBenchmarkSummary) -> Path:
    report_path = summary.report_paths.json
    atomic_write_json(report_path, asdict(summary), default=_json_default)
    return report_path


def _format_checks(checks: list[str]) -> str:
    return ", ".join(checks) if checks else "-"


def _write_markdown_report(summary: MultiAgentBenchmarkSummary) -> Path:
    report_path = summary.report_paths.markdown
    lines = [
        "# AgentGuard Benchmark Summary",
        "",
        f"Task: {summary.task_id}",
        f"Config: {summary.config_path}",
        f"Agents: {summary.total_agents}",
        f"Passed: {summary.pass_count}",
        f"Failed: {summary.fail_count}",
        "",
        "| Agent | Result | Score | Failed Checks | Warnings |",
        "|---|---|---:|---|---|",
    ]
    for agent in summary.agents:
        lines.append(
            f"| {agent.agent} | {agent.result} | {agent.score} | "
            f"{_format_checks(agent.failed_checks)} | "
            f"{_format_checks(agent.warning_checks)} |"
        )

    lines.extend(["", "## Individual Reports"])
    for agent in summary.agents:
        lines.append(f"- {agent.agent}:")
        lines.append(f"  - Run directory: {agent.run_dir}")
        lines.append(f"  - JSON: {agent.json_report_path}")
        lines.append(f"  - Markdown: {agent.markdown_report_path}")

    atomic_write_text(report_path, "\n".join(lines) + "\n")
    return report_path


def write_benchmark_reports(summary: MultiAgentBenchmarkSummary) -> BenchmarkSummaryPaths:
    json_path = _write_json_report(summary)
    markdown_path = _write_markdown_report(summary)
    return BenchmarkSummaryPaths(json=json_path, markdown=markdown_path)


def run_multi_agent_benchmark(
    config_path: Path,
    agent_names: list[str],
    benchmarks_root: Path = Path(".agentguard/benchmarks"),
) -> MultiAgentBenchmarkSummary:
    if not agent_names:
        raise ValueError("At least one agent must be provided.")

    results = [run_benchmark(config_path, agent_name) for agent_name in agent_names]
    task_id = results[0].task_id
    summary_dir = _summary_dir(task_id, benchmarks_root)
    report_paths = BenchmarkSummaryPaths(
        json=summary_dir / "benchmark.json",
        markdown=summary_dir / "benchmark.md",
    )
    agents = [_agent_summary(result) for result in results]
    summary = MultiAgentBenchmarkSummary(
        task_id=task_id,
        config_path=results[0].config_path,
        total_agents=len(agents),
        pass_count=sum(1 for agent in agents if agent.result == "PASS"),
        fail_count=sum(1 for agent in agents if agent.result == "FAIL"),
        agents=agents,
        report_paths=report_paths,
    )
    written_paths = write_benchmark_reports(summary)
    return MultiAgentBenchmarkSummary(
        task_id=summary.task_id,
        config_path=summary.config_path,
        total_agents=summary.total_agents,
        pass_count=summary.pass_count,
        fail_count=summary.fail_count,
        agents=summary.agents,
        report_paths=written_paths,
    )
