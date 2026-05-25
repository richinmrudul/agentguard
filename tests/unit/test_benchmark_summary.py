import json
from pathlib import Path

import pytest

from agentguard.core.benchmark import parse_agent_list, write_benchmark_reports
from agentguard.core.result import (
    AgentBenchmarkSummary,
    BenchmarkSummaryPaths,
    MultiAgentBenchmarkSummary,
)


def test_parse_agent_list_trims_comma_separated_agents() -> None:
    assert parse_agent_list(" mock-safe, mock-test-cheater ,mock-overbroad ") == [
        "mock-safe",
        "mock-test-cheater",
        "mock-overbroad",
    ]


def test_parse_agent_list_rejects_empty_list() -> None:
    with pytest.raises(ValueError, match="At least one agent"):
        parse_agent_list(" , ")


def test_write_benchmark_summary_reports(tmp_path: Path) -> None:
    summary = MultiAgentBenchmarkSummary(
        task_id="fix_auth_bug",
        config_path=Path("examples/configs/fix_auth_bug.yaml"),
        total_agents=2,
        pass_count=1,
        fail_count=1,
        agents=[
            AgentBenchmarkSummary(
                agent="mock-safe",
                result="PASS",
                score=100,
                failed_checks=[],
                warning_checks=[],
                json_report_path=Path("runs/mock-safe/reports/report.json"),
                markdown_report_path=Path("runs/mock-safe/reports/report.md"),
                run_dir=Path("runs/mock-safe"),
            ),
            AgentBenchmarkSummary(
                agent="mock-test-cheater",
                result="FAIL",
                score=60,
                failed_checks=["Test tampering", "Scope adherence"],
                warning_checks=["Scope adherence"],
                json_report_path=Path("runs/mock-test-cheater/reports/report.json"),
                markdown_report_path=Path("runs/mock-test-cheater/reports/report.md"),
                run_dir=Path("runs/mock-test-cheater"),
            ),
        ],
        report_paths=BenchmarkSummaryPaths(
            json=tmp_path / "benchmark.json",
            markdown=tmp_path / "benchmark.md",
        ),
    )

    paths = write_benchmark_reports(summary)
    data = json.loads(paths.json.read_text(encoding="utf-8"))
    markdown = paths.markdown.read_text(encoding="utf-8")

    assert data["task_id"] == "fix_auth_bug"
    assert data["total_agents"] == 2
    assert data["agents"][1]["failed_checks"] == [
        "Test tampering",
        "Scope adherence",
    ]
    assert "| Agent | Result | Score | Failed Checks | Warnings |" in markdown
    assert (
        "| mock-test-cheater | FAIL | 60 | "
        "Test tampering, Scope adherence | Scope adherence |"
    ) in markdown
