from pathlib import Path

from agentguard.agents.mock_agent import get_agent
from agentguard.checks.base import Check
from agentguard.checks.diff_size import DiffSizeCheck
from agentguard.checks.forbidden_paths import ForbiddenPathsCheck
from agentguard.checks.secret_scan import SecretScanCheck
from agentguard.checks.scope_adherence import ScopeAdherenceCheck
from agentguard.checks.test_tampering import TestTamperingCheck
from agentguard.checks.tests_pass import TestsPassCheck
from agentguard.checks.unsafe_commands import UnsafeCommandsCheck
from agentguard.config.loader import load_config
from agentguard.core.result import BenchmarkResult, ReportPaths
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner
from agentguard.repo.git_diff import collect_diff
from agentguard.repo.manager import RepoManager
from agentguard.reports.json_report import write_json_report
from agentguard.reports.markdown_report import write_markdown_report
from agentguard.scoring.scorer import score_checks


def default_checks() -> list[Check]:
    return [
        TestsPassCheck(),
        ForbiddenPathsCheck(),
        TestTamperingCheck(),
        UnsafeCommandsCheck(),
        ScopeAdherenceCheck(),
        DiffSizeCheck(),
        SecretScanCheck(),
    ]


def run_benchmark(config_path: Path, agent_name: str) -> BenchmarkResult:
    config = load_config(config_path)
    prepared = RepoManager().prepare(config, agent_name)
    command_tracker = CommandTracker()

    agent = get_agent(agent_name)
    agent.run(prepared.repo_dir)

    test_result = TestRunner(command_tracker).run(prepared.repo_dir, config.test_command)
    diff_summary = collect_diff(prepared.repo_dir)
    check_results = [
        check.run(config, test_result, diff_summary, command_tracker.commands)
        for check in default_checks()
    ]
    score_result = score_checks(check_results)

    reports_dir = prepared.run_dir / "reports"
    partial_result = BenchmarkResult(
        task_id=config.task_id,
        agent=agent_name,
        result=score_result.result,
        score=score_result.score,
        config_path=config.config_path,
        run_dir=prepared.run_dir,
        repo_dir=prepared.repo_dir,
        test_result=test_result,
        diff_summary=diff_summary,
        check_results=check_results,
        report_paths=ReportPaths(
            json=reports_dir / "report.json",
            markdown=reports_dir / "report.md",
        ),
    )
    json_path = write_json_report(partial_result, reports_dir)
    markdown_path = write_markdown_report(partial_result, reports_dir)

    return BenchmarkResult(
        task_id=partial_result.task_id,
        agent=partial_result.agent,
        result=partial_result.result,
        score=partial_result.score,
        config_path=partial_result.config_path,
        run_dir=partial_result.run_dir,
        repo_dir=partial_result.repo_dir,
        test_result=partial_result.test_result,
        diff_summary=partial_result.diff_summary,
        check_results=partial_result.check_results,
        report_paths=ReportPaths(json=json_path, markdown=markdown_path),
    )
