from pathlib import Path

from typer.testing import CliRunner

import agentguard.cli.main as cli_main
from agentguard import __version__
from agentguard.cli.main import app
from agentguard.core.baseline import BaselineComparison
from agentguard.core.suite import (
    SuiteResult,
    SuiteRunHeadline,
    SuiteRunSummary,
)

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_run_mock_safe_exits_zero() -> None:
    config_path = "examples/configs/fix_auth_bug.yaml"
    agent_name = "mock-safe"

    result = runner.invoke(app, ["run", config_path, "--agent", agent_name])

    assert result.exit_code == 0
    assert "AgentGuard Report" in result.output
    assert "Task: fix_auth_bug" in result.output
    assert agent_name in result.output
    assert "Result: PASS" in result.output
    assert "JSON report path:" in result.output
    assert "Markdown report path:" in result.output


def test_run_mock_test_cheater_exits_nonzero_by_default() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "examples/configs/fix_auth_bug.yaml",
            "--agent",
            "mock-test-cheater",
        ],
    )

    assert result.exit_code != 0
    assert "Result: FAIL" in result.output


def test_run_mock_test_cheater_exits_zero_with_allow_fail_result() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "examples/configs/fix_auth_bug.yaml",
            "--agent",
            "mock-test-cheater",
            "--allow-fail-result",
        ],
    )

    assert result.exit_code == 0
    assert "Result: FAIL" in result.output


def test_run_custom_command_without_agent_command_fails_clearly() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "examples/configs/fix_auth_bug_docker.yaml",
            "--agent",
            "custom-command",
        ],
    )

    assert result.exit_code == 2
    assert "requires config field 'agent_command'" in result.output


def test_run_local_command_without_agent_command_fails_clearly() -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "examples/configs/fix_auth_bug.yaml",
            "--agent",
            "local-command",
        ],
    )

    assert result.exit_code == 2
    assert (
        "Agent 'local-command' requires config field 'agent_command'" in result.output
    )


def test_benchmark_mock_safe_exits_zero() -> None:
    result = runner.invoke(
        app,
        [
            "benchmark",
            "examples/configs/fix_auth_bug.yaml",
            "--agents",
            "mock-safe",
        ],
    )

    assert result.exit_code == 0
    assert "AgentGuard Benchmark Summary" in result.output
    assert "Failed: 0" in result.output


def test_benchmark_with_failure_exits_nonzero_by_default() -> None:
    result = runner.invoke(
        app,
        [
            "benchmark",
            "examples/configs/fix_auth_bug.yaml",
            "--agents",
            "mock-safe,mock-test-cheater",
        ],
    )

    assert result.exit_code != 0
    assert "Failed: 1" in result.output


def test_benchmark_with_failure_exits_zero_with_allow_failures() -> None:
    result = runner.invoke(
        app,
        [
            "benchmark",
            "examples/configs/fix_auth_bug.yaml",
            "--agents",
            "mock-safe,mock-test-cheater",
            "--allow-failures",
        ],
    )

    assert result.exit_code == 0
    assert "Failed: 1" in result.output


def test_suite_allow_version_mismatch_passes_flag_and_prints_details(
    monkeypatch,
    tmp_path: Path,
) -> None:
    captured = {}

    def fake_run_suite(*args, **kwargs):
        captured["allow_version_mismatch"] = kwargs["allow_version_mismatch"]
        return SuiteResult(
            suite_id="core",
            description="Core suite.",
            suite_path=Path("suite.yaml"),
            total_runs=1,
            passed=1,
            failed=0,
            pass_rate=100.0,
            average_score=100,
            best_run=SuiteRunHeadline(
                task_id="fix_auth_bug",
                agent="mock-safe",
                result="PASS",
                score=100,
            ),
            worst_run=SuiteRunHeadline(
                task_id="fix_auth_bug",
                agent="mock-safe",
                result="PASS",
                score=100,
            ),
            failed_check_counts={},
            warning_check_counts={},
            result_counts={"PASS": 1},
            runs=[
                SuiteRunSummary(
                    task_id="fix_auth_bug",
                    config_path=Path("config.yaml"),
                    agent="mock-safe",
                    result="PASS",
                    score=100,
                    failed_checks=[],
                    warning_checks=[],
                    json_report_path=Path("report.json"),
                    markdown_report_path=Path("report.md"),
                    run_dir=Path("run"),
                )
            ],
            json_report_path=tmp_path / "suite.json",
            markdown_report_path=tmp_path / "suite.md",
            baseline_comparison=BaselineComparison(
                baseline_path="baseline.json",
                has_regressions=False,
                regressions=[],
                improvements=[],
                unchanged_count=0,
                version_mismatches=[
                    "Benchmark version mismatch for fix_auth_bug/mock-safe "
                    "(auth_bug): baseline 1 -> current 2"
                ],
            ),
        )

    monkeypatch.setattr(cli_main, "run_suite", fake_run_suite)

    result = runner.invoke(
        app,
        [
            "suite",
            "suite.yaml",
            "--compare-baseline",
            "baseline.json",
            "--allow-version-mismatch",
        ],
    )

    assert result.exit_code == 0
    assert captured["allow_version_mismatch"] is True
    assert "Benchmark version mismatches:" in result.output
    assert "baseline 1 -> current 2" in result.output
