from pathlib import Path
from typing import Optional

import pytest
import yaml
from typer.testing import CliRunner

import agentguard.cli.main as cli_main
from agentguard import __version__
from agentguard.cli.main import app
from agentguard.core.baseline import BaselineComparison
from agentguard.core.contained_run import (
    ContainedRunFailure,
    ContainedRunResult,
    EXIT_PREFLIGHT,
)
from agentguard.core.result import CommandResult, DiffSummary
from agentguard.core.suite import (
    SuiteResult,
    SuiteRunHeadline,
    SuiteRunSummary,
)

runner = CliRunner()


def _successful_contained_run_result(
    tmp_path: Path,
    config_path: Path,
    command: list[str],
    *,
    source_dir: Optional[Path] = None,
) -> ContainedRunResult:
    return ContainedRunResult(
        task_id="task",
        config_path=Path(config_path),
        source_dir=source_dir or Path("."),
        run_dir=tmp_path,
        command=list(command),
        docker_argv=["docker", "run"],
        preflight=None,
        command_result=CommandResult("contained-run", 0, "", "", 0.01),
        diff_summary=DiffSummary([], ["space name.txt"], [], 0, 0, ""),
        check_results=[],
        result="PASS",
        score=100,
        mutations={},
        cleanup_complete=True,
        report_path=tmp_path / "contained-run.json",
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["run", "missing.yaml", "--agent", "mock-safe"],
        ["ci", "--config", "missing.yaml"],
        ["benchmark", "missing.yaml", "--agents", "mock-safe"],
        ["suite", "missing.yaml"],
        ["matrix", "missing.yaml"],
        ["gate", "suite", "missing.yaml", "--baseline", "missing.json"],
    ],
)
def test_execution_commands_report_missing_inputs_as_invalid(
    tmp_path: Path,
    monkeypatch,
    arguments: list[str],
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "Traceback" not in result.output


def test_run_rejects_unknown_config_field_with_exit_code_2(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "task_id": "task",
                "description": "Task.",
                "repo_template": "examples/repos/auth_bug",
                "test_command": "pytest",
                "expected_modified_files": {"min": 0, "max": 2},
                "forbiden_paths": ["secrets/**"],
            }
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["run", str(config_path), "--agent", "mock-safe"],
    )

    assert result.exit_code == 2
    assert "Unknown config field 'forbiden_paths'" in result.output
    assert "Did you mean 'forbidden_paths'?" in result.output
    assert "Traceback" not in result.output


def test_version() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_version_option() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.output.strip() == __version__


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


def test_contained_run_requires_command_after_boundary() -> None:
    result = runner.invoke(app, ["contained-run", "agentguard.yaml"])

    assert result.exit_code == 2
    assert "requires an argv after '--'" in result.output
    assert "Traceback" not in result.output


def test_contained_run_rejects_command_without_boundary() -> None:
    result = runner.invoke(app, ["contained-run", "agentguard.yaml", "true"])

    assert result.exit_code == 2
    assert "requires an argv after '--'" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "arguments",
    [
        ["contained-run", "--help"],
        ["contained-run", "agentguard.yaml", "--help"],
    ],
)
def test_contained_run_help_before_boundary_shows_agentguard_help(
    monkeypatch,
    arguments: list[str],
) -> None:
    def fail_if_called(config_path, command, *, source_dir=None):
        raise AssertionError("contained-run implementation should not be called")

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fail_if_called)

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "Run one explicit argv" in result.output
    assert "Path to the AgentGuard config file" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("child_help", ["--help", "-h"])
def test_contained_run_preserves_child_help_flags_after_boundary(
    monkeypatch,
    tmp_path: Path,
    child_help: str,
) -> None:
    captured = {}

    def fake_contained_run(config_path, command, *, source_dir=None):
        captured["command"] = command
        return _successful_contained_run_result(
            tmp_path,
            config_path,
            command,
            source_dir=source_dir,
        )

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fake_contained_run)

    result = runner.invoke(
        app,
        ["contained-run", "agentguard.yaml", "--", child_help],
    )

    assert result.exit_code == 0
    assert captured["command"] == [child_help]
    assert "Usage:" not in result.output
    assert "AgentGuard Contained Run" in result.output


def test_contained_run_preserves_child_flags_ordering_and_dash_executable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    captured = {}

    def fake_contained_run(config_path, command, *, source_dir=None):
        captured["command"] = command
        return _successful_contained_run_result(
            tmp_path,
            config_path,
            command,
            source_dir=source_dir,
        )

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fake_contained_run)
    child_argv = [
        "-leading-executable",
        "--flag",
        "one",
        "--flag",
        "two",
        "--empty=",
        "--",
        "literal-boundary",
        "-h",
    ]

    result = runner.invoke(app, ["contained-run", "agentguard.yaml", "--", *child_argv])

    assert result.exit_code == 0
    assert captured["command"] == child_argv


def test_contained_run_preserves_no_shell_interpolation_string(
    monkeypatch,
    tmp_path: Path,
) -> None:
    captured = {}

    def fake_contained_run(config_path, command, *, source_dir=None):
        captured["command"] = command
        return _successful_contained_run_result(
            tmp_path,
            config_path,
            command,
            source_dir=source_dir,
        )

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fake_contained_run)
    shell_sensitive = 'printf "$HOME"; echo $(whoami); echo `id`; echo "semi;colon"'

    result = runner.invoke(
        app,
        ["contained-run", "agentguard.yaml", "--", "sh", "-c", shell_sensitive],
    )

    assert result.exit_code == 0
    assert captured["command"] == ["sh", "-c", shell_sensitive]


def test_contained_run_rejects_missing_executable_after_boundary() -> None:
    result = runner.invoke(app, ["contained-run", "agentguard.yaml", "--"])

    assert result.exit_code == 2
    assert "requires an argv after '--'" in result.output
    assert "Traceback" not in result.output


def test_contained_run_rejects_malformed_option_before_boundary(monkeypatch) -> None:
    def fail_if_called(config_path, command, *, source_dir=None):
        raise AssertionError("contained-run implementation should not be called")

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fail_if_called)

    result = runner.invoke(
        app,
        ["contained-run", "agentguard.yaml", "--bogus", "--", "true"],
    )

    assert result.exit_code == 2
    assert "--bogus" in result.output
    assert "Traceback" not in result.output


def test_contained_run_rejects_boundary_before_config_without_traceback() -> None:
    result = runner.invoke(app, ["contained-run", "--", "true"])

    assert result.exit_code == 2
    assert "Missing argument" in result.output
    assert "config_path" in result.output.lower()
    assert "Traceback" not in result.output


def test_contained_run_preserves_argv_after_boundary(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    def fake_contained_run(config_path, command, *, source_dir=None):
        captured["config_path"] = config_path
        captured["command"] = command
        captured["source_dir"] = source_dir
        return _successful_contained_run_result(
            tmp_path,
            config_path,
            command,
            source_dir=source_dir,
        )

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fake_contained_run)

    result = runner.invoke(
        app,
        [
            "contained-run",
            "agentguard.yaml",
            "--repo",
            str(tmp_path),
            "--",
            "python",
            "-c",
            "print('Δ shell; $HOME \"quoted\"')",
        ],
    )

    assert result.exit_code == 0
    assert captured["command"] == [
        "python",
        "-c",
        "print('Δ shell; $HOME \"quoted\"')",
    ]
    assert captured["source_dir"] == tmp_path
    assert "AgentGuard Contained Run" in result.output
    assert "space name.txt" in result.output


def test_contained_run_operational_failure_uses_controlled_exit(
    monkeypatch,
    tmp_path: Path,
) -> None:
    def fake_contained_run(config_path, command, *, source_dir=None):
        return ContainedRunResult(
            task_id="task",
            config_path=Path(config_path),
            source_dir=Path("."),
            run_dir=tmp_path,
            command=list(command),
            docker_argv=[],
            preflight=None,
            command_result=None,
            diff_summary=DiffSummary([], [], [], 0, 0, ""),
            check_results=[],
            result="FAIL",
            score=0,
            mutations={},
            cleanup_complete=True,
            failure=ContainedRunFailure(
                "preflight",
                EXIT_PREFLIGHT,
                "Docker unavailable.",
            ),
            report_path=tmp_path / "contained-run.json",
        )

    monkeypatch.setattr(cli_main, "run_contained_agent_command", fake_contained_run)

    result = runner.invoke(app, ["contained-run", "agentguard.yaml", "--", "true"])

    assert result.exit_code == EXIT_PREFLIGHT
    assert "Failure: preflight: Docker unavailable." in result.output
    assert "Traceback" not in result.output


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
