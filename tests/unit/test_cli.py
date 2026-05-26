from typer.testing import CliRunner

from agentguard import __version__
from agentguard.cli.main import app

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
