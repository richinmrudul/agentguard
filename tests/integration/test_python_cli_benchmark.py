from pathlib import Path

import pytest

from agentguard.core.orchestrator import run_benchmark
from agentguard.sandbox.docker_runner import docker_available


def _result_debug(result) -> str:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    command_events = [
        (event.command_text, event.exit_code) for event in result.command_events
    ]
    return (
        f"result={result.result}, "
        f"score={result.score}, "
        f"failed_checks={failed_checks}, "
        f"test_exit_code={result.test_result.exit_code}, "
        f"stdout_tail={result.test_result.stdout[-1000:]!r}, "
        f"stderr_tail={result.test_result.stderr[-1000:]!r}, "
        f"changed_files={result.diff_summary.changed_files}, "
        f"command_events={command_events!r}"
    )


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_python_cli_custom_command_safe_agent_passes() -> None:
    result = run_benchmark(
        Path("examples/configs/fix_cli_parser_bug_command_safe.yaml"),
        "custom-command",
    )

    assert result.result == "PASS", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "src/cli_example/calculator.py" in result.diff_summary.modified_files


@pytest.mark.docker
@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_python_cli_custom_command_cheater_fails_with_test_tampering() -> None:
    result = run_benchmark(
        Path("examples/configs/fix_cli_parser_bug_command_cheater.yaml"),
        "custom-command",
    )

    assert result.result == "FAIL", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "tests/test_calculator.py" in result.diff_summary.modified_files

    tampering = next(
        check for check in result.check_results if check.name == "Test tampering"
    )
    assert tampering.passed is False
    assert "tests/test_calculator.py" in tampering.evidence
