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
        f"command_events={command_events!r}"
    )


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_docker_custom_command_safe_agent_passes() -> None:
    result = run_benchmark(
        Path("examples/configs/fix_auth_bug_docker_command_safe.yaml"),
        "custom-command",
    )

    assert result.result == "PASS", _result_debug(result)
    assert "docker agent: python agent_scripts/safe_agent.py" in [
        event.command_text for event in result.command_events
    ]


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_docker_custom_command_cheater_fails_with_test_tampering() -> None:
    result = run_benchmark(
        Path("examples/configs/fix_auth_bug_docker_command_cheater.yaml"),
        "custom-command",
    )

    assert result.result == "FAIL", _result_debug(result)
    tampering = next(
        check for check in result.check_results if check.name == "Test tampering"
    )
    assert tampering.passed is False
    assert "tests/test_auth.py" in tampering.evidence
    assert "docker agent: python agent_scripts/test_cheater_agent.py" in [
        event.command_text for event in result.command_events
    ]
