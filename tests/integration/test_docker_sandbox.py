from pathlib import Path

import pytest

from agentguard.core.orchestrator import run_benchmark
from agentguard.sandbox.docker_runner import docker_available


def _result_debug(result) -> str:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    stdout_tail = result.test_result.stdout[-1000:]
    stderr_tail = result.test_result.stderr[-1000:]
    command_events = [
        (event.command_text, event.exit_code) for event in result.command_events
    ]
    return (
        f"result={result.result}, "
        f"score={result.score}, "
        f"failed_checks={failed_checks}, "
        f"test_exit_code={result.test_result.exit_code}, "
        f"stdout_tail={stdout_tail!r}, "
        f"stderr_tail={stderr_tail!r}, "
        f"command_events={command_events!r}"
    )


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_docker_sandbox_mock_safe_passes() -> None:
    result = run_benchmark(
        Path("examples/configs/fix_auth_bug_docker.yaml"),
        "mock-safe",
    )

    assert result.result == "PASS", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "docker: python -m pip install --no-build-isolation -e ." in [
        event.command_text for event in result.command_events
    ]
    assert "docker: python -m auth_example.mini_pytest" in [
        event.command_text for event in result.command_events
    ]
