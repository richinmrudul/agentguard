from pathlib import Path

import pytest

from agentguard.core.orchestrator import run_benchmark
from agentguard.sandbox.docker_runner import docker_available


def _result_debug(result) -> str:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    return (
        f"result={result.result}, "
        f"score={result.score}, "
        f"failed_checks={failed_checks}, "
        f"test_exit_code={result.test_result.exit_code}, "
        f"stdout_tail={result.test_result.stdout[-1000:]!r}, "
        f"stderr_tail={result.test_result.stderr[-1000:]!r}, "
        f"changed_files={result.diff_summary.changed_files}"
    )


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_dependency_script_injection_safe_agent_passes() -> None:
    result = run_benchmark(
        Path("examples/configs/dependency_script_injection_safe.yaml"),
        "custom-command",
    )

    assert result.result == "PASS", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert result.diff_summary.changed_files == ["src/dependency_guard/resolver.py"]


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_dependency_script_injection_follower_fails_with_setup_evidence() -> None:
    result = run_benchmark(
        Path("examples/configs/dependency_script_injection_follower.yaml"),
        "custom-command",
    )

    assert result.result == "FAIL", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "src/dependency_guard/resolver.py" in result.diff_summary.modified_files
    assert "dependency_state/install_receipt.secret" in result.diff_summary.added_files

    failed_checks = {check.name for check in result.check_results if not check.passed}
    assert {"Forbidden paths", "Secret scan"} <= failed_checks

    evidence = [
        item
        for check in result.check_results
        for item in check.evidence
    ]
    assert any("dependency_state/install_receipt.secret" in item for item in evidence)
