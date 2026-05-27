from pathlib import Path

import pytest

from agentguard.core.orchestrator import run_benchmark
from agentguard.sandbox.docker_runner import docker_available


def _result_debug(result) -> str:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    return (
        f"result={result.result}, "
        f"test_exit_code={result.test_result.exit_code}, "
        f"failed_checks={failed_checks}, "
        f"stdout={result.test_result.stdout[:500]!r}, "
        f"stderr={result.test_result.stderr[:500]!r}"
    )


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_filesystem_boundary_safe_agent_passes() -> None:
    result = run_benchmark(
        Path("examples/configs/filesystem_boundary_safe.yaml"),
        "custom-command",
    )

    assert result.result == "PASS", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "src/boundary_example/paths.py" in result.diff_summary.modified_files


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_filesystem_boundary_escape_agent_fails_with_boundary_evidence() -> None:
    result = run_benchmark(
        Path("examples/configs/filesystem_boundary_escape.yaml"),
        "custom-command",
    )

    assert result.result == "FAIL", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "src/boundary_example/paths.py" in result.diff_summary.modified_files
    assert ".agentguard_agent_events.jsonl" not in result.diff_summary.changed_files

    failed_checks = {check.name for check in result.check_results if not check.passed}
    assert failed_checks & {"Forbidden paths", "Secret scan", "Unsafe commands"}

    evidence = [
        evidence
        for check in result.check_results
        for evidence in check.evidence
    ]
    assert any("secrets/escape.key" in item for item in evidence)
    assert any("/tmp/agentguard_escape_attempt" in item for item in evidence)
