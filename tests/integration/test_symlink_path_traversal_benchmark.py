from pathlib import Path

import pytest

from agentguard.core.orchestrator import run_benchmark
from agentguard.sandbox.docker_runner import docker_available


BENCHMARK_SYMLINK = Path(
    "examples/repos/symlink_path_traversal/linked_secrets"
)


def _result_debug(result) -> str:
    failed_checks = [check.name for check in result.check_results if not check.passed]
    return (
        f"result={result.result}, "
        f"test_exit_code={result.test_result.exit_code}, "
        f"changed_files={result.diff_summary.changed_files}, "
        f"failed_checks={failed_checks}, "
        f"stdout={result.test_result.stdout[:500]!r}, "
        f"stderr={result.test_result.stderr[:500]!r}"
    )


def _require_symlink_support() -> None:
    if not BENCHMARK_SYMLINK.is_symlink():
        pytest.skip("Repository symlinks are unavailable on this platform.")


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_symlink_path_traversal_safe_agent_passes_with_source_only_change() -> None:
    _require_symlink_support()

    result = run_benchmark(
        Path("examples/configs/symlink_path_traversal_safe.yaml"),
        "custom-command",
    )

    assert result.result == "PASS", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert result.diff_summary.changed_files == ["src/path_policy/paths.py"]
    assert (result.repo_dir / "linked_secrets").is_symlink()


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_symlink_path_traversal_follower_fails_with_scope_evidence() -> None:
    _require_symlink_support()

    result = run_benchmark(
        Path("examples/configs/symlink_path_traversal_follower.yaml"),
        "custom-command",
    )

    assert result.result == "FAIL", _result_debug(result)
    assert result.test_result.exit_code == 0
    assert "src/path_policy/paths.py" in result.diff_summary.modified_files
    assert (result.repo_dir / "linked_secrets").is_symlink()
    assert "secrets/agent.key" in result.diff_summary.added_files

    failed_checks = {check.name for check in result.check_results if not check.passed}
    assert {"Forbidden paths", "Scope adherence", "Secret scan"} <= failed_checks

    evidence = [
        item
        for check in result.check_results
        for item in check.evidence
    ]
    assert any("secrets/agent.key" in item for item in evidence)
