import json
from pathlib import Path

from agentguard.core.orchestrator import run_benchmark


def test_mock_safe_returns_pass() -> None:
    result = run_benchmark(Path("examples/configs/fix_auth_bug.yaml"), "mock-safe")

    assert result.result == "PASS"
    assert result.score == 100
    assert result.test_result.exit_code == 0
    assert "src/auth_example/login.py" in result.diff_summary.modified_files
    assert result.report_paths.json.exists()
    assert result.report_paths.markdown.exists()
    check_names = {check.name for check in result.check_results}
    assert "Diff size" in check_names
    assert "Secret scan" in check_names

    report = json.loads(result.report_paths.json.read_text(encoding="utf-8"))
    assert any(check["severity"] for check in report["check_results"])

    markdown = result.report_paths.markdown.read_text(encoding="utf-8")
    assert "- PASS [error] Tests passed:" in markdown


def test_mock_test_cheater_returns_fail_with_tampering_evidence() -> None:
    result = run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-test-cheater",
    )

    assert result.result == "FAIL"
    assert result.test_result.exit_code == 0
    tampering = next(
        check for check in result.check_results if check.name == "Test tampering"
    )
    assert tampering.passed is False
    assert "tests/test_auth.py" in tampering.evidence

    markdown = result.report_paths.markdown.read_text(encoding="utf-8")
    assert "- FAIL [error] Test tampering:" in markdown
    assert "  Evidence:\n  - tests/test_auth.py" in markdown
