import json
from pathlib import Path

from agentguard.core.suite import SuiteResult, SuiteRunSummary, write_suite_reports


def test_write_suite_reports_include_summary_and_paths(tmp_path: Path) -> None:
    result = SuiteResult(
        suite_id="core",
        description="Core suite.",
        suite_path=Path("examples/suites/core.yaml"),
        total_runs=2,
        passed=1,
        failed=1,
        average_score=80,
        runs=[
            SuiteRunSummary(
                task_id="fix_auth_bug",
                config_path=Path("examples/configs/fix_auth_bug.yaml"),
                agent="mock-safe",
                result="PASS",
                score=100,
                failed_checks=[],
                warning_checks=[],
                json_report_path=Path("runs/safe/reports/report.json"),
                markdown_report_path=Path("runs/safe/reports/report.md"),
                run_dir=Path("runs/safe"),
            ),
            SuiteRunSummary(
                task_id="fix_cli_parser_bug",
                config_path=Path("examples/configs/fix_cli_parser_bug.yaml"),
                agent="mock-test-cheater",
                result="FAIL",
                score=60,
                failed_checks=["Test tampering", "Scope adherence"],
                warning_checks=["Scope adherence"],
                json_report_path=Path("runs/cheater/reports/report.json"),
                markdown_report_path=Path("runs/cheater/reports/report.md"),
                run_dir=Path("runs/cheater"),
            ),
        ],
        json_report_path=tmp_path / "suite.json",
        markdown_report_path=tmp_path / "suite.md",
    )

    written = write_suite_reports(result)
    data = json.loads(written.json_report_path.read_text(encoding="utf-8"))
    markdown = written.markdown_report_path.read_text(encoding="utf-8")

    assert data["suite_id"] == "core"
    assert data["passed"] == 1
    assert data["failed"] == 1
    assert "# AgentGuard Suite Summary" in markdown
    assert "Suite: core" in markdown
    assert "Passed: 1" in markdown
    assert "Failed: 1" in markdown
    assert "fix_auth_bug" in markdown
    assert "fix_cli_parser_bug" in markdown
    assert "runs/safe/reports/report.json" in markdown
    assert "runs/cheater/reports/report.md" in markdown
