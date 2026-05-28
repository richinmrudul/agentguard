import json
from pathlib import Path

from agentguard.core.suite import (
    SuiteResult,
    SuiteRunHeadline,
    SuiteRunSummary,
    write_suite_reports,
)


def test_write_suite_reports_include_summary_and_paths(tmp_path: Path) -> None:
    result = SuiteResult(
        suite_id="core",
        description="Core suite.",
        suite_path=Path("examples/suites/core.yaml"),
        total_runs=2,
        passed=1,
        failed=1,
        pass_rate=50.0,
        average_score=80,
        best_run=SuiteRunHeadline(
            task_id="fix_auth_bug",
            agent="mock-safe",
            result="PASS",
            score=100,
        ),
        worst_run=SuiteRunHeadline(
            task_id="fix_cli_parser_bug",
            agent="mock-test-cheater",
            result="FAIL",
            score=60,
        ),
        failed_check_counts={"Test tampering": 1, "Scope adherence": 1},
        warning_check_counts={"Scope adherence": 1},
        result_counts={"PASS": 1, "FAIL": 1},
        runs=[
            SuiteRunSummary(
                task_id="fix_auth_bug",
                config_path=Path("examples/configs/fix_auth_bug.yaml"),
                agent="mock-safe",
                result="PASS",
                score=100,
                benchmark_id="auth_bug_safe",
                category="source_fix",
                difficulty="easy",
                tags=["docker", "python", "source-fix"],
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
                benchmark_id="cli_parser_cheater",
                category="test_tampering",
                difficulty="medium",
                tags=["docker", "python", "test-tampering"],
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
    assert data["pass_rate"] == 50.0
    assert data["best_run"] == {
        "task_id": "fix_auth_bug",
        "agent": "mock-safe",
        "result": "PASS",
        "score": 100,
    }
    assert data["worst_run"] == {
        "task_id": "fix_cli_parser_bug",
        "agent": "mock-test-cheater",
        "result": "FAIL",
        "score": 60,
    }
    assert data["failed_check_counts"] == {
        "Test tampering": 1,
        "Scope adherence": 1,
    }
    assert data["runs"][0]["benchmark_id"] == "auth_bug_safe"
    assert data["runs"][0]["category"] == "source_fix"
    assert data["runs"][0]["difficulty"] == "easy"
    assert data["runs"][0]["tags"] == ["docker", "python", "source-fix"]
    assert "# AgentGuard Suite Summary" in markdown
    assert "## Summary" in markdown
    assert "Suite: core" in markdown
    assert "Passed: 1" in markdown
    assert "Failed: 1" in markdown
    assert "Pass rate: 50.0%" in markdown
    assert "Best run: fix_auth_bug / mock-safe / PASS / 100" in markdown
    assert (
        "Worst run: fix_cli_parser_bug / mock-test-cheater / FAIL / 60"
        in markdown
    )
    assert "## Failed Check Counts" in markdown
    assert "- Test tampering: 1" in markdown
    assert "## Warning Check Counts" in markdown
    assert "- Scope adherence: 1" in markdown
    assert "| Task | Category | Difficulty | Agent | Result | Score |" in markdown
    assert "| fix_auth_bug | source_fix | easy | mock-safe | PASS | 100 |" in markdown
    assert (
        "| fix_cli_parser_bug | test_tampering | medium | "
        "mock-test-cheater | FAIL | 60 |" in markdown
    )
    assert "fix_auth_bug" in markdown
    assert "fix_cli_parser_bug" in markdown
    assert "runs/safe/reports/report.json" in markdown
    assert "runs/cheater/reports/report.md" in markdown
