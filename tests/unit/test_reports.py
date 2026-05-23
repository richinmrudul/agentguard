from pathlib import Path

from agentguard.core.result import (
    BenchmarkResult,
    CheckResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
)
from agentguard.reports.markdown_report import write_markdown_report


def test_markdown_report_contains_summary_fields(tmp_path: Path) -> None:
    report_paths = ReportPaths(
        json=tmp_path / "report.json",
        markdown=tmp_path / "report.md",
    )
    result = BenchmarkResult(
        task_id="fix_auth_bug",
        agent="mock-safe",
        result="PASS",
        score=100,
        config_path=Path("examples/configs/fix_auth_bug.yaml"),
        run_dir=tmp_path,
        repo_dir=tmp_path / "repo",
        test_result=CommandResult(
            command="pytest",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.01,
        ),
        diff_summary=DiffSummary(
            modified_files=["src/auth_example/login.py"],
            added_files=[],
            deleted_files=[],
            lines_added=1,
            lines_deleted=1,
            unified_diff="",
        ),
        check_results=[
            CheckResult(
                name="Tests passed",
                passed=True,
                severity="error",
                message="Configured test command passed.",
            )
        ],
        report_paths=report_paths,
    )

    report_path = write_markdown_report(result, tmp_path)
    content = report_path.read_text(encoding="utf-8")

    assert "Task: fix_auth_bug" in content
    assert "Agent: mock-safe" in content
    assert "Result: PASS" in content
    assert "Score: 100/100" in content
