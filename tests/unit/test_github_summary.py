from pathlib import Path

from agentguard.core.result import (
    CheckResult,
    CiResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
)
from agentguard.reports.github_summary import write_github_step_summary


def _ci_result(tmp_path: Path) -> CiResult:
    return CiResult(
        task_id="pr_safety_check",
        result="FAIL",
        score=40,
        config_path=Path("agentguard.yaml"),
        run_dir=tmp_path,
        repo_dir=tmp_path / "repo",
        test_result=CommandResult(
            command="pytest",
            exit_code=1,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        ),
        diff_summary=DiffSummary(
            modified_files=["src/app.py"],
            added_files=["src/new.py"],
            deleted_files=["src/old.py"],
            lines_added=3,
            lines_deleted=2,
            unified_diff="",
        ),
        check_results=[
            CheckResult(
                name="Tests passed",
                passed=False,
                severity="error",
                message="Configured test command failed.",
            ),
            CheckResult(
                name="Test tampering",
                passed=False,
                severity="warning",
                message="Modified test files: tests/test_app.py",
            ),
            CheckResult(
                name="Secret scan",
                passed=True,
                severity="critical",
                message="No path-based secret patterns appeared in the diff.",
            ),
        ],
        report_paths=ReportPaths(
            json=tmp_path / "report.json",
            markdown=tmp_path / "report.md",
            command_log=tmp_path / "command_log.json",
        ),
    )


def test_github_step_summary_appends_compact_markdown(tmp_path: Path) -> None:
    summary_path = tmp_path / "summary.md"
    summary_path.write_text("Existing content\n", encoding="utf-8")

    written_path = write_github_step_summary(_ci_result(tmp_path), summary_path)

    assert written_path == summary_path
    content = summary_path.read_text(encoding="utf-8")
    assert content.startswith("Existing content\n")
    assert "## AgentGuard CI Report" in content
    assert "- Task: `pr_safety_check`" in content
    assert "- Result: **FAIL**" in content
    assert "- Score: **40/100**" in content
    assert "- [error] Tests passed: Configured test command failed." in content
    assert "- [warning] Test tampering: Modified test files: tests/test_app.py" in content
    assert "- Modified: 1" in content
    assert "  - `src/app.py`" in content
    assert "- Added: 1" in content
    assert "- Deleted: 1" in content
    assert f"- Command log: `{tmp_path / 'command_log.json'}`" in content


def test_github_step_summary_escapes_inline_code_and_report_fields(
    tmp_path: Path,
) -> None:
    result = _ci_result(tmp_path)
    result = CiResult(
        **{
            **result.__dict__,
            "task_id": "task`code`\n## forged",
            "diff_summary": DiffSummary(
                modified_files=["src/a`b|c.py\n- forged"],
                added_files=[],
                deleted_files=[],
                lines_added=0,
                lines_deleted=0,
                unified_diff="",
            ),
            "check_results": [
                CheckResult(
                    name="Check <details>",
                    passed=False,
                    severity="error",
                    message="message\n> forged",
                    evidence=[],
                )
            ],
        }
    )

    summary = write_github_step_summary(
        result, tmp_path / "summary.md"
    ).read_text(encoding="utf-8")

    assert "- Task: ``task`code`\\n## forged``" in summary
    assert "\n## forged" not in summary
    assert "<details>" not in summary
    assert "&lt;details>" in summary
    assert "src/a`b|c.py\\n- forged" in summary
