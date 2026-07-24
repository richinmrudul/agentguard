import json
import os
from pathlib import Path

from typer.testing import CliRunner

import agentguard.reports.browser as report_browser
from agentguard.cli.main import app
from agentguard.reports.browser import (
    discover_reports,
    format_report_summary,
    latest_report,
)


runner = CliRunner()


def test_no_reports_found(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    assert discover_reports() == []


def test_discovers_run_suite_matrix_and_ci_reports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "fix_auth_bug-1", mtime=100)
    _write_suite_report(tmp_path, "core-1", mtime=200)
    _write_matrix_report(tmp_path, "core-matrix-1", mtime=250)
    _write_ci_report(tmp_path, "pr_safety_check-1", mtime=300)

    reports = discover_reports()

    assert [report.type for report in reports] == ["ci", "matrix", "suite", "run"]
    assert {report.name for report in reports} == {
        "fix_auth_bug",
        "core",
        "pr_safety_check",
    }


def test_type_filter_works(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "fix_auth_bug-1")
    _write_suite_report(tmp_path, "core-1")

    reports = discover_reports(report_type="suite")

    assert len(reports) == 1
    assert reports[0].type == "suite"
    assert reports[0].name == "core"


def test_matrix_type_filter_and_summary_include_matrix_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_matrix_report(tmp_path, "core-matrix-1")

    report = discover_reports(report_type="matrix")[0]
    summary = format_report_summary(report)
    listed = runner.invoke(app, ["reports", "list", "--type", "matrix"])

    assert report.type == "matrix"
    assert report.name == "core"
    assert report.result == "FAIL"
    assert report.score == 75
    assert "AgentGuard Matrix Report" in summary
    assert "Agents: mock-safe, mock-test-cheater" in summary
    assert "Trials per combination: 3" in summary
    assert "Workers: 2 effective / 4 requested" in summary
    assert "Attempts: 5 executed / 6 planned" in summary
    assert "Reliability success rate: 50.0%" in summary
    assert "Guard incidents: 2 runs / 1 blocked / 3 violations" in summary
    assert "Reliability baseline: REGRESSION" in summary
    assert listed.exit_code == 0
    assert "matrix | core-matrix-1 | core | FAIL | 75" in listed.output


def test_limit_works_through_cli(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "old", mtime=100)
    _write_run_report(tmp_path, "new", task_id="new_task", mtime=200)

    result = runner.invoke(app, ["reports", "list", "--limit", "1"])

    assert result.exit_code == 0
    assert "new_task" in result.output
    assert "fix_auth_bug" not in result.output


def test_limit_bounds_full_report_parsing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    for index in range(50):
        _write_run_report(tmp_path, f"run-{index}", mtime=index + 1)
    parsed = 0
    original = report_browser._load_report_item

    def counting_loader(path, report_type, root):
        nonlocal parsed
        parsed += 1
        return original(path, report_type, root)

    monkeypatch.setattr(report_browser, "_load_report_item", counting_loader)

    reports = discover_reports(limit=3)

    assert parsed == 3
    assert [report.id for report in reports] == ["run-49", "run-48", "run-47"]


def test_oversized_reports_are_skipped_and_show_fails_cleanly(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(report_browser, "MAX_REPORT_BYTES", 32)
    report_path = _write_run_report(tmp_path, "oversized")

    assert discover_reports() == []

    result = runner.invoke(app, ["reports", "show", str(report_path)])

    assert result.exit_code == 2
    assert "report exceeds the 32-byte read limit" in result.output
    assert "Traceback" not in result.output


def test_invalid_json_is_skipped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "valid")
    invalid_path = tmp_path / ".agentguard/runs/bad/reports/report.json"
    invalid_path.parent.mkdir(parents=True)
    invalid_path.write_text("{not json", encoding="utf-8")

    reports = discover_reports()

    assert len(reports) == 1
    assert reports[0].id == "valid"


def test_non_object_report_is_skipped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / ".agentguard/runs/list/reports/report.json"
    _write_json(path, ["not", "an", "object"], 100)

    assert discover_reports() == []


def test_latest_selects_newest_report(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "old", mtime=100)
    _write_ci_report(tmp_path, "new", task_id="new_task", mtime=200)

    report = latest_report()

    assert report is not None
    assert report.type == "ci"
    assert report.name == "new_task"


def test_show_run_summary_includes_task_result_and_score(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "fix_auth_bug-1")
    report = discover_reports(report_type="run")[0]

    summary = format_report_summary(report)

    assert "Task: fix_auth_bug" in summary
    assert "Result: PASS" in summary
    assert "Score: 100/100" in summary


def test_show_suite_summary_includes_suite_and_pass_rate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_suite_report(tmp_path, "core-1")
    report = discover_reports(report_type="suite")[0]

    summary = format_report_summary(report)

    assert "Suite: core" in summary
    assert "Pass rate: 50.0%" in summary


def test_show_latest_with_type_suite_works(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, "new-run", task_id="new_task", mtime=200)
    _write_suite_report(tmp_path, "old-suite", mtime=100)

    report = latest_report(report_type="suite")

    assert report is not None
    assert report.type == "suite"
    assert report.name == "core"


def test_cli_reports_list_exits_zero_with_no_reports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["reports", "list"])

    assert result.exit_code == 0
    assert "No reports found." in result.output


def test_cli_invalid_limit_exits_two(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["reports", "list", "--limit", "0"])

    assert result.exit_code == 2
    assert "limit must be positive" in result.output


def test_cli_invalid_report_type_exits_two_without_traceback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["reports", "list", "--type", "unknown"])

    assert result.exit_code == 2
    assert "report type must be one of: ci, matrix, run" in result.output
    assert "suite." in result.output
    assert "Traceback" not in result.output


def test_cli_show_rejects_conflicting_or_missing_selector(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_run_report(tmp_path, "run")

    conflicting = runner.invoke(
        app,
        ["reports", "show", str(report_path), "--latest"],
    )
    missing = runner.invoke(app, ["reports", "show"])

    assert conflicting.exit_code == 2
    assert "not both" in conflicting.output
    assert missing.exit_code == 2
    assert "provide a report path or use --latest" in missing.output


def test_cli_show_invalid_report_exits_two_without_traceback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "invalid.json"
    path.write_text("{invalid", encoding="utf-8")

    result = runner.invoke(app, ["reports", "show", str(path)])

    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "Traceback" not in result.output


def test_cli_show_latest_with_no_reports_exits_nonzero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["reports", "show", "--latest"])

    assert result.exit_code == 1
    assert "No reports found." in result.output


def test_cli_show_path_prints_summary(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_run_report(tmp_path, "fix_auth_bug-1")

    result = runner.invoke(app, ["reports", "show", str(report_path)])

    assert result.exit_code == 0
    assert "AgentGuard Run Report" in result.output
    assert "Task: fix_auth_bug" in result.output


def test_cli_show_matrix_path_prints_matrix_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report_path = _write_matrix_report(tmp_path, "core-matrix-1")

    result = runner.invoke(app, ["reports", "show", str(report_path)])

    assert result.exit_code == 0
    assert "AgentGuard Matrix Report" in result.output
    assert "Matrix: matrix-core-1" in result.output


def _write_run_report(
    tmp_path: Path,
    run_id: str,
    task_id: str = "fix_auth_bug",
    mtime: int = 100,
) -> Path:
    path = tmp_path / ".agentguard/runs" / run_id / "reports/report.json"
    data = {
        "task_id": task_id,
        "agent": "mock-safe",
        "result": "PASS",
        "score": 100,
        "diff_summary": {
            "modified_files": ["src/login.py"],
            "added_files": [],
            "deleted_files": [],
        },
        "check_results": [
            {"name": "Tests passed", "passed": True, "severity": "error"}
        ],
        "report_paths": {
            "json": str(path),
            "markdown": str(path.with_suffix(".md")),
        },
    }
    return _write_json(path, data, mtime)


def _write_suite_report(
    tmp_path: Path,
    suite_id: str,
    mtime: int = 100,
) -> Path:
    path = tmp_path / ".agentguard/suites" / suite_id / "suite.json"
    data = {
        "suite_id": "core",
        "total_runs": 2,
        "passed": 1,
        "failed": 1,
        "pass_rate": 50.0,
        "average_score": 65,
        "filters": {"category": "prompt_injection"},
        "failed_check_counts": {"Forbidden paths": 1},
        "runs": [],
        "json_report_path": str(path),
        "markdown_report_path": str(path.with_suffix(".md")),
    }
    return _write_json(path, data, mtime)


def _write_matrix_report(
    tmp_path: Path,
    matrix_id: str,
    mtime: int = 100,
) -> Path:
    path = tmp_path / ".agentguard/matrices" / matrix_id / "matrix.json"
    data = {
        "matrix_id": "matrix-core-1",
        "suite_id": "core",
        "agents": ["mock-safe", "mock-test-cheater"],
        "trials": 3,
        "requested_workers": 4,
        "effective_workers": 2,
        "attempts_planned": 6,
        "attempts_executed": 5,
        "passed": 3,
        "failed": 2,
        "pass_rate": 60.0,
        "average_score": 75,
        "reliability": {"success_rate": 50.0},
        "guard_mode": "audit",
        "guard_summary": {
            "incident_runs": 2,
            "blocked_runs": 1,
            "violations_total": 3,
        },
        "reliability_comparison": {"has_regressions": True},
        "failed_check_counts": {"Test tampering": 2},
        "runs": [],
        "json_report_path": str(path),
        "markdown_report_path": str(path.with_suffix(".md")),
    }
    return _write_json(path, data, mtime)


def _write_ci_report(
    tmp_path: Path,
    ci_id: str,
    task_id: str = "pr_safety_check",
    mtime: int = 100,
) -> Path:
    path = tmp_path / ".agentguard/ci" / ci_id / "report.json"
    data = {
        "task_id": task_id,
        "result": "PASS",
        "score": 80,
        "diff_summary": {
            "modified_files": ["README.md"],
            "added_files": ["src/new.py"],
            "deleted_files": [],
        },
        "check_results": [
            {"name": "Scope adherence", "passed": True, "severity": "warning"}
        ],
        "report_paths": {
            "json": str(path),
            "markdown": str(path.with_suffix(".md")),
        },
        "repo_dir": str(tmp_path),
    }
    return _write_json(path, data, mtime)


def _write_json(path: Path, data: object, mtime: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path
