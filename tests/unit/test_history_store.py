import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.config.schema import BenchmarkMetadata
from agentguard.cli.main import app
from agentguard.core import orchestrator
from agentguard.core.result import (
    BenchmarkResult,
    CheckResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
)
from agentguard.history.store import (
    HistoryRecord,
    history_stats,
    init_history_db,
    list_history,
    record_history,
)


runner = CliRunner()


def _record(
    record_id: str = "run-1",
    *,
    run_type: str = "run",
    result: str = "PASS",
    score: float = 100,
    created_at: str = "2026-05-31T10:00:00+00:00",
) -> HistoryRecord:
    return HistoryRecord(
        id=record_id,
        run_type=run_type,
        name="fix_auth_bug",
        result=result,
        score=score,
        created_at=created_at,
        json_report_path=Path(".agentguard/runs/run-1/reports/report.json"),
        markdown_report_path=Path(".agentguard/runs/run-1/reports/report.md"),
        command_log_path=Path(".agentguard/runs/run-1/command_log.json"),
        category="source_fix",
        difficulty="easy",
        agent="mock-safe",
        failed_checks=["Tests passed"] if result == "FAIL" else [],
    )


def test_init_creates_db_schema_and_version(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"

    init_history_db(db_path)

    with sqlite3.connect(db_path) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert "runs" in tables
    assert user_version == 1


def test_record_inserts_row(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"

    record_history(_record(), db_path)

    records = list_history(db_path)
    assert len(records) == 1
    assert records[0].id == "run-1"
    assert records[0].failed_checks == []


def test_record_same_id_updates_row(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"

    record_history(_record(result="PASS"), db_path)
    record_history(_record(result="FAIL", score=60), db_path)

    records = list_history(db_path)
    assert len(records) == 1
    assert records[0].result == "FAIL"
    assert records[0].score == 60
    assert records[0].failed_checks == ["Tests passed"]


def test_list_respects_limit(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("old", created_at="2026-05-31T10:00:00+00:00"), db_path)
    record_history(_record("new", created_at="2026-05-31T11:00:00+00:00"), db_path)

    records = list_history(db_path, limit=1)

    assert [record.id for record in records] == ["new"]


def test_list_filters_by_run_type(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", run_type="run"), db_path)
    record_history(_record("suite-1", run_type="suite"), db_path)

    records = list_history(db_path, run_type="suite")

    assert [record.id for record in records] == ["suite-1"]


def test_list_filters_by_result(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("pass-1", result="PASS"), db_path)
    record_history(_record("fail-1", result="FAIL"), db_path)

    records = list_history(db_path, result="FAIL")

    assert [record.id for record in records] == ["fail-1"]


def test_stats_returns_counts_and_average_score(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", result="PASS", score=100), db_path)
    record_history(_record("suite-1", run_type="suite", result="FAIL", score=50), db_path)

    stats = history_stats(db_path)

    assert stats.total_records == 2
    assert stats.counts_by_type == {"run": 1, "suite": 1}
    assert stats.counts_by_result == {"PASS": 1, "FAIL": 1}
    assert stats.average_score == 75


def test_missing_db_returns_empty_history_and_stats(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.db"

    assert list_history(db_path) == []
    assert history_stats(db_path).total_records == 0


def test_history_list_cli_with_no_db_exits_zero(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["history", "list"])

    assert result.exit_code == 0
    assert "No history found." in result.output


def test_history_list_cli_rejects_non_positive_limit() -> None:
    result = runner.invoke(app, ["history", "list", "--limit", "0"])

    assert result.exit_code == 2
    assert "limit must be positive" in result.output


def test_history_stats_cli_prints_stats(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record(), Path(".agentguard/history.db"))

    result = runner.invoke(app, ["history", "stats"])

    assert result.exit_code == 0
    assert "AgentGuard History Stats" in result.output
    assert "Total records: 1" in result.output
    assert "- run: 1" in result.output


def test_history_write_failure_warns_without_raising(
    tmp_path: Path,
    monkeypatch,
) -> None:
    def fail_record_history(*args, **kwargs) -> None:
        raise sqlite3.OperationalError("readonly database")

    monkeypatch.setattr(orchestrator, "record_history", fail_record_history)
    result = BenchmarkResult(
        task_id="fix_auth_bug",
        agent="mock-safe",
        result="PASS",
        score=100,
        config_path=tmp_path / "config.yaml",
        run_dir=tmp_path / ".agentguard/runs/run-1",
        repo_dir=tmp_path / "repo",
        test_result=CommandResult(
            command="pytest",
            exit_code=0,
            stdout="",
            stderr="",
            duration_seconds=0.1,
        ),
        diff_summary=DiffSummary(
            modified_files=[],
            added_files=[],
            deleted_files=[],
            lines_added=0,
            lines_deleted=0,
            unified_diff="",
        ),
        check_results=[
            CheckResult(
                name="Tests passed",
                passed=True,
                severity="error",
                message="ok",
            )
        ],
        report_paths=ReportPaths(
            json=tmp_path / "report.json",
            markdown=tmp_path / "report.md",
        ),
        benchmark=BenchmarkMetadata(category="source_fix", difficulty="easy"),
    )

    with pytest.warns(RuntimeWarning, match="history write failed"):
        orchestrator._record_run_history(result)
