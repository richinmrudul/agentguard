import csv
import json
import sqlite3
from dataclasses import replace
from io import StringIO
from pathlib import Path
from typing import Optional

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
    export_history_csv,
    export_history_json,
    history_records_to_dicts,
    history_stats,
    history_trends,
    init_history_db,
    list_history,
    record_history,
)


runner = CliRunner()


def _record(
    record_id: str = "run-1",
    *,
    run_type: str = "run",
    name: str = "fix_auth_bug",
    result: str = "PASS",
    score: float = 100,
    created_at: str = "2026-05-31T10:00:00+00:00",
    category: str = "source_fix",
    difficulty: str = "easy",
    benchmark_id: str = "auth_bug_safe",
    benchmark_version: int = 1,
    agent: str = "mock-safe",
    guard_blocked: bool = False,
    guard_violations_total: int = 0,
    guard_incident_path: Optional[Path] = None,
) -> HistoryRecord:
    return HistoryRecord(
        id=record_id,
        run_type=run_type,
        name=name,
        result=result,
        score=score,
        created_at=created_at,
        json_report_path=Path(".agentguard/runs/run-1/reports/report.json"),
        markdown_report_path=Path(".agentguard/runs/run-1/reports/report.md"),
        command_log_path=Path(".agentguard/runs/run-1/command_log.json"),
        category=category,
        difficulty=difficulty,
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
        agent=agent,
        failed_checks=["Tests passed"] if result == "FAIL" else [],
        guard_blocked=guard_blocked,
        guard_violations_total=guard_violations_total,
        guard_incident_path=guard_incident_path,
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
    assert user_version == 4


def test_record_inserts_row(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"

    record_history(_record(), db_path)

    records = list_history(db_path)
    assert len(records) == 1
    assert records[0].id == "run-1"
    assert records[0].benchmark_id == "auth_bug_safe"
    assert records[0].benchmark_version == 1
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


def test_list_filters_by_name(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("auth-1", name="fix_auth_bug"), db_path)
    record_history(_record("core-1", name="core", run_type="suite"), db_path)

    records = list_history(db_path, name="core")

    assert [record.id for record in records] == ["core-1"]


def test_list_filters_by_category(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("source-1", category="source_fix"), db_path)
    record_history(_record("prompt-1", category="prompt_injection"), db_path)

    records = list_history(db_path, category="prompt_injection")

    assert [record.id for record in records] == ["prompt-1"]


def test_list_filters_by_difficulty(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("easy-1", difficulty="easy"), db_path)
    record_history(_record("medium-1", difficulty="medium"), db_path)

    records = list_history(db_path, difficulty="medium")

    assert [record.id for record in records] == ["medium-1"]


def test_stats_returns_counts_and_average_score(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", result="PASS", score=100), db_path)
    record_history(_record("suite-1", run_type="suite", result="FAIL", score=50), db_path)

    stats = history_stats(db_path)

    assert stats.total_records == 2
    assert stats.counts_by_type == {"run": 1, "suite": 1}
    assert stats.counts_by_result == {"PASS": 1, "FAIL": 1}
    assert stats.average_score == 75


def test_stats_respects_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", name="fix_auth_bug", score=100), db_path)
    record_history(
        _record("suite-1", run_type="suite", name="core", result="FAIL", score=50),
        db_path,
    )

    stats = history_stats(db_path, run_type="suite", name="core")

    assert stats.total_records == 1
    assert stats.counts_by_type == {"suite": 1}
    assert stats.counts_by_result == {"FAIL": 1}
    assert stats.average_score == 50


def test_stats_empty_filter_returns_zero_counts(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record(), db_path)

    stats = history_stats(db_path, name="missing")

    assert stats.total_records == 0
    assert stats.counts_by_type == {}
    assert stats.counts_by_result == {}
    assert stats.average_score is None
    assert stats.latest_created_at is None


def test_trends_with_one_record_has_no_previous_score_or_delta(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("core-1", run_type="suite", name="core", score=65), db_path)

    trends = history_trends(db_path, name="core", run_type="suite")

    assert trends.records_count == 1
    assert trends.latest_score == 65
    assert trends.previous_score is None
    assert trends.delta is None
    assert trends.pass_count == 1
    assert trends.fail_count == 0
    assert trends.pass_rate == 100
    assert trends.recent_results == ["PASS"]


def test_trends_with_multiple_records_computes_delta_and_pass_rate(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "history.db"
    record_history(
        _record(
            "core-old",
            run_type="suite",
            name="core",
            result="FAIL",
            score=50,
            created_at="2026-05-31T10:00:00+00:00",
        ),
        db_path,
    )
    record_history(
        _record(
            "core-new",
            run_type="suite",
            name="core",
            result="PASS",
            score=65,
            created_at="2026-05-31T11:00:00+00:00",
        ),
        db_path,
    )

    trends = history_trends(db_path, name="core", run_type="suite")

    assert trends.records_count == 2
    assert trends.latest_score == 65
    assert trends.previous_score == 50
    assert trends.delta == 15
    assert trends.pass_count == 1
    assert trends.fail_count == 1
    assert trends.pass_rate == 50
    assert trends.recent_results == ["PASS", "FAIL"]


def test_trends_respects_limit(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(
        _record("old", name="core", score=30, created_at="2026-05-31T09:00:00+00:00"),
        db_path,
    )
    record_history(
        _record("mid", name="core", score=50, created_at="2026-05-31T10:00:00+00:00"),
        db_path,
    )
    record_history(
        _record("new", name="core", score=70, created_at="2026-05-31T11:00:00+00:00"),
        db_path,
    )

    trends = history_trends(db_path, name="core", limit=2)

    assert trends.records_count == 2
    assert trends.latest_score == 70
    assert trends.previous_score == 50
    assert trends.delta == 20


def test_trends_respects_type_and_name_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-core", run_type="run", name="core", score=90), db_path)
    record_history(
        _record("suite-core", run_type="suite", name="core", score=60),
        db_path,
    )
    record_history(
        _record("suite-other", run_type="suite", name="other", score=10),
        db_path,
    )

    trends = history_trends(db_path, name="core", run_type="suite")

    assert trends.records_count == 1
    assert trends.latest_score == 60
    assert trends.run_type == "suite"


def test_json_export_returns_list_of_dicts(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", result="FAIL"), db_path)

    records = list_history(db_path)
    exported = json.loads(export_history_json(records))

    assert exported == history_records_to_dicts(records)
    assert exported[0]["id"] == "run-1"
    assert exported[0]["failed_checks"] == ["Tests passed"]


def test_csv_export_includes_header_and_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", result="FAIL"), db_path)

    exported = export_history_csv(list_history(db_path))
    rows = list(csv.DictReader(StringIO(exported)))

    assert exported.startswith("id,run_type,name,result,score,created_at")
    assert rows[0]["id"] == "run-1"
    assert rows[0]["failed_checks"] == "Tests passed"


def test_csv_export_neutralizes_formula_capable_string_cells() -> None:
    record = replace(
        _record(),
        id="=1+1",
        run_type=" +SUM(1,1)",
        name="\t-1+1",
        result="\r\n@SUM(1,1)",
        created_at="\n=created",
        json_report_path=Path(" =report.json"),
        markdown_report_path=Path("\x0b+report.md"),
        command_log_path=Path("\x7f-report.json"),
        manifest_path=Path("@manifest.json"),
        trace_path=Path("\n=trace.jsonl"),
        category="+category",
        difficulty="-difficulty",
        benchmark_id="@benchmark",
        agent="=agent",
        failed_checks=["@SUM(1,1)", "ordinary"],
        guard_incident_path=Path("\t=incident.json"),
    )

    rows = list(csv.DictReader(StringIO(export_history_csv([record]))))

    assert rows == [
        {
            "id": "'=1+1",
            "run_type": "' +SUM(1,1)",
            "name": "'\t-1+1",
            "result": "'\r\n@SUM(1,1)",
            "score": "100",
            "created_at": "'\n=created",
            "json_report_path": "' =report.json",
            "markdown_report_path": "'\x0b+report.md",
            "command_log_path": "'\x7f-report.json",
            "manifest_path": "'@manifest.json",
            "trace_path": "'\n=trace.jsonl",
            "category": "'+category",
            "difficulty": "'-difficulty",
            "benchmark_id": "'@benchmark",
            "benchmark_version": "1",
            "agent": "'=agent",
            "failed_checks": "'@SUM(1,1);ordinary",
            "guard_blocked": "False",
            "guard_violations_total": "0",
            "guard_incident_path": "'\t=incident.json",
            "time_to_first_violation_ms": "",
        }
    ]


def test_csv_formula_safety_does_not_change_json_or_ordinary_csv_values() -> None:
    record = replace(
        _record(),
        name="=1+1",
        agent="ordinary-agent",
        failed_checks=["+SUM(1,1)"],
    )

    csv_row = next(csv.DictReader(StringIO(export_history_csv([record]))))
    json_row = json.loads(export_history_json([record]))[0]

    assert csv_row["name"] == "'=1+1"
    assert csv_row["agent"] == "ordinary-agent"
    assert csv_row["failed_checks"] == "'+SUM(1,1)"
    assert json_row["name"] == "=1+1"
    assert json_row["agent"] == "ordinary-agent"
    assert json_row["failed_checks"] == ["+SUM(1,1)"]


def test_filters_apply_to_exported_records(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record("run-1", name="fix_auth_bug"), db_path)
    record_history(_record("suite-1", run_type="suite", name="core"), db_path)

    records = list_history(db_path, limit=None, name="core")
    exported = json.loads(export_history_json(records))

    assert [record["id"] for record in exported] == ["suite-1"]


def test_empty_export_json_is_empty_list() -> None:
    assert export_history_json([]) == "[]\n"


def test_empty_export_csv_has_header_only() -> None:
    exported = export_history_csv([])

    assert exported.startswith("id,run_type,name,result,score,created_at")
    assert list(csv.DictReader(StringIO(exported))) == []


def test_missing_db_returns_empty_history_and_stats(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.db"

    assert list_history(db_path) == []
    assert history_stats(db_path).total_records == 0
    assert history_trends(db_path, name="missing").records_count == 0


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


def test_history_list_cli_filters_by_name(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("auth-1", name="fix_auth_bug"), Path(".agentguard/history.db"))
    record_history(
        _record("core-1", run_type="suite", name="core"),
        Path(".agentguard/history.db"),
    )

    result = runner.invoke(app, ["history", "list", "--name", "core"])

    assert result.exit_code == 0
    assert "core-1" in result.output
    assert "auth-1" not in result.output


def test_history_stats_cli_filters_by_type(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("run-1"), Path(".agentguard/history.db"))
    record_history(
        _record("suite-1", run_type="suite", name="core"),
        Path(".agentguard/history.db"),
    )

    result = runner.invoke(app, ["history", "stats", "--type", "suite"])

    assert result.exit_code == 0
    assert "Total records: 1" in result.output
    assert "- suite: 1" in result.output
    assert "- run:" not in result.output


def test_history_trends_cli_prints_scores_delta_and_pass_rate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    db_path = Path(".agentguard/history.db")
    record_history(
        _record(
            "core-old",
            run_type="suite",
            name="core",
            result="FAIL",
            score=50,
            created_at="2026-05-31T10:00:00+00:00",
        ),
        db_path,
    )
    record_history(
        _record(
            "core-new",
            run_type="suite",
            name="core",
            result="FAIL",
            score=65,
            created_at="2026-05-31T11:00:00+00:00",
        ),
        db_path,
    )

    result = runner.invoke(
        app,
        ["history", "trends", "--name", "core", "--type", "suite"],
    )

    assert result.exit_code == 0
    assert "AgentGuard History Trends" in result.output
    assert "Latest score: 65" in result.output
    assert "Previous score: 50" in result.output
    assert "Delta: +15" in result.output
    assert "Pass rate: 0.0%" in result.output
    assert "Recent results newest-first: FAIL FAIL" in result.output


def test_history_trends_cli_with_no_matches_exits_zero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record(), Path(".agentguard/history.db"))

    result = runner.invoke(app, ["history", "trends", "--name", "missing"])

    assert result.exit_code == 0
    assert "No history found for selected filters." in result.output


def test_history_cli_rejects_invalid_type_result_and_limit() -> None:
    invalid_type = runner.invoke(app, ["history", "stats", "--type", "bad"])
    invalid_result = runner.invoke(app, ["history", "list", "--result", "MAYBE"])
    invalid_limit = runner.invoke(app, ["history", "trends", "--name", "core", "--limit", "0"])

    assert invalid_type.exit_code == 2
    assert "run type must be one of" in invalid_type.output
    assert invalid_result.exit_code == 2
    assert "result must be one of" in invalid_result.output
    assert invalid_limit.exit_code == 2
    assert "limit must be positive" in invalid_limit.output


def test_history_export_cli_writes_output_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("run-1"), Path(".agentguard/history.db"))
    output = tmp_path / "exports/history.json"

    result = runner.invoke(
        app,
        [
            "history",
            "export",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert f"History exported: {output}" in result.output
    assert json.loads(output.read_text(encoding="utf-8"))[0]["id"] == "run-1"


def test_history_export_cli_existing_output_without_force_exits_2(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("run-1"), Path(".agentguard/history.db"))
    output = tmp_path / "history.json"
    output.write_text("existing", encoding="utf-8")

    result = runner.invoke(
        app,
        ["history", "export", "--output", str(output)],
    )

    assert result.exit_code == 2
    assert "output already exists" in result.output
    assert output.read_text(encoding="utf-8") == "existing"


def test_history_export_cli_force_overwrites_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("run-1"), Path(".agentguard/history.db"))
    output = tmp_path / "history.json"
    output.write_text("existing", encoding="utf-8")

    result = runner.invoke(
        app,
        ["history", "export", "--output", str(output), "--force"],
    )

    assert result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))[0]["id"] == "run-1"


def test_history_export_cli_stdout_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("run-1"), Path(".agentguard/history.db"))

    result = runner.invoke(app, ["history", "export", "--format", "json"])

    assert result.exit_code == 0
    assert json.loads(result.output)[0]["id"] == "run-1"


def test_history_export_cli_stdout_csv(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record("run-1"), Path(".agentguard/history.db"))

    result = runner.invoke(app, ["history", "export", "--format", "csv"])

    assert result.exit_code == 0
    rows = list(csv.DictReader(StringIO(result.output)))
    assert rows[0]["id"] == "run-1"


def test_history_export_cli_invalid_format_exits_2() -> None:
    result = runner.invoke(app, ["history", "export", "--format", "yaml"])

    assert result.exit_code == 2
    assert "format must be one of" in result.output


def test_history_export_cli_invalid_limit_exits_2() -> None:
    result = runner.invoke(app, ["history", "export", "--limit", "0"])

    assert result.exit_code == 2
    assert "limit must be positive" in result.output


def test_history_export_cli_empty_outputs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    json_result = runner.invoke(app, ["history", "export", "--format", "json"])
    csv_result = runner.invoke(app, ["history", "export", "--format", "csv"])

    assert json_result.exit_code == 0
    assert json_result.output == "[]\n"
    assert csv_result.exit_code == 0
    assert csv_result.output.startswith("id,run_type,name,result,score,created_at")
    assert list(csv.DictReader(StringIO(csv_result.output))) == []


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


def test_run_history_recording_includes_benchmark_id_and_version(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    result = BenchmarkResult(
        task_id="fix_auth_bug",
        agent="mock-safe",
        result="PASS",
        score=100,
        config_path=tmp_path / "config.yaml",
        run_dir=Path(".agentguard/runs/run-1"),
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
            json=Path(".agentguard/runs/run-1/reports/report.json"),
            markdown=Path(".agentguard/runs/run-1/reports/report.md"),
        ),
        benchmark=BenchmarkMetadata(
            id="auth_bug_safe",
            version=2,
            category="source_fix",
            difficulty="easy",
        ),
    )

    orchestrator._record_run_history(result)

    records = list_history(Path(".agentguard/history.db"))
    assert records[0].benchmark_id == "auth_bug_safe"
    assert records[0].benchmark_version == 2
