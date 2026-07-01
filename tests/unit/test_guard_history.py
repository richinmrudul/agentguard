import csv
import json
import sqlite3
from io import StringIO
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.history.store import (
    HISTORY_CSV_COLUMNS,
    HistoryRecord,
    list_history,
    record_history,
)


runner = CliRunner()


def _record(
    record_id: str,
    *,
    created_at: str,
    incident: bool = False,
    blocked: bool = False,
    agent: str = "local-command",
    benchmark_id: str = "auth_bug_local_test_cheater",
    category: str = "test_tampering",
) -> HistoryRecord:
    return HistoryRecord(
        id=record_id,
        run_type="run",
        name=benchmark_id,
        result="FAIL",
        score=0,
        created_at=created_at,
        json_report_path=Path(f".agentguard/runs/{record_id}/reports/report.json"),
        category=category,
        difficulty="medium",
        benchmark_id=benchmark_id,
        benchmark_version=1,
        agent=agent,
        guard_blocked=blocked,
        guard_violations_total=2 if incident else 0,
        guard_incident_path=(
            Path(f".agentguard/runs/{record_id}/guard/incident.json")
            if incident
            else None
        ),
        time_to_first_violation_ms=12 if incident else None,
    )


def _seed(db_path: Path) -> None:
    record_history(
        _record(
            "audit",
            created_at="2026-06-01T10:00:00+00:00",
            incident=True,
            agent="local-command",
        ),
        db_path,
    )
    record_history(
        _record(
            "blocked",
            created_at="2026-06-01T11:00:00+00:00",
            incident=True,
            blocked=True,
            agent="mock-safe",
            benchmark_id="blocked-benchmark",
            category="source_fix",
        ),
        db_path,
    )
    record_history(
        _record("ordinary", created_at="2026-06-01T12:00:00+00:00"),
        db_path,
    )


def test_list_history_filters_incidents_and_guard_status(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    _seed(db_path)

    assert [item.id for item in list_history(db_path, incidents_only=True)] == [
        "blocked",
        "audit",
    ]
    assert [item.id for item in list_history(db_path, guard_blocked=True)] == [
        "blocked"
    ]
    assert [item.id for item in list_history(db_path, guard_blocked=False)] == [
        "audit"
    ]


def test_audit_filter_excludes_non_incidents_and_empty_paths(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    _seed(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE runs SET guard_incident_path = '' WHERE id = ?",
            ("ordinary",),
        )

    assert [item.id for item in list_history(db_path, guard_blocked=False)] == [
        "audit"
    ]


def test_exact_metadata_filters_combine_with_incidents(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    _seed(db_path)

    records = list_history(
        db_path,
        incidents_only=True,
        guard_blocked=False,
        agent="local-command",
        benchmark_id="auth_bug_local_test_cheater",
        category="test_tampering",
    )

    assert [item.id for item in records] == ["audit"]
    assert list_history(
        db_path,
        incidents_only=True,
        agent="local%",
        benchmark_id="' OR 1=1 --",
    ) == []


def test_ordering_and_limit_apply_after_incident_filters(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(
        _record(
            "older-incident",
            created_at="2026-06-01T09:00:00+00:00",
            incident=True,
        ),
        db_path,
    )
    for index in range(3):
        record_history(
            _record(
                f"newer-{index}",
                created_at=f"2026-06-01T1{index}:00:00+00:00",
            ),
            db_path,
        )

    assert [
        item.id for item in list_history(db_path, incidents_only=True, limit=1)
    ] == ["older-incident"]


def test_equal_timestamps_retain_descending_id_order(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    for record_id in ("a", "b"):
        record_history(
            _record(
                record_id,
                created_at="2026-06-01T10:00:00+00:00",
                incident=True,
            ),
            db_path,
        )

    assert [item.id for item in list_history(db_path, incidents_only=True)] == [
        "b",
        "a",
    ]


def test_incident_path_need_not_exist_and_defaults_remain_unchanged(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "history.db"
    _seed(db_path)

    assert [item.id for item in list_history(db_path)] == [
        "ordinary",
        "blocked",
        "audit",
    ]
    assert list_history(db_path, incidents_only=True)[0].guard_incident_path


@pytest.mark.parametrize(
    ("arguments", "expected", "excluded"),
    [
        (["--status", "all"], ("audit", "blocked"), ("ordinary",)),
        (["--status", "blocked"], ("blocked",), ("audit", "ordinary")),
        (["--status", "audit"], ("audit",), ("blocked", "ordinary")),
        (["--agent", "local-command"], ("audit",), ("blocked",)),
        (["--benchmark", "blocked-benchmark"], ("blocked",), ("audit",)),
        (["--category", "source_fix"], ("blocked",), ("audit",)),
    ],
)
def test_guard_list_filters(
    tmp_path: Path,
    monkeypatch,
    arguments: list[str],
    expected: tuple[str, ...],
    excluded: tuple[str, ...],
) -> None:
    monkeypatch.chdir(tmp_path)
    _seed(Path(".agentguard/history.db"))

    result = runner.invoke(app, ["guard", "list", *arguments])

    assert result.exit_code == 0
    for value in expected:
        assert value in result.output
    for value in excluded:
        assert value not in result.output


def test_guard_list_combines_filters_and_applies_limit_last(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    db_path = Path(".agentguard/history.db")
    record_history(
        _record(
            "older-incident",
            created_at="2026-06-01T09:00:00+00:00",
            incident=True,
        ),
        db_path,
    )
    for index in range(3):
        record_history(
            _record(f"newer-{index}", created_at=f"2026-06-01T1{index}:00:00+00:00"),
            db_path,
        )

    result = runner.invoke(
        app,
        [
            "guard",
            "list",
            "--status",
            "audit",
            "--agent",
            "local-command",
            "--benchmark",
            "auth_bug_local_test_cheater",
            "--category",
            "test_tampering",
            "--limit",
            "1",
        ],
    )

    assert result.exit_code == 0
    assert "older-incident" in result.output
    assert result.output.count("violation(s)") == 1


@pytest.mark.parametrize(
    "arguments",
    [["--status", "unknown"], ["--limit", "0"]],
)
def test_guard_list_rejects_invalid_options(arguments: list[str]) -> None:
    result = runner.invoke(app, ["guard", "list", *arguments])

    assert result.exit_code == 2


def test_guard_list_empty_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(app, ["guard", "list"])

    assert result.exit_code == 0
    assert "No guard incidents found." in result.output


@pytest.mark.parametrize(
    ("arguments", "expected", "excluded"),
    [
        (["--incidents-only"], ("audit", "blocked"), ("ordinary",)),
        (["--guard-status", "blocked"], ("blocked",), ("audit", "ordinary")),
        (["--guard-status", "audit"], ("audit",), ("blocked", "ordinary")),
        (
            [
                "--agent",
                "mock-safe",
                "--benchmark",
                "blocked-benchmark",
            ],
            ("blocked",),
            ("audit", "ordinary"),
        ),
    ],
)
def test_history_list_guard_filters(
    tmp_path: Path,
    monkeypatch,
    arguments: list[str],
    expected: tuple[str, ...],
    excluded: tuple[str, ...],
) -> None:
    monkeypatch.chdir(tmp_path)
    _seed(Path(".agentguard/history.db"))

    result = runner.invoke(app, ["history", "list", *arguments])

    assert result.exit_code == 0
    for value in expected:
        assert value in result.output
    for value in excluded:
        assert value not in result.output


def test_history_list_rejects_invalid_guard_status() -> None:
    result = runner.invoke(app, ["history", "list", "--guard-status", "all"])

    assert result.exit_code == 2
    assert "guard status must be one of: audit, blocked" in result.output


@pytest.mark.parametrize("export_format", ["json", "csv"])
def test_history_export_guard_filters(
    tmp_path: Path,
    monkeypatch,
    export_format: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    _seed(Path(".agentguard/history.db"))

    result = runner.invoke(
        app,
        [
            "history",
            "export",
            "--format",
            export_format,
            "--guard-status",
            "audit",
            "--agent",
            "local-command",
            "--benchmark",
            "auth_bug_local_test_cheater",
        ],
    )

    assert result.exit_code == 0
    if export_format == "json":
        rows = json.loads(result.output)
        assert [row["id"] for row in rows] == ["audit"]
        assert list(rows[0]) == HISTORY_CSV_COLUMNS
    else:
        reader = csv.DictReader(StringIO(result.output))
        assert reader.fieldnames == HISTORY_CSV_COLUMNS
        assert [row["id"] for row in reader] == ["audit"]


@pytest.mark.parametrize("export_format", ["json", "csv"])
def test_history_export_empty_incident_filter_is_valid(
    tmp_path: Path,
    monkeypatch,
    export_format: str,
) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["history", "export", "--format", export_format, "--incidents-only"],
    )

    assert result.exit_code == 0
    if export_format == "json":
        assert json.loads(result.output) == []
    else:
        reader = csv.DictReader(StringIO(result.output))
        assert reader.fieldnames == HISTORY_CSV_COLUMNS
        assert list(reader) == []


def test_history_export_rejects_invalid_guard_status() -> None:
    result = runner.invoke(
        app,
        ["history", "export", "--guard-status", "everything"],
    )

    assert result.exit_code == 2
    assert "guard status must be one of: audit, blocked" in result.output


def test_guard_filters_do_not_change_database_version(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    _seed(db_path)
    list_history(db_path, incidents_only=True, guard_blocked=False)

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4
