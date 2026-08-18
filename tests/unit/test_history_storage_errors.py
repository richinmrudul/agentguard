import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.history import store
from agentguard.history.store import (
    HistoryRecord,
    HistoryStorageError,
    history_stats,
    init_history_db,
    list_history,
    record_history,
)


runner = CliRunner()


def _record(record_id: str = "run-1") -> HistoryRecord:
    return HistoryRecord(
        id=record_id,
        run_type="run",
        name="example",
        result="PASS",
        score=100,
        created_at="2026-08-17T12:00:00+00:00",
        json_report_path=Path(".agentguard/runs/run-1/report.json"),
    )


@pytest.mark.parametrize(
    "operation",
    [
        lambda path: init_history_db(path),
        lambda path: record_history(_record(), path),
        lambda path: list_history(path),
        lambda path: history_stats(path),
    ],
)
def test_directory_collision_is_a_sanitized_storage_failure(
    tmp_path: Path,
    operation,
) -> None:
    private_path = tmp_path / "private history" / "history.db"
    private_path.mkdir(parents=True)

    with pytest.raises(HistoryStorageError) as raised:
        operation(private_path)

    assert "History storage is unavailable" in str(raised.value)
    assert str(tmp_path) not in str(raised.value)
    assert "sqlite" not in str(raised.value).lower()


def test_inaccessible_database_parent_preserves_user_file(tmp_path: Path) -> None:
    parent = tmp_path / "not-a-directory"
    parent.write_text("user content", encoding="utf-8")

    with pytest.raises(HistoryStorageError, match="during setup"):
        record_history(_record(), parent / "history.db")

    assert parent.read_text(encoding="utf-8") == "user content"


def test_corrupt_database_is_not_deleted_or_recreated(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    original = b"not a sqlite database\nprivate-payload"
    db_path.write_bytes(original)

    with pytest.raises(HistoryStorageError, match="during setup"):
        list_history(db_path)

    assert db_path.read_bytes() == original


def test_malformed_stored_record_is_a_sanitized_read_failure(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record(), db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE runs SET failed_checks_json = ? WHERE id = ?",
            ("hostile malformed value", "run-1"),
        )

    with pytest.raises(HistoryStorageError) as raised:
        list_history(db_path)

    assert "during read" in str(raised.value)
    assert "hostile malformed value" not in str(raised.value)


def test_schema_migration_failure_is_atomic(monkeypatch, tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TABLE runs ("
            "id TEXT PRIMARY KEY, run_type TEXT NOT NULL, name TEXT NOT NULL, "
            "result TEXT NOT NULL, score REAL, created_at TEXT NOT NULL, "
            "json_report_path TEXT NOT NULL, failed_checks_json TEXT NOT NULL)"
        )
        connection.execute("PRAGMA user_version = 1")

    original_ensure_column = store._ensure_column

    def fail_during_migration(connection, column_name, column_type) -> None:
        if column_name == "benchmark_version":
            raise sqlite3.OperationalError("hostile migration details")
        original_ensure_column(connection, column_name, column_type)

    monkeypatch.setattr(store, "_ensure_column", fail_during_migration)

    with pytest.raises(HistoryStorageError, match="during setup"):
        init_history_db(db_path)

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()
        }
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert "benchmark_id" not in columns
    assert version == 1


def test_locked_write_is_controlled_and_does_not_claim_persistence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record(), db_path)
    monkeypatch.setattr(store, "_SQLITE_TIMEOUT_SECONDS", 0.01)

    lock = sqlite3.connect(db_path)
    lock.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(HistoryStorageError) as raised:
            record_history(_record("run-2"), db_path)
        assert "private" not in str(raised.value)
    finally:
        lock.rollback()
        lock.close()

    assert [item.id for item in list_history(db_path)] == ["run-1"]


def test_read_only_database_can_be_read_but_not_written(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record(), db_path)
    db_path.chmod(0o444)
    try:
        assert [item.id for item in list_history(db_path)] == ["run-1"]
        with pytest.raises(HistoryStorageError, match="during write"):
            record_history(_record("run-2"), db_path)
    finally:
        db_path.chmod(0o644)

    assert [item.id for item in list_history(db_path)] == ["run-1"]


def test_operational_read_failure_closes_connection(
    monkeypatch,
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "history.db"
    record_history(_record(), db_path)
    real_connect = sqlite3.connect
    connect_calls = 0

    class FailingReadConnection:
        closed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.closed = True

        def execute(self, *_args, **_kwargs):
            raise sqlite3.OperationalError("private SQL and path details")

    failing_connection = FailingReadConnection()

    def connect(*args, **kwargs):
        nonlocal connect_calls
        connect_calls += 1
        if connect_calls == 1:
            return real_connect(*args, **kwargs)
        return failing_connection

    monkeypatch.setattr(store.sqlite3, "connect", connect)

    with pytest.raises(HistoryStorageError) as raised:
        list_history(db_path)

    assert "during read" in str(raised.value)
    assert "private SQL" not in str(raised.value)
    assert failing_connection.closed


def test_valid_empty_history_is_still_empty(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    init_history_db(db_path)

    assert list_history(db_path) == []
    assert history_stats(db_path).total_records == 0


@pytest.mark.parametrize(
    "arguments",
    [
        ["history", "list"],
        ["history", "stats"],
        ["history", "trends", "--name", "core"],
        ["history", "export"],
        ["guard", "list"],
    ],
)
def test_history_cli_commands_report_clean_storage_errors(
    tmp_path: Path,
    monkeypatch,
    arguments: list[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    Path(".agentguard/history.db").mkdir(parents=True)

    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert result.output == "Error: History storage is unavailable during setup.\n"
    assert "Traceback" not in result.output
    assert "OperationalError" not in result.output
    assert str(tmp_path) not in result.output


def test_export_output_failure_is_not_misreported_as_storage_or_success(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    record_history(_record(), Path(".agentguard/history.db"))
    private_output = tmp_path / "private exports" / "history.json"

    def fail_write(*_args, **_kwargs):
        raise OSError(f"permission denied: {private_output}\nhostile")

    monkeypatch.setattr("agentguard.cli.main.atomic_write_text", fail_write)

    result = runner.invoke(
        app,
        ["history", "export", "--output", str(private_output)],
    )

    assert result.exit_code == 2
    assert result.output == "Error: could not write history export output.\n"
    assert "History storage" not in result.output
    assert "History exported" not in result.output
    assert str(tmp_path) not in result.output
    assert "Traceback" not in result.output


def test_existing_export_error_does_not_echo_private_output_path(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    private_output = tmp_path / "private exports" / "history.json"
    private_output.parent.mkdir()
    private_output.write_text(json.dumps({"private": True}), encoding="utf-8")

    result = runner.invoke(
        app,
        ["history", "export", "--output", str(private_output)],
    )

    assert result.exit_code == 2
    assert "history export output already exists" in result.output
    assert str(tmp_path) not in result.output


def test_matrix_cli_controls_checkpoint_history_failure(monkeypatch) -> None:
    def fail_matrix(*_args, **_kwargs):
        raise HistoryStorageError("read")

    monkeypatch.setattr("agentguard.cli.main.run_matrix", fail_matrix)

    result = runner.invoke(app, ["matrix", "private-suite.yaml"])

    assert result.exit_code == 2
    assert result.output == "Error: History storage is unavailable during read.\n"
    assert "Traceback" not in result.output


def test_external_evaluation_cli_controls_checkpoint_history_failure(
    monkeypatch,
) -> None:
    def fail_evaluation(*_args, **_kwargs):
        raise HistoryStorageError("write")

    monkeypatch.setattr(
        "agentguard.cli.main.build_evaluation_plan",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr("agentguard.cli.main.run_evaluation", fail_evaluation)

    result = runner.invoke(
        app,
        [
            "evaluate",
            "run",
            "--profile",
            "private-profile.yaml",
            "--suite",
            "private-suite.yaml",
            "--yes",
        ],
    )

    assert result.exit_code == 2
    assert result.output == "Error: History storage is unavailable during write.\n"
    assert "Traceback" not in result.output
