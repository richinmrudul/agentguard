import csv
import json
import sqlite3
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from io import StringIO
from pathlib import Path
from typing import Optional

from agentguard.terminal import sanitize_terminal_text


DEFAULT_HISTORY_DB_PATH = Path(".agentguard/history.db")
VALID_RUN_TYPES = {"run", "suite", "matrix", "ci"}
VALID_RESULTS = {"PASS", "FAIL"}
HISTORY_CSV_COLUMNS = [
    "id",
    "run_type",
    "name",
    "result",
    "score",
    "created_at",
    "json_report_path",
    "markdown_report_path",
    "command_log_path",
    "manifest_path",
    "trace_path",
    "category",
    "difficulty",
    "benchmark_id",
    "benchmark_version",
    "agent",
    "failed_checks",
    "guard_blocked",
    "guard_violations_total",
    "guard_incident_path",
    "time_to_first_violation_ms",
]
_SCHEMA_LOCK = threading.Lock()
_SQLITE_TIMEOUT_SECONDS = 30
_CSV_FORMULA_MARKERS = frozenset("=+-@")


class HistoryStorageError(RuntimeError):
    """A sanitized expected failure of the local history store."""

    def __init__(self, operation: str) -> None:
        super().__init__(f"History storage is unavailable during {operation}.")


def _translate_storage_errors(operation: str, extra_errors: tuple = ()):
    expected_errors = (OSError, sqlite3.Error, *extra_errors)

    def decorator(function):
        @wraps(function)
        def translated(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except HistoryStorageError:
                raise
            except expected_errors as error:
                raise HistoryStorageError(operation) from error

        return translated

    return decorator


@dataclass(frozen=True)
class HistoryRecord:
    id: str
    run_type: str
    name: str
    result: str
    score: Optional[float]
    created_at: str
    json_report_path: Path
    markdown_report_path: Optional[Path] = None
    command_log_path: Optional[Path] = None
    manifest_path: Optional[Path] = None
    trace_path: Optional[Path] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    benchmark_id: Optional[str] = None
    benchmark_version: Optional[int] = None
    agent: Optional[str] = None
    failed_checks: list[str] = field(default_factory=list)
    guard_blocked: bool = False
    guard_violations_total: int = 0
    guard_incident_path: Optional[Path] = None
    time_to_first_violation_ms: Optional[int] = None


@dataclass(frozen=True)
class HistoryStats:
    total_records: int = 0
    counts_by_type: dict[str, int] = field(default_factory=dict)
    counts_by_result: dict[str, int] = field(default_factory=dict)
    average_score: Optional[float] = None
    latest_created_at: Optional[str] = None


@dataclass(frozen=True)
class HistoryTrends:
    name: str
    run_type: Optional[str]
    records_count: int = 0
    latest_score: Optional[float] = None
    previous_score: Optional[float] = None
    delta: Optional[float] = None
    pass_count: int = 0
    fail_count: int = 0
    pass_rate: Optional[float] = None
    recent_results: list[str] = field(default_factory=list)
    latest_report_path: Optional[Path] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@_translate_storage_errors("setup")
def init_history_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # Schema setup is process-local serialized; record writes still use separate connections.
    with _SCHEMA_LOCK:
        with sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS) as connection:
            connection.execute("BEGIN")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                  id TEXT PRIMARY KEY,
                  run_type TEXT NOT NULL,
                  name TEXT NOT NULL,
                  result TEXT NOT NULL,
                  score REAL,
                  created_at TEXT NOT NULL,
                  json_report_path TEXT NOT NULL,
                  markdown_report_path TEXT,
                  command_log_path TEXT,
                  manifest_path TEXT,
                  trace_path TEXT,
                  category TEXT,
                  difficulty TEXT,
                  benchmark_id TEXT,
                  benchmark_version INTEGER,
                  agent TEXT,
                  failed_checks_json TEXT NOT NULL
                )
                """
            )
            _ensure_column(connection, "benchmark_id", "TEXT")
            _ensure_column(connection, "benchmark_version", "INTEGER")
            _ensure_column(connection, "manifest_path", "TEXT")
            _ensure_column(connection, "trace_path", "TEXT")
            _ensure_column(connection, "guard_blocked", "INTEGER DEFAULT 0")
            _ensure_column(
                connection,
                "guard_violations_total",
                "INTEGER DEFAULT 0",
            )
            _ensure_column(connection, "guard_incident_path", "TEXT")
            _ensure_column(connection, "time_to_first_violation_ms", "INTEGER")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_run_type ON runs(run_type)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_result ON runs(result)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at)"
            )
            current_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if current_version != 4:
                connection.execute("PRAGMA user_version = 4")


@_translate_storage_errors("write")
def record_history(
    record: HistoryRecord,
    db_path: Path = DEFAULT_HISTORY_DB_PATH,
) -> None:
    init_history_db(db_path)
    with sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS) as connection:
        connection.execute(f"PRAGMA busy_timeout = {_SQLITE_TIMEOUT_SECONDS * 1000}")
        connection.execute(
            """
            INSERT INTO runs (
              id,
              run_type,
              name,
              result,
              score,
              created_at,
              json_report_path,
              markdown_report_path,
              command_log_path,
              manifest_path,
              trace_path,
              category,
              difficulty,
              benchmark_id,
              benchmark_version,
              agent,
              failed_checks_json,
              guard_blocked,
              guard_violations_total,
              guard_incident_path,
              time_to_first_violation_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              run_type = excluded.run_type,
              name = excluded.name,
              result = excluded.result,
              score = excluded.score,
              created_at = excluded.created_at,
              json_report_path = excluded.json_report_path,
              markdown_report_path = excluded.markdown_report_path,
              command_log_path = excluded.command_log_path,
              manifest_path = excluded.manifest_path,
              trace_path = excluded.trace_path,
              category = excluded.category,
              difficulty = excluded.difficulty,
              benchmark_id = excluded.benchmark_id,
              benchmark_version = excluded.benchmark_version,
              agent = excluded.agent,
              failed_checks_json = excluded.failed_checks_json,
              guard_blocked = excluded.guard_blocked,
              guard_violations_total = excluded.guard_violations_total,
              guard_incident_path = excluded.guard_incident_path,
              time_to_first_violation_ms = excluded.time_to_first_violation_ms
            """,
            (
                record.id,
                record.run_type,
                record.name,
                record.result,
                record.score,
                record.created_at,
                str(record.json_report_path),
                _optional_path(record.markdown_report_path),
                _optional_path(record.command_log_path),
                _optional_path(record.manifest_path),
                _optional_path(record.trace_path),
                record.category,
                record.difficulty,
                record.benchmark_id,
                record.benchmark_version,
                record.agent,
                json.dumps(record.failed_checks),
                1 if record.guard_blocked else 0,
                record.guard_violations_total,
                _optional_path(record.guard_incident_path),
                record.time_to_first_violation_ms,
            ),
        )


@_translate_storage_errors("read")
def list_history(
    db_path: Path = DEFAULT_HISTORY_DB_PATH,
    limit: Optional[int] = 20,
    run_type: Optional[str] = None,
    result: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    incidents_only: bool = False,
    guard_blocked: Optional[bool] = None,
    agent: Optional[str] = None,
    benchmark_id: Optional[str] = None,
) -> list[HistoryRecord]:
    if limit is not None and limit <= 0:
        raise ValueError("limit must be positive.")
    validate_run_type(run_type)
    validate_result(result)
    if not db_path.exists():
        return []
    init_history_db(db_path)

    where, params = _history_where_clause(
        run_type=run_type,
        result=result,
        name=name,
        category=category,
        difficulty=difficulty,
        incidents_only=incidents_only,
        guard_blocked=guard_blocked,
        agent=agent,
        benchmark_id=benchmark_id,
    )

    limit_clause = "LIMIT ?" if limit is not None else ""
    query = f"""
        SELECT
          id,
          run_type,
          name,
          result,
          score,
          created_at,
          json_report_path,
          markdown_report_path,
          command_log_path,
          manifest_path,
          trace_path,
          category,
          difficulty,
          benchmark_id,
          benchmark_version,
          agent,
          failed_checks_json,
          guard_blocked,
          guard_violations_total,
          guard_incident_path,
          time_to_first_violation_ms
        FROM runs
        {where}
        ORDER BY created_at DESC, id DESC
        {limit_clause}
    """
    if limit is not None:
        params.append(limit)

    with sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS) as connection:
        rows = connection.execute(query, params).fetchall()
    return [_record_from_row(row) for row in rows]


@_translate_storage_errors("read")
def history_stats(
    db_path: Path = DEFAULT_HISTORY_DB_PATH,
    run_type: Optional[str] = None,
    result: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
) -> HistoryStats:
    validate_run_type(run_type)
    validate_result(result)
    if not db_path.exists():
        return HistoryStats()
    init_history_db(db_path)

    where, params = _history_where_clause(
        run_type=run_type,
        result=result,
        name=name,
        category=category,
        difficulty=difficulty,
    )
    with sqlite3.connect(db_path, timeout=_SQLITE_TIMEOUT_SECONDS) as connection:
        rows = connection.execute(
            f"SELECT run_type, result, score, created_at FROM runs {where}",
            params,
        ).fetchall()
    if not rows:
        return HistoryStats()

    scores = [row[2] for row in rows if row[2] is not None]
    average_score = sum(scores) / len(scores) if scores else None
    return HistoryStats(
        total_records=len(rows),
        counts_by_type=dict(Counter(row[0] for row in rows)),
        counts_by_result=dict(Counter(row[1] for row in rows)),
        average_score=average_score,
        latest_created_at=max(row[3] for row in rows),
    )


def history_trends(
    db_path: Path = DEFAULT_HISTORY_DB_PATH,
    *,
    name: str,
    limit: int = 10,
    run_type: Optional[str] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
) -> HistoryTrends:
    if limit <= 0:
        raise ValueError("limit must be positive.")
    records = list_history(
        db_path,
        limit=limit,
        run_type=run_type,
        name=name,
        category=category,
        difficulty=difficulty,
    )
    if not records:
        return HistoryTrends(name=name, run_type=run_type)

    latest = records[0]
    previous_score = records[1].score if len(records) > 1 else None
    delta = (
        latest.score - previous_score
        if latest.score is not None and previous_score is not None
        else None
    )
    pass_count = sum(1 for record in records if record.result == "PASS")
    fail_count = sum(1 for record in records if record.result == "FAIL")
    return HistoryTrends(
        name=name,
        run_type=run_type or _single_run_type(records),
        records_count=len(records),
        latest_score=latest.score,
        previous_score=previous_score,
        delta=delta,
        pass_count=pass_count,
        fail_count=fail_count,
        pass_rate=(pass_count / len(records)) * 100,
        recent_results=[record.result for record in records],
        latest_report_path=latest.json_report_path,
    )


def history_records_to_dicts(records: list[HistoryRecord]) -> list[dict[str, object]]:
    return [
        {
            "id": record.id,
            "run_type": record.run_type,
            "name": record.name,
            "result": record.result,
            "score": record.score,
            "created_at": record.created_at,
            "json_report_path": str(record.json_report_path),
            "markdown_report_path": _optional_path(record.markdown_report_path),
            "command_log_path": _optional_path(record.command_log_path),
            "manifest_path": _optional_path(record.manifest_path),
            "trace_path": _optional_path(record.trace_path),
            "category": record.category,
            "difficulty": record.difficulty,
            "benchmark_id": record.benchmark_id,
            "benchmark_version": record.benchmark_version,
            "agent": record.agent,
            "failed_checks": record.failed_checks,
            "guard_blocked": record.guard_blocked,
            "guard_violations_total": record.guard_violations_total,
            "guard_incident_path": _optional_path(record.guard_incident_path),
            "time_to_first_violation_ms": record.time_to_first_violation_ms,
        }
        for record in records
    ]


def export_history_json(records: list[HistoryRecord]) -> str:
    return json.dumps(history_records_to_dicts(records), indent=2) + "\n"


def export_history_csv(records: list[HistoryRecord]) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=HISTORY_CSV_COLUMNS)
    writer.writeheader()
    for record in records:
        row = history_records_to_dicts([record])[0]
        row["failed_checks"] = ";".join(record.failed_checks)
        writer.writerow(
            {
                column: _spreadsheet_safe_csv_cell(
                    sanitize_terminal_text(value, preserve_newlines=False)
                    if isinstance(value, str)
                    else value
                )
                for column, value in row.items()
            }
        )
    return output.getvalue()


def _spreadsheet_safe_csv_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    for character in value:
        if character.isspace() or ord(character) < 32 or ord(character) == 127:
            continue
        if character in _CSV_FORMULA_MARKERS:
            return f"'{value}"
        break
    return value


def validate_run_type(run_type: Optional[str]) -> Optional[str]:
    if run_type is None:
        return None
    if run_type not in VALID_RUN_TYPES:
        choices = ", ".join(sorted(VALID_RUN_TYPES))
        raise ValueError(f"run type must be one of: {choices}.")
    return run_type


def validate_result(result: Optional[str]) -> Optional[str]:
    if result is None:
        return None
    if result not in VALID_RESULTS:
        choices = ", ".join(sorted(VALID_RESULTS))
        raise ValueError(f"result must be one of: {choices}.")
    return result


def _optional_path(path: Optional[Path]) -> Optional[str]:
    return str(path) if path is not None else None


def _optional_path_from_value(value: Optional[str]) -> Optional[Path]:
    return Path(value) if value is not None else None


def _optional_int_from_value(value: Optional[object]) -> Optional[int]:
    return int(value) if value is not None else None


def _ensure_column(
    connection: sqlite3.Connection,
    column_name: str,
    column_type: str,
) -> None:
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(runs)").fetchall()
    }
    if column_name not in columns:
        connection.execute(f"ALTER TABLE runs ADD COLUMN {column_name} {column_type}")


def _history_where_clause(
    *,
    run_type: Optional[str] = None,
    result: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    incidents_only: bool = False,
    guard_blocked: Optional[bool] = None,
    agent: Optional[str] = None,
    benchmark_id: Optional[str] = None,
) -> tuple[str, list[object]]:
    filters = []
    params: list[object] = []
    for column, value in [
        ("run_type", run_type),
        ("result", result),
        ("name", name),
        ("category", category),
        ("difficulty", difficulty),
        ("agent", agent),
        ("benchmark_id", benchmark_id),
    ]:
        if value is not None:
            filters.append(f"{column} = ?")
            params.append(value)
    if incidents_only or guard_blocked is not None:
        filters.append(
            "guard_incident_path IS NOT NULL AND guard_incident_path != ''"
        )
    if guard_blocked is not None:
        filters.append("guard_blocked = ?")
        params.append(1 if guard_blocked else 0)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    return where, params


def _single_run_type(records: list[HistoryRecord]) -> Optional[str]:
    run_types = {record.run_type for record in records}
    if len(run_types) == 1:
        return records[0].run_type
    return None


@_translate_storage_errors(
    "read",
    (json.JSONDecodeError, IndexError, TypeError, ValueError),
)
def _record_from_row(row: tuple) -> HistoryRecord:
    return HistoryRecord(
        id=row[0],
        run_type=row[1],
        name=row[2],
        result=row[3],
        score=row[4],
        created_at=row[5],
        json_report_path=Path(row[6]),
        markdown_report_path=_optional_path_from_value(row[7]),
        command_log_path=_optional_path_from_value(row[8]),
        manifest_path=_optional_path_from_value(row[9]),
        trace_path=_optional_path_from_value(row[10]),
        category=row[11],
        difficulty=row[12],
        benchmark_id=row[13],
        benchmark_version=_optional_int_from_value(row[14]),
        agent=row[15],
        failed_checks=json.loads(row[16]),
        guard_blocked=bool(row[17]),
        guard_violations_total=int(row[18] or 0),
        guard_incident_path=_optional_path_from_value(row[19]),
        time_to_first_violation_ms=_optional_int_from_value(row[20]),
    )
