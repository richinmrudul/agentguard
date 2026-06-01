import json
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


DEFAULT_HISTORY_DB_PATH = Path(".agentguard/history.db")
VALID_RUN_TYPES = {"run", "suite", "ci"}
VALID_RESULTS = {"PASS", "FAIL"}


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
    category: Optional[str] = None
    difficulty: Optional[str] = None
    agent: Optional[str] = None
    failed_checks: list[str] = field(default_factory=list)


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


def init_history_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as connection:
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
              category TEXT,
              difficulty TEXT,
              agent TEXT,
              failed_checks_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_runs_run_type ON runs(run_type)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_runs_result ON runs(result)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_runs_created_at ON runs(created_at)"
        )
        connection.execute("PRAGMA user_version = 1")


def record_history(
    record: HistoryRecord,
    db_path: Path = DEFAULT_HISTORY_DB_PATH,
) -> None:
    init_history_db(db_path)
    with sqlite3.connect(db_path) as connection:
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
              category,
              difficulty,
              agent,
              failed_checks_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              run_type = excluded.run_type,
              name = excluded.name,
              result = excluded.result,
              score = excluded.score,
              created_at = excluded.created_at,
              json_report_path = excluded.json_report_path,
              markdown_report_path = excluded.markdown_report_path,
              command_log_path = excluded.command_log_path,
              category = excluded.category,
              difficulty = excluded.difficulty,
              agent = excluded.agent,
              failed_checks_json = excluded.failed_checks_json
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
                record.category,
                record.difficulty,
                record.agent,
                json.dumps(record.failed_checks),
            ),
        )


def list_history(
    db_path: Path = DEFAULT_HISTORY_DB_PATH,
    limit: int = 20,
    run_type: Optional[str] = None,
    result: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
) -> list[HistoryRecord]:
    if limit <= 0:
        raise ValueError("limit must be positive.")
    validate_run_type(run_type)
    validate_result(result)
    if not db_path.exists():
        return []

    where, params = _history_where_clause(
        run_type=run_type,
        result=result,
        name=name,
        category=category,
        difficulty=difficulty,
    )

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
          category,
          difficulty,
          agent,
          failed_checks_json
        FROM runs
        {where}
        ORDER BY created_at DESC, id DESC
        LIMIT ?
    """
    params.append(limit)

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(query, params).fetchall()
    return [_record_from_row(row) for row in rows]


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

    where, params = _history_where_clause(
        run_type=run_type,
        result=result,
        name=name,
        category=category,
        difficulty=difficulty,
    )
    with sqlite3.connect(db_path) as connection:
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


def _history_where_clause(
    *,
    run_type: Optional[str] = None,
    result: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
) -> tuple[str, list[object]]:
    filters = []
    params: list[object] = []
    for column, value in [
        ("run_type", run_type),
        ("result", result),
        ("name", name),
        ("category", category),
        ("difficulty", difficulty),
    ]:
        if value is not None:
            filters.append(f"{column} = ?")
            params.append(value)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    return where, params


def _single_run_type(records: list[HistoryRecord]) -> Optional[str]:
    run_types = {record.run_type for record in records}
    if len(run_types) == 1:
        return records[0].run_type
    return None


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
        category=row[9],
        difficulty=row[10],
        agent=row[11],
        failed_checks=json.loads(row[12]),
    )
