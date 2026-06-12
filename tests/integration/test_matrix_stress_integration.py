import sqlite3
from pathlib import Path

from agentguard.diagnostics.matrix_stress import run_matrix_stress


def test_lightweight_real_concurrency_history_and_order(tmp_path: Path) -> None:
    result = run_matrix_stress(
        attempts=[12],
        workers=[1, 4],
        task_duration_ms=2,
        repetitions=1,
        output_dir=tmp_path,
    )

    assert result.integrity_passed
    parallel = next(
        row for row in result.raw_repetitions if row.requested_workers == 4
    )
    assert parallel.attempts_executed == 12
    assert [row.attempt_index for row in parallel.rows] == list(range(12))
    history_db = (
        result.json_report_path.parent
        / "history"
        / parallel.cell_id
        / "repetition-1.db"
    )
    with sqlite3.connect(history_db) as connection:
        count = connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        distinct = connection.execute(
            "SELECT COUNT(DISTINCT id) FROM runs"
        ).fetchone()[0]
    assert count == distinct == 12
    assert parallel.history_records_written == 12
    assert parallel.missing_history_records == 0
    assert parallel.duplicate_history_records == 0
