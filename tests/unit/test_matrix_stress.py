import json
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.scheduler import run_bounded_schedule
from agentguard.diagnostics import matrix_stress
from agentguard.diagnostics.matrix_stress import (
    StressAttemptRow,
    _aggregate,
    _integrity,
    deterministic_failure,
    normalize_positive_int_values,
    run_matrix_stress,
    saturation_points,
    validate_stress_inputs,
)


runner = CliRunner()


def _row(index: int, result: str = "PASS") -> StressAttemptRow:
    return StressAttemptRow(
        attempt_id=f"attempt-{index:06d}",
        attempt_index=index,
        result=result,
        score=100 if result == "PASS" else 0,
        duration_seconds=0.01,
        history_id=f"history-{index}",
    )


def test_option_parsing_and_validation() -> None:
    assert normalize_positive_int_values(
        ["10,50", "100"],
        default=[],
        option_name="attempts",
    ) == [10, 50, 100]
    with pytest.raises(ValueError, match="Duplicate attempts"):
        normalize_positive_int_values(
            ["10,10"],
            default=[],
            option_name="attempts",
        )
    with pytest.raises(ValueError, match="positive integers"):
        normalize_positive_int_values(
            ["false"],
            default=[],
            option_name="workers",
        )
    with pytest.raises(ValueError, match="include 1"):
        validate_stress_inputs(
            [10],
            [2],
            task_duration_ms=1,
            failure_rate_percent=0,
            repetitions=1,
            unsafe_large_run=False,
        )
    with pytest.raises(ValueError, match="failure rate"):
        validate_stress_inputs(
            [10],
            [1],
            task_duration_ms=1,
            failure_rate_percent=101,
            repetitions=1,
            unsafe_large_run=False,
        )
    with pytest.raises(ValueError, match="safe maximum"):
        validate_stress_inputs(
            [matrix_stress.SAFE_MAX_ATTEMPTS + 1],
            [1],
            task_duration_ms=1,
            failure_rate_percent=0,
            repetitions=1,
            unsafe_large_run=False,
        )
    with pytest.raises(ValueError, match="Task duration exceeds safe maximum"):
        validate_stress_inputs(
            [10],
            [1],
            task_duration_ms=matrix_stress.SAFE_MAX_TASK_DURATION_MS + 1,
            failure_rate_percent=0,
            repetitions=1,
            unsafe_large_run=False,
        )
    with pytest.raises(ValueError, match="positive integers"):
        validate_stress_inputs(
            [True],
            [1],
            task_duration_ms=1,
            failure_rate_percent=0,
            repetitions=1,
            unsafe_large_run=True,
        )


def test_deterministic_failure_placement() -> None:
    assert [
        index for index in range(20) if deterministic_failure(index, 20)
    ] == [4, 9, 14, 19]
    assert not any(deterministic_failure(index, 0) for index in range(20))
    assert all(deterministic_failure(index, 100) for index in range(20))


def test_bounded_scheduler_executes_all_and_restores_order() -> None:
    releases = [threading.Event() for _ in range(4)]

    def runner_fn(index: int) -> int:
        assert releases[index].wait(timeout=2)
        return index

    def release_reverse() -> None:
        for event in reversed(releases):
            event.set()
            time.sleep(0.005)

    releaser = threading.Thread(target=release_reverse)
    releaser.start()
    scheduled = run_bounded_schedule(
        list(range(4)),
        workers=4,
        fail_fast=False,
        runner=runner_fn,
        is_failure=lambda _: False,
    )
    releaser.join()

    assert scheduled.results == [0, 1, 2, 3]
    assert scheduled.submitted == scheduled.executed == 4
    assert not scheduled.stopped_early


def test_integrity_detects_missing_duplicate_history_and_totals() -> None:
    rows = [_row(0), _row(1)]
    integrity = _integrity(
        attempts_planned=2,
        attempts_submitted=2,
        rows=rows,
        history_ids=["history-0"],
        duplicate_history_ids=["history-0"],
        fail_fast=False,
        reported_passed=1,
        reported_failed=0,
        reliability_attempts=1,
        reliability_passed=1,
        reliability_failed=0,
    )

    assert not integrity.passed
    assert integrity.missing_history_ids == ["history-1"]
    assert integrity.duplicate_history_ids == ["history-0"]
    assert not integrity.result_total_integrity
    assert not integrity.reliability_total_integrity


def test_real_cell_metrics_baseline_memory_and_reports(tmp_path: Path) -> None:
    result = run_matrix_stress(
        attempts=[6],
        workers=[1, 2],
        task_duration_ms=1,
        repetitions=2,
        output_dir=tmp_path,
    )

    assert result.integrity_passed
    assert all(row.attempts_executed == 6 for row in result.raw_repetitions)
    assert all(row.peak_traced_memory_bytes >= 0 for row in result.raw_repetitions)
    one_worker = next(
        cell for cell in result.aggregated_cells if cell.workers == 1
    )
    two_workers = next(
        cell for cell in result.aggregated_cells if cell.workers == 2
    )
    assert one_worker.median_speedup == 1.0
    assert one_worker.median_parallel_efficiency == 1.0
    assert two_workers.median_speedup is not None
    assert two_workers.median_parallel_efficiency == pytest.approx(
        two_workers.median_speedup / 2,
        abs=0.0002,
    )
    assert one_worker.duration_minimum_seconds <= (
        one_worker.duration_mean_seconds
    ) <= one_worker.duration_maximum_seconds
    data = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")
    assert data["schema"] == "agentguard.matrix-stress"
    assert data["schema_version"] == 1
    assert data["synthetic_workload"] is True
    assert "## Throughput Scaling" in markdown
    assert "## Integrity Checks" in markdown
    assert "not an external-agent benchmark" in markdown


def test_duration_aggregate_calculations(tmp_path: Path) -> None:
    result = run_matrix_stress(
        attempts=[2],
        workers=[1],
        task_duration_ms=1,
        repetitions=3,
        output_dir=tmp_path,
    )
    rows = [
        replace(
            row,
            wall_clock_seconds=duration,
            attempts_per_second=2 / duration,
            speedup_vs_one_worker=1.0,
            parallel_efficiency=1.0,
        )
        for row, duration in zip(
            result.raw_repetitions,
            [1.0, 2.0, 3.0],
        )
    ]
    aggregate = _aggregate(rows)[0]
    assert aggregate.duration_minimum_seconds == 1.0
    assert aggregate.duration_maximum_seconds == 3.0
    assert aggregate.duration_mean_seconds == 2.0
    assert aggregate.duration_median_seconds == 2.0
    assert aggregate.duration_standard_deviation_seconds == 1.0
    assert aggregate.median_throughput_attempts_per_second == 1.0


def test_fail_fast_accounting_and_estimated_savings(tmp_path: Path) -> None:
    result = run_matrix_stress(
        attempts=[20],
        workers=[1, 2],
        task_duration_ms=1,
        failure_rate_percent=20,
        fail_fast=True,
        repetitions=1,
        output_dir=tmp_path,
    )
    serial, parallel = result.raw_repetitions
    assert serial.attempts_submitted == serial.attempts_executed == 5
    assert serial.attempts_avoided == 15
    assert parallel.attempts_submitted == parallel.attempts_executed == 6
    assert parallel.attempts_avoided == 14
    assert serial.stopped_early and parallel.stopped_early
    assert serial.estimated_time_saved_seconds > 0
    assert result.integrity_passed


def test_saturation_calculation(tmp_path: Path) -> None:
    result = run_matrix_stress(
        attempts=[4],
        workers=[1, 2, 4],
        task_duration_ms=1,
        repetitions=1,
        output_dir=tmp_path,
    )
    cells = result.aggregated_cells
    adjusted = [
        replace(
            cell,
            median_throughput_attempts_per_second=throughput,
            median_parallel_efficiency=efficiency,
        )
        for cell, throughput, efficiency in zip(
            cells,
            [100.0, 180.0, 185.0],
            [1.0, 0.9, 0.46],
        )
    ]
    assert saturation_points(adjusted) == {"4": 4}


def test_cli_exit_codes_and_integrity_failure_preservation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    valid = runner.invoke(
        app,
        [
            "diagnostics",
            "matrix-stress",
            "--attempts",
            "4",
            "--workers",
            "1,2",
            "--task-duration-ms",
            "1",
            "--repetitions",
            "1",
            "--output-dir",
            str(tmp_path / "valid"),
        ],
    )
    assert valid.exit_code == 0
    assert "AgentGuard Matrix Stress Study" in valid.output
    assert "Integrity status: PASS" in valid.output

    invalid = runner.invoke(
        app,
        ["diagnostics", "matrix-stress", "--workers", "2"],
    )
    assert invalid.exit_code == 2
    assert "include 1" in invalid.output
    assert "Traceback" not in invalid.output

    actual = run_matrix_stress(
        attempts=[2],
        workers=[1],
        task_duration_ms=1,
        repetitions=1,
        output_dir=tmp_path / "failure-source",
    )
    failed_result = replace(actual, integrity_findings=["controlled failure"])
    monkeypatch.setattr(
        "agentguard.cli.main.run_matrix_stress",
        lambda **_: failed_result,
    )
    failed = runner.invoke(
        app,
        ["diagnostics", "matrix-stress", "--attempts", "2", "--workers", "1"],
    )
    allowed = runner.invoke(
        app,
        [
            "diagnostics",
            "matrix-stress",
            "--attempts",
            "2",
            "--workers",
            "1",
            "--allow-study-failures",
        ],
    )
    assert failed.exit_code == 1
    assert allowed.exit_code == 0
