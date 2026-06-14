import math
import shutil
import sqlite3
import statistics
import time
import tracemalloc
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from agentguard.core.scheduler import run_bounded_schedule
from agentguard.history.store import HistoryRecord, record_history, utc_now_iso
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.provenance.manifest import agentguard_identity, host_identity


SCHEMA = "agentguard.matrix-stress"
SCHEMA_VERSION = 1
DEFAULT_ATTEMPTS = [10, 50, 100, 250]
DEFAULT_WORKERS = [1, 2, 4, 8]
DEFAULT_OUTPUT_DIR = Path(".agentguard/diagnostics/matrix-stress")
SAFE_MAX_ATTEMPTS = 5000
SAFE_MAX_WORKERS = 64
SAFE_MAX_REPETITIONS = 20
SAFE_MAX_TASK_DURATION_MS = 1000
SAFE_MAX_TOTAL_ATTEMPTS = 100000


@dataclass(frozen=True)
class StressAttemptRow:
    attempt_id: str
    attempt_index: int
    result: str
    score: int
    duration_seconds: float
    history_id: str
    history_error: Optional[str] = None


@dataclass(frozen=True)
class StressIntegrity:
    passed: bool
    findings: list[str]
    missing_row_ids: list[str]
    duplicate_row_ids: list[str]
    missing_history_ids: list[str]
    duplicate_history_ids: list[str]
    output_order_integrity: bool
    report_row_integrity: bool
    result_total_integrity: bool
    reliability_total_integrity: bool
    fail_fast_accounting_integrity: bool


@dataclass(frozen=True)
class StressRepetition:
    cell_id: str
    repetition: int
    attempts_planned: int
    attempts_submitted: int
    attempts_executed: int
    passed: int
    failed: int
    reliability_attempts: int
    reliability_passed: int
    reliability_failed: int
    requested_workers: int
    effective_workers: int
    wall_clock_seconds: float
    attempts_per_second: float
    speedup_vs_one_worker: Optional[float]
    parallel_efficiency: Optional[float]
    median_attempt_duration_seconds: float
    p95_attempt_duration_seconds: float
    peak_traced_memory_bytes: int
    history_records_expected: int
    history_records_written: int
    missing_history_records: int
    duplicate_history_records: int
    stopped_early: bool
    attempts_avoided: int
    estimated_time_saved_seconds: float
    integrity: StressIntegrity
    rows: list[StressAttemptRow]


@dataclass(frozen=True)
class StressCellAggregate:
    cell_id: str
    attempts: int
    workers: int
    repetitions: int
    duration_minimum_seconds: float
    duration_maximum_seconds: float
    duration_mean_seconds: float
    duration_median_seconds: float
    duration_standard_deviation_seconds: float
    median_throughput_attempts_per_second: float
    median_speedup: Optional[float]
    median_parallel_efficiency: Optional[float]
    maximum_peak_memory_bytes: int
    total_attempts_executed: int
    total_attempts_avoided: int
    median_estimated_time_saved_seconds: float
    integrity_passed: bool
    integrity_findings: list[str]


@dataclass(frozen=True)
class MatrixStressResult:
    study_id: str
    schema: str
    schema_version: int
    created_at: str
    synthetic_workload: bool
    attempts: list[int]
    workers: list[int]
    repetitions: int
    task_duration_ms: int
    failure_rate_percent: float
    fail_fast: bool
    raw_repetitions: list[StressRepetition]
    aggregated_cells: list[StressCellAggregate]
    baseline_worker_comparisons: dict[str, dict[str, object]]
    integrity_findings: list[str]
    scaling_summary: dict[str, object]
    saturation_points: dict[str, Optional[int]]
    duration_seconds: float
    environment: dict[str, object]
    limitations: list[str]
    json_report_path: Path
    markdown_report_path: Path

    @property
    def integrity_passed(self) -> bool:
        return not self.integrity_findings


def normalize_positive_int_values(
    raw_values: Optional[list[str]],
    *,
    default: list[int],
    option_name: str,
) -> list[int]:
    if raw_values is None:
        return list(default)
    values: list[int] = []
    for raw_value in raw_values:
        for value in raw_value.split(","):
            text = value.strip()
            if not text:
                continue
            try:
                parsed = int(text)
            except ValueError as error:
                raise ValueError(
                    f"{option_name} values must be positive integers."
                ) from error
            if parsed <= 0:
                raise ValueError(
                    f"{option_name} values must be positive integers."
                )
            if parsed in values:
                raise ValueError(f"Duplicate {option_name} value: {parsed}")
            values.append(parsed)
    if not values:
        raise ValueError(f"{option_name} requires at least one value.")
    return values


def validate_stress_inputs(
    attempts: list[int],
    workers: list[int],
    *,
    task_duration_ms: int,
    failure_rate_percent: float,
    repetitions: int,
    unsafe_large_run: bool,
) -> None:
    if not attempts or any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in attempts
    ):
        raise ValueError("Matrix stress attempts must be positive integers.")
    if not workers or any(
        isinstance(value, bool) or not isinstance(value, int) or value <= 0
        for value in workers
    ):
        raise ValueError("Matrix stress workers must be positive integers.")
    if len(attempts) != len(set(attempts)):
        raise ValueError("Matrix stress attempts must not contain duplicates.")
    if len(workers) != len(set(workers)):
        raise ValueError("Matrix stress workers must not contain duplicates.")
    if 1 not in workers:
        raise ValueError(
            "Matrix stress workers must include 1 for baseline comparisons."
        )
    for value, name in [
        (task_duration_ms, "task duration"),
        (repetitions, "repetitions"),
    ]:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"Matrix stress {name} must be a positive integer.")
    if isinstance(failure_rate_percent, bool) or not isinstance(
        failure_rate_percent, (int, float)
    ):
        raise ValueError("Matrix stress failure rate must be from 0 to 100.")
    if failure_rate_percent < 0 or failure_rate_percent > 100:
        raise ValueError("Matrix stress failure rate must be from 0 to 100.")
    if not unsafe_large_run:
        if max(attempts) > SAFE_MAX_ATTEMPTS:
            raise ValueError(
                f"Attempts exceed safe maximum {SAFE_MAX_ATTEMPTS}; "
                "use --unsafe-large-run to continue."
            )
        if max(workers) > SAFE_MAX_WORKERS:
            raise ValueError(
                f"Workers exceed safe maximum {SAFE_MAX_WORKERS}; "
                "use --unsafe-large-run to continue."
            )
        if repetitions > SAFE_MAX_REPETITIONS:
            raise ValueError(
                f"Repetitions exceed safe maximum {SAFE_MAX_REPETITIONS}; "
                "use --unsafe-large-run to continue."
            )
        if task_duration_ms > SAFE_MAX_TASK_DURATION_MS:
            raise ValueError(
                f"Task duration exceeds safe maximum "
                f"{SAFE_MAX_TASK_DURATION_MS} ms; "
                "use --unsafe-large-run to continue."
            )
        total = sum(attempts) * len(workers) * repetitions
        if total > SAFE_MAX_TOTAL_ATTEMPTS:
            raise ValueError(
                f"Study exceeds safe maximum {SAFE_MAX_TOTAL_ATTEMPTS} "
                "planned attempts; use --unsafe-large-run to continue."
            )


def deterministic_failure(
    attempt_index: int,
    failure_rate_percent: float,
) -> bool:
    if failure_rate_percent <= 0:
        return False
    previous = math.floor(attempt_index * failure_rate_percent / 100.0)
    current = math.floor((attempt_index + 1) * failure_rate_percent / 100.0)
    return current > previous


def _study_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"matrix-stress-{timestamp}-{uuid4().hex[:8]}"


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    rank = math.ceil(percentile / 100.0 * len(ordered))
    return ordered[rank - 1]


def _history_ids(db_path: Path) -> tuple[list[str], list[str]]:
    if not db_path.exists():
        return [], []
    with sqlite3.connect(db_path) as connection:
        ids = [row[0] for row in connection.execute("SELECT id FROM runs")]
        duplicates = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM runs GROUP BY id HAVING COUNT(*) > 1"
            )
        ]
    return ids, duplicates


def _integrity(
    *,
    attempts_planned: int,
    attempts_submitted: int,
    rows: list[StressAttemptRow],
    history_ids: list[str],
    duplicate_history_ids: list[str],
    fail_fast: bool,
    reported_passed: Optional[int] = None,
    reported_failed: Optional[int] = None,
    reliability_attempts: Optional[int] = None,
    reliability_passed: Optional[int] = None,
    reliability_failed: Optional[int] = None,
) -> StressIntegrity:
    executed = len(rows)
    expected_row_ids = [f"attempt-{index:06d}" for index in range(executed)]
    row_ids = [row.attempt_id for row in rows]
    row_counts = Counter(row_ids)
    duplicate_rows = sorted(
        row_id for row_id, count in row_counts.items() if count > 1
    )
    missing_rows = sorted(set(expected_row_ids) - set(row_ids))
    expected_history = {row.history_id for row in rows}
    missing_history = sorted(expected_history - set(history_ids))
    output_order = [row.attempt_index for row in rows] == list(range(executed))
    report_rows = (
        len(rows) == executed
        and len(set(row_ids)) == executed
        and not missing_rows
    )
    passed = sum(row.result == "PASS" for row in rows)
    failed = sum(row.result == "FAIL" for row in rows)
    result_totals = (
        (reported_passed if reported_passed is not None else passed) == passed
        and (reported_failed if reported_failed is not None else failed) == failed
        and passed + failed == executed
    )
    reliability_totals = (
        (
            reliability_attempts
            if reliability_attempts is not None
            else executed
        )
        == executed
        and (
            reliability_passed
            if reliability_passed is not None
            else passed
        )
        == passed
        and (
            reliability_failed
            if reliability_failed is not None
            else failed
        )
        == failed
    )
    accounting = (
        attempts_planned >= attempts_submitted >= executed
        and (fail_fast or attempts_planned == attempts_submitted == executed)
    )
    findings = []
    if missing_rows:
        findings.append(f"Missing report rows: {', '.join(missing_rows)}")
    if duplicate_rows:
        findings.append(f"Duplicate report rows: {', '.join(duplicate_rows)}")
    if missing_history:
        findings.append(
            f"Missing history records: {', '.join(missing_history)}"
        )
    if duplicate_history_ids:
        findings.append(
            f"Duplicate history records: {', '.join(duplicate_history_ids)}"
        )
    if not output_order:
        findings.append("Output rows are not in stable attempt-index order.")
    if not report_rows:
        findings.append("Report-row count or identity integrity failed.")
    if not result_totals:
        findings.append("Result totals do not equal executed attempts.")
    if not reliability_totals:
        findings.append("Reliability totals do not equal executed attempts.")
    if not accounting:
        findings.append("Fail-fast planned/submitted/executed accounting failed.")
    history_errors = [row.history_error for row in rows if row.history_error]
    findings.extend(f"History write failed: {error}" for error in history_errors)
    return StressIntegrity(
        passed=not findings,
        findings=findings,
        missing_row_ids=missing_rows,
        duplicate_row_ids=duplicate_rows,
        missing_history_ids=missing_history,
        duplicate_history_ids=duplicate_history_ids,
        output_order_integrity=output_order,
        report_row_integrity=report_rows,
        result_total_integrity=result_totals,
        reliability_total_integrity=reliability_totals,
        fail_fast_accounting_integrity=accounting,
    )


def _run_repetition(
    *,
    study_id: str,
    study_dir: Path,
    attempts: int,
    workers: int,
    repetition: int,
    task_duration_ms: int,
    failure_rate_percent: float,
    fail_fast: bool,
) -> StressRepetition:
    cell_id = f"attempts-{attempts}-workers-{workers}"
    history_db = study_dir / "history" / cell_id / f"repetition-{repetition}.db"
    report_path = study_dir / "matrix-stress.json"

    def run_attempt(attempt_index: int) -> StressAttemptRow:
        started = time.perf_counter()
        accumulator = 0
        for value in range(256):
            accumulator = (accumulator + (attempt_index + 1) * value) % 104729
        time.sleep(task_duration_ms / 1000.0)
        failed = deterministic_failure(attempt_index, failure_rate_percent)
        result = "FAIL" if failed else "PASS"
        history_id = (
            f"{study_id}:{cell_id}:repetition-{repetition}:"
            f"attempt-{attempt_index:06d}"
        )
        history_error = None
        try:
            record_history(
                HistoryRecord(
                    id=history_id,
                    run_type="run",
                    name="matrix-stress-synthetic",
                    result=result,
                    score=0 if failed else 100,
                    created_at=utc_now_iso(),
                    json_report_path=report_path,
                    category="diagnostic",
                    difficulty="synthetic",
                    benchmark_id="matrix-stress-synthetic",
                    benchmark_version=1,
                    agent="internal-matrix-stress",
                    failed_checks=["Synthetic failure"] if failed else [],
                ),
                history_db,
            )
        except Exception as error:
            history_error = f"{type(error).__name__}: {error}"
        if accumulator < 0:
            raise AssertionError("unreachable deterministic workload state")
        return StressAttemptRow(
            attempt_id=f"attempt-{attempt_index:06d}",
            attempt_index=attempt_index,
            result=result,
            score=0 if failed else 100,
            duration_seconds=round(time.perf_counter() - started, 6),
            history_id=history_id,
            history_error=history_error,
        )

    effective_workers = min(workers, attempts)
    tracemalloc.start()
    started = time.perf_counter()
    try:
        scheduled = run_bounded_schedule(
            list(range(attempts)),
            workers=workers,
            fail_fast=fail_fast,
            runner=run_attempt,
            is_failure=lambda row: row.result == "FAIL",
        )
        wall_clock = time.perf_counter() - started
        _, peak_memory = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    rows = scheduled.results
    history_ids, duplicate_history_ids = _history_ids(history_db)
    passed = sum(row.result == "PASS" for row in rows)
    failed = sum(row.result == "FAIL" for row in rows)
    integrity = _integrity(
        attempts_planned=attempts,
        attempts_submitted=scheduled.submitted,
        rows=rows,
        history_ids=history_ids,
        duplicate_history_ids=duplicate_history_ids,
        fail_fast=fail_fast,
        reported_passed=passed,
        reported_failed=failed,
        reliability_attempts=scheduled.executed,
        reliability_passed=passed,
        reliability_failed=failed,
    )
    durations = [row.duration_seconds for row in rows]
    avoided = attempts - scheduled.executed
    estimated_saved = (
        statistics.median(durations) * avoided / effective_workers
        if durations
        else 0.0
    )
    return StressRepetition(
        cell_id=cell_id,
        repetition=repetition,
        attempts_planned=attempts,
        attempts_submitted=scheduled.submitted,
        attempts_executed=scheduled.executed,
        passed=passed,
        failed=failed,
        reliability_attempts=scheduled.executed,
        reliability_passed=passed,
        reliability_failed=failed,
        requested_workers=workers,
        effective_workers=effective_workers,
        wall_clock_seconds=round(wall_clock, 6),
        attempts_per_second=round(scheduled.executed / wall_clock, 2),
        speedup_vs_one_worker=None,
        parallel_efficiency=None,
        median_attempt_duration_seconds=round(statistics.median(durations), 6),
        p95_attempt_duration_seconds=round(_nearest_rank(durations, 95), 6),
        peak_traced_memory_bytes=peak_memory,
        history_records_expected=scheduled.executed,
        history_records_written=len(history_ids),
        missing_history_records=len(integrity.missing_history_ids),
        duplicate_history_records=len(integrity.duplicate_history_ids),
        stopped_early=scheduled.stopped_early,
        attempts_avoided=avoided,
        estimated_time_saved_seconds=round(estimated_saved, 6),
        integrity=integrity,
        rows=rows,
    )


def _add_baseline_comparisons(
    repetitions: list[StressRepetition],
) -> list[StressRepetition]:
    baselines = {
        (row.attempts_planned, row.repetition): row.wall_clock_seconds
        for row in repetitions
        if row.requested_workers == 1
    }
    compared = []
    for row in repetitions:
        baseline = baselines.get((row.attempts_planned, row.repetition))
        if baseline is None:
            compared.append(row)
            continue
        speedup = baseline / row.wall_clock_seconds
        compared.append(
            replace(
                row,
                speedup_vs_one_worker=round(speedup, 4),
                parallel_efficiency=round(
                    speedup / row.effective_workers,
                    4,
                ),
            )
        )
    return compared


def _aggregate(
    repetitions: list[StressRepetition],
) -> list[StressCellAggregate]:
    grouped: dict[tuple[int, int], list[StressRepetition]] = {}
    for row in repetitions:
        grouped.setdefault(
            (row.attempts_planned, row.requested_workers),
            [],
        ).append(row)
    aggregates = []
    for (attempts, workers), rows in grouped.items():
        durations = [row.wall_clock_seconds for row in rows]
        speedups = [
            row.speedup_vs_one_worker
            for row in rows
            if row.speedup_vs_one_worker is not None
        ]
        efficiencies = [
            row.parallel_efficiency
            for row in rows
            if row.parallel_efficiency is not None
        ]
        findings = [
            f"repetition {row.repetition}: {finding}"
            for row in rows
            for finding in row.integrity.findings
        ]
        aggregates.append(
            StressCellAggregate(
                cell_id=rows[0].cell_id,
                attempts=attempts,
                workers=workers,
                repetitions=len(rows),
                duration_minimum_seconds=round(min(durations), 6),
                duration_maximum_seconds=round(max(durations), 6),
                duration_mean_seconds=round(statistics.fmean(durations), 6),
                duration_median_seconds=round(statistics.median(durations), 6),
                duration_standard_deviation_seconds=round(
                    statistics.stdev(durations) if len(durations) > 1 else 0.0,
                    6,
                ),
                median_throughput_attempts_per_second=round(
                    statistics.median(
                        row.attempts_per_second for row in rows
                    ),
                    2,
                ),
                median_speedup=(
                    round(statistics.median(speedups), 4)
                    if speedups
                    else None
                ),
                median_parallel_efficiency=(
                    round(statistics.median(efficiencies), 4)
                    if efficiencies
                    else None
                ),
                maximum_peak_memory_bytes=max(
                    row.peak_traced_memory_bytes for row in rows
                ),
                total_attempts_executed=sum(
                    row.attempts_executed for row in rows
                ),
                total_attempts_avoided=sum(row.attempts_avoided for row in rows),
                median_estimated_time_saved_seconds=round(
                    statistics.median(
                        row.estimated_time_saved_seconds for row in rows
                    ),
                    6,
                ),
                integrity_passed=not findings,
                integrity_findings=findings,
            )
        )
    return aggregates


def saturation_points(
    aggregates: list[StressCellAggregate],
) -> dict[str, Optional[int]]:
    grouped: dict[int, list[StressCellAggregate]] = {}
    for cell in aggregates:
        grouped.setdefault(cell.attempts, []).append(cell)
    points: dict[str, Optional[int]] = {}
    for attempts, cells in grouped.items():
        ordered = sorted(cells, key=lambda item: item.workers)
        point = None
        for previous, current in zip(ordered, ordered[1:]):
            improvement = (
                current.median_throughput_attempts_per_second
                / previous.median_throughput_attempts_per_second
                - 1.0
            )
            efficiency = current.median_parallel_efficiency
            if improvement < 0.10 or (
                efficiency is not None and efficiency < 0.50
            ):
                point = current.workers
                break
        points[str(attempts)] = point
    return points


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _write_reports(result: MatrixStressResult) -> None:
    atomic_write_json(
        result.json_report_path,
        asdict(result),
        default=_json_default,
        sort_keys=True,
    )
    lines = [
        "# AgentGuard Matrix Stress Study",
        "",
        "## Study Summary",
        "",
        "- Workload: synthetic scheduler/report/history stress workload",
        f"- Attempts: {', '.join(map(str, result.attempts))}",
        f"- Workers: {', '.join(map(str, result.workers))}",
        f"- Repetitions: {result.repetitions}",
        f"- Task duration: {result.task_duration_ms} ms",
        f"- Failure rate: {result.failure_rate_percent:.2f}%",
        f"- Fail fast: {'yes' if result.fail_fast else 'no'}",
        f"- Integrity: {'PASS' if result.integrity_passed else 'FAIL'}",
        f"- Duration: {result.duration_seconds:.6f}s",
        "",
        "## Throughput Scaling",
        "",
        "| Attempts | Workers | Median Duration | Median Throughput | "
        "Median Speedup | Median Efficiency |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for cell in result.aggregated_cells:
        speedup = (
            f"{cell.median_speedup:.2f}x"
            if cell.median_speedup is not None
            else "-"
        )
        efficiency = (
            f"{cell.median_parallel_efficiency * 100:.2f}%"
            if cell.median_parallel_efficiency is not None
            else "-"
        )
        lines.append(
            f"| {cell.attempts} | {cell.workers} | "
            f"{cell.duration_median_seconds:.6f}s | "
            f"{cell.median_throughput_attempts_per_second:.2f}/s | "
            f"{speedup} | {efficiency} |"
        )
    lines.extend(
        [
            "",
            "## Memory Scaling",
            "",
            "| Attempts | Workers | Maximum Traced Python Memory |",
            "|---:|---:|---:|",
        ]
    )
    for cell in result.aggregated_cells:
        lines.append(
            f"| {cell.attempts} | {cell.workers} | "
            f"{cell.maximum_peak_memory_bytes} bytes |"
        )
    lines.extend(["", "## Integrity Checks", ""])
    lines.extend(
        [f"- {finding}" for finding in result.integrity_findings]
        or ["- All cells passed row, history, total, ordering, and accounting gates."]
    )
    lines.extend(
        [
            "",
            "## Fail-Fast Results",
            "",
            "| Attempts | Workers | Executed | Avoided | Estimated Time Saved |",
            "|---:|---:|---:|---:|---:|",
        ]
    )
    for cell in result.aggregated_cells:
        lines.append(
            f"| {cell.attempts} | {cell.workers} | "
            f"{cell.total_attempts_executed} | "
            f"{cell.total_attempts_avoided} | "
            f"{cell.median_estimated_time_saved_seconds:.6f}s |"
        )
    lines.extend(["", "## Saturation Point", ""])
    for attempts, workers in result.saturation_points.items():
        lines.append(
            f"- {attempts} attempts: "
            + (
                f"{workers} workers"
                if workers is not None
                else f"not observed through {max(result.workers)} workers"
            )
        )
    lines.extend(
        [
            "",
            "The observed saturation point is the first worker increase where "
            "throughput improves by less than 10% or parallel efficiency falls "
            "below 50%. It is machine- and workload-specific.",
            "",
            "## Methodology and Limitations",
            "",
        ]
    )
    lines.extend(f"- {limitation}" for limitation in result.limitations)
    lines.append("")
    atomic_write_text(result.markdown_report_path, "\n".join(lines))


def run_matrix_stress(
    *,
    attempts: Optional[list[int]] = None,
    workers: Optional[list[int]] = None,
    task_duration_ms: int = 25,
    failure_rate_percent: float = 0.0,
    fail_fast: bool = False,
    repetitions: int = 3,
    output_dir: Optional[Path] = None,
    force: bool = False,
    unsafe_large_run: bool = False,
) -> MatrixStressResult:
    attempt_values = list(DEFAULT_ATTEMPTS if attempts is None else attempts)
    worker_values = list(DEFAULT_WORKERS if workers is None else workers)
    validate_stress_inputs(
        attempt_values,
        worker_values,
        task_duration_ms=task_duration_ms,
        failure_rate_percent=failure_rate_percent,
        repetitions=repetitions,
        unsafe_large_run=unsafe_large_run,
    )
    study_id = _study_id()
    study_dir = (output_dir or DEFAULT_OUTPUT_DIR) / study_id
    if study_dir.exists():
        if not force:
            raise FileExistsError(f"Matrix stress output exists: {study_dir}")
        shutil.rmtree(study_dir)
    if study_dir.parent.exists() and not study_dir.parent.is_dir():
        raise ValueError(
            f"Matrix stress output parent is not a directory: {study_dir.parent}"
        )
    started = time.perf_counter()
    raw = [
        _run_repetition(
            study_id=study_id,
            study_dir=study_dir,
            attempts=attempt_count,
            workers=worker_count,
            repetition=repetition,
            task_duration_ms=task_duration_ms,
            failure_rate_percent=failure_rate_percent,
            fail_fast=fail_fast,
        )
        for attempt_count in attempt_values
        for worker_count in worker_values
        for repetition in range(1, repetitions + 1)
    ]
    raw = _add_baseline_comparisons(raw)
    aggregates = _aggregate(raw)
    integrity_findings = [
        f"{cell.cell_id}: {finding}"
        for cell in aggregates
        for finding in cell.integrity_findings
    ]
    comparison = {
        cell.cell_id: {
            "attempts": cell.attempts,
            "workers": cell.workers,
            "median_speedup": cell.median_speedup,
            "median_parallel_efficiency": cell.median_parallel_efficiency,
        }
        for cell in aggregates
    }
    comparable = [
        cell for cell in aggregates if cell.median_speedup is not None
    ]
    best_speedup = max(
        comparable,
        key=lambda item: item.median_speedup or 0.0,
    )
    best_throughput = max(
        aggregates,
        key=lambda item: item.median_throughput_attempts_per_second,
    )
    identity = agentguard_identity()
    host = host_identity(docker_relevant=False)
    result = MatrixStressResult(
        study_id=study_id,
        schema=SCHEMA,
        schema_version=SCHEMA_VERSION,
        created_at=datetime.now(timezone.utc).isoformat(),
        synthetic_workload=True,
        attempts=attempt_values,
        workers=worker_values,
        repetitions=repetitions,
        task_duration_ms=task_duration_ms,
        failure_rate_percent=float(failure_rate_percent),
        fail_fast=fail_fast,
        raw_repetitions=raw,
        aggregated_cells=aggregates,
        baseline_worker_comparisons=comparison,
        integrity_findings=integrity_findings,
        scaling_summary={
            "maximum_validated_attempts": (
                max(attempt_values) if not integrity_findings else None
            ),
            "best_measured_speedup": best_speedup.median_speedup,
            "best_speedup_workers": best_speedup.workers,
            "best_speedup_attempts": best_speedup.attempts,
            "best_throughput_attempts_per_second": (
                best_throughput.median_throughput_attempts_per_second
            ),
            "best_throughput_workers": best_throughput.workers,
            "best_throughput_attempts": best_throughput.attempts,
            "maximum_peak_memory_bytes": max(
                cell.maximum_peak_memory_bytes for cell in aggregates
            ),
        },
        saturation_points=saturation_points(aggregates),
        duration_seconds=round(time.perf_counter() - started, 6),
        environment={
            "agentguard_version": identity.version,
            "agentguard_git_commit": identity.git_commit,
            "agentguard_dirty_worktree": identity.dirty_worktree,
            "python_version": host.python_version,
            "operating_system": host.operating_system,
            "architecture": host.architecture,
        },
        limitations=[
            "This is a synthetic scheduler/report/history workload, not an external-agent benchmark.",
            "Attempts per second must not be presented as coding-agent throughput.",
            "Tracemalloc measures traced Python allocations, not total process memory.",
            "Sleep-dominated tasks favor parallel scheduling and do not model repository or agent work.",
            "Measured efficiency can exceed 100% when sleep and SQLite work overlap or matching repetitions vary.",
            "SQLite and filesystem performance are machine-specific.",
            "Fail-fast time savings are estimates from observed median attempt duration.",
            "Saturation points are specific to this machine and workload configuration.",
        ],
        json_report_path=study_dir / "matrix-stress.json",
        markdown_report_path=study_dir / "matrix-stress.md",
    )
    _write_reports(result)
    return result
