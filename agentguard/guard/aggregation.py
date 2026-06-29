from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from statistics import median
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from agentguard.core.matrix import MatrixRowSummary


@dataclass(frozen=True)
class GuardTimingDistribution:
    samples: int = 0
    minimum_ms: Optional[int] = None
    median_ms: Optional[float] = None
    p95_ms: Optional[int] = None
    maximum_ms: Optional[int] = None


@dataclass(frozen=True)
class GuardGroupSummary:
    runs: int = 0
    incident_runs: int = 0
    blocked_runs: int = 0
    audit_only_runs: int = 0
    violations_total: int = 0
    filesystem_violations: int = 0
    command_violations: int = 0


@dataclass(frozen=True)
class GuardTypeSummary:
    incident_runs: int = 0
    blocked_runs: int = 0
    violations_total: int = 0


@dataclass(frozen=True)
class GuardIncidentReference:
    execution_id: Optional[str]
    task_id: str
    benchmark_id: str
    category: str
    agent: str
    trial_index: int
    blocked: bool
    violations_total: int
    time_to_first_violation_ms: Optional[int]
    incident_json: Optional[str]
    incident_markdown: Optional[str]


@dataclass(frozen=True)
class GuardAggregateSummary:
    runs_evaluated: int = 0
    incident_runs: int = 0
    blocked_runs: int = 0
    audit_only_runs: int = 0
    violations_total: int = 0
    filesystem_violations: int = 0
    command_violations: int = 0
    time_to_first_violation: GuardTimingDistribution = field(
        default_factory=GuardTimingDistribution
    )
    time_to_block: GuardTimingDistribution = field(
        default_factory=GuardTimingDistribution
    )
    by_agent: dict[str, GuardGroupSummary] = field(default_factory=dict)
    by_benchmark: dict[str, GuardGroupSummary] = field(default_factory=dict)
    by_category: dict[str, GuardGroupSummary] = field(default_factory=dict)
    by_guard_type: dict[str, GuardTypeSummary] = field(default_factory=dict)
    incidents: list[GuardIncidentReference] = field(default_factory=list)


def timing_distribution(values: list[Optional[int]]) -> GuardTimingDistribution:
    """Summarize valid timings using a deterministic nearest-rank p95."""
    valid = sorted(
        value
        for value in values
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
    )
    if not valid:
        return GuardTimingDistribution()
    p95_rank = math.ceil(0.95 * len(valid))
    return GuardTimingDistribution(
        samples=len(valid),
        minimum_ms=valid[0],
        median_ms=median(valid),
        p95_ms=valid[p95_rank - 1],
        maximum_ms=valid[-1],
    )


def aggregate_matrix_guard(
    rows: list[MatrixRowSummary],
    matrix_markdown_path: Path,
) -> GuardAggregateSummary:
    ordered_rows = sorted(rows, key=_row_sort_key)
    incident_rows = [row for row in ordered_rows if row.guard_violations_total > 0]
    blocked_rows = [row for row in incident_rows if row.guard_blocked]
    return GuardAggregateSummary(
        runs_evaluated=len(rows),
        incident_runs=len(incident_rows),
        blocked_runs=len(blocked_rows),
        audit_only_runs=len(incident_rows) - len(blocked_rows),
        violations_total=sum(row.guard_violations_total for row in rows),
        filesystem_violations=sum(row.filesystem_guard_violations for row in rows),
        command_violations=sum(row.command_guard_violations for row in rows),
        time_to_first_violation=timing_distribution(
            [row.time_to_first_violation_ms for row in rows]
        ),
        time_to_block=timing_distribution([row.time_to_block_ms for row in rows]),
        by_agent=_grouped(rows, "agent", "unknown"),
        by_benchmark=_grouped(rows, "benchmark_id", "unidentified"),
        by_category=_grouped(rows, "category", "uncategorized"),
        by_guard_type={
            "command": _guard_type_summary(rows, "command"),
            "filesystem": _guard_type_summary(rows, "filesystem"),
        },
        incidents=[
            GuardIncidentReference(
                execution_id=row.execution_id,
                task_id=row.task_id,
                benchmark_id=row.benchmark_id or "unidentified",
                category=row.category or "uncategorized",
                agent=row.agent,
                trial_index=row.trial_index,
                blocked=row.guard_blocked,
                violations_total=row.guard_violations_total,
                time_to_first_violation_ms=row.time_to_first_violation_ms,
                incident_json=_safe_incident_reference(
                    row.guard_incident_json_path,
                    row.run_dir,
                    matrix_markdown_path.parent,
                ),
                incident_markdown=_safe_incident_reference(
                    row.guard_incident_markdown_path,
                    row.run_dir,
                    matrix_markdown_path.parent,
                ),
            )
            for row in incident_rows
        ],
    )


def _grouped(
    rows: list[MatrixRowSummary],
    field_name: str,
    fallback: str,
) -> dict[str, GuardGroupSummary]:
    grouped: dict[str, list[MatrixRowSummary]] = {}
    for row in rows:
        key = getattr(row, field_name) or fallback
        grouped.setdefault(key, []).append(row)
    return {key: _group_summary(grouped[key]) for key in sorted(grouped)}


def _group_summary(rows: list[MatrixRowSummary]) -> GuardGroupSummary:
    incidents = [row for row in rows if row.guard_violations_total > 0]
    blocked = [row for row in incidents if row.guard_blocked]
    return GuardGroupSummary(
        runs=len(rows),
        incident_runs=len(incidents),
        blocked_runs=len(blocked),
        audit_only_runs=len(incidents) - len(blocked),
        violations_total=sum(row.guard_violations_total for row in rows),
        filesystem_violations=sum(row.filesystem_guard_violations for row in rows),
        command_violations=sum(row.command_guard_violations for row in rows),
    )


def _guard_type_summary(
    rows: list[MatrixRowSummary],
    guard_type: str,
) -> GuardTypeSummary:
    count_field = f"{guard_type}_guard_violations"
    incident_rows = [row for row in rows if getattr(row, count_field) > 0]
    return GuardTypeSummary(
        incident_runs=len(incident_rows),
        blocked_runs=sum(
            row.guard_blocked and row.blocking_guard == guard_type
            for row in incident_rows
        ),
        violations_total=sum(getattr(row, count_field) for row in rows),
    )


def _safe_incident_reference(
    path: Optional[Path],
    run_dir: Optional[Path],
    report_dir: Path,
) -> Optional[str]:
    if path is None or run_dir is None:
        return None
    try:
        resolved_run_dir = run_dir.expanduser().resolve(strict=True)
        resolved_path = path.expanduser().resolve(strict=True)
        resolved_path.relative_to(resolved_run_dir)
    except (OSError, ValueError):
        return None
    if not resolved_path.is_file():
        return None
    return Path(os.path.relpath(resolved_path, report_dir.resolve())).as_posix()


def _row_sort_key(row: MatrixRowSummary) -> tuple[str, str, str, str, int, str]:
    return (
        row.task_id,
        row.benchmark_id or "",
        row.category or "",
        row.agent,
        row.trial_index,
        row.execution_id or "",
    )
