import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from heapq import nlargest
from pathlib import Path
from typing import Any, Iterator, Optional

from agentguard.terminal import sanitize_terminal_text


REPORT_TYPES = {"run", "suite", "matrix", "ci"}
MAX_REPORT_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class ReportItem:
    type: str
    id: str
    name: str
    result: Optional[str]
    score: Optional[int]
    path: Path
    modified_at: str
    data: dict[str, Any]


def validate_report_type(report_type: Optional[str]) -> Optional[str]:
    if report_type is None:
        return None
    if report_type not in REPORT_TYPES:
        choices = ", ".join(sorted(REPORT_TYPES))
        raise ValueError(f"report type must be one of: {choices}.")
    return report_type


def discover_reports(
    root: Optional[Path] = None,
    report_type: Optional[str] = None,
    limit: Optional[int] = None,
) -> list[ReportItem]:
    validate_report_type(report_type)
    if limit is not None and limit <= 0:
        raise ValueError("report limit must be positive.")
    root = root or Path.cwd()
    agentguard_dir = root / ".agentguard"
    if not agentguard_dir.exists():
        return []

    patterns = {
        "run": "runs/*/reports/report.json",
        "suite": "suites/*/suite.json",
        "matrix": "matrices/*/matrix.json",
        "ci": "ci/*/report.json",
    }
    selected_types = [report_type] if report_type is not None else sorted(patterns)
    candidates = _report_candidates(agentguard_dir, patterns, selected_types)
    selected = (
        nlargest(limit, candidates)
        if limit is not None
        else sorted(candidates, reverse=True)
    )
    reports = []
    for _, _, path, selected_type in selected:
        item = _load_report_item(path, selected_type, root)
        if item is not None:
            reports.append(item)
    return reports


def _report_candidates(
    agentguard_dir: Path,
    patterns: dict[str, str],
    selected_types: list[str],
) -> Iterator[tuple[float, str, Path, str]]:
    for selected_type in selected_types:
        for path in agentguard_dir.glob(patterns[selected_type]):
            try:
                modified_at = path.stat().st_mtime
            except OSError:
                continue
            yield modified_at, str(path), path, selected_type


def latest_report(
    root: Optional[Path] = None,
    report_type: Optional[str] = None,
) -> Optional[ReportItem]:
    reports = discover_reports(root=root, report_type=report_type, limit=1)
    return reports[0] if reports else None


def load_report(path: Path, root: Optional[Path] = None) -> ReportItem:
    root = root or Path.cwd()
    resolved_path = path.expanduser()
    if not resolved_path.is_absolute():
        resolved_path = root / resolved_path
    data = _read_report_data(resolved_path)
    report_type = _infer_report_type(resolved_path, data)
    return _report_item_from_data(resolved_path, report_type, data, root)


def format_reports_table(reports: list[ReportItem]) -> str:
    if not reports:
        return "No reports found."

    lines = [
        "Recent AgentGuard Reports",
        "Type | ID | Name | Result | Score | Path",
        "--- | --- | --- | --- | ---: | ---",
    ]
    for report in reports:
        lines.append(
            " | ".join(
                [
                    report.type,
                    report.id,
                    report.name or "-",
                    report.result or "-",
                    _format_optional(report.score),
                    _relative_path(report.path),
                ]
            )
        )
    return sanitize_terminal_text("\n".join(lines))


def format_report_summary(report: ReportItem) -> str:
    if report.type == "matrix":
        summary = _format_matrix_summary(report)
    elif report.type == "suite":
        summary = _format_suite_summary(report)
    elif report.type == "ci":
        summary = _format_ci_summary(report)
    else:
        summary = _format_run_summary(report)
    return sanitize_terminal_text(summary)


def _load_report_item(
    path: Path,
    report_type: str,
    root: Path,
) -> Optional[ReportItem]:
    try:
        data = _read_report_data(path)
        return _report_item_from_data(path, report_type, data, root)
    except (OSError, ValueError):
        return None


def _read_report_data(path: Path) -> dict[str, Any]:
    with path.open("rb") as file:
        content = file.read(MAX_REPORT_BYTES + 1)
    if len(content) > MAX_REPORT_BYTES:
        raise ValueError(
            f"report exceeds the {MAX_REPORT_BYTES}-byte read limit: {path}"
        )
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"report is not valid UTF-8 JSON: {path}") from error
    if not isinstance(data, dict):
        raise ValueError("report JSON must be an object.")
    return data


def _report_item_from_data(
    path: Path,
    report_type: str,
    data: dict[str, Any],
    root: Path,
) -> ReportItem:
    return ReportItem(
        type=report_type,
        id=_report_id(path, report_type),
        name=_report_name(data, report_type),
        result=_report_result(data, report_type),
        score=_report_score(data, report_type),
        path=_display_path(path, root),
        modified_at=_modified_at(path),
        data=data,
    )


def _report_id(path: Path, report_type: str) -> str:
    if report_type == "run":
        return path.parent.parent.name
    return path.parent.name


def _report_name(data: dict[str, Any], report_type: str) -> str:
    if report_type in {"suite", "matrix"}:
        return str(data.get("suite_id") or _report_id_from_data(data) or "-")
    return str(data.get("task_id") or data.get("suite_id") or "-")


def _report_id_from_data(data: dict[str, Any]) -> Optional[str]:
    value = data.get("id")
    return str(value) if value is not None else None


def _report_result(data: dict[str, Any], report_type: str) -> Optional[str]:
    value = data.get("result")
    if value is not None:
        return str(value)
    if report_type in {"suite", "matrix"}:
        failed = data.get("failed")
        return "PASS" if failed == 0 else "FAIL"
    return None


def _report_score(data: dict[str, Any], report_type: str) -> Optional[int]:
    key = "average_score" if report_type in {"suite", "matrix"} else "score"
    value = data.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(round(value))
    return None


def _infer_report_type(path: Path, data: dict[str, Any]) -> str:
    parts = path.parts
    if "matrices" in parts or "matrix_id" in data:
        return "matrix"
    if "suites" in parts or "suite_id" in data or "average_score" in data:
        return "suite"
    if "ci" in parts or ("repo_dir" in data and "agent" not in data):
        return "ci"
    return "run"


def _display_path(path: Path, root: Path) -> Path:
    try:
        return path.relative_to(root)
    except ValueError:
        return path


def _relative_path(path: Path) -> str:
    return str(path)


def _modified_at(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")


def _format_optional(value: Optional[int]) -> str:
    return "-" if value is None else str(value)


def _format_run_summary(report: ReportItem) -> str:
    data = report.data
    lines = [
        "AgentGuard Run Report",
        f"Task: {data.get('task_id', '-')}",
        f"Agent: {data.get('agent', '-')}",
        f"Result: {data.get('result', '-')}",
        f"Score: {_format_score(data.get('score'))}",
        "Failed checks:",
        *_format_failed_checks(data),
        "Modified files:",
        *_format_changed_files(data),
        f"JSON path: {report.path}",
    ]
    markdown_path = _markdown_path(data)
    if markdown_path is not None:
        lines.append(f"Markdown path: {markdown_path}")
    return "\n".join(lines)


def _format_suite_summary(report: ReportItem) -> str:
    data = report.data
    lines = [
        "AgentGuard Suite Report",
        f"Suite: {data.get('suite_id', '-')}",
        f"Runs: {data.get('total_runs', '-')}",
        f"Passed: {data.get('passed', '-')}",
        f"Failed: {data.get('failed', '-')}",
        f"Pass rate: {_format_percent(data.get('pass_rate'))}",
        f"Average score: {_format_optional(_report_score(data, 'suite'))}",
    ]
    filters = _format_filters(data.get("filters"))
    if filters is not None:
        lines.append(f"Filters: {filters}")
    lines.extend(["Most common failed checks:", *_format_failed_check_counts(data)])
    lines.append(f"JSON path: {report.path}")
    markdown_path = data.get("markdown_report_path")
    if markdown_path is not None:
        lines.append(f"Markdown path: {markdown_path}")
    return "\n".join(lines)


def _format_matrix_summary(report: ReportItem) -> str:
    data = report.data
    reliability = data.get("reliability")
    reliability_data = reliability if isinstance(reliability, dict) else {}
    guard_summary = data.get("guard_summary")
    guard_data = guard_summary if isinstance(guard_summary, dict) else {}
    lines = [
        "AgentGuard Matrix Report",
        f"Matrix: {data.get('matrix_id', report.id)}",
        f"Suite: {data.get('suite_id', '-')}",
        f"Agents: {', '.join(_list_value(data.get('agents'))) or '-'}",
        f"Trials per combination: {data.get('trials', '-')}",
        (
            "Workers: "
            f"{data.get('effective_workers', '-')} effective / "
            f"{data.get('requested_workers', '-')} requested"
        ),
        (
            "Attempts: "
            f"{data.get('attempts_executed', '-')} executed / "
            f"{data.get('attempts_planned', '-')} planned"
        ),
        f"Passed: {data.get('passed', '-')}",
        f"Failed: {data.get('failed', '-')}",
        f"Pass rate: {_format_percent(data.get('pass_rate'))}",
        f"Average score: {_format_optional(_report_score(data, 'matrix'))}",
        (
            "Reliability success rate: "
            f"{_format_percent(reliability_data.get('success_rate'))}"
        ),
        f"Guard mode: {data.get('guard_mode', '-')}",
        (
            "Guard incidents: "
            f"{guard_data.get('incident_runs', 0)} runs / "
            f"{guard_data.get('blocked_runs', 0)} blocked / "
            f"{guard_data.get('violations_total', 0)} violations"
        ),
        f"Suite baseline: {_comparison_status(data.get('baseline_comparison'))}",
        (
            "Reliability baseline: "
            f"{_comparison_status(data.get('reliability_comparison'))}"
        ),
        "Most common failed checks:",
        *_format_failed_check_counts(data),
        f"JSON path: {report.path}",
    ]
    markdown_path = data.get("markdown_report_path")
    if markdown_path is not None:
        lines.append(f"Markdown path: {markdown_path}")
    return "\n".join(lines)


def _format_ci_summary(report: ReportItem) -> str:
    data = report.data
    diff_summary = data.get("diff_summary")
    diff = diff_summary if isinstance(diff_summary, dict) else {}
    lines = [
        "AgentGuard CI Report",
        f"Task: {data.get('task_id', '-')}",
        f"Result: {data.get('result', '-')}",
        f"Score: {_format_score(data.get('score'))}",
        "Failed checks:",
        *_format_failed_checks(data),
        "Files:",
        f"- Modified: {len(_list_value(diff.get('modified_files')))}",
        f"- Added: {len(_list_value(diff.get('added_files')))}",
        f"- Deleted: {len(_list_value(diff.get('deleted_files')))}",
        f"JSON path: {report.path}",
    ]
    markdown_path = _markdown_path(data)
    if markdown_path is not None:
        lines.append(f"Markdown path: {markdown_path}")
    return "\n".join(lines)


def _format_score(value: Any) -> str:
    if isinstance(value, (int, float)):
        return f"{value}/100"
    return "-"


def _format_percent(value: Any) -> str:
    if isinstance(value, (int, float)):
        return f"{value}%"
    return "-"


def _format_failed_checks(data: dict[str, Any]) -> list[str]:
    checks = data.get("check_results")
    if not isinstance(checks, list):
        return ["- None"]
    failed = []
    for check in checks:
        if isinstance(check, dict) and not check.get("passed", True):
            failed.append(str(check.get("name", "Unknown")))
    return [f"- {name}" for name in failed] if failed else ["- None"]


def _format_changed_files(data: dict[str, Any]) -> list[str]:
    diff_summary = data.get("diff_summary")
    if not isinstance(diff_summary, dict):
        return ["- None"]
    changed_files = _list_value(diff_summary.get("changed_files"))
    if not changed_files:
        changed_files = (
            _list_value(diff_summary.get("modified_files"))
            + _list_value(diff_summary.get("added_files"))
            + _list_value(diff_summary.get("deleted_files"))
        )
    return [f"- {path}" for path in changed_files] if changed_files else ["- None"]


def _format_failed_check_counts(data: dict[str, Any]) -> list[str]:
    counts = data.get("failed_check_counts")
    if isinstance(counts, dict) and counts:
        return [
            f"- {name}: {count}"
            for name, count in sorted(
                counts.items(),
                key=lambda item: -_count_value(item[1]),
            )
        ]
    runs = data.get("runs")
    if not isinstance(runs, list):
        return ["- None"]
    counter: Counter[str] = Counter()
    for run in runs:
        if isinstance(run, dict):
            counter.update(_list_value(run.get("failed_checks")))
    if not counter:
        return ["- None"]
    return [f"- {name}: {count}" for name, count in counter.most_common()]


def _format_filters(value: Any) -> Optional[str]:
    if not isinstance(value, dict) or not value:
        return None
    parts = []
    for key in ["category", "difficulty", "tags"]:
        item = value.get(key)
        if item:
            if isinstance(item, list):
                item = ",".join(str(part) for part in item)
            parts.append(f"{key}={item}")
    return ", ".join(parts) if parts else None


def _markdown_path(data: dict[str, Any]) -> Optional[str]:
    report_paths = data.get("report_paths")
    if isinstance(report_paths, dict) and report_paths.get("markdown") is not None:
        return str(report_paths["markdown"])
    value = data.get("markdown_report_path")
    return str(value) if value is not None else None


def _list_value(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _count_value(value: Any) -> int:
    return value if isinstance(value, int) else 0


def _comparison_status(value: Any) -> str:
    if not isinstance(value, dict):
        return "not compared"
    return "REGRESSION" if value.get("has_regressions") else "PASS"
