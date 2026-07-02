from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from agentguard.core.result import ReportPaths
from agentguard.guard.command import CommandGuardSummary
from agentguard.guard.filesystem import LiveGuardSummary, LiveGuardViolation
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.provenance.manifest import sanitize_text


INCIDENT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class GuardIncidentViolation:
    guard_type: str
    policy: str
    severity: str
    action: str
    detected_at: Optional[str]
    elapsed_ms: Optional[int]
    evidence_summary: str
    path: Optional[str] = None
    normalized_relative_path: Optional[str] = None
    command: Optional[str] = None
    matched_pattern: Optional[str] = None


@dataclass(frozen=True)
class GuardIncident:
    schema_version: int
    run_id: str
    task_id: str
    agent: str
    guard_mode: str
    result: str
    blocked: bool
    blocking_guard: Optional[str]
    started_at: str
    detected_at: Optional[str]
    completed_at: str
    time_to_first_violation_ms: Optional[int]
    time_to_block_ms: Optional[int]
    violations: list[GuardIncidentViolation]
    artifacts: dict[str, Optional[str]]
    redaction: dict[str, object]


@dataclass(frozen=True)
class GuardMetrics:
    guard_violations_total: int = 0
    guard_blocked: bool = False
    time_to_first_violation_ms: Optional[int] = None
    time_to_block_ms: Optional[int] = None
    filesystem_guard_violations: int = 0
    command_guard_violations: int = 0


@dataclass(frozen=True)
class GuardIncidentPaths:
    json: Path
    markdown: Path


def guard_metrics(
    filesystem: LiveGuardSummary,
    command: CommandGuardSummary,
) -> GuardMetrics:
    first = _first_elapsed(filesystem, command)
    block = _block_elapsed(filesystem, command)
    filesystem_count = len(filesystem.violations)
    command_count = len(command.violations)
    return GuardMetrics(
        guard_violations_total=filesystem_count + command_count,
        guard_blocked=filesystem.terminated_agent or command.terminated_agent,
        time_to_first_violation_ms=_ms(first),
        time_to_block_ms=_ms(block),
        filesystem_guard_violations=filesystem_count,
        command_guard_violations=command_count,
    )


def build_guard_incident(
    *,
    run_id: str,
    task_id: str,
    agent: str,
    guard_mode: str,
    result: str,
    started_at: str,
    completed_at: str,
    filesystem: LiveGuardSummary,
    command: CommandGuardSummary,
    report_paths: ReportPaths,
    sensitive_values: Optional[list[str]] = None,
) -> Optional[GuardIncident]:
    metrics = guard_metrics(filesystem, command)
    if metrics.guard_violations_total == 0:
        return None
    sensitive = sensitive_values or []
    violations = [
        *_filesystem_violations(filesystem, started_at, sensitive),
        *_command_violations(command, started_at, sensitive),
    ]
    violations = sorted(
        violations,
        key=lambda item: item.elapsed_ms if item.elapsed_ms is not None else -1,
    )
    detected_at = violations[0].detected_at if violations else None
    blocking_guard = None
    if filesystem.terminated_agent:
        blocking_guard = "filesystem"
    elif command.terminated_agent:
        blocking_guard = "command"
    return GuardIncident(
        schema_version=INCIDENT_SCHEMA_VERSION,
        run_id=run_id,
        task_id=sanitize_text(task_id, sensitive),
        agent=sanitize_text(agent, sensitive),
        guard_mode=guard_mode,
        result=result,
        blocked=metrics.guard_blocked,
        blocking_guard=blocking_guard,
        started_at=started_at,
        detected_at=detected_at,
        completed_at=completed_at,
        time_to_first_violation_ms=metrics.time_to_first_violation_ms,
        time_to_block_ms=metrics.time_to_block_ms,
        violations=violations,
        artifacts={
            "report_json": _path(report_paths.json),
            "report_markdown": _path(report_paths.markdown),
            "command_log": _path(report_paths.command_log),
            "manifest": _path(report_paths.manifest),
            "trace": _path(report_paths.trace),
        },
        redaction={
            "applied": bool(sensitive),
            "strategy": "agentguard.provenance.sanitize_text",
            "sensitive_values_count": len(sensitive),
        },
    )


def write_guard_incident(
    incident: GuardIncident,
    run_dir: Path,
) -> GuardIncidentPaths:
    guard_dir = run_dir / "guard"
    json_path = guard_dir / "incident.json"
    markdown_path = guard_dir / "incident.md"
    atomic_write_json(json_path, asdict(incident))
    atomic_write_text(markdown_path, render_guard_incident_markdown(incident))
    return GuardIncidentPaths(json=json_path, markdown=markdown_path)


def render_guard_incident_markdown(incident: GuardIncident) -> str:
    status = "Blocked" if incident.blocked else "Audit only"
    lines = [
        "# AgentGuard Guard Incident",
        "",
        f"- Run: {incident.run_id}",
        f"- Task: {incident.task_id}",
        f"- Agent: {incident.agent}",
        f"- Mode: {incident.guard_mode}",
        f"- Status: {status}",
        f"- Blocking guard: {incident.blocking_guard or '-'}",
        f"- Time to first violation: {_fmt_ms(incident.time_to_first_violation_ms)}",
        f"- Time to block: {_fmt_ms(incident.time_to_block_ms)}",
        "",
        "## Violations",
        "| Guard | Policy | Severity | Action | Elapsed | Evidence |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for violation in incident.violations:
        lines.append(
            "| "
            f"{violation.guard_type} | "
            f"{violation.policy} | "
            f"{violation.severity} | "
            f"{violation.action} | "
            f"{_fmt_ms(violation.elapsed_ms)} | "
            f"{_escape_table(violation.evidence_summary)} |"
        )
    lines.extend(
        [
            "",
            "## Artifacts",
            f"- JSON report: {incident.artifacts.get('report_json') or '-'}",
            f"- Markdown report: {incident.artifacts.get('report_markdown') or '-'}",
            f"- Command log: {incident.artifacts.get('command_log') or '-'}",
            f"- Manifest: {incident.artifacts.get('manifest') or '-'}",
            f"- Trace: {incident.artifacts.get('trace') or '-'}",
            "",
            "## Limitations",
            "- Filesystem guard uses polling and may miss very short-lived changes.",
            "- Command guard is event/log based, not syscall interception.",
            "- Secret content scanning remains a post-hoc policy check.",
            "",
        ]
    )
    return "\n".join(lines)


def incident_summary(incident: dict[str, object]) -> str:
    violations = incident.get("violations")
    count = len(violations) if isinstance(violations, list) else 0
    blocked = "blocked" if incident.get("blocked") else "audit"
    return "\n".join(
        [
            f"Guard incident: {incident.get('run_id')}",
            f"Status: {blocked}",
            f"Mode: {incident.get('guard_mode')}",
            f"Violations: {count}",
            "Time to first violation: "
            f"{_fmt_ms(_optional_int(incident.get('time_to_first_violation_ms')))}",
            f"Blocking guard: {incident.get('blocking_guard') or '-'}",
        ]
    )


def _filesystem_violations(
    summary: LiveGuardSummary,
    started_at: str,
    sensitive: list[str],
) -> list[GuardIncidentViolation]:
    return [
        GuardIncidentViolation(
            guard_type="filesystem",
            policy=_filesystem_policy(violation),
            severity=_filesystem_severity(violation),
            path=sanitize_text(violation.path, sensitive),
            normalized_relative_path=sanitize_text(violation.path, sensitive),
            action=_action(violation.action),
            detected_at=_timestamp(started_at, violation.observed_at),
            elapsed_ms=_ms(violation.observed_at),
            evidence_summary=sanitize_text(violation.message, sensitive),
        )
        for violation in summary.violations
    ]


def _command_violations(
    summary: CommandGuardSummary,
    started_at: str,
    sensitive: list[str],
) -> list[GuardIncidentViolation]:
    violations = []
    for violation in summary.violations:
        pattern = ", ".join(violation.matched_patterns) or None
        violations.append(
            GuardIncidentViolation(
                guard_type="command",
                policy="unsafe_commands",
                severity="critical",
                command=sanitize_text(violation.command_text, sensitive),
                matched_pattern=sanitize_text(pattern, sensitive) if pattern else None,
                action=_action(violation.action),
                detected_at=_timestamp(started_at, violation.observed_at),
                elapsed_ms=_ms(violation.observed_at),
                evidence_summary=sanitize_text(violation.message, sensitive),
            )
        )
    return violations


def _filesystem_policy(violation: LiveGuardViolation) -> str:
    return {
        "forbidden_path": "forbidden_paths",
        "test_tampering": "test_tampering",
        "out_of_scope_path": "scope_adherence",
        "secret_like_path": "secret_scan",
        "protected_deletion": "protected_deletion",
        "diff_size": "diff_size",
        "diff_lines_added": "diff_size",
        "diff_lines_deleted": "diff_size",
        "symlink_escape": "scope_adherence",
    }.get(violation.violation_type, violation.violation_type)


def _filesystem_severity(violation: LiveGuardViolation) -> str:
    return {
        "forbidden_path": "critical",
        "secret_like_path": "critical",
        "symlink_escape": "critical",
        "test_tampering": "error",
        "protected_deletion": "error",
        "out_of_scope_path": "warning",
        "diff_size": "warning",
        "diff_lines_added": "warning",
        "diff_lines_deleted": "warning",
    }.get(violation.violation_type, "warning")


def _first_elapsed(
    filesystem: LiveGuardSummary,
    command: CommandGuardSummary,
) -> Optional[float]:
    values = [
        value
        for value in [
            filesystem.first_violation_time,
            command.first_violation_time,
        ]
        if value is not None
    ]
    return min(values) if values else None


def _block_elapsed(
    filesystem: LiveGuardSummary,
    command: CommandGuardSummary,
) -> Optional[float]:
    values = []
    if filesystem.terminated_agent:
        values.append(filesystem.first_violation_time)
    if command.terminated_agent:
        values.append(command.first_violation_time)
    compact = [value for value in values if value is not None]
    return min(compact) if compact else None


def _timestamp(started_at: str, elapsed_seconds: float) -> Optional[str]:
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        return None
    return (started + timedelta(seconds=elapsed_seconds)).isoformat()


def _ms(value: Optional[float]) -> Optional[int]:
    if value is None:
        return None
    return max(0, int(round(value * 1000)))


def _optional_int(value: object) -> Optional[int]:
    return int(value) if isinstance(value, int) else None


def _fmt_ms(value: Optional[int]) -> str:
    return f"{value} ms" if value is not None else "-"


def _action(action: str) -> str:
    return "block" if action == "terminated" else "audit"


def _path(path: Optional[Path]) -> Optional[str]:
    return str(path) if path is not None else None


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
