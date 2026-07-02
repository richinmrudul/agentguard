import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from agentguard.checks.registry import registered_checks
from agentguard.config.schema import VALID_SEVERITIES, AgentGuardConfig
from agentguard.core.result import BenchmarkResult, CheckResult, CommandResult
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.io import atomic_write_text
from agentguard.provenance.manifest import (
    SECRET_KEY_PATTERN,
    sanitize_arguments,
    sanitize_text,
    sha256_file,
)
from agentguard.scoring.scorer import DEDUCTIONS
from agentguard.traces.models import ReplayPolicySnapshot


TRACE_SCHEMA = "agentguard.execution-trace"
TRACE_SCHEMA_VERSION = 2
SUPPORTED_TRACE_SCHEMA_VERSIONS = {1, 2}
HASH_ALGORITHM = "sha256"
ZERO_HASH = "0" * 64
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EVENT_TYPES = {
    "execution_started",
    "agent_command",
    "guard_summary",
    "command_guard_summary",
    "guard_metrics",
    "file_change",
    "test_result",
    "check_result",
    "execution_completed",
}
MAX_STRING_CHARS = 4096
MAX_EVIDENCE_ITEMS = 64
MAX_CHANGED_FILES = 4096
MAX_DIFF_CHARS = 32768
MAX_PATTERNS = 64


@dataclass(frozen=True)
class TraceIntegrity:
    hash_algorithm: str
    root_hash: str
    final_event_hash: str


@dataclass(frozen=True)
class TraceSourceArtifact:
    role: str
    path: str
    sha256: str
    required: bool = False


@dataclass(frozen=True)
class TraceHeader:
    trace_id: str
    execution_id: str
    created_at: str
    source_execution_type: str
    agentguard_version: str
    agentguard_commit: Optional[str]
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    task_id: str
    agent_adapter: str
    agent_name: Optional[str]
    agent_model: Optional[str]
    agent_version: Optional[str]
    configuration_hash: str
    policy_summary: str
    sandbox_summary: str
    source_report_id: Optional[str]
    source_manifest_id: Optional[str]
    source_artifacts: list[TraceSourceArtifact]
    event_count: int
    integrity: TraceIntegrity
    policy_snapshot: Optional[ReplayPolicySnapshot] = None
    policy_snapshot_hash: Optional[str] = None
    schema: str = TRACE_SCHEMA
    schema_version: int = TRACE_SCHEMA_VERSION


@dataclass(frozen=True)
class TraceEvent:
    sequence: int
    event_type: str
    payload: dict[str, object]
    previous_event_hash: str
    event_hash: str
    relative_offset_seconds: Optional[float] = None


@dataclass(frozen=True)
class ExecutionTrace:
    header: TraceHeader
    events: list[TraceEvent]


@dataclass(frozen=True)
class TraceSourceStatus:
    role: str
    path: str
    status: str
    message: str


@dataclass(frozen=True)
class TraceVerificationResult:
    integrity_valid: bool
    source_statuses: list[TraceSourceStatus] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    malformed: bool = False
    strict_sources: bool = False

    @property
    def exit_code(self) -> int:
        if self.malformed or not self.integrity_valid:
            return 2
        mismatched = any(
            source.status == "changed" for source in self.source_statuses
        )
        missing_strict = self.strict_sources and any(
            source.status == "unavailable" for source in self.source_statuses
        )
        return 1 if mismatched or missing_strict else 0


@dataclass(frozen=True)
class TraceExportOptions:
    include_diff: bool = False
    force: bool = False


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_policy_snapshot(config: AgentGuardConfig) -> ReplayPolicySnapshot:
    default_severities = {
        "tests-passed": "error",
        "forbidden-paths": "critical",
        "test-tampering": "error",
        "unsafe-commands": "critical",
        "scope-adherence": "warning",
        "diff-size": "warning",
        "secret-scan": "critical",
    }
    config_keys = {
        "tests-passed": "tests_pass",
        "forbidden-paths": "forbidden_paths",
        "test-tampering": "test_tampering",
        "unsafe-commands": "unsafe_commands",
        "scope-adherence": "scope_adherence",
        "diff-size": "diff_size",
        "secret-scan": "secret_scan",
    }
    enabled = [registration.identifier for registration in registered_checks()]
    sensitive_values = [
        value for value in config.agent_environment.values() if value
    ] + [
        str(value)
        for key, value in config.agent_metadata.items()
        if SECRET_KEY_PATTERN.search(key) and str(value)
    ]
    redacted_inputs = []

    def sanitized_patterns(values: list[str], field_name: str) -> list[str]:
        sanitized = [
            sanitize_text(value, sensitive_values) for value in values
        ]
        if sanitized != values:
            redacted_inputs.append(field_name)
        return sanitized

    return ReplayPolicySnapshot(
        enabled_checks=enabled,
        severities={
            identifier: config.severity_for(
                config_keys[identifier],
                default_severities[identifier],
            )
            for identifier in enabled
        },
        score_weights=dict(DEDUCTIONS),
        forbidden_paths=sanitized_patterns(
            config.forbidden_paths,
            "forbidden_paths",
        ),
        allowed_paths=sanitized_patterns(config.allowed_paths, "allowed_paths"),
        test_paths=sanitized_patterns(config.test_paths, "test_paths"),
        unsafe_commands=sanitized_patterns(
            config.unsafe_commands,
            "unsafe_commands",
        ),
        secret_patterns=sanitized_patterns(
            config.secret_patterns,
            "secret_patterns",
        ),
        expected_modified_files_min=config.expected_modified_files.min,
        expected_modified_files_max=config.expected_modified_files.max,
        max_files_changed=config.diff_limits.max_files_changed,
        max_lines_added=config.diff_limits.max_lines_added,
        max_lines_deleted=config.diff_limits.max_lines_deleted,
        command_policy_mode=config.command_policy.mode,
        command_policy_patterns=sanitized_patterns(
            config.unsafe_commands,
            "command_policy_patterns",
        ),
        redacted_inputs=redacted_inputs,
    )


def policy_snapshot_hash(snapshot: ReplayPolicySnapshot) -> str:
    return _sha256_text(canonical_json(asdict(snapshot)))


def _bounded_text(
    value: str,
    sensitive_values: Optional[list[str]] = None,
    *,
    limit: int = MAX_STRING_CHARS,
) -> tuple[str, bool]:
    sanitized = sanitize_text(value, sensitive_values)
    if len(sanitized) <= limit:
        return sanitized, False
    return sanitized[:limit], True


def _safe_evidence(
    values: list[str],
    sensitive_values: Optional[list[str]],
) -> tuple[list[str], bool]:
    truncated = len(values) > MAX_EVIDENCE_ITEMS
    bounded = []
    for value in values[:MAX_EVIDENCE_ITEMS]:
        text, text_truncated = _bounded_text(value, sensitive_values)
        bounded.append(text)
        truncated = truncated or text_truncated
    return bounded, truncated


def _normalized_path(value: str) -> str:
    candidate = value.replace("\\", "/")
    path = PurePosixPath(candidate)
    if (
        not candidate
        or candidate.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"Trace path must be repository-relative: {value!r}.")
    normalized = path.as_posix()
    if len(normalized) > MAX_STRING_CHARS:
        raise ValueError("Trace path exceeds the maximum length.")
    return normalized


def _working_directory_role(cwd: str, result: BenchmarkResult) -> str:
    if not cwd:
        return "unspecified"
    try:
        resolved = Path(cwd).expanduser().resolve()
        if resolved == result.repo_dir.expanduser().resolve():
            return "repository"
        if resolved == result.run_dir.expanduser().resolve():
            return "run"
        if resolved == result.config_path.parent.expanduser().resolve():
            return "configuration"
    except OSError:
        pass
    return "external"


def _portable_text(value: str, result: BenchmarkResult) -> str:
    replacements = [
        (result.repo_dir, "${REPOSITORY_ROOT}"),
        (result.run_dir, "${RUN_ROOT}"),
        (result.config_path.parent, "${CONFIG_ROOT}"),
        (Path.cwd(), "${AGENTGUARD_ROOT}"),
    ]
    portable = value
    for path, role in replacements:
        try:
            variants = {str(path), str(path.expanduser().resolve())}
        except OSError:
            variants = {str(path)}
        for variant in sorted(variants, key=len, reverse=True):
            if variant:
                portable = portable.replace(variant, role)
    return portable


def _output_identity(
    value: str,
    sensitive_values: Optional[list[str]],
    truncated: bool,
) -> dict[str, object]:
    sanitized = sanitize_text(value, sensitive_values)
    encoded = sanitized.encode("utf-8")
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "bytes": len(encoded),
        "truncated": truncated,
    }


def _command_payload(
    event: CommandEvent,
    result: BenchmarkResult,
    sensitive_values: Optional[list[str]],
) -> dict[str, object]:
    argv = [
        _portable_text(argument, result)
        for argument in sanitize_arguments(event.command, sensitive_values)
    ]
    command, command_truncated = _bounded_text(
        _portable_text(event.command_text, result)
        if event.command_text
        else shlex.join(argv),
        sensitive_values,
    )
    patterns, patterns_truncated = _safe_evidence(
        event.preflight_matched_patterns[:MAX_PATTERNS],
        sensitive_values,
    )
    return {
        "argv": argv[:128],
        "command": command,
        "working_directory_role": _working_directory_role(event.cwd, result),
        "exit_code": event.exit_code,
        "duration_seconds": event.duration_seconds,
        "executed": event.executed,
        "blocked": event.blocked,
        "timed_out": event.timed_out,
        "stdout": _output_identity(
            event.stdout,
            sensitive_values,
            event.stdout_truncated,
        ),
        "stderr": _output_identity(
            event.stderr,
            sensitive_values,
            event.stderr_truncated,
        ),
        "preflight": {
            "mode": event.policy_mode,
            "blocked": event.preflight_blocked,
            "matched_patterns": patterns,
        },
        "agent": event.agent_name or result.agent,
        "truncation": {
            "command": command_truncated,
            "argv": len(argv) > 128,
            "patterns": patterns_truncated,
        },
    }


def _git_bytes(repo_dir: Path, *args: str) -> Optional[bytes]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_dir,
            check=False,
            capture_output=True,
        )
    except OSError:
        return None
    return completed.stdout if completed.returncode == 0 else None


def _hash_bytes(value: Optional[bytes]) -> Optional[str]:
    if value is None:
        return None
    return hashlib.sha256(value).hexdigest()


def _mode_from_git(repo_dir: Path, path: str) -> Optional[str]:
    output = _git_bytes(repo_dir, "ls-tree", "HEAD", "--", path)
    if not output:
        return None
    first = output.decode("utf-8", errors="replace").split(maxsplit=1)[0]
    return first if first.isdigit() else None


def _current_file_identity(
    repo_dir: Path,
    path: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    candidate = repo_dir / path
    try:
        file_stat = candidate.lstat()
    except OSError:
        return None, None, None
    if candidate.is_symlink():
        target = os.readlink(candidate)
        safe_target = "[ABSOLUTE_TARGET]" if Path(target).is_absolute() else target
        safe_target, _ = _bounded_text(safe_target)
        return _sha256_text(target), "120000", safe_target
    if candidate.is_file():
        mode = "100755" if file_stat.st_mode & stat.S_IXUSR else "100644"
        try:
            return sha256_file(candidate), mode, None
        except OSError:
            return None, mode, None
    return None, None, None


def _line_stats(repo_dir: Path, path: str) -> tuple[int, int]:
    output = _git_bytes(repo_dir, "diff", "HEAD", "--numstat", "--", path)
    if not output:
        candidate = repo_dir / path
        if candidate.is_file() and not candidate.is_symlink():
            try:
                return len(
                    candidate.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ).splitlines()
                ), 0
            except OSError:
                pass
        return 0, 0
    parts = output.decode("utf-8", errors="replace").strip().split("\t")
    if len(parts) < 2:
        return 0, 0
    added = int(parts[0]) if parts[0].isdigit() else 0
    deleted = int(parts[1]) if parts[1].isdigit() else 0
    return added, deleted


def _diff_for_path(
    repo_dir: Path,
    path: str,
    sensitive_values: Optional[list[str]],
) -> tuple[Optional[str], bool]:
    output = _git_bytes(repo_dir, "diff", "HEAD", "--", path) or b""
    if not output and (repo_dir / path).is_file():
        try:
            content = (repo_dir / path).read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            content = ""
        output = (
            f"--- /dev/null\n+++ b/{path}\n"
            + "\n".join(f"+{line}" for line in content.splitlines())
        ).encode("utf-8")
    text, truncated = _bounded_text(
        output.decode("utf-8", errors="replace"),
        sensitive_values,
        limit=MAX_DIFF_CHARS,
    )
    return (text or None), truncated


def _file_payloads(
    result: BenchmarkResult,
    sensitive_values: Optional[list[str]],
    include_diff: bool,
) -> list[dict[str, object]]:
    changes = [
        ("modified", path) for path in result.diff_summary.modified_files
    ]
    changes.extend(("added", path) for path in result.diff_summary.added_files)
    changes.extend(("deleted", path) for path in result.diff_summary.deleted_files)
    if len(changes) > MAX_CHANGED_FILES:
        raise ValueError("Trace has too many changed files.")
    payloads = []
    for change_type, raw_path in changes:
        path = _normalized_path(raw_path)
        old_content = _git_bytes(result.repo_dir, "show", f"HEAD:{path}")
        new_hash, new_mode, symlink_target = _current_file_identity(
            result.repo_dir,
            path,
        )
        old_mode = _mode_from_git(result.repo_dir, path)
        if symlink_target is not None or old_mode == "120000":
            change_type = "symlink"
        lines_added, lines_deleted = _line_stats(result.repo_dir, path)
        payload: dict[str, object] = {
            "path": path,
            "change_type": change_type,
            "old_content_sha256": _hash_bytes(old_content),
            "new_content_sha256": new_hash,
            "old_mode": old_mode,
            "new_mode": new_mode,
            "lines_added": lines_added,
            "lines_deleted": lines_deleted,
            "symlink_target": symlink_target,
            "diff_included": include_diff,
        }
        if include_diff:
            diff, truncated = _diff_for_path(
                result.repo_dir,
                path,
                sensitive_values,
            )
            payload["unified_diff"] = diff
            payload["diff_truncated"] = truncated
        payloads.append(payload)
    return payloads


def _test_payload(
    test_result: CommandResult,
    result: BenchmarkResult,
    sensitive_values: Optional[list[str]],
) -> dict[str, object]:
    command, command_truncated = _bounded_text(
        _portable_text(
            " ".join(sanitize_arguments(test_result.command, sensitive_values)),
            result,
        ),
        sensitive_values,
    )
    return {
        "command": command,
        "exit_code": test_result.exit_code,
        "duration_seconds": test_result.duration_seconds,
        "timed_out": test_result.timed_out,
        "functional_pass": test_result.exit_code == 0 and not test_result.timed_out,
        "stdout": _output_identity(
            test_result.stdout,
            sensitive_values,
            test_result.stdout_truncated,
        ),
        "stderr": _output_identity(
            test_result.stderr,
            sensitive_values,
            test_result.stderr_truncated,
        ),
        "truncation": {"command": command_truncated},
    }


def _check_payload(
    check: CheckResult,
    result: BenchmarkResult,
    sensitive_values: Optional[list[str]],
) -> dict[str, object]:
    message, message_truncated = _bounded_text(
        _portable_text(check.message, result),
        sensitive_values,
    )
    evidence, evidence_truncated = _safe_evidence(
        [_portable_text(item, result) for item in check.evidence],
        sensitive_values,
    )
    return {
        "name": check.name,
        "passed": check.passed,
        "severity": check.severity,
        "score_contribution": (
            0 if check.passed else -DEDUCTIONS.get(check.severity, 0)
        ),
        "message": message,
        "evidence": evidence,
        "truncation": {
            "message": message_truncated,
            "evidence": evidence_truncated,
        },
    }


def _source_artifact(
    role: str,
    path: Optional[Path],
    *,
    required: bool = False,
) -> Optional[TraceSourceArtifact]:
    if path is None or not path.is_file():
        return None
    stable_paths = {
        "report": "reports/report.json",
        "manifest": "manifest.json",
        "command_log": "command_log.json",
    }
    relative = stable_paths.get(role, path.name)
    return TraceSourceArtifact(
        role=role,
        path=relative,
        sha256=sha256_file(path),
        required=required,
    )


def _header_identity(header: TraceHeader) -> dict[str, object]:
    data = asdict(header)
    data.pop("trace_id")
    data.pop("integrity")
    if header.schema_version == 1:
        data.pop("policy_snapshot")
        data.pop("policy_snapshot_hash")
    return data


def _event_hash(
    sequence: int,
    event_type: str,
    payload: dict[str, object],
    previous_event_hash: str,
    relative_offset_seconds: Optional[float],
    schema_version: int = TRACE_SCHEMA_VERSION,
) -> str:
    context = {
        "schema": TRACE_SCHEMA,
        "schema_version": schema_version,
        "sequence": sequence,
        "event_type": event_type,
        "payload": payload,
        "previous_event_hash": previous_event_hash,
        "relative_offset_seconds": relative_offset_seconds,
    }
    return _sha256_text(canonical_json(context))


def _chain_events(
    event_values: list[tuple[str, dict[str, object]]],
    *,
    schema_version: int = TRACE_SCHEMA_VERSION,
) -> list[TraceEvent]:
    previous = ZERO_HASH
    events = []
    for sequence, (event_type, payload) in enumerate(event_values, start=1):
        event_hash = _event_hash(
            sequence,
            event_type,
            payload,
            previous,
            None,
            schema_version,
        )
        events.append(
            TraceEvent(
                sequence=sequence,
                event_type=event_type,
                payload=payload,
                previous_event_hash=previous,
                event_hash=event_hash,
            )
        )
        previous = event_hash
    return events


def rehash_execution_trace(trace: ExecutionTrace) -> ExecutionTrace:
    previous = ZERO_HASH
    events = []
    for event in trace.events:
        event_hash = _event_hash(
            event.sequence,
            event.event_type,
            event.payload,
            previous,
            event.relative_offset_seconds,
            trace.header.schema_version,
        )
        events.append(
            TraceEvent(
                sequence=event.sequence,
                event_type=event.event_type,
                payload=event.payload,
                previous_event_hash=previous,
                event_hash=event_hash,
                relative_offset_seconds=event.relative_offset_seconds,
            )
        )
        previous = event_hash
    provisional = TraceHeader(
        **{
            **asdict(trace.header),
            "trace_id": ZERO_HASH,
            "source_artifacts": trace.header.source_artifacts,
            "policy_snapshot": trace.header.policy_snapshot,
            "integrity": TraceIntegrity(
                hash_algorithm=HASH_ALGORITHM,
                root_hash=ZERO_HASH,
                final_event_hash=previous,
            ),
        }
    )
    root_hash = _sha256_text(
        canonical_json(
            {
                "header": _header_identity(provisional),
                "final_event_hash": previous,
            }
        )
    )
    header = TraceHeader(
        **{
            **asdict(provisional),
            "trace_id": root_hash,
            "source_artifacts": provisional.source_artifacts,
            "policy_snapshot": provisional.policy_snapshot,
            "integrity": TraceIntegrity(
                hash_algorithm=HASH_ALGORITHM,
                root_hash=root_hash,
                final_event_hash=previous,
            ),
        }
    )
    return ExecutionTrace(header=header, events=events)


def build_execution_trace(
    result: BenchmarkResult,
    *,
    created_at: str,
    configuration_hash: str,
    agentguard_version: str,
    agentguard_commit: Optional[str],
    agent_version: Optional[str],
    policy_summary: str,
    sandbox_summary: str,
    source_report_id: Optional[str],
    source_manifest_id: Optional[str],
    policy_snapshot: ReplayPolicySnapshot,
    execution_duration_seconds: Optional[float] = None,
    include_diff: bool = False,
    sensitive_values: Optional[list[str]] = None,
) -> ExecutionTrace:
    event_values: list[tuple[str, dict[str, object]]] = [
        (
            "execution_started",
            {
                "task_id": result.task_id,
                "execution_id": result.execution_id or result.run_dir.name,
                "source_execution_type": "run",
            },
        )
    ]
    event_values.extend(
        (
            "agent_command",
            _command_payload(event, result, sensitive_values),
        )
        for event in result.command_events
    )
    if (
        result.guard_summary.mode != "off"
        or result.guard_summary.configured_ignore_patterns
    ):
        event_values.append(
            (
                "guard_summary",
                {
                    "mode": result.guard_summary.mode,
                    "triggered": result.guard_summary.triggered,
                    "terminated_agent": result.guard_summary.terminated_agent,
                    "kill_required": result.guard_summary.kill_required,
                    "files_observed": result.guard_summary.files_observed,
                    "scan_count": result.guard_summary.scan_count,
                    "monitor_duration_seconds": (
                        result.guard_summary.monitor_duration_seconds
                    ),
                    "configured_ignore_patterns": list(
                        result.guard_summary.configured_ignore_patterns
                    ),
                    "live_lines_added": result.guard_summary.live_lines_added,
                    "live_lines_deleted": result.guard_summary.live_lines_deleted,
                    "line_measurement_complete": (
                        result.guard_summary.line_measurement_complete
                    ),
                    "line_measurement_skipped_files": (
                        result.guard_summary.line_measurement_skipped_files
                    ),
                    "line_measurement_error": (
                        sanitize_text(
                            result.guard_summary.line_measurement_error,
                            sensitive_values,
                        )[:MAX_STRING_CHARS]
                        if result.guard_summary.line_measurement_error
                        else None
                    ),
                    "violations": [
                        {
                            "violation_type": violation.violation_type,
                            "path": _normalized_path(violation.path)
                            if violation.path != "(workspace)"
                            else violation.path,
                            "message": sanitize_text(
                                violation.message,
                                sensitive_values,
                            ),
                            "action": violation.action,
                        }
                        for violation in result.guard_summary.violations
                    ],
                },
            )
        )
    if result.command_guard_summary.mode != "off":
        event_values.append(
            (
                "command_guard_summary",
                {
                    "mode": result.command_guard_summary.mode,
                    "triggered": result.command_guard_summary.triggered,
                    "terminated_agent": (
                        result.command_guard_summary.terminated_agent
                    ),
                    "kill_required": result.command_guard_summary.kill_required,
                    "events_observed": (
                        result.command_guard_summary.events_observed
                    ),
                    "scan_count": result.command_guard_summary.scan_count,
                    "monitor_duration_seconds": (
                        result.command_guard_summary.monitor_duration_seconds
                    ),
                    "event_file": result.command_guard_summary.event_file,
                    "violations": [
                        {
                            "violation_type": violation.violation_type,
                            "command_text": sanitize_text(
                                violation.command_text,
                                sensitive_values,
                            ),
                            "matched_patterns": [
                                sanitize_text(pattern, sensitive_values)
                                for pattern in violation.matched_patterns
                            ],
                            "message": sanitize_text(
                                violation.message,
                                sensitive_values,
                            ),
                            "action": violation.action,
                        }
                        for violation in result.command_guard_summary.violations
                    ],
                },
            )
        )
    if int(result.guard_metrics.get("guard_violations_total") or 0) > 0:
        event_values.append(("guard_metrics", dict(result.guard_metrics)))
    event_values.extend(
        ("file_change", payload)
        for payload in _file_payloads(
            result,
            sensitive_values,
            include_diff,
        )
    )
    event_values.append(
        (
            "test_result",
            _test_payload(result.test_result, result, sensitive_values),
        )
    )
    event_values.extend(
        (
            "check_result",
            _check_payload(check, result, sensitive_values),
        )
        for check in result.check_results
    )
    failed = [check.name for check in result.check_results if not check.passed]
    warnings = [
        check.name
        for check in result.check_results
        if not check.passed and check.severity == "warning"
    ]
    event_values.append(
        (
            "execution_completed",
            {
                "result": result.result,
                "score": result.score,
                "modified_files": {
                    "count": len(result.diff_summary.changed_files),
                    "paths": result.diff_summary.changed_files[
                        :MAX_CHANGED_FILES
                    ],
                    "truncated": (
                        len(result.diff_summary.changed_files)
                        > MAX_CHANGED_FILES
                    ),
                    "lines_added": result.diff_summary.lines_added,
                    "lines_deleted": result.diff_summary.lines_deleted,
                },
                "failed_checks": failed,
                "warning_checks": warnings,
                "duration_seconds": (
                    execution_duration_seconds
                    if execution_duration_seconds is not None
                    else sum(
                        event.duration_seconds or 0.0
                        for event in result.command_events
                    )
                ),
                "source_report_sha256": (
                    sha256_file(result.report_paths.json)
                    if result.report_paths.json.is_file()
                    else None
                ),
                "source_manifest_sha256": (
                    sha256_file(result.report_paths.manifest)
                    if result.report_paths.manifest is not None
                    and result.report_paths.manifest.is_file()
                    else None
                ),
            },
        )
    )
    events = _chain_events(event_values)
    sources = [
        source
        for source in [
            _source_artifact(
                "report",
                result.report_paths.json,
                required=True,
            ),
            _source_artifact(
                "manifest",
                result.report_paths.manifest,
            ),
            _source_artifact(
                "command_log",
                result.report_paths.command_log,
            ),
            _source_artifact(
                "guard_incident",
                result.report_paths.guard_incident_json,
            ),
            _source_artifact(
                "guard_incident_markdown",
                result.report_paths.guard_incident_markdown,
            ),
        ]
        if source is not None
    ]
    provisional = TraceHeader(
        trace_id=ZERO_HASH,
        execution_id=result.execution_id or result.run_dir.name,
        created_at=created_at,
        source_execution_type="run",
        agentguard_version=agentguard_version,
        agentguard_commit=agentguard_commit,
        benchmark_id=result.benchmark.id,
        benchmark_version=result.benchmark.version,
        task_id=result.task_id,
        agent_adapter=result.agent,
        agent_name=result.profile_name or result.agent,
        agent_model=result.profile_model,
        agent_version=agent_version,
        configuration_hash=configuration_hash,
        policy_summary=policy_summary,
        sandbox_summary=sandbox_summary,
        source_report_id=source_report_id,
        source_manifest_id=source_manifest_id,
        source_artifacts=sources,
        event_count=len(events),
        policy_snapshot=policy_snapshot,
        policy_snapshot_hash=policy_snapshot_hash(policy_snapshot),
        integrity=TraceIntegrity(
            hash_algorithm=HASH_ALGORITHM,
            root_hash=ZERO_HASH,
            final_event_hash=events[-1].event_hash,
        ),
    )
    root_hash = _sha256_text(
        canonical_json(
            {
                "header": _header_identity(provisional),
                "final_event_hash": events[-1].event_hash,
            }
        )
    )
    header = TraceHeader(
        **{
            **asdict(provisional),
            "trace_id": root_hash,
            "source_artifacts": sources,
            "policy_snapshot": provisional.policy_snapshot,
            "integrity": TraceIntegrity(
                hash_algorithm=HASH_ALGORITHM,
                root_hash=root_hash,
                final_event_hash=events[-1].event_hash,
            ),
        }
    )
    return ExecutionTrace(header=header, events=events)


def serialize_execution_trace(trace: ExecutionTrace) -> str:
    header_data = asdict(trace.header)
    if trace.header.schema_version == 1:
        header_data.pop("policy_snapshot")
        header_data.pop("policy_snapshot_hash")
    header = {"record_type": "header", **header_data}
    lines = [canonical_json(header)]
    lines.extend(
        canonical_json({"record_type": "event", **asdict(event)})
        for event in trace.events
    )
    return "\n".join(lines) + "\n"


def write_execution_trace(
    trace: ExecutionTrace,
    path: Path,
    *,
    force: bool = True,
) -> Path:
    if path.exists() and not force:
        raise FileExistsError(f"Trace output already exists: {path}")
    return atomic_write_text(path, serialize_execution_trace(trace))


def _require_exact_fields(
    data: dict[str, Any],
    expected: set[str],
    label: str,
) -> None:
    actual = set(data)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if unknown:
            details.append(f"unknown {', '.join(unknown)}")
        raise ValueError(f"Invalid {label} fields: {'; '.join(details)}.")


def _parse_source_artifact(data: object) -> TraceSourceArtifact:
    if not isinstance(data, dict):
        raise ValueError("Trace source artifact must be an object.")
    _require_exact_fields(
        data,
        {"role", "path", "sha256", "required"},
        "source artifact",
    )
    source = TraceSourceArtifact(**data)
    _validate_sha256(source.sha256, "source artifact hash")
    if Path(source.path).is_absolute():
        raise ValueError("Trace source artifact paths must be relative.")
    return source


def _parse_header(data: dict[str, Any]) -> TraceHeader:
    base_expected = {
        "record_type",
        "trace_id",
        "execution_id",
        "created_at",
        "source_execution_type",
        "agentguard_version",
        "agentguard_commit",
        "benchmark_id",
        "benchmark_version",
        "task_id",
        "agent_adapter",
        "agent_name",
        "agent_model",
        "agent_version",
        "configuration_hash",
        "policy_summary",
        "sandbox_summary",
        "source_report_id",
        "source_manifest_id",
        "source_artifacts",
        "event_count",
        "integrity",
        "schema",
        "schema_version",
    }
    schema_version = data.get("schema_version")
    expected = set(base_expected)
    if schema_version == 2:
        expected.update({"policy_snapshot", "policy_snapshot_hash"})
    _require_exact_fields(data, expected, "trace header")
    if data.pop("record_type") != "header":
        raise ValueError("First trace record must be a header.")
    integrity_data = data.pop("integrity")
    source_data = data.pop("source_artifacts")
    snapshot_data = data.pop("policy_snapshot", None)
    snapshot_hash = data.pop("policy_snapshot_hash", None)
    if not isinstance(integrity_data, dict):
        raise ValueError("Trace integrity must be an object.")
    _require_exact_fields(
        integrity_data,
        {"hash_algorithm", "root_hash", "final_event_hash"},
        "trace integrity",
    )
    if not isinstance(source_data, list):
        raise ValueError("Trace source_artifacts must be a list.")
    snapshot = None
    if snapshot_data is not None:
        if not isinstance(snapshot_data, dict):
            raise ValueError("Trace policy snapshot must be an object.")
        _require_exact_fields(
            snapshot_data,
            {
                "enabled_checks",
                "severities",
                "score_weights",
                "forbidden_paths",
                "allowed_paths",
                "test_paths",
                "unsafe_commands",
                "secret_patterns",
                "expected_modified_files_min",
                "expected_modified_files_max",
                "max_files_changed",
                "max_lines_added",
                "max_lines_deleted",
                "command_policy_mode",
                "command_policy_patterns",
                "redacted_inputs",
            },
            "trace policy snapshot",
        )
        try:
            snapshot = ReplayPolicySnapshot(**snapshot_data)
        except TypeError as error:
            raise ValueError(f"Invalid trace policy snapshot: {error}") from error
    return TraceHeader(
        **data,
        source_artifacts=[_parse_source_artifact(item) for item in source_data],
        integrity=TraceIntegrity(**integrity_data),
        policy_snapshot=snapshot,
        policy_snapshot_hash=snapshot_hash,
    )


def _parse_event(data: dict[str, Any]) -> TraceEvent:
    _require_exact_fields(
        data,
        {
            "record_type",
            "sequence",
            "event_type",
            "payload",
            "previous_event_hash",
            "event_hash",
            "relative_offset_seconds",
        },
        "trace event",
    )
    if data.pop("record_type") != "event":
        raise ValueError("Non-header trace records must be events.")
    if not isinstance(data.get("payload"), dict):
        raise ValueError("Trace event payload must be an object.")
    return TraceEvent(**data)


def load_execution_trace(path: Path) -> ExecutionTrace:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"Unable to read trace: {error}") from error
    if not content.endswith("\n"):
        raise ValueError("Trace is truncated: final newline is missing.")
    lines = content.splitlines()
    if len(lines) < 2:
        raise ValueError("Trace must contain a header and events.")
    records = []
    for line_number, line in enumerate(lines, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Invalid trace JSON on line {line_number}: {error}"
            ) from error
        if not isinstance(record, dict):
            raise ValueError(f"Trace line {line_number} must be an object.")
        records.append(record)
    header = _parse_header(records[0])
    events = [_parse_event(record) for record in records[1:]]
    return ExecutionTrace(header=header, events=events)


def _validate_sha256(value: object, label: str) -> None:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"Invalid {label}.")


def _validate_bounds(value: object, key: Optional[str] = None) -> None:
    if isinstance(value, str):
        limit = MAX_DIFF_CHARS if key == "unified_diff" else MAX_STRING_CHARS
        if len(value) > limit:
            raise ValueError(f"Trace string field {key or '<value>'} is too long.")
        return
    if isinstance(value, list):
        if len(value) > MAX_CHANGED_FILES:
            raise ValueError(f"Trace list field {key or '<value>'} is too long.")
        for item in value:
            _validate_bounds(item, key)
        return
    if isinstance(value, dict):
        for child_key, item in value.items():
            if not isinstance(child_key, str):
                raise ValueError("Trace object keys must be strings.")
            _validate_bounds(item, child_key)


def _validate_output_identity(value: object, label: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"Trace {label} identity must be an object.")
    _require_exact_fields(value, {"sha256", "bytes", "truncated"}, label)
    _validate_sha256(value["sha256"], f"{label} hash")
    if not isinstance(value["bytes"], int) or value["bytes"] < 0:
        raise ValueError(f"Trace {label} byte count must be nonnegative.")
    if not isinstance(value["truncated"], bool):
        raise ValueError(f"Trace {label} truncation flag must be boolean.")


def _validate_policy_snapshot(snapshot: ReplayPolicySnapshot) -> None:
    string_lists = [
        snapshot.enabled_checks,
        snapshot.forbidden_paths,
        snapshot.allowed_paths,
        snapshot.test_paths,
        snapshot.unsafe_commands,
        snapshot.secret_patterns,
        snapshot.command_policy_patterns,
        snapshot.redacted_inputs,
    ]
    if any(
        not isinstance(values, list)
        or any(not isinstance(value, str) for value in values)
        for values in string_lists
    ):
        raise ValueError("Trace policy snapshot lists must contain strings.")
    if not isinstance(snapshot.severities, dict) or any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or value not in VALID_SEVERITIES
        for key, value in snapshot.severities.items()
    ):
        raise ValueError("Trace policy severities are invalid.")
    if not isinstance(snapshot.score_weights, dict) or any(
        not isinstance(key, str)
        or not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        for key, value in snapshot.score_weights.items()
    ):
        raise ValueError("Trace score weights must be nonnegative integers.")
    if (
        not isinstance(snapshot.expected_modified_files_min, int)
        or not isinstance(snapshot.expected_modified_files_max, int)
        or isinstance(snapshot.expected_modified_files_min, bool)
        or isinstance(snapshot.expected_modified_files_max, bool)
        or snapshot.expected_modified_files_min < 0
        or snapshot.expected_modified_files_max
        < snapshot.expected_modified_files_min
    ):
        raise ValueError("Trace expected modified-file bounds are invalid.")
    for value in (
        snapshot.max_files_changed,
        snapshot.max_lines_added,
        snapshot.max_lines_deleted,
    ):
        if value is not None and (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise ValueError("Trace diff thresholds must be nonnegative integers.")
    if snapshot.command_policy_mode not in {"audit", "enforce"}:
        raise ValueError("Trace command policy mode is invalid.")


def _validate_payload(event: TraceEvent) -> None:
    expected = {
        "execution_started": {
            "task_id",
            "execution_id",
            "source_execution_type",
        },
        "agent_command": {
            "argv",
            "command",
            "working_directory_role",
            "exit_code",
            "duration_seconds",
            "executed",
            "blocked",
            "timed_out",
            "stdout",
            "stderr",
            "preflight",
            "agent",
            "truncation",
        },
        "guard_summary": {
            "mode",
            "triggered",
            "terminated_agent",
            "kill_required",
            "files_observed",
            "scan_count",
            "monitor_duration_seconds",
            "violations",
        },
        "command_guard_summary": {
            "mode",
            "triggered",
            "terminated_agent",
            "kill_required",
            "events_observed",
            "scan_count",
            "monitor_duration_seconds",
            "event_file",
            "violations",
        },
        "guard_metrics": {
            "guard_violations_total",
            "guard_blocked",
            "time_to_first_violation_ms",
            "time_to_block_ms",
            "filesystem_guard_violations",
            "command_guard_violations",
        },
        "test_result": {
            "command",
            "exit_code",
            "duration_seconds",
            "timed_out",
            "functional_pass",
            "stdout",
            "stderr",
            "truncation",
        },
        "check_result": {
            "name",
            "passed",
            "severity",
            "score_contribution",
            "message",
            "evidence",
            "truncation",
        },
        "execution_completed": {
            "result",
            "score",
            "modified_files",
            "failed_checks",
            "warning_checks",
            "duration_seconds",
            "source_report_sha256",
            "source_manifest_sha256",
        },
    }
    if event.event_type == "file_change":
        event_fields = {
            "path",
            "change_type",
            "old_content_sha256",
            "new_content_sha256",
            "old_mode",
            "new_mode",
            "lines_added",
            "lines_deleted",
            "symlink_target",
            "diff_included",
        }
        if event.payload.get("diff_included") is True:
            event_fields = event_fields | {"unified_diff", "diff_truncated"}
    else:
        event_fields = expected[event.event_type]
        if (
            event.event_type == "guard_summary"
            and "configured_ignore_patterns" in event.payload
        ):
            event_fields = event_fields | {"configured_ignore_patterns"}
        line_measurement_fields = {
            "live_lines_added",
            "live_lines_deleted",
            "line_measurement_complete",
            "line_measurement_skipped_files",
            "line_measurement_error",
        }
        if (
            event.event_type == "guard_summary"
            and line_measurement_fields & set(event.payload)
        ):
            event_fields = event_fields | line_measurement_fields
    _require_exact_fields(event.payload, event_fields, f"{event.event_type} payload")
    _validate_bounds(event.payload)
    if event.event_type == "guard_summary":
        patterns = event.payload.get("configured_ignore_patterns", [])
        if not isinstance(patterns, list) or not all(
            isinstance(pattern, str) for pattern in patterns
        ):
            raise ValueError(
                "Trace configured guard ignore patterns must be strings."
            )
        if "live_lines_added" in event.payload:
            for field_name in (
                "live_lines_added",
                "live_lines_deleted",
                "line_measurement_skipped_files",
            ):
                value = event.payload.get(field_name)
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 0
                ):
                    raise ValueError(
                        f"Trace {field_name} must be a nonnegative integer."
                    )
            if not isinstance(
                event.payload.get("line_measurement_complete"),
                bool,
            ):
                raise ValueError(
                    "Trace line_measurement_complete must be boolean."
                )
            error = event.payload.get("line_measurement_error")
            if error is not None and not isinstance(error, str):
                raise ValueError(
                    "Trace line_measurement_error must be a string or null."
                )
    if event.event_type == "file_change":
        path = event.payload.get("path")
        if not isinstance(path, str):
            raise ValueError("File change path must be a string.")
        _normalized_path(path)
        if event.payload.get("change_type") not in {
            "added",
            "modified",
            "deleted",
            "symlink",
        }:
            raise ValueError("Invalid file change type.")
        for hash_field in ("old_content_sha256", "new_content_sha256"):
            value = event.payload.get(hash_field)
            if value is not None:
                _validate_sha256(value, hash_field)
        for mode_field in ("old_mode", "new_mode"):
            mode = event.payload.get(mode_field)
            if mode is not None and mode not in {"100644", "100755", "120000"}:
                raise ValueError(f"Invalid file mode in {mode_field}.")
        for line_field in ("lines_added", "lines_deleted"):
            value = event.payload.get(line_field)
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"Invalid nonnegative {line_field}.")
        if not isinstance(event.payload.get("diff_included"), bool):
            raise ValueError("Trace diff_included must be boolean.")
        if "diff_truncated" in event.payload and not isinstance(
            event.payload["diff_truncated"],
            bool,
        ):
            raise ValueError("Trace diff_truncated must be boolean.")
    if event.event_type in {"agent_command", "test_result"}:
        exit_code = event.payload.get("exit_code")
        if exit_code is not None and not isinstance(exit_code, int):
            raise ValueError("Trace exit code must be an integer.")
        _validate_output_identity(event.payload.get("stdout"), "stdout")
        _validate_output_identity(event.payload.get("stderr"), "stderr")
    for key in ("duration_seconds",):
        value = event.payload.get(key)
        if value is not None and (
            not isinstance(value, (int, float)) or value < 0
        ):
            raise ValueError(f"Invalid nonnegative {key}.")
    if event.event_type == "execution_completed":
        score = event.payload.get("score")
        if not isinstance(score, (int, float)) or not 0 <= score <= 100:
            raise ValueError("Trace score must be between 0 and 100.")
        modified = event.payload.get("modified_files")
        if not isinstance(modified, dict):
            raise ValueError("Trace modified_files must be an object.")
        _require_exact_fields(
            modified,
            {
                "count",
                "paths",
                "truncated",
                "lines_added",
                "lines_deleted",
            },
            "modified file summary",
        )
        paths = modified.get("paths")
        if not isinstance(paths, list) or any(
            not isinstance(path, str) for path in paths
        ):
            raise ValueError("Trace modified file paths must be a string list.")
        for path in paths:
            _normalized_path(path)
        for hash_field in (
            "source_report_sha256",
            "source_manifest_sha256",
        ):
            value = event.payload.get(hash_field)
            if value is not None:
                _validate_sha256(value, hash_field)


def _validate_structure(trace: ExecutionTrace) -> None:
    header = trace.header
    if header.schema != TRACE_SCHEMA:
        raise ValueError("Invalid trace schema identifier.")
    if header.schema_version not in SUPPORTED_TRACE_SCHEMA_VERSIONS:
        raise ValueError("Unsupported trace schema version.")
    if header.source_execution_type != "run":
        raise ValueError("Unsupported trace source execution type.")
    if header.integrity.hash_algorithm != HASH_ALGORITHM:
        raise ValueError("Unsupported trace hash algorithm.")
    _validate_bounds(asdict(header))
    if header.schema_version == 1:
        if (
            header.policy_snapshot is not None
            or header.policy_snapshot_hash is not None
        ):
            raise ValueError("Trace v1 cannot contain a policy snapshot.")
    else:
        if header.policy_snapshot is None:
            raise ValueError("Trace v2 requires a policy snapshot.")
        _validate_policy_snapshot(header.policy_snapshot)
        _validate_sha256(header.policy_snapshot_hash, "policy snapshot hash")
        expected_snapshot_hash = policy_snapshot_hash(header.policy_snapshot)
        if header.policy_snapshot_hash != expected_snapshot_hash:
            raise ValueError("Trace policy snapshot hash is invalid.")
    for value, label in [
        (header.trace_id, "trace ID"),
        (header.configuration_hash, "configuration hash"),
        (header.integrity.root_hash, "root hash"),
        (header.integrity.final_event_hash, "final event hash"),
    ]:
        _validate_sha256(value, label)
    if header.event_count != len(trace.events):
        raise ValueError("Trace event count does not match the file.")
    if not trace.events:
        raise ValueError("Trace must contain events.")
    sequences = [event.sequence for event in trace.events]
    if sequences != list(range(1, len(trace.events) + 1)):
        raise ValueError("Trace event sequences must be contiguous from 1.")
    types = [event.event_type for event in trace.events]
    if any(event_type not in EVENT_TYPES for event_type in types):
        raise ValueError("Trace contains an unsupported event type.")
    if types[0] != "execution_started" or types[-1] != "execution_completed":
        raise ValueError("Trace start/completion event ordering is invalid.")
    if types.count("execution_started") != 1:
        raise ValueError("Trace must contain one execution_started event.")
    if types.count("test_result") != 1:
        raise ValueError("Trace must contain one test_result event.")
    if types.count("execution_completed") != 1:
        raise ValueError("Trace must contain one execution_completed event.")
    order = {
        "execution_started": 0,
        "agent_command": 1,
        "guard_summary": 2,
        "command_guard_summary": 2,
        "guard_metrics": 2,
        "file_change": 3,
        "test_result": 4,
        "check_result": 5,
        "execution_completed": 6,
    }
    if [order[event_type] for event_type in types] != sorted(
        order[event_type] for event_type in types
    ):
        raise ValueError("Trace event type ordering is invalid.")
    for event in trace.events:
        _validate_sha256(event.previous_event_hash, "previous event hash")
        _validate_sha256(event.event_hash, "event hash")
        if event.relative_offset_seconds is not None and (
            not isinstance(event.relative_offset_seconds, (int, float))
            or event.relative_offset_seconds < 0
        ):
            raise ValueError("Trace relative offsets must be nonnegative.")
        _validate_payload(event)


def _verify_integrity(trace: ExecutionTrace) -> None:
    _validate_structure(trace)
    previous = ZERO_HASH
    for event in trace.events:
        if event.previous_event_hash != previous:
            raise ValueError(
                f"Trace hash chain is broken at event {event.sequence}."
            )
        expected = _event_hash(
            event.sequence,
            event.event_type,
            event.payload,
            event.previous_event_hash,
            event.relative_offset_seconds,
            trace.header.schema_version,
        )
        if event.event_hash != expected:
            raise ValueError(f"Trace event {event.sequence} hash is invalid.")
        previous = event.event_hash
    if trace.header.integrity.final_event_hash != previous:
        raise ValueError("Trace final event hash does not match the chain.")
    expected_root = _sha256_text(
        canonical_json(
            {
                "header": _header_identity(trace.header),
                "final_event_hash": previous,
            }
        )
    )
    if trace.header.integrity.root_hash != expected_root:
        raise ValueError("Trace root integrity hash is invalid.")
    if trace.header.trace_id != expected_root:
        raise ValueError("Trace ID does not match its content digest.")


def _source_status(
    trace_path: Path,
    source: TraceSourceArtifact,
) -> TraceSourceStatus:
    candidate = Path(source.path)
    resolved = (
        candidate
        if candidate.is_absolute()
        else (trace_path.parent / candidate)
    )
    if not resolved.is_file():
        return TraceSourceStatus(
            role=source.role,
            path=source.path,
            status="unavailable",
            message=f"MISSING {source.role}: {source.path}",
        )
    try:
        actual = sha256_file(resolved)
    except OSError:
        return TraceSourceStatus(
            role=source.role,
            path=source.path,
            status="unavailable",
            message=f"UNAVAILABLE {source.role}: {source.path}",
        )
    if actual != source.sha256:
        return TraceSourceStatus(
            role=source.role,
            path=source.path,
            status="changed",
            message=f"CHANGED {source.role}: {source.path}",
        )
    return TraceSourceStatus(
        role=source.role,
        path=source.path,
        status="match",
        message=f"MATCH {source.role}: {source.path}",
    )


def verify_execution_trace(
    path: Path,
    *,
    strict_sources: bool = False,
) -> TraceVerificationResult:
    try:
        trace = load_execution_trace(path)
        _verify_integrity(trace)
    except ValueError as error:
        return TraceVerificationResult(
            integrity_valid=False,
            messages=[str(error)],
            malformed=True,
            strict_sources=strict_sources,
        )
    statuses = [
        _source_status(path, source) for source in trace.header.source_artifacts
    ]
    messages = ["Trace integrity valid."]
    if not statuses:
        messages.append("Source artifacts unavailable: none were recorded.")
    else:
        messages.extend(status.message for status in statuses)
    return TraceVerificationResult(
        integrity_valid=True,
        source_statuses=statuses,
        messages=messages,
        strict_sources=strict_sources,
    )


def trace_summary(trace: ExecutionTrace) -> str:
    counts = Counter(event.event_type for event in trace.events)
    completed = trace.events[-1].payload
    truncated = sum(
        1
        for event in trace.events
        if "truncation" in event.payload
        and any(bool(value) for value in event.payload["truncation"].values())
    )
    redacted = "[REDACTED]" in serialize_execution_trace(trace)
    lines = [
        f"Trace: {trace.header.trace_id}",
        f"Execution: {trace.header.execution_id}",
        (
            "Benchmark: "
            f"{trace.header.benchmark_id or trace.header.task_id}"
            f" v{trace.header.benchmark_version or '-'}"
        ),
        (
            f"Agent: {trace.header.agent_name or trace.header.agent_adapter}"
            f" / model {trace.header.agent_model or '-'}"
        ),
        f"Result: {completed.get('result')} / score {completed.get('score')}",
        "Events: "
        + ", ".join(
            f"{event_type}={counts[event_type]}"
            for event_type in sorted(counts)
        ),
        f"Truncated event payloads: {truncated}",
        f"Redaction markers present: {'yes' if redacted else 'no'}",
        f"Root digest: {trace.header.integrity.root_hash}",
    ]
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Unable to load source JSON {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"Source JSON must be an object: {path}")
    return value


def _resolve_export_source(source: Path) -> tuple[Path, Optional[Path]]:
    if source.is_dir():
        report = source / "reports" / "report.json"
        manifest = source / "manifest.json"
    elif source.name == "report.json":
        report = source
        manifest = source.parent.parent / "manifest.json"
    elif source.name == "manifest.json":
        manifest = source
        report = source.parent / "reports" / "report.json"
    else:
        raise ValueError(
            "Trace source must be a run directory, report.json, or manifest.json."
        )
    if not report.is_file():
        raise ValueError(f"Required report evidence is unavailable: {report}")
    return report, manifest if manifest.is_file() else None


def _command_event_from_dict(data: dict[str, Any]) -> CommandEvent:
    return CommandEvent(
        command=list(data.get("command") or []),
        command_text=str(data.get("command_text") or ""),
        cwd=str(data.get("cwd") or ""),
        exit_code=data.get("exit_code"),
        stdout=str(data.get("stdout") or ""),
        stderr=str(data.get("stderr") or ""),
        duration_seconds=data.get("duration_seconds"),
        executed=bool(data.get("executed")),
        blocked=bool(data.get("blocked")),
        reason=data.get("reason"),
        timed_out=bool(data.get("timed_out")),
        stdout_truncated=bool(data.get("stdout_truncated")),
        stderr_truncated=bool(data.get("stderr_truncated")),
        preflight_blocked=bool(data.get("preflight_blocked")),
        preflight_matched_patterns=list(
            data.get("preflight_matched_patterns") or []
        ),
        policy_mode=data.get("policy_mode"),
        agent_name=data.get("agent_name"),
    )


def _guard_summary_from_dict(data: object):
    from agentguard.guard.filesystem import LiveGuardSummary, LiveGuardViolation

    if not isinstance(data, dict):
        return LiveGuardSummary()
    first_violation = data.get("first_violation_time")
    try:
        first_violation_time = (
            float(first_violation) if first_violation is not None else None
        )
    except (TypeError, ValueError):
        first_violation_time = None
    violations = [
        LiveGuardViolation(
            violation_type=str(item.get("violation_type") or ""),
            path=str(item.get("path") or ""),
            message=str(item.get("message") or ""),
            action=str(item.get("action") or "recorded"),
            observed_at=float(item.get("observed_at") or 0.0),
        )
        for item in data.get("violations", [])
        if isinstance(item, dict)
    ]
    configured_ignore_patterns = data.get("configured_ignore_patterns", [])
    if not isinstance(configured_ignore_patterns, list) or not all(
        isinstance(pattern, str) for pattern in configured_ignore_patterns
    ):
        configured_ignore_patterns = []
    live_lines_added = _nonnegative_int(data.get("live_lines_added"))
    live_lines_deleted = _nonnegative_int(data.get("live_lines_deleted"))
    skipped_files = _nonnegative_int(
        data.get("line_measurement_skipped_files")
    )
    measurement_complete = data.get("line_measurement_complete", True)
    if not isinstance(measurement_complete, bool):
        measurement_complete = False
    measurement_error = data.get("line_measurement_error")
    if isinstance(measurement_error, str):
        measurement_error = sanitize_text(measurement_error)[:MAX_STRING_CHARS]
    else:
        measurement_error = None
    return LiveGuardSummary(
        mode=str(data.get("mode") or "off"),
        triggered=bool(data.get("triggered")),
        first_violation_time=first_violation_time,
        violations=violations,
        files_observed=int(data.get("files_observed") or 0),
        scan_count=int(data.get("scan_count") or 0),
        monitor_duration_seconds=float(data.get("monitor_duration_seconds") or 0.0),
        terminated_agent=bool(data.get("terminated_agent")),
        kill_required=bool(data.get("kill_required")),
        graceful_timeout_seconds=float(data.get("graceful_timeout_seconds") or 0.0),
        configured_ignore_patterns=list(configured_ignore_patterns),
        live_lines_added=live_lines_added,
        live_lines_deleted=live_lines_deleted,
        line_measurement_complete=measurement_complete,
        line_measurement_skipped_files=skipped_files,
        line_measurement_error=measurement_error,
    )


def _command_guard_summary_from_dict(data: object):
    from agentguard.guard.command import CommandGuardSummary, CommandGuardViolation

    if not isinstance(data, dict):
        return CommandGuardSummary()
    first_violation = data.get("first_violation_time")
    try:
        first_violation_time = (
            float(first_violation) if first_violation is not None else None
        )
    except (TypeError, ValueError):
        first_violation_time = None
    violations = [
        CommandGuardViolation(
            violation_type=str(item.get("violation_type") or ""),
            command_text=str(item.get("command_text") or ""),
            matched_patterns=[
                str(pattern)
                for pattern in item.get("matched_patterns", [])
            ],
            message=str(item.get("message") or ""),
            action=str(item.get("action") or "recorded"),
            observed_at=float(item.get("observed_at") or 0.0),
        )
        for item in data.get("violations", [])
        if isinstance(item, dict)
    ]
    return CommandGuardSummary(
        mode=str(data.get("mode") or "off"),
        triggered=bool(data.get("triggered")),
        first_violation_time=first_violation_time,
        violations=violations,
        events_observed=int(data.get("events_observed") or 0),
        scan_count=int(data.get("scan_count") or 0),
        monitor_duration_seconds=float(data.get("monitor_duration_seconds") or 0.0),
        terminated_agent=bool(data.get("terminated_agent")),
        kill_required=bool(data.get("kill_required")),
        graceful_timeout_seconds=float(data.get("graceful_timeout_seconds") or 0.0),
        event_file=str(data.get("event_file") or ".agentguard_agent_events.jsonl"),
    )


def _optional_report_path(data: object, key: str) -> Optional[Path]:
    if not isinstance(data, dict):
        return None
    value = data.get(key)
    return Path(str(value)) if value else None


def _nonnegative_int(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def _result_from_report(
    report_path: Path,
    manifest_path: Optional[Path],
) -> tuple[BenchmarkResult, dict[str, Any]]:
    from agentguard.config.schema import BenchmarkMetadata
    from agentguard.core.result import DiffSummary, ReportPaths, SandboxMetadata

    report = _load_json(report_path)
    required = {
        "task_id",
        "agent",
        "result",
        "score",
        "config_path",
        "run_dir",
        "repo_dir",
        "test_result",
        "diff_summary",
        "check_results",
        "command_events",
    }
    missing = sorted(required - set(report))
    if missing:
        raise ValueError(
            "Required report evidence is unavailable: " + ", ".join(missing)
        )
    run_dir = report_path.parent.parent
    repo_dir = Path(str(report["repo_dir"]))
    if not repo_dir.is_dir():
        candidate = run_dir / "repo"
        if candidate.is_dir():
            repo_dir = candidate
        else:
            raise ValueError(
                "Required repository evidence is unavailable for file changes."
            )
    command_log_path = run_dir / "command_log.json"
    command_events = report["command_events"]
    if command_log_path.is_file():
        log_data = json.loads(command_log_path.read_text(encoding="utf-8"))
        if log_data != command_events:
            raise ValueError("Command log evidence is inconsistent with report.")
    benchmark_data = report.get("benchmark") or {}
    sandbox_data = report.get("sandbox")
    test_data = report["test_result"]
    diff_data = report["diff_summary"]
    checks = [CheckResult(**item) for item in report["check_results"]]
    result = BenchmarkResult(
        task_id=str(report["task_id"]),
        agent=str(report["agent"]),
        result=str(report["result"]),
        score=int(report["score"]),
        config_path=Path(str(report["config_path"])),
        run_dir=run_dir,
        repo_dir=repo_dir,
        test_result=CommandResult(**test_data),
        diff_summary=DiffSummary(**diff_data),
        check_results=checks,
        report_paths=ReportPaths(
            json=report_path,
            markdown=report_path.with_suffix(".md"),
            command_log=command_log_path if command_log_path.is_file() else None,
            manifest=manifest_path,
            trace=None,
            guard_incident_json=_optional_report_path(
                report.get("report_paths"),
                "guard_incident_json",
            ),
            guard_incident_markdown=_optional_report_path(
                report.get("report_paths"),
                "guard_incident_markdown",
            ),
        ),
        sandbox=SandboxMetadata(**sandbox_data) if sandbox_data else None,
        benchmark=BenchmarkMetadata(**benchmark_data),
        command_events=[
            _command_event_from_dict(item) for item in command_events
        ],
        execution_id=report.get("execution_id") or run_dir.name,
        provenance_summary=report.get("provenance") or {},
        profile_id=report.get("profile_id"),
        profile_name=report.get("profile_name"),
        profile_model=report.get("profile_model"),
        guard_summary=_guard_summary_from_dict(report.get("guard_summary")),
        command_guard_summary=_command_guard_summary_from_dict(
            report.get("command_guard_summary")
        ),
        guard_metrics=(
            report.get("guard_metrics")
            if isinstance(report.get("guard_metrics"), dict)
            else {}
        ),
    )
    return result, report


def _validate_manifest_artifact_hashes(
    manifest: dict[str, Any],
    report_path: Path,
    manifest_path: Optional[Path],
) -> None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        return
    references = [
        ("json_report_sha256", report_path, "report"),
        (
            "command_log_sha256",
            report_path.parent.parent / "command_log.json",
            "command log",
        ),
    ]
    for hash_field, path, label in references:
        expected = artifacts.get(hash_field)
        if expected is None:
            continue
        _validate_sha256(expected, f"manifest {label} hash")
        if not path.is_file():
            raise ValueError(
                f"Manifest-referenced {label} evidence is unavailable: {path}"
            )
        if sha256_file(path) != expected:
            raise ValueError(
                f"Manifest-referenced {label} evidence has changed: {path}"
            )
    if manifest_path is not None and not manifest_path.is_file():
        raise ValueError("Manifest source disappeared during trace export.")


def export_execution_trace(
    source: Path,
    output: Path,
    options: TraceExportOptions = TraceExportOptions(),
) -> Path:
    if output.exists() and not options.force:
        raise FileExistsError(f"Trace output already exists: {output}")
    report_path, manifest_path = _resolve_export_source(source)
    result, report = _result_from_report(report_path, manifest_path)
    from agentguard.config.loader import load_config

    if not result.config_path.is_file():
        raise ValueError(
            "Required policy configuration is unavailable for trace export: "
            f"{result.config_path}"
        )
    config = load_config(result.config_path)
    manifest = _load_json(manifest_path) if manifest_path is not None else {}
    _validate_manifest_artifact_hashes(manifest, report_path, manifest_path)
    configuration_hash = (
        manifest.get("configuration", {}).get("sha256")
        or _sha256_text(canonical_json(report.get("config_path")))
    )
    agentguard = manifest.get("agentguard") or {}
    agent = manifest.get("agent") or {}
    policies = manifest.get("policies") or []
    policy_summary = canonical_json(policies[0]) if policies else "unavailable"
    sandbox_summary = (
        canonical_json(report.get("sandbox"))
        if report.get("sandbox")
        else "unavailable"
    )
    trace = build_execution_trace(
        result,
        created_at=str(manifest.get("created_at") or "unavailable"),
        configuration_hash=str(configuration_hash),
        agentguard_version=str(agentguard.get("version") or "unknown"),
        agentguard_commit=agentguard.get("git_commit"),
        agent_version=agent.get("version"),
        policy_summary=policy_summary,
        sandbox_summary=sandbox_summary,
        source_report_id=report_path.name,
        source_manifest_id=manifest_path.name if manifest_path else None,
        policy_snapshot=build_policy_snapshot(config),
        execution_duration_seconds=manifest.get("duration_seconds"),
        include_diff=options.include_diff,
    )
    return write_execution_trace(trace, output, force=options.force)
