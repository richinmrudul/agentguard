import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from agentguard import __version__
from agentguard.checks.registry import registered_checks
from agentguard.config.schema import (
    AgentGuardConfig,
    CommandPolicyConfig,
    DiffLimits,
    ExpectedModifiedFiles,
)
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.sandbox.docker_identity import parse_docker_image_identity
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.reports.markdown import markdown_table_cell, markdown_text
from agentguard.policy.evaluation import (
    PolicyEvaluationContext,
    evaluate_policy_checks,
)
from agentguard.scoring.scorer import score_checks
from agentguard.traces.execution import (
    ExecutionTrace,
    TraceVerificationResult,
    load_execution_trace,
    verify_execution_trace,
)
from agentguard.traces.models import (
    ReplayCheckComparison,
    ReplayDivergence,
    ReplayEvidence,
    ReplayPolicySnapshot,
    ReplayReportPaths,
    ReplayResult,
    ReplayabilityStatus,
)


def replayability_status(trace: ExecutionTrace) -> ReplayabilityStatus:
    supported = [registration.identifier for registration in registered_checks()]
    if trace.header.schema_version == 1:
        return ReplayabilityStatus(
            replayable=False,
            supported_checks=supported,
            missing_inputs=[
                "policy_snapshot",
                "enabled_checks",
                "check_severities",
                "score_weights",
                "path_patterns",
                "diff_thresholds",
                "expected_modified_file_bounds",
            ],
            reasons=[
                "Trace schema v1 did not capture normalized policy inputs.",
                "Current defaults are not inferred for historical traces.",
            ],
        )
    snapshot = trace.header.policy_snapshot
    missing = []
    reasons = []
    if snapshot is None:
        missing.append("policy_snapshot")
    else:
        if snapshot.redacted_inputs:
            reasons.append(
                "Policy inputs were redacted and cannot be replayed exactly: "
                + ", ".join(snapshot.redacted_inputs)
            )
        if snapshot.command_policy_patterns != snapshot.unsafe_commands:
            reasons.append(
                "Command-policy and unsafe-command patterns are inconsistent."
            )
        unsupported = sorted(set(snapshot.enabled_checks) - set(supported))
        if unsupported:
            reasons.append(
                "Unsupported check identifier(s): " + ", ".join(unsupported)
            )
        for identifier in snapshot.enabled_checks:
            if identifier not in snapshot.severities:
                missing.append(f"severity:{identifier}")
        if set(snapshot.score_weights) != {
            "critical",
            "error",
            "warning",
            "info",
        }:
            missing.append("score_weights")
    for event in trace.events:
        truncation = event.payload.get("truncation")
        if isinstance(truncation, dict) and any(truncation.values()):
            if event.event_type in {"agent_command", "check_result", "test_result"}:
                reasons.append(
                    f"Policy-relevant {event.event_type} evidence was truncated."
                )
        if event.event_type == "execution_completed":
            modified = event.payload.get("modified_files")
            if isinstance(modified, dict) and modified.get("truncated"):
                reasons.append("Modified-file evidence was truncated.")
    return ReplayabilityStatus(
        replayable=not missing and not reasons,
        supported_checks=supported,
        missing_inputs=sorted(set(missing)),
        reasons=sorted(set(reasons)),
    )


def inspect_replayability(
    path: Path,
    *,
    strict_sources: bool = False,
) -> tuple[ReplayabilityStatus, TraceVerificationResult]:
    verification = verify_execution_trace(path, strict_sources=strict_sources)
    if verification.exit_code == 2:
        raise ValueError(verification.messages[0])
    trace = load_execution_trace(path)
    status = replayability_status(trace)
    if strict_sources and verification.exit_code == 1:
        status = ReplayabilityStatus(
            replayable=False,
            supported_checks=status.supported_checks,
            missing_inputs=status.missing_inputs,
            reasons=[
                *status.reasons,
                "Strict source verification failed.",
            ],
        )
    return status, verification


def _event(trace: ExecutionTrace, event_type: str) -> dict[str, object]:
    matches = [
        event.payload for event in trace.events if event.event_type == event_type
    ]
    if len(matches) != 1:
        raise ValueError(f"Trace requires exactly one {event_type} event.")
    return matches[0]


def reconstruct_replay_evidence(trace: ExecutionTrace) -> ReplayEvidence:
    started = _event(trace, "execution_started")
    test = _event(trace, "test_result")
    completed = _event(trace, "execution_completed")
    modified = completed["modified_files"]
    if not isinstance(modified, dict):
        raise ValueError("Trace modified-file summary is invalid.")
    paths = modified["paths"]
    if not isinstance(paths, list):
        raise ValueError("Trace modified-file paths are invalid.")
    modified_files = []
    added_files = []
    deleted_files = []
    event_paths = []
    for event in trace.events:
        if event.event_type != "file_change":
            continue
        path = str(event.payload["path"])
        event_paths.append(path)
        change_type = event.payload["change_type"]
        if change_type == "added":
            added_files.append(path)
        elif change_type == "deleted":
            deleted_files.append(path)
        elif (
            change_type == "symlink"
            and event.payload["old_content_sha256"] is None
            and event.payload["old_mode"] is None
        ):
            added_files.append(path)
        else:
            modified_files.append(path)
    if event_paths != paths:
        raise ValueError(
            "Trace file-change events are inconsistent with completion evidence."
        )
    test_result = CommandResult(
        command=str(test["command"]),
        exit_code=int(test["exit_code"]),
        stdout="",
        stderr="",
        duration_seconds=float(test["duration_seconds"]),
        timed_out=bool(test["timed_out"]),
        stdout_truncated=bool(test["stdout"]["truncated"]),
        stderr_truncated=bool(test["stderr"]["truncated"]),
        process_cleanup_attempted=bool(
            (test.get("process_cleanup") or {}).get("attempted")
        ),
        process_cleanup_complete=(
            bool((test.get("process_cleanup") or {}).get("complete"))
            if "complete" in (test.get("process_cleanup") or {})
            else True
        ),
        process_cleanup_message=(test.get("process_cleanup") or {}).get("message"),
        docker_image=(
            parse_docker_image_identity(test["docker_image"])
            if test.get("docker_image") is not None
            else None
        ),
    )
    command_events = []
    for event in trace.events:
        if event.event_type != "agent_command":
            continue
        payload = event.payload
        preflight = payload["preflight"]
        cleanup = payload.get("process_cleanup") or {}
        command_events.append(
            CommandEvent(
                command=list(payload["argv"]),
                command_text=str(payload["command"]),
                cwd=str(payload["working_directory_role"]),
                exit_code=payload["exit_code"],
                stdout="",
                stderr="",
                duration_seconds=payload["duration_seconds"],
                executed=bool(payload["executed"]),
                blocked=bool(payload["blocked"]),
                reason=None,
                timed_out=bool(payload["timed_out"]),
                stdout_truncated=bool(payload["stdout"]["truncated"]),
                stderr_truncated=bool(payload["stderr"]["truncated"]),
                preflight_blocked=bool(preflight["blocked"]),
                preflight_matched_patterns=list(
                    preflight["matched_patterns"]
                ),
                policy_mode=preflight["mode"],
                agent_name=str(payload["agent"]),
                process_cleanup_attempted=bool(cleanup.get("attempted")),
                process_cleanup_complete=(
                    bool(cleanup.get("complete"))
                    if "complete" in cleanup
                    else True
                ),
                process_cleanup_message=cleanup.get("message"),
                docker_image=(
                    parse_docker_image_identity(payload["docker_image"])
                    if payload.get("docker_image") is not None
                    else None
                ),
            )
        )
    return ReplayEvidence(
        task_id=str(started["task_id"]),
        benchmark_id=trace.header.benchmark_id,
        benchmark_version=trace.header.benchmark_version,
        configuration_hash=trace.header.configuration_hash,
        test_result=test_result,
        diff_summary=DiffSummary(
            modified_files=modified_files,
            added_files=added_files,
            deleted_files=deleted_files,
            lines_added=int(modified["lines_added"]),
            lines_deleted=int(modified["lines_deleted"]),
            unified_diff="",
        ),
        command_events=command_events,
    )


def _config_from_snapshot(
    evidence: ReplayEvidence,
    snapshot: ReplayPolicySnapshot,
) -> AgentGuardConfig:
    policy_keys = {
        "tests-passed": "tests_pass",
        "forbidden-paths": "forbidden_paths",
        "test-tampering": "test_tampering",
        "unsafe-commands": "unsafe_commands",
        "scope-adherence": "scope_adherence",
        "diff-size": "diff_size",
        "secret-scan": "secret_scan",
    }
    return AgentGuardConfig(
        task_id=evidence.task_id,
        description="Offline trace replay",
        repo_template=None,
        test_command=evidence.test_result.command,
        allowed_paths=snapshot.allowed_paths,
        forbidden_paths=snapshot.forbidden_paths,
        test_paths=snapshot.test_paths,
        expected_modified_files=ExpectedModifiedFiles(
            min=snapshot.expected_modified_files_min,
            max=snapshot.expected_modified_files_max,
        ),
        unsafe_commands=snapshot.unsafe_commands,
        policy={
            policy_keys[identifier]: severity
            for identifier, severity in snapshot.severities.items()
            if identifier in policy_keys
        },
        diff_limits=DiffLimits(
            max_files_changed=snapshot.max_files_changed,
            max_lines_added=snapshot.max_lines_added,
            max_lines_deleted=snapshot.max_lines_deleted,
        ),
        secret_patterns=snapshot.secret_patterns,
        config_path=Path("trace-policy-snapshot"),
        command_policy=CommandPolicyConfig(
            mode=snapshot.command_policy_mode,
        ),
    )


def _recorded_checks(trace: ExecutionTrace) -> tuple[list[CheckResult], list[int]]:
    checks = []
    contributions = []
    for event in trace.events:
        if event.event_type != "check_result":
            continue
        payload = event.payload
        checks.append(
            CheckResult(
                name=str(payload["name"]),
                passed=bool(payload["passed"]),
                severity=str(payload["severity"]),
                message=str(payload["message"]),
                evidence=[str(item) for item in payload["evidence"]],
            )
        )
        contribution = payload.get("score_contribution")
        contributions.append(int(contribution) if contribution is not None else 0)
    return checks, contributions


def _contribution(check: CheckResult, snapshot: ReplayPolicySnapshot) -> int:
    return 0 if check.passed else -snapshot.score_weights.get(check.severity, 0)


def _compare_checks(
    recorded: list[CheckResult],
    recorded_contributions: list[int],
    recomputed: list[CheckResult],
    snapshot: ReplayPolicySnapshot,
) -> tuple[list[ReplayCheckComparison], list[ReplayDivergence]]:
    comparisons = []
    divergences = []
    size = max(len(recorded), len(recomputed))
    for index in range(size):
        old = recorded[index] if index < len(recorded) else None
        new = recomputed[index] if index < len(recomputed) else None
        name = old.name if old is not None else new.name if new is not None else "-"
        differences = []
        classification = "exact"
        if old is None or new is None:
            differences.append("check missing")
            classification = "divergent"
        else:
            for field in ("name", "passed", "severity", "evidence"):
                if getattr(old, field) != getattr(new, field):
                    differences.append(field)
            if old.message != new.message:
                differences.append("message")
            old_contribution = recorded_contributions[index]
            new_contribution = _contribution(new, snapshot)
            if old_contribution != new_contribution:
                differences.append("score_contribution")
            policy_differences = set(differences) - {"message"}
            if policy_differences:
                classification = "divergent"
            elif differences:
                classification = "semantic"
        old_contribution = (
            recorded_contributions[index] if index < len(recorded_contributions) else None
        )
        new_contribution = (
            _contribution(new, snapshot) if new is not None else None
        )
        comparison = ReplayCheckComparison(
            name=name,
            classification=classification,
            recorded=old,
            recomputed=new,
            score_contribution_recorded=old_contribution,
            score_contribution_recomputed=new_contribution,
            differences=differences,
        )
        comparisons.append(comparison)
        if classification == "divergent":
            divergences.append(
                ReplayDivergence(
                    field=f"check[{index}]",
                    recorded=asdict(old) if old is not None else None,
                    recomputed=asdict(new) if new is not None else None,
                    classification="policy",
                )
            )
    return comparisons, divergences


def _failed_sets(checks: list[CheckResult]) -> tuple[list[str], list[str]]:
    failed = [check.name for check in checks if not check.passed]
    warnings = [
        check.name
        for check in checks
        if not check.passed and check.severity == "warning"
    ]
    return failed, warnings


def _report_data(result: ReplayResult) -> dict[str, object]:
    return asdict(result)


def _write_replay_reports(result: ReplayResult) -> None:
    atomic_write_json(
        result.report_paths.json,
        _report_data(result),
        default=lambda value: str(value) if isinstance(value, Path) else value,
        sort_keys=True,
    )
    lines = [
        "# AgentGuard Trace Replay",
        "",
        f"- Replay ID: {markdown_text(result.replay_id)}",
        f"- Trace ID: {markdown_text(result.trace_id)}",
        f"- Trace schema: {result.trace_schema_version}",
        f"- Replayable: {result.replayability.replayable}",
        f"- Equivalence: {markdown_text(result.equivalence)}",
        "- Original AgentGuard: "
        f"{markdown_text(result.original_agentguard_version)}",
        f"- Replay AgentGuard: {markdown_text(result.replay_agentguard_version)}",
        f"- Policy snapshot SHA-256: {markdown_text(result.policy_snapshot_hash)}",
        f"- Recorded result/score: {markdown_text(result.recorded_result)} / "
        f"{result.recorded_score}",
        (
            f"- Recomputed result/score: "
            f"{markdown_text(result.recomputed_result)} / {result.recomputed_score}"
        ),
        f"- Replay duration: {result.replay_duration_seconds:.6f}s",
        (
            f"- Recorded duration: {result.original_duration_seconds}s"
            if result.original_duration_seconds is not None
            else "- Recorded duration: unavailable"
        ),
        (
            f"- Measured speedup: {result.speedup_ratio:.2f}x"
            if result.speedup_ratio is not None
            else "- Measured speedup: unavailable"
        ),
        "- External execution: none",
        "",
        "## Check Comparison",
        "",
        "| Check | Classification | Recorded | Recomputed | Differences |",
        "| --- | --- | --- | --- | --- |",
    ]
    for comparison in result.comparisons:
        lines.append(
            f"| {markdown_table_cell(comparison.name)} | "
            f"{markdown_table_cell(comparison.classification)} | "
            f"{comparison.recorded.passed if comparison.recorded else '-'} | "
            f"{comparison.recomputed.passed if comparison.recomputed else '-'} | "
            f"{markdown_table_cell(', '.join(comparison.differences) or '-')} |"
        )
    lines.extend(["", "## Divergences", ""])
    if result.divergences:
        lines.extend(
            f"- {markdown_text(item.field)}: {markdown_text(item.classification)}"
            for item in result.divergences
        )
    else:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Source Verification",
            "",
            *[
                f"- {markdown_text(message)}"
                for message in result.source_verification
            ],
            "",
            "Replay reconstructs policy evaluation from captured evidence. "
            "It does not rerun or reproduce agent behavior.",
            "",
        ]
    )
    atomic_write_text(result.report_paths.markdown, "\n".join(lines))


def replay_trace(
    path: Path,
    *,
    output_dir: Optional[Path] = None,
    strict_sources: bool = False,
    force: bool = False,
) -> ReplayResult:
    started = time.monotonic()
    status, verification = inspect_replayability(
        path,
        strict_sources=strict_sources,
    )
    if not status.replayable:
        details = status.missing_inputs + status.reasons
        raise ValueError("Trace is non-replayable: " + "; ".join(details))
    trace = load_execution_trace(path)
    snapshot = trace.header.policy_snapshot
    assert snapshot is not None
    evidence = reconstruct_replay_evidence(trace)
    context = PolicyEvaluationContext(
        config=_config_from_snapshot(evidence, snapshot),
        test_result=evidence.test_result,
        diff_summary=evidence.diff_summary,
        command_events=evidence.command_events,
    )
    recorded, recorded_contributions = _recorded_checks(trace)
    recomputed = evaluate_policy_checks(
        context,
        enabled_identifiers=snapshot.enabled_checks,
    )
    recorded_secret_scan = next(
        (
            check
            for check in recorded
            if check.name == "Secret scan"
            and (
                "content-based" in check.message.lower()
                or "scan was incomplete" in check.message.lower()
            )
        ),
        None,
    )
    if recorded_secret_scan is not None:
        recomputed = [
            recorded_secret_scan if check.name == "Secret scan" else check
            for check in recomputed
        ]
    recomputed_score = score_checks(
        recomputed,
        deductions=snapshot.score_weights,
    )
    comparisons, divergences = _compare_checks(
        recorded,
        recorded_contributions,
        recomputed,
        snapshot,
    )
    completed = _event(trace, "execution_completed")
    recorded_score = int(completed["score"])
    recorded_result = str(completed["result"])
    for field, old, new in [
        ("score", recorded_score, recomputed_score.score),
        ("result", recorded_result, recomputed_score.result),
        ("failed_checks", completed["failed_checks"], _failed_sets(recomputed)[0]),
        ("warning_checks", completed["warning_checks"], _failed_sets(recomputed)[1]),
    ]:
        if old != new:
            divergences.append(
                ReplayDivergence(
                    field=field,
                    recorded=old,
                    recomputed=new,
                    classification="policy",
                )
            )
    classifications = {comparison.classification for comparison in comparisons}
    equivalence = (
        "divergent"
        if divergences or "divergent" in classifications
        else "semantic"
        if "semantic" in classifications
        else "exact"
    )
    replay_id = f"replay-{trace.header.trace_id[:16]}"
    root = output_dir or Path(".agentguard/replays")
    replay_dir = root / replay_id
    if replay_dir.exists() and not force:
        raise FileExistsError(f"Replay output already exists: {replay_dir}")
    replay_dir.mkdir(parents=True, exist_ok=True)
    paths = ReplayReportPaths(
        json=replay_dir / "replay.json",
        markdown=replay_dir / "replay.md",
    )
    duration = time.monotonic() - started
    original_duration = completed.get("duration_seconds")
    original_duration_value = (
        float(original_duration) if original_duration is not None else None
    )
    result = ReplayResult(
        replay_id=replay_id,
        trace_id=trace.header.trace_id,
        trace_schema_version=trace.header.schema_version,
        replayability=status,
        original_agentguard_version=trace.header.agentguard_version,
        replay_agentguard_version=__version__,
        policy_snapshot_hash=trace.header.policy_snapshot_hash,
        recorded_checks=recorded,
        recomputed_checks=recomputed,
        comparisons=comparisons,
        recorded_score=recorded_score,
        recomputed_score=recomputed_score.score,
        recorded_result=recorded_result,
        recomputed_result=recomputed_score.result,
        equivalence=equivalence,
        divergences=divergences,
        source_verification=verification.messages,
        original_duration_seconds=original_duration_value,
        replay_duration_seconds=duration,
        speedup_ratio=(
            original_duration_value / duration
            if original_duration_value is not None and duration > 0
            else None
        ),
        no_external_execution=True,
        report_paths=paths,
    )
    _write_replay_reports(result)
    return result


def replayability_summary(
    trace: ExecutionTrace,
    status: ReplayabilityStatus,
) -> str:
    lines = [
        f"Trace: {trace.header.trace_id}",
        f"Schema version: {trace.header.schema_version}",
        f"Replayable: {'yes' if status.replayable else 'no'}",
        "Supported checks: " + ", ".join(status.supported_checks),
    ]
    if status.missing_inputs:
        lines.append("Missing inputs: " + ", ".join(status.missing_inputs))
    if status.reasons:
        lines.extend(f"Reason: {reason}" for reason in status.reasons)
    return "\n".join(lines)
