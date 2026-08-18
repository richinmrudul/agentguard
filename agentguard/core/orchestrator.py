import time
import warnings
from contextlib import nullcontext
from dataclasses import asdict, replace
from pathlib import Path
from typing import ContextManager, Optional

from agentguard.agents.agent_command_agent import AgentCommandAgent
from agentguard.agents.base import Agent
from agentguard.agents.custom_command_agent import CustomCommandAgent
from agentguard.agents.local_command_agent import LocalCommandAgent
from agentguard.agents.mock_agent import get_agent
from agentguard.checks.base import Check
from agentguard.checks.registry import instantiate_checks
from agentguard.checks.secret_content import with_secret_content_scan
from agentguard.config.loader import load_config
from agentguard.core.result import (
    BenchmarkResult,
    CheckResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
    SandboxMetadata,
)
from agentguard.core.timeline import TimelineEvent, TimelineRecorder
from agentguard.core.timing import StageTimingRecorder
from agentguard.evaluation.profile import (
    AgentProfile,
    render_invocation,
    resolve_profile_argv,
)
from agentguard.history.store import (
    HistoryRecord,
    HistoryStorageError,
    record_history,
    utc_now_iso,
)
from agentguard.guard.command import (
    CommandGuardSummary,
    RuntimeCommandGuard,
)
from agentguard.guard.filesystem import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    GuardMode,
    validate_guard_configuration,
    LiveGuardSummary,
    ProcessController,
    RuntimeFilesystemGuard,
)
from agentguard.guard.incident import (
    build_guard_incident,
    guard_metrics,
    write_guard_incident,
)
from agentguard.instrumentation.agent_event_reader import (
    DEFAULT_AGENT_EVENT_FILE,
    read_agent_events_with_artifact,
)
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner
from agentguard.policy.evaluation import (
    PolicyEvaluationContext,
    evaluate_policy_checks,
)
from agentguard.repo.git_diff import collect_diff
from agentguard.repo.manager import RepoManager
from agentguard.provenance.manifest import (
    ExecutionManifest,
    agent_identity,
    agentguard_identity,
    artifact_identity,
    benchmark_identity,
    configuration_identity,
    detect_agent_version,
    host_identity,
    policy_identity,
    sanitize_text,
    sensitive_values_for_config,
    sha256_file,
    source_identity,
    utc_now_iso as manifest_utc_now_iso,
    write_manifest,
)
from agentguard.reports.json_report import write_json_report
from agentguard.reports.markdown_report import write_markdown_report
from agentguard.scoring.scorer import score_checks
from agentguard.sandbox.docker_runner import DockerTestRunner
from agentguard.traces.execution import (
    build_execution_trace,
    build_policy_snapshot,
    canonical_json,
    write_execution_trace,
)


def default_checks() -> list[Check]:
    return instantiate_checks()


def _record_command_events(
    timeline: TimelineRecorder,
    command_tracker: CommandTracker,
    start_index: int,
) -> int:
    events = command_tracker.events
    for event in events[start_index:]:
        if event.blocked:
            message = f"Blocked command: {event.command_text}"
        elif event.executed:
            message = f"Ran command: {event.command_text} (exit {event.exit_code})"
        else:
            message = f"Simulated command: {event.command_text}"
        timeline.add(
            "command_event",
            message,
            {
                "command_text": event.command_text,
                "executed": event.executed,
                "blocked": event.blocked,
                "exit_code": event.exit_code,
                "timed_out": event.timed_out,
                "stdout_truncated": event.stdout_truncated,
                "stderr_truncated": event.stderr_truncated,
                "preflight_blocked": event.preflight_blocked,
                "preflight_matched_patterns": event.preflight_matched_patterns,
                "policy_mode": event.policy_mode,
                "agent_name": event.agent_name,
            },
        )
    return len(events)


def _test_runner(config, command_tracker: CommandTracker):
    if config.sandbox.type == "docker":
        return DockerTestRunner(
            command_tracker,
            config.sandbox,
            timeout_seconds=config.command_timeout_seconds,
            max_output_bytes=config.max_output_bytes,
        )
    return TestRunner(
        command_tracker,
        timeout_seconds=config.command_timeout_seconds,
        max_output_bytes=config.max_output_bytes,
    )


def _sandbox_metadata(config) -> SandboxMetadata:
    if config.sandbox.type == "docker":
        return SandboxMetadata(
            type="docker",
            network=config.sandbox.network,
            memory=config.sandbox.memory,
            cpus=config.sandbox.cpus,
            read_only=config.sandbox.read_only,
            configured_image=config.sandbox.image,
            timeout_seconds=config.command_timeout_seconds,
            max_output_bytes=config.max_output_bytes,
        )
    return SandboxMetadata(
        type="local",
        timeout_seconds=config.command_timeout_seconds,
        max_output_bytes=config.max_output_bytes,
    )


def _preflight_blocked_event(command_tracker: CommandTracker):
    for event in command_tracker.events:
        if event.preflight_blocked:
            return event
    return None


def _failed_agent_event(command_tracker: CommandTracker):
    for event in command_tracker.events:
        if (
            event.executed
            and (
                event.command_text.startswith("local agent:")
                or event.command_text.startswith("agent command:")
                or event.command_text.startswith("agent profile ")
                or event.command_text.startswith("docker agent:")
            )
            and event.exit_code != 0
        ):
            return event
    return None


def _guard_check_result(guard_summary: LiveGuardSummary) -> Optional[CheckResult]:
    if (
        guard_summary.mode != GuardMode.ENFORCE.value
        or not guard_summary.triggered
    ):
        return None
    evidence = [
        f"{violation.violation_type}: {violation.path} ({violation.action})"
        for violation in guard_summary.violations
    ]
    return CheckResult(
        name="Live filesystem guard",
        passed=False,
        severity="critical",
        message=(
            "Online filesystem guard observed "
            f"{len(guard_summary.violations)} live policy violation(s)."
        ),
        evidence=evidence,
    )


def _command_guard_check_result(
    command_guard_summary: CommandGuardSummary,
) -> Optional[CheckResult]:
    if (
        command_guard_summary.mode != GuardMode.ENFORCE.value
        or not command_guard_summary.triggered
    ):
        return None
    evidence = [
        (
            f"{violation.violation_type}: {violation.command_text} "
            f"({', '.join(violation.matched_patterns)}; {violation.action})"
        )
        for violation in command_guard_summary.violations
    ]
    return CheckResult(
        name="Live command guard",
        passed=False,
        severity="critical",
        message=(
            "Online command guard observed "
            f"{len(command_guard_summary.violations)} live policy violation(s)."
        ),
        evidence=evidence,
    )


def _guard_timeline_events(
    timeline: TimelineRecorder,
    guard_summary: LiveGuardSummary,
) -> None:
    if guard_summary.mode == GuardMode.OFF.value:
        return
    for violation in guard_summary.violations:
        timeline.add(
            "guard_violation_detected",
            violation.message,
            {
                "mode": guard_summary.mode,
                "violation_type": violation.violation_type,
                "path": violation.path,
                "action": violation.action,
            },
        )
    if guard_summary.terminated_agent:
        first = guard_summary.violations[0] if guard_summary.violations else None
        timeline.add(
            "guard_terminated_agent",
            "Online filesystem guard terminated the agent.",
            {
                "mode": guard_summary.mode,
                "violation_type": first.violation_type if first is not None else None,
                "path": first.path if first is not None else None,
            },
        )
    timeline.add(
        "guard_completed",
        (
            "Online filesystem guard completed with "
            f"{len(guard_summary.violations)} violation(s)."
        ),
        {
            "mode": guard_summary.mode,
            "triggered": guard_summary.triggered,
            "files_observed": guard_summary.files_observed,
            "scan_count": guard_summary.scan_count,
            "monitor_duration_seconds": guard_summary.monitor_duration_seconds,
            "live_lines_added": guard_summary.live_lines_added,
            "live_lines_deleted": guard_summary.live_lines_deleted,
            "line_measurement_complete": (
                guard_summary.line_measurement_complete
            ),
            "line_measurement_skipped_files": (
                guard_summary.line_measurement_skipped_files
            ),
            "scan_complete": guard_summary.scan_complete,
            "incomplete_scan_count": guard_summary.incomplete_scan_count,
            "scan_error": guard_summary.scan_error,
        },
    )


def _command_guard_timeline_events(
    timeline: TimelineRecorder,
    command_guard_summary: CommandGuardSummary,
) -> None:
    if command_guard_summary.mode == GuardMode.OFF.value:
        return
    for violation in command_guard_summary.violations:
        timeline.add(
            "command_guard_violation_detected",
            violation.message,
            {
                "mode": command_guard_summary.mode,
                "violation_type": violation.violation_type,
                "command_text": violation.command_text,
                "matched_patterns": violation.matched_patterns,
                "action": violation.action,
            },
        )
    if command_guard_summary.terminated_agent:
        first = (
            command_guard_summary.violations[0]
            if command_guard_summary.violations
            else None
        )
        timeline.add(
            "command_guard_terminated_agent",
            "Online command guard terminated the agent.",
            {
                "mode": command_guard_summary.mode,
                "violation_type": (
                    first.violation_type if first is not None else None
                ),
                "command_text": first.command_text if first is not None else None,
            },
        )
    timeline.add(
        "command_guard_completed",
        (
            "Online command guard completed with "
            f"{len(command_guard_summary.violations)} violation(s)."
        ),
        {
            "mode": command_guard_summary.mode,
            "triggered": command_guard_summary.triggered,
            "events_observed": command_guard_summary.events_observed,
            "scan_count": command_guard_summary.scan_count,
            "monitor_duration_seconds": (
                command_guard_summary.monitor_duration_seconds
            ),
        },
    )


def _supports_guard_termination(agent_name: str) -> bool:
    return agent_name in {LocalCommandAgent.name, AgentCommandAgent.name}


def _sanitize_value(value, sensitive_values: list[str]):
    if isinstance(value, str):
        return sanitize_text(value, sensitive_values)
    if isinstance(value, list):
        return [_sanitize_value(item, sensitive_values) for item in value]
    if isinstance(value, dict):
        return {
            key: _sanitize_value(item, sensitive_values)
            for key, item in value.items()
        }
    return value


def _sanitize_profile_evidence(
    test_result: CommandResult,
    diff_summary: DiffSummary,
    check_results: list[CheckResult],
    command_tracker: CommandTracker,
    sensitive_values: list[str],
) -> tuple[
    CommandResult,
    DiffSummary,
    list[CheckResult],
]:
    for event in command_tracker.events:
        event.command = [
            sanitize_text(argument, sensitive_values) for argument in event.command
        ]
        event.command_text = sanitize_text(event.command_text, sensitive_values)
        event.cwd = sanitize_text(event.cwd, sensitive_values)
        event.stdout = sanitize_text(event.stdout, sensitive_values)
        event.stderr = sanitize_text(event.stderr, sensitive_values)
        if event.reason is not None:
            event.reason = sanitize_text(event.reason, sensitive_values)
    return (
        replace(
            test_result,
            command=sanitize_text(test_result.command, sensitive_values),
            stdout=sanitize_text(test_result.stdout, sensitive_values),
            stderr=sanitize_text(test_result.stderr, sensitive_values),
        ),
        replace(
            diff_summary,
            unified_diff=sanitize_text(
                diff_summary.unified_diff,
                sensitive_values,
            ),
        ),
        [
            replace(
                check,
                message=sanitize_text(check.message, sensitive_values),
                evidence=[
                    sanitize_text(item, sensitive_values)
                    for item in check.evidence
                ],
            )
            for check in check_results
        ],
    )


def _config_sensitive_values(config) -> list[str]:
    return sensitive_values_for_config(config)


def _sanitize_timeline_events(
    events: list[TimelineEvent],
    sensitive_values: list[str],
) -> list[TimelineEvent]:
    return [
        replace(
            event,
            message=sanitize_text(event.message, sensitive_values),
            metadata=_sanitize_value(event.metadata, sensitive_values),
        )
        for event in events
    ]


def _agent_for_config(config, agent_name: str) -> Agent:
    if agent_name == AgentCommandAgent.name:
        return AgentCommandAgent(config)
    if agent_name == CustomCommandAgent.name:
        return CustomCommandAgent(config)
    if agent_name == LocalCommandAgent.name:
        return LocalCommandAgent(config)
    return get_agent(agent_name)


def _validate_agent_config(config, agent_name: str) -> None:
    if agent_name == AgentCommandAgent.name and not config.agent_command:
        raise ValueError("Agent 'agent-command' requires config field 'agent_command'.")
    if agent_name == CustomCommandAgent.name:
        if not config.agent_command:
            raise ValueError(
                "Agent 'custom-command' requires config field 'agent_command'."
            )
        if config.sandbox.type != "docker":
            raise ValueError("Agent 'custom-command' currently requires docker sandbox.")
    if agent_name == LocalCommandAgent.name and not config.agent_command:
        raise ValueError("Agent 'local-command' requires config field 'agent_command'.")


def _record_run_history(result: BenchmarkResult) -> None:
    try:
        record_history(
            HistoryRecord(
                id=result.run_dir.name,
                run_type="run",
                name=result.task_id,
                result=result.result,
                score=result.score,
                created_at=utc_now_iso(),
                json_report_path=result.report_paths.json,
                markdown_report_path=result.report_paths.markdown,
                command_log_path=result.report_paths.command_log,
                manifest_path=result.report_paths.manifest,
                trace_path=result.report_paths.trace,
                category=result.benchmark.category,
                difficulty=result.benchmark.difficulty,
                benchmark_id=result.benchmark.id,
                benchmark_version=result.benchmark.version,
                agent=result.agent,
                failed_checks=[
                    check.name for check in result.check_results if not check.passed
                ],
                guard_blocked=bool(
                    result.guard_metrics.get("guard_blocked", False)
                ),
                guard_violations_total=int(
                    result.guard_metrics.get("guard_violations_total", 0)
                ),
                guard_incident_path=result.report_paths.guard_incident_json,
                time_to_first_violation_ms=(
                    result.guard_metrics.get("time_to_first_violation_ms")
                ),
            )
        )
    except HistoryStorageError:
        warnings.warn(
            "AgentGuard history write failed: history storage is unavailable.",
            RuntimeWarning,
            stacklevel=2,
        )


def _measure_stage(
    timing_recorder: Optional[StageTimingRecorder],
    stage: str,
) -> ContextManager[None]:
    if timing_recorder is None:
        return nullcontext()
    return timing_recorder.measure(stage)


def _warn_online_guard_cleanup_failures(errors: list[BaseException]) -> None:
    """Report cleanup failures without exposing exception-controlled text."""
    if not errors:
        return
    kinds = ", ".join(type(error).__name__ for error in errors)
    try:
        warnings.warn(
            "AgentGuard online guard cleanup reported "
            f"{len(errors)} failure(s): {kinds}.",
            RuntimeWarning,
            stacklevel=3,
        )
    except BaseException:
        # Warning filters may promote warnings to exceptions. Cleanup reporting
        # must never replace the exception that triggered cleanup.
        pass


def run_benchmark(
    config_path: Path,
    agent_name: str,
    *,
    parent_execution_id: Optional[str] = None,
    parent_execution_type: Optional[str] = None,
    evaluation_profile: Optional[AgentProfile] = None,
    timing_recorder: Optional[StageTimingRecorder] = None,
    record_history_enabled: bool = True,
    write_manifest_enabled: bool = True,
    guard_mode: GuardMode = GuardMode.OFF,
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> BenchmarkResult:
    guard_mode, guard_poll_interval_seconds = validate_guard_configuration(
        guard_mode,
        guard_poll_interval_seconds,
    )
    if timing_recorder is not None:
        timing_recorder.start_total()
    created_at = manifest_utc_now_iso()
    started = time.monotonic()
    with _measure_stage(timing_recorder, "configuration"):
        config = load_config(config_path)
    if evaluation_profile is None:
        _validate_agent_config(config, agent_name)
    timeline = TimelineRecorder()
    timeline.add(
        "run_started",
        f"Run started for task {config.task_id} with agent {agent_name}",
        {"task_id": config.task_id, "agent": agent_name},
    )
    with _measure_stage(timing_recorder, "workspace_preparation"):
        prepared = RepoManager().prepare(config, agent_name)
        baseline_event_path = prepared.repo_dir / DEFAULT_AGENT_EVENT_FILE
        baseline_owns_event_path = (
            baseline_event_path.exists() or baseline_event_path.is_symlink()
        )
    timeline.add(
        "repo_prepared",
        "Prepared isolated repo workspace",
        {"run_dir": str(prepared.run_dir), "repo_dir": str(prepared.repo_dir)},
    )
    command_tracker = CommandTracker()
    command_event_index = 0
    task_prompt_source = None
    task_prompt_sha256 = None
    if evaluation_profile is not None:
        invocation = render_invocation(evaluation_profile, config, prepared.repo_dir)
        config = replace(
            config,
            agent_command=invocation.argv,
            agent_display_command=invocation.display_argv,
            agent_name=evaluation_profile.id,
            agent_environment=invocation.environment,
            agent_environment_isolated=True,
            agent_version_command=(
                resolve_profile_argv(
                    evaluation_profile,
                    evaluation_profile.version_command,
                )
                if evaluation_profile.version_command is not None
                else None
            ),
            agent_model=evaluation_profile.model,
            agent_metadata={
                **evaluation_profile.metadata,
                "profile_id": evaluation_profile.id,
                "profile_name": evaluation_profile.name,
            },
            agent_workdir=(
                "repo_root"
                if evaluation_profile.workdir == "repo_root"
                else "config_dir"
            ),
            agent_workdir_path=invocation.workdir,
        )
        task_prompt_source = invocation.task_prompt.source
        task_prompt_sha256 = invocation.task_prompt.sha256
        _validate_agent_config(config, agent_name)
    with _measure_stage(timing_recorder, "agent_setup"):
        detected_version, version_status, version_warning = detect_agent_version(
            config,
            repo_dir=prepared.repo_dir,
            command_tracker=command_tracker,
        )
    if version_warning is not None:
        warnings.warn(
            f"AgentGuard agent version detection: {version_warning}",
            RuntimeWarning,
            stacklevel=2,
        )

    agent = _agent_for_config(config, agent_name)
    process_controller = (
        ProcessController()
        if guard_mode != GuardMode.OFF and _supports_guard_termination(agent_name)
        else None
    )
    guard = RuntimeFilesystemGuard(
        repo_dir=prepared.repo_dir,
        config=config,
        mode=guard_mode,
        process_controller=process_controller,
        poll_interval_seconds=guard_poll_interval_seconds,
    )
    command_guard = RuntimeCommandGuard(
        repo_dir=prepared.repo_dir,
        config=config,
        mode=guard_mode,
        process_controller=process_controller,
        poll_interval_seconds=guard_poll_interval_seconds,
    )
    guard_summary = LiveGuardSummary(
        mode=guard_mode.value,
        configured_ignore_patterns=list(config.guard_ignore_paths),
        watcher_mode=config.filesystem_watcher.mode,
    )
    command_guard_summary = CommandGuardSummary(mode=guard_mode.value)
    guard_start_attempted = False
    command_guard_start_attempted = False
    primary_error: Optional[BaseException] = None
    try:
        if guard_mode != GuardMode.OFF:
            timeline.add(
                "guard_started",
                f"Online filesystem guard started in {guard_mode.value} mode.",
                {
                    "mode": guard_mode.value,
                    "poll_interval_seconds": guard_poll_interval_seconds,
                    "termination_supported": process_controller is not None,
                    "configured_ignore_patterns": list(config.guard_ignore_paths),
                    "filesystem_watcher_mode": config.filesystem_watcher.mode,
                },
            )
            guard_start_attempted = True
            guard.start()
            timeline.add(
                "command_guard_started",
                f"Online command guard started in {guard_mode.value} mode.",
                {
                    "mode": guard_mode.value,
                    "poll_interval_seconds": guard_poll_interval_seconds,
                    "termination_supported": process_controller is not None,
                    "event_file": DEFAULT_AGENT_EVENT_FILE,
                },
            )
            command_guard_start_attempted = True
            command_guard.start()
        timeline.add(
            "agent_started", f"Agent {agent_name} started", {"agent": agent_name}
        )
        with _measure_stage(timing_recorder, "agent_execution"):
            agent.run(
                prepared.repo_dir,
                command_tracker,
                process_controller=process_controller,
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if command_guard_start_attempted:
            try:
                command_guard_summary = command_guard.stop()
            except BaseException as error:
                cleanup_errors.append(error)
        if guard_start_attempted:
            try:
                guard_summary = guard.stop()
                guard.scan_once()
                guard_summary = guard.summary()
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            if primary_error is not None:
                _warn_online_guard_cleanup_failures(cleanup_errors)
            else:
                first_cleanup_error = cleanup_errors[0]
                if len(cleanup_errors) > 1:
                    _warn_online_guard_cleanup_failures(cleanup_errors[1:])
                raise first_cleanup_error
    if guard_mode != GuardMode.OFF:
        _guard_timeline_events(timeline, guard_summary)
        _command_guard_timeline_events(timeline, command_guard_summary)
    guard_terminated_agent = (
        guard_summary.terminated_agent
        or command_guard_summary.terminated_agent
    )
    if guard_terminated_agent:
        timeline.add(
            "agent_completed",
            f"Agent {agent_name} was terminated by online guard",
            {
                "agent": agent_name,
                "filesystem_guard_terminated": guard_summary.terminated_agent,
                "command_guard_terminated": (
                    command_guard_summary.terminated_agent
                ),
            },
        )
    else:
        timeline.add(
            "agent_completed",
            f"Agent {agent_name} completed",
            {"agent": agent_name},
        )
    command_event_index = _record_command_events(
        timeline,
        command_tracker,
        command_event_index,
    )
    ingested_events, event_artifact = read_agent_events_with_artifact(
        prepared.repo_dir
    )
    if baseline_owns_event_path and event_artifact is not None:
        event_artifact.close()
        event_artifact = None
    command_tracker.extend(ingested_events)
    timeline.add(
        "ingested_agent_events",
        f"Ingested {len(ingested_events)} agent event(s)",
        {
            "event_count": len(ingested_events),
            "event_file": str(prepared.repo_dir / DEFAULT_AGENT_EVENT_FILE),
        },
    )
    command_event_index = _record_command_events(
        timeline,
        command_tracker,
        command_event_index,
    )

    preflight_blocked = _preflight_blocked_event(command_tracker)
    failed_agent = _failed_agent_event(command_tracker)
    if preflight_blocked is not None:
        test_result = CommandResult(
            command=config.test_command,
            exit_code=126,
            stdout="",
            stderr=preflight_blocked.stderr,
            duration_seconds=0.0,
        )
        timeline.add(
            "tests_skipped",
            "Tests skipped because command preflight policy blocked the agent.",
            {"test_exit_code": test_result.exit_code},
        )
    elif guard_terminated_agent and failed_agent is not None:
        test_result = CommandResult(
            command=failed_agent.command_text,
            exit_code=failed_agent.exit_code or 1,
            stdout=failed_agent.stdout,
            stderr=failed_agent.stderr,
            duration_seconds=failed_agent.duration_seconds or 0.0,
            timed_out=failed_agent.timed_out,
            stdout_truncated=failed_agent.stdout_truncated,
            stderr_truncated=failed_agent.stderr_truncated,
            process_cleanup_attempted=failed_agent.process_cleanup_attempted,
            process_cleanup_complete=failed_agent.process_cleanup_complete,
            process_cleanup_message=failed_agent.process_cleanup_message,
            docker_image=failed_agent.docker_image,
        )
        timeline.add(
            "tests_skipped",
            "Tests skipped because online guard terminated the agent.",
            {"test_exit_code": test_result.exit_code},
        )
    elif failed_agent is not None:
        test_result = CommandResult(
            command=failed_agent.command_text,
            exit_code=failed_agent.exit_code or 1,
            stdout=failed_agent.stdout,
            stderr=failed_agent.stderr,
            duration_seconds=failed_agent.duration_seconds or 0.0,
            timed_out=failed_agent.timed_out,
            stdout_truncated=failed_agent.stdout_truncated,
            stderr_truncated=failed_agent.stderr_truncated,
            process_cleanup_attempted=failed_agent.process_cleanup_attempted,
            process_cleanup_complete=failed_agent.process_cleanup_complete,
            process_cleanup_message=failed_agent.process_cleanup_message,
            docker_image=failed_agent.docker_image,
        )
        timeline.add(
            "tests_skipped",
            "Tests skipped because the agent command failed.",
            {"test_exit_code": test_result.exit_code},
        )
    else:
        timeline.add(
            "tests_started",
            f"Tests started: {config.test_command}",
            {"command": config.test_command},
        )
        with _measure_stage(timing_recorder, "test_execution"):
            test_result = _test_runner(config, command_tracker).run(
                prepared.repo_dir,
                config.test_command,
            )
        timeline.add(
            "tests_completed",
            f"Tests completed with exit code {test_result.exit_code}",
            {"test_exit_code": test_result.exit_code},
        )
        command_event_index = _record_command_events(
            timeline,
            command_tracker,
            command_event_index,
        )
    policy_started = timing_recorder.now() if timing_recorder is not None else None
    try:
        diff_summary = collect_diff(
            prepared.repo_dir,
            prepared.baseline_commit,
            include_ignored=True,
            owned_artifacts=(event_artifact,) if event_artifact is not None else (),
        )
    finally:
        if event_artifact is not None:
            event_artifact.close()
    diff_summary = with_secret_content_scan(
        prepared.repo_dir,
        diff_summary,
        config.secret_content_patterns,
        baseline_ref=prepared.baseline_commit,
    )
    timeline.add(
        "diff_collected",
        (
            "Collected diff: "
            f"{len(diff_summary.modified_files)} modified, "
            f"{len(diff_summary.added_files)} added, "
            f"{len(diff_summary.deleted_files)} deleted"
        ),
        {
            "modified_files": diff_summary.modified_files,
            "added_files": diff_summary.added_files,
            "deleted_files": diff_summary.deleted_files,
        },
    )
    check_results = evaluate_policy_checks(
        PolicyEvaluationContext(
            config=config,
            test_result=test_result,
            diff_summary=diff_summary,
            command_events=command_tracker.events,
        )
    )
    guard_check = _guard_check_result(guard_summary)
    if guard_check is not None:
        check_results.append(guard_check)
    command_guard_check = _command_guard_check_result(command_guard_summary)
    if command_guard_check is not None:
        check_results.append(command_guard_check)
    score_result = score_checks(check_results)
    if timing_recorder is not None and policy_started is not None:
        timing_recorder.stages["policy_check_evaluation"] = (
            timing_recorder.now() - policy_started
        )
    failed_check_names = [check.name for check in check_results if not check.passed]
    blocking_failures = [
        check.name
        for check in check_results
        if not check.passed and check.severity in {"error", "critical"}
    ]
    timeline.add(
        "checks_completed",
        f"Checks completed: {len(blocking_failures)} blocking failures",
        {
            "failed_check_names": failed_check_names,
            "blocking_failure_count": len(blocking_failures),
            "score": score_result.score,
            "result": score_result.result,
        },
    )
    sensitive_values = _config_sensitive_values(config)
    if agent_name == CustomCommandAgent.name:
        sensitive_values.extend(
            [str(prepared.repo_dir), str(prepared.repo_dir.resolve())]
        )
    if evaluation_profile is not None or sensitive_values:
        (
            test_result,
            diff_summary,
            check_results,
        ) = _sanitize_profile_evidence(
            test_result,
            diff_summary,
            check_results,
            command_tracker,
            sensitive_values,
        )
    with _measure_stage(timing_recorder, "report_writing"):
        command_log_path = command_tracker.write_json(prepared.run_dir)

    reports_dir = prepared.run_dir / "reports"
    metrics = guard_metrics(guard_summary, command_guard_summary)
    incident_json_path = (
        prepared.run_dir / "guard" / "incident.json"
        if metrics.guard_violations_total
        else None
    )
    incident_markdown_path = (
        prepared.run_dir / "guard" / "incident.md"
        if metrics.guard_violations_total
        else None
    )
    report_paths = ReportPaths(
        json=reports_dir / "report.json",
        markdown=reports_dir / "report.md",
        command_log=command_log_path,
        manifest=(
            prepared.run_dir / "manifest.json"
            if write_manifest_enabled
            else None
        ),
        trace=prepared.run_dir / "trace.jsonl",
        guard_incident_json=incident_json_path,
        guard_incident_markdown=incident_markdown_path,
    )
    timeline.add(
        "reports_written",
        "Reports written",
        {
            "json_report_path": str(report_paths.json),
            "markdown_report_path": str(report_paths.markdown),
            "command_log_path": str(command_log_path),
        },
    )
    timeline.add(
        "run_completed",
        f"Final result: {score_result.result}, score {score_result.score}/100",
        {
            "result": score_result.result,
            "score": score_result.score,
            "failed_check_names": failed_check_names,
        },
    )
    timeline_events = timeline.events
    if evaluation_profile is not None or sensitive_values:
        timeline_events = _sanitize_timeline_events(
            timeline_events,
            sensitive_values,
        )
    partial_result = BenchmarkResult(
        task_id=config.task_id,
        agent=evaluation_profile.id if evaluation_profile else agent_name,
        result=score_result.result,
        score=score_result.score,
        config_path=config.config_path,
        run_dir=prepared.run_dir,
        repo_dir=prepared.repo_dir,
        test_result=test_result,
        diff_summary=diff_summary,
        check_results=check_results,
        report_paths=report_paths,
        sandbox=_sandbox_metadata(config),
        benchmark=config.benchmark,
        command_events=command_tracker.events,
        timeline=timeline_events,
        execution_id=prepared.run_id,
        parent_execution_id=parent_execution_id,
        parent_execution_type=parent_execution_type,
        provenance_summary={
            "execution_id": prepared.run_id,
            "execution_type": "run",
            "manifest_path": str(report_paths.manifest),
            "parent_execution_id": parent_execution_id,
            "profile_id": (
                evaluation_profile.id if evaluation_profile is not None else None
            ),
            "task_prompt_source": task_prompt_source,
            "task_prompt_sha256": task_prompt_sha256,
        },
        task_prompt_source=task_prompt_source,
        task_prompt_sha256=task_prompt_sha256,
        profile_id=evaluation_profile.id if evaluation_profile else None,
        profile_name=evaluation_profile.name if evaluation_profile else None,
        profile_model=evaluation_profile.model if evaluation_profile else None,
        guard_summary=guard_summary,
        command_guard_summary=command_guard_summary,
        guard_metrics=asdict(metrics),
    )
    with _measure_stage(timing_recorder, "report_writing"):
        json_path = write_json_report(partial_result, reports_dir)
        markdown_path = write_markdown_report(partial_result, reports_dir)
        incident = build_guard_incident(
            run_id=prepared.run_id,
            task_id=config.task_id,
            agent=partial_result.agent,
            guard_mode=guard_mode.value,
            result=score_result.result,
            started_at=created_at,
            completed_at=manifest_utc_now_iso(),
            filesystem=guard_summary,
            command=command_guard_summary,
            report_paths=replace(
                report_paths,
                json=json_path,
                markdown=markdown_path,
            ),
            sensitive_values=sensitive_values,
        )
        if incident is not None:
            incident_paths = write_guard_incident(incident, prepared.run_dir)
            report_paths = replace(
                report_paths,
                json=json_path,
                markdown=markdown_path,
                guard_incident_json=incident_paths.json,
                guard_incident_markdown=incident_paths.markdown,
            )
            partial_result = replace(partial_result, report_paths=report_paths)
            json_path = write_json_report(partial_result, reports_dir)
            markdown_path = write_markdown_report(partial_result, reports_dir)

    result = BenchmarkResult(
        task_id=partial_result.task_id,
        agent=partial_result.agent,
        result=partial_result.result,
        score=partial_result.score,
        config_path=partial_result.config_path,
        run_dir=partial_result.run_dir,
        repo_dir=partial_result.repo_dir,
        test_result=partial_result.test_result,
        diff_summary=partial_result.diff_summary,
        check_results=partial_result.check_results,
        report_paths=ReportPaths(
            json=json_path,
            markdown=markdown_path,
            command_log=command_log_path,
            manifest=report_paths.manifest,
            trace=report_paths.trace,
            guard_incident_json=report_paths.guard_incident_json,
            guard_incident_markdown=report_paths.guard_incident_markdown,
        ),
        sandbox=partial_result.sandbox,
        benchmark=partial_result.benchmark,
        command_events=partial_result.command_events,
        timeline=partial_result.timeline,
        execution_id=partial_result.execution_id,
        parent_execution_id=partial_result.parent_execution_id,
        parent_execution_type=partial_result.parent_execution_type,
        provenance_summary=partial_result.provenance_summary,
        task_prompt_source=partial_result.task_prompt_source,
        task_prompt_sha256=partial_result.task_prompt_sha256,
        profile_id=partial_result.profile_id,
        profile_name=partial_result.profile_name,
        profile_model=partial_result.profile_model,
        guard_summary=partial_result.guard_summary,
        command_guard_summary=partial_result.command_guard_summary,
        guard_metrics=partial_result.guard_metrics,
    )
    agentguard_details = agentguard_identity()
    policy_details = policy_identity(config)
    agent_details = agent_identity(
        config,
        agent_name,
        detected_version,
        version_status,
        version_warning,
    )
    manifest = ExecutionManifest(
        execution_id=prepared.run_id,
        execution_type="run",
        created_at=created_at,
        completed_at=manifest_utc_now_iso(),
        duration_seconds=round(time.monotonic() - started, 6),
        agentguard=agentguard_details,
        host=host_identity(docker_relevant=config.sandbox.type == "docker"),
        source=source_identity(config.repo_template),
        configuration=configuration_identity(
            config.config_path,
            {
                "task_id": config.task_id,
                "mode": config.mode,
                "guard_mode": guard_mode.value,
                "guard_poll_interval_seconds": guard_poll_interval_seconds,
                "guard_ignore_paths": list(config.guard_ignore_paths),
                "agent_workdir": config.agent_workdir,
                "profile_id": (
                    evaluation_profile.id if evaluation_profile is not None else None
                ),
                "task_prompt_source": task_prompt_source,
                "task_prompt_sha256": task_prompt_sha256,
            },
        ),
        agent=agent_details,
        benchmarks=[benchmark_identity(config)],
        policies=[policy_details],
        artifacts=artifact_identity(
            json_path,
            markdown_path,
            command_log_path,
            report_paths.trace,
        ),
        docker_images=[
            asdict(event.docker_image)
            for event in result.command_events
            if event.docker_image is not None
        ],
        parent_execution_id=parent_execution_id,
        parent_execution_type=parent_execution_type,
        guard=asdict(guard_summary),
        command_guard=asdict(command_guard_summary),
        guard_metrics=asdict(metrics),
        guard_incident=(
            {
                "json": str(result.report_paths.guard_incident_json),
                "markdown": str(result.report_paths.guard_incident_markdown),
            }
            if result.report_paths.guard_incident_json is not None
            else None
        ),
    )
    if write_manifest_enabled:
        with _measure_stage(timing_recorder, "manifest_writing"):
            if (
                report_paths.manifest is None
                or write_manifest(manifest, report_paths.manifest) is None
            ):
                result = replace(
                    result,
                    report_paths=replace(result.report_paths, manifest=None),
                )
    else:
        result = replace(
            result,
            report_paths=replace(result.report_paths, manifest=None),
        )
    try:
        trace_path = result.report_paths.trace
        if trace_path is None:
            raise ValueError("Trace output path is unavailable.")
        trace = build_execution_trace(
            result,
            created_at=created_at,
            configuration_hash=sha256_file(config.config_path),
            agentguard_version=agentguard_details.version,
            agentguard_commit=agentguard_details.git_commit,
            agent_version=agent_details.version,
            policy_summary=canonical_json(asdict(policy_details)),
            sandbox_summary=canonical_json(asdict(_sandbox_metadata(config))),
            source_report_id=json_path.name,
            source_manifest_id=(
                result.report_paths.manifest.name
                if result.report_paths.manifest is not None
                else None
            ),
            policy_snapshot=build_policy_snapshot(config),
            execution_duration_seconds=manifest.duration_seconds,
            sensitive_values=sensitive_values,
        )
        write_execution_trace(trace, trace_path)
    except (OSError, TypeError, ValueError) as error:
        warnings.warn(
            f"AgentGuard trace write failed: {error}",
            RuntimeWarning,
            stacklevel=2,
        )
        result = replace(
            result,
            report_paths=replace(result.report_paths, trace=None),
        )
    if record_history_enabled:
        with _measure_stage(timing_recorder, "history_writing"):
            _record_run_history(result)
    if timing_recorder is not None:
        timing_recorder.finish_total()
    return result
