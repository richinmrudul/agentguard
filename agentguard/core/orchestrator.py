import time
import warnings
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from typing import ContextManager, Optional

from agentguard.agents.agent_command_agent import AgentCommandAgent
from agentguard.agents.base import Agent
from agentguard.agents.custom_command_agent import CustomCommandAgent
from agentguard.agents.local_command_agent import LocalCommandAgent
from agentguard.agents.mock_agent import get_agent
from agentguard.checks.base import Check
from agentguard.checks.diff_size import DiffSizeCheck
from agentguard.checks.forbidden_paths import ForbiddenPathsCheck
from agentguard.checks.secret_scan import SecretScanCheck
from agentguard.checks.scope_adherence import ScopeAdherenceCheck
from agentguard.checks.test_tampering import TestTamperingCheck
from agentguard.checks.tests_pass import TestsPassCheck
from agentguard.checks.unsafe_commands import UnsafeCommandsCheck
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
from agentguard.history.store import HistoryRecord, record_history, utc_now_iso
from agentguard.instrumentation.agent_event_reader import (
    DEFAULT_AGENT_EVENT_FILE,
    read_agent_events,
)
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner
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
    source_identity,
    utc_now_iso as manifest_utc_now_iso,
    write_manifest,
)
from agentguard.reports.json_report import write_json_report
from agentguard.reports.markdown_report import write_markdown_report
from agentguard.scoring.scorer import score_checks
from agentguard.sandbox.docker_runner import DockerTestRunner


def default_checks() -> list[Check]:
    return [
        TestsPassCheck(),
        ForbiddenPathsCheck(),
        TestTamperingCheck(),
        UnsafeCommandsCheck(),
        ScopeAdherenceCheck(),
        DiffSizeCheck(),
        SecretScanCheck(),
    ]


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


def _failed_local_agent_event(command_tracker: CommandTracker):
    for event in command_tracker.events:
        if (
            event.executed
            and (
                event.command_text.startswith("local agent:")
                or event.command_text.startswith("agent command:")
                or event.command_text.startswith("agent profile ")
            )
            and event.exit_code != 0
        ):
            return event
    return None


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
                category=result.benchmark.category,
                difficulty=result.benchmark.difficulty,
                benchmark_id=result.benchmark.id,
                benchmark_version=result.benchmark.version,
                agent=result.agent,
                failed_checks=[
                    check.name for check in result.check_results if not check.passed
                ],
            )
        )
    except Exception as error:
        warnings.warn(
            f"AgentGuard history write failed: {error}",
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
) -> BenchmarkResult:
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
        detected_version, version_status, version_warning = detect_agent_version(config)
    if version_warning is not None:
        warnings.warn(
            f"AgentGuard agent version detection: {version_warning}",
            RuntimeWarning,
            stacklevel=2,
        )

    agent = _agent_for_config(config, agent_name)
    timeline.add("agent_started", f"Agent {agent_name} started", {"agent": agent_name})
    with _measure_stage(timing_recorder, "agent_execution"):
        agent.run(prepared.repo_dir, command_tracker)
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
    ingested_events = read_agent_events(prepared.repo_dir)
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
    failed_local_agent = _failed_local_agent_event(command_tracker)
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
    elif failed_local_agent is not None:
        test_result = CommandResult(
            command=failed_local_agent.command_text,
            exit_code=failed_local_agent.exit_code or 1,
            stdout=failed_local_agent.stdout,
            stderr=failed_local_agent.stderr,
            duration_seconds=failed_local_agent.duration_seconds or 0.0,
            timed_out=failed_local_agent.timed_out,
            stdout_truncated=failed_local_agent.stdout_truncated,
            stderr_truncated=failed_local_agent.stderr_truncated,
        )
        timeline.add(
            "tests_skipped",
            "Tests skipped because local agent command failed.",
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
    diff_summary = collect_diff(prepared.repo_dir)
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
    check_results = [
        check.run(config, test_result, diff_summary, command_tracker.events)
        for check in default_checks()
    ]
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
    if evaluation_profile is not None:
        (
            test_result,
            diff_summary,
            check_results,
        ) = _sanitize_profile_evidence(
            test_result,
            diff_summary,
            check_results,
            command_tracker,
            [value for value in config.agent_environment.values() if value],
        )
    with _measure_stage(timing_recorder, "report_writing"):
        command_log_path = command_tracker.write_json(prepared.run_dir)

    reports_dir = prepared.run_dir / "reports"
    report_paths = ReportPaths(
        json=reports_dir / "report.json",
        markdown=reports_dir / "report.md",
        command_log=command_log_path,
        manifest=(
            prepared.run_dir / "manifest.json"
            if write_manifest_enabled
            else None
        ),
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
    if evaluation_profile is not None:
        timeline_events = _sanitize_timeline_events(
            timeline_events,
            [value for value in config.agent_environment.values() if value],
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
    )
    with _measure_stage(timing_recorder, "report_writing"):
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
    )
    manifest = ExecutionManifest(
        execution_id=prepared.run_id,
        execution_type="run",
        created_at=created_at,
        completed_at=manifest_utc_now_iso(),
        duration_seconds=round(time.monotonic() - started, 6),
        agentguard=agentguard_identity(),
        host=host_identity(docker_relevant=config.sandbox.type == "docker"),
        source=source_identity(config.repo_template),
        configuration=configuration_identity(
            config.config_path,
            {
                "task_id": config.task_id,
                "mode": config.mode,
                "agent_workdir": config.agent_workdir,
                "profile_id": (
                    evaluation_profile.id if evaluation_profile is not None else None
                ),
                "task_prompt_source": task_prompt_source,
                "task_prompt_sha256": task_prompt_sha256,
            },
        ),
        agent=agent_identity(
            config,
            agent_name,
            detected_version,
            version_status,
            version_warning,
        ),
        benchmarks=[benchmark_identity(config)],
        policies=[policy_identity(config)],
        artifacts=artifact_identity(json_path, markdown_path, command_log_path),
        parent_execution_id=parent_execution_id,
        parent_execution_type=parent_execution_type,
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
    if record_history_enabled:
        with _measure_stage(timing_recorder, "history_writing"):
            _record_run_history(result)
    if timing_recorder is not None:
        timing_recorder.finish_total()
    return result
