from pathlib import Path

from agentguard.agents.base import Agent
from agentguard.agents.custom_command_agent import CustomCommandAgent
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
from agentguard.core.result import BenchmarkResult, ReportPaths, SandboxMetadata
from agentguard.core.timeline import TimelineRecorder
from agentguard.instrumentation.agent_event_reader import (
    DEFAULT_AGENT_EVENT_FILE,
    read_agent_events,
)
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner
from agentguard.repo.git_diff import collect_diff
from agentguard.repo.manager import RepoManager
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


def _agent_for_config(config, agent_name: str) -> Agent:
    if agent_name == CustomCommandAgent.name:
        return CustomCommandAgent(config)
    return get_agent(agent_name)


def _validate_agent_config(config, agent_name: str) -> None:
    if agent_name != CustomCommandAgent.name:
        return
    if not config.agent_command:
        raise ValueError("Agent 'custom-command' requires config field 'agent_command'.")
    if config.sandbox.type != "docker":
        raise ValueError("Agent 'custom-command' currently requires docker sandbox.")


def run_benchmark(config_path: Path, agent_name: str) -> BenchmarkResult:
    config = load_config(config_path)
    _validate_agent_config(config, agent_name)
    timeline = TimelineRecorder()
    timeline.add(
        "run_started",
        f"Run started for task {config.task_id} with agent {agent_name}",
        {"task_id": config.task_id, "agent": agent_name},
    )
    prepared = RepoManager().prepare(config, agent_name)
    timeline.add(
        "repo_prepared",
        "Prepared isolated repo workspace",
        {"run_dir": str(prepared.run_dir), "repo_dir": str(prepared.repo_dir)},
    )
    command_tracker = CommandTracker()
    command_event_index = 0

    agent = _agent_for_config(config, agent_name)
    timeline.add("agent_started", f"Agent {agent_name} started", {"agent": agent_name})
    agent.run(prepared.repo_dir, command_tracker)
    timeline.add(
        "agent_completed",
        f"Agent {agent_name} completed",
        {"agent": agent_name},
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

    timeline.add(
        "tests_started",
        f"Tests started: {config.test_command}",
        {"command": config.test_command},
    )
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
    command_log_path = command_tracker.write_json(prepared.run_dir)

    reports_dir = prepared.run_dir / "reports"
    report_paths = ReportPaths(
        json=reports_dir / "report.json",
        markdown=reports_dir / "report.md",
        command_log=command_log_path,
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
    partial_result = BenchmarkResult(
        task_id=config.task_id,
        agent=agent_name,
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
        command_events=command_tracker.events,
        timeline=timeline.events,
    )
    json_path = write_json_report(partial_result, reports_dir)
    markdown_path = write_markdown_report(partial_result, reports_dir)

    return BenchmarkResult(
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
        ),
        sandbox=partial_result.sandbox,
        command_events=partial_result.command_events,
        timeline=partial_result.timeline,
    )
