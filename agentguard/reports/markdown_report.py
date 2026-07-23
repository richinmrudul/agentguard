from pathlib import Path

from agentguard.core.result import BenchmarkResult
from agentguard.io import atomic_write_text
from agentguard.reports.markdown import markdown_text


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def _event_flags(event) -> str:
    flags = []
    if event.policy_mode and event.preflight_matched_patterns:
        patterns = ", ".join(event.preflight_matched_patterns)
        flags.append(f"policy {event.policy_mode} match: {patterns}")
    if event.preflight_blocked:
        flags.append("preflight blocked")
    if event.timed_out:
        flags.append("timed out")
    if event.stdout_truncated:
        flags.append("stdout truncated")
    if event.stderr_truncated:
        flags.append("stderr truncated")
    if event.process_cleanup_attempted:
        status = (
            "process cleanup complete"
            if event.process_cleanup_complete
            else "process cleanup incomplete"
        )
        if event.process_cleanup_message:
            status = f"{status}: {event.process_cleanup_message}"
        flags.append(status)
    return f" ({', '.join(flags)})" if flags else ""


def _sandbox_lines(result: BenchmarkResult) -> list[str]:
    if result.sandbox is None:
        return []
    sandbox = result.sandbox
    lines = [
        "",
        "## Sandbox",
        f"- Type: {_escape_markdown(sandbox.type)}",
        f"- Timeout: {sandbox.timeout_seconds}s",
        f"- Max output: {sandbox.max_output_bytes} bytes",
    ]
    if sandbox.type == "docker":
        lines.extend(
            [
                f"- Network: {_escape_markdown(sandbox.network)}",
                f"- Memory: {_escape_markdown(sandbox.memory or 'unlimited')}",
                f"- CPUs: {sandbox.cpus if sandbox.cpus is not None else 'unlimited'}",
                f"- Read-only root: {sandbox.read_only}",
            ]
        )
    return lines


def _benchmark_lines(result: BenchmarkResult) -> list[str]:
    benchmark = result.benchmark
    if not benchmark.has_values():
        return []

    lines = ["", "## Benchmark"]
    if benchmark.id:
        lines.append(f"- ID: {_escape_markdown(benchmark.id)}")
    if benchmark.version:
        lines.append(f"- Version: {_escape_markdown(benchmark.version)}")
    if benchmark.category:
        lines.append(f"- Category: {_escape_markdown(benchmark.category)}")
    if benchmark.difficulty:
        lines.append(f"- Difficulty: {_escape_markdown(benchmark.difficulty)}")
    if benchmark.tags:
        lines.append(f"- Tags: {_escape_markdown(', '.join(benchmark.tags))}")
    if benchmark.expected_behavior:
        lines.append(
            f"- Expected behavior: {_escape_markdown(benchmark.expected_behavior)}"
        )
    if benchmark.failure_mode:
        lines.append(f"- Failure mode: {_escape_markdown(benchmark.failure_mode)}")
    return lines


def _guard_lines(result: BenchmarkResult) -> list[str]:
    summary = result.guard_summary
    if summary.mode == "off" and not summary.configured_ignore_patterns:
        return []
    lines = [
        "",
        "## Online Filesystem Guard",
        f"- Mode: {_escape_markdown(summary.mode)}",
        f"- Triggered: {summary.triggered}",
        f"- Terminated agent: {summary.terminated_agent}",
        f"- Kill required: {summary.kill_required}",
        f"- Files observed: {summary.files_observed}",
        f"- Scans: {summary.scan_count}",
        f"- Duration: {summary.monitor_duration_seconds:.3f}s",
        f"- Filesystem watcher mode: {_escape_markdown(summary.watcher_mode)}",
        f"- Filesystem watcher events observed: {summary.watcher_events_observed}",
        "- Filesystem watcher event limit exceeded: "
        f"{summary.watcher_event_limit_exceeded}",
        f"- Current lines added: {summary.live_lines_added}",
        f"- Current lines deleted: {summary.live_lines_deleted}",
        f"- Line measurement complete: {summary.line_measurement_complete}",
        "- Line measurement skipped files: "
        f"{summary.line_measurement_skipped_files}",
    ]
    if summary.line_measurement_error:
        lines.append(
            "- Line measurement status: "
            f"{_escape_markdown(summary.line_measurement_error)}"
        )
    if summary.watcher_event_error:
        lines.append(
            "- Filesystem watcher status: "
            f"{_escape_markdown(summary.watcher_event_error)}"
        )
    if summary.configured_ignore_patterns:
        lines.append("- Configured ignore patterns:")
        lines.extend(
            f"  - {_escape_markdown(pattern)}"
            for pattern in summary.configured_ignore_patterns
        )
    if summary.first_violation_time is not None:
        lines.append(f"- First violation time: {summary.first_violation_time:.6f}")
    if summary.violations:
        lines.append("- Violations:")
        lines.extend(
            "  - "
            f"{_escape_markdown(violation.violation_type)}: "
            f"{_escape_markdown(violation.path)} "
            f"({_escape_markdown(violation.action)}) - "
            f"{_escape_markdown(violation.message)}"
            for violation in summary.violations
        )
    if summary.watcher_events:
        lines.append("- Watcher events:")
        lines.extend(
            "  - "
            f"{event.observed_at_sequence}: {_escape_markdown(event.event_type)} "
            f"{_escape_markdown(event.path)} ({_escape_markdown(event.source)})"
            for event in summary.watcher_events[:10]
        )
    return lines


def _escape_markdown(value: object) -> str:
    return markdown_text(value)


def _command_guard_lines(result: BenchmarkResult) -> list[str]:
    summary = result.command_guard_summary
    if summary.mode == "off":
        return []
    lines = [
        "",
        "## Online Command Guard",
        f"- Mode: {_escape_markdown(summary.mode)}",
        f"- Triggered: {summary.triggered}",
        f"- Terminated agent: {summary.terminated_agent}",
        f"- Kill required: {summary.kill_required}",
        f"- Events observed: {summary.events_observed}",
        f"- Scans: {summary.scan_count}",
        f"- Duration: {summary.monitor_duration_seconds:.3f}s",
        f"- Event file: {_escape_markdown(summary.event_file)}",
    ]
    if summary.first_violation_time is not None:
        lines.append(f"- First violation time: {summary.first_violation_time:.6f}")
    if summary.violations:
        lines.append("- Violations:")
        lines.extend(
            "  - "
            f"{_escape_markdown(violation.violation_type)}: "
            f"{_escape_markdown(violation.command_text)} "
            f"({_escape_markdown(', '.join(violation.matched_patterns))}; "
            f"{_escape_markdown(violation.action)}) "
            f"- {_escape_markdown(violation.message)}"
            for violation in summary.violations
        )
    return lines


def _guard_metric_lines(result: BenchmarkResult) -> list[str]:
    if not result.guard_metrics:
        return []
    metrics = result.guard_metrics
    lines = [
        "",
        "## Guard Metrics",
        f"- Violations total: {metrics.get('guard_violations_total', 0)}",
        f"- Blocked: {metrics.get('guard_blocked', False)}",
        "- Time to first violation: "
        f"{_fmt_metric_ms(metrics.get('time_to_first_violation_ms'))}",
        f"- Time to block: {_fmt_metric_ms(metrics.get('time_to_block_ms'))}",
        "- Filesystem guard violations: "
        f"{metrics.get('filesystem_guard_violations', 0)}",
        f"- Command guard violations: {metrics.get('command_guard_violations', 0)}",
    ]
    if result.report_paths.guard_incident_json is not None:
        lines.extend(
            [
                "- Incident JSON: "
                f"{_escape_markdown(result.report_paths.guard_incident_json)}",
                (
                    "- Incident Markdown: "
                    f"{_escape_markdown(result.report_paths.guard_incident_markdown or '-')}"
                ),
            ]
        )
    return lines


def _fmt_metric_ms(value: object) -> str:
    return f"{value} ms" if isinstance(value, int) else "-"


def write_markdown_report(result: BenchmarkResult, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.md"
    lines = [
        "# AgentGuard Report",
        "",
        f"Task: {_escape_markdown(result.task_id)}",
        f"Agent: {_escape_markdown(result.agent)}",
        f"Result: {_escape_markdown(result.result)}",
        f"Score: {result.score}/100",
        "",
        "## Checks",
    ]
    for check in result.check_results:
        lines.append(
            f"- {_status(check.passed)} [{_escape_markdown(check.severity)}] "
            f"{_escape_markdown(check.name)}: {_escape_markdown(check.message)}"
        )
        if not check.passed and check.evidence:
            lines.append("  Evidence:")
            lines.extend(f"  - {_escape_markdown(evidence)}" for evidence in check.evidence)

    lines.extend(_benchmark_lines(result))
    lines.extend(_sandbox_lines(result))
    lines.extend(_guard_lines(result))
    lines.extend(_command_guard_lines(result))
    lines.extend(_guard_metric_lines(result))
    if result.profile_id is not None:
        lines.extend(
            [
                "",
                "## Evaluation Profile",
                f"- Profile: {_escape_markdown(result.profile_name)} "
                f"({_escape_markdown(result.profile_id)})",
                f"- Model: {_escape_markdown(result.profile_model or '-')}",
                "- Task prompt source: "
                f"{_escape_markdown(result.task_prompt_source)}",
                "- Task prompt SHA-256: "
                f"{_escape_markdown(result.task_prompt_sha256)}",
            ]
        )
    if result.report_paths.manifest is not None:
        lines.extend(
            [
                "",
                "## Provenance",
                "- Execution ID: "
                f"{_escape_markdown(result.execution_id or result.run_dir.name)}",
                f"- Manifest: {_escape_markdown(result.report_paths.manifest)}",
                f"- Trace: {_escape_markdown(result.report_paths.trace or '-')}",
            ]
        )
        if result.parent_execution_id is not None:
            lines.append(
                "- Parent: "
                f"{_escape_markdown(result.parent_execution_type or 'execution')} "
                f"{_escape_markdown(result.parent_execution_id)}"
            )

    lines.extend(["", "## Modified Files"])
    if result.diff_summary.changed_files:
        lines.extend(f"- {_escape_markdown(path)}" for path in result.diff_summary.changed_files)
    else:
        lines.append("- None")

    lines.extend(["", "## Timeline"])
    if result.timeline:
        lines.extend(
            f"{event.order}. {_escape_markdown(event.message)}"
            for event in result.timeline
        )
    else:
        lines.append("- None")

    lines.extend(["", "## Command Events"])
    if result.report_paths.command_log is not None:
        lines.append(
            f"Command log: {_escape_markdown(result.report_paths.command_log)}"
        )
    if result.command_events:
        for event in result.command_events:
            if event.blocked:
                status = "blocked"
            elif event.executed:
                status = "executed"
            else:
                status = "simulated"
            lines.append(
                f"- [{status}] {_escape_markdown(event.command_text)}"
                f"{_escape_markdown(_event_flags(event))}"
            )
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Reports",
            f"- JSON: {_escape_markdown(result.report_paths.json)}",
            f"- Markdown: {_escape_markdown(result.report_paths.markdown)}",
            f"- Manifest: {_escape_markdown(result.report_paths.manifest or '-')}",
            f"- Trace: {_escape_markdown(result.report_paths.trace or '-')}",
            "",
        ]
    )
    atomic_write_text(report_path, "\n".join(lines))
    return report_path
