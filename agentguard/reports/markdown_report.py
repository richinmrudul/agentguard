from pathlib import Path

from agentguard.core.result import BenchmarkResult


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
    return f" ({', '.join(flags)})" if flags else ""


def _sandbox_lines(result: BenchmarkResult) -> list[str]:
    if result.sandbox is None:
        return []
    sandbox = result.sandbox
    lines = [
        "",
        "## Sandbox",
        f"- Type: {sandbox.type}",
        f"- Timeout: {sandbox.timeout_seconds}s",
        f"- Max output: {sandbox.max_output_bytes} bytes",
    ]
    if sandbox.type == "docker":
        lines.extend(
            [
                f"- Network: {sandbox.network}",
                f"- Memory: {sandbox.memory or 'unlimited'}",
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
        lines.append(f"- ID: {benchmark.id}")
    if benchmark.category:
        lines.append(f"- Category: {benchmark.category}")
    if benchmark.difficulty:
        lines.append(f"- Difficulty: {benchmark.difficulty}")
    if benchmark.tags:
        lines.append(f"- Tags: {', '.join(benchmark.tags)}")
    if benchmark.expected_behavior:
        lines.append(f"- Expected behavior: {benchmark.expected_behavior}")
    if benchmark.failure_mode:
        lines.append(f"- Failure mode: {benchmark.failure_mode}")
    return lines


def write_markdown_report(result: BenchmarkResult, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "report.md"
    lines = [
        "# AgentGuard Report",
        "",
        f"Task: {result.task_id}",
        f"Agent: {result.agent}",
        f"Result: {result.result}",
        f"Score: {result.score}/100",
        "",
        "## Checks",
    ]
    for check in result.check_results:
        lines.append(
            f"- {_status(check.passed)} [{check.severity}] "
            f"{check.name}: {check.message}"
        )
        if not check.passed and check.evidence:
            lines.append("  Evidence:")
            lines.extend(f"  - {evidence}" for evidence in check.evidence)

    lines.extend(_benchmark_lines(result))
    lines.extend(_sandbox_lines(result))

    lines.extend(["", "## Modified Files"])
    if result.diff_summary.changed_files:
        lines.extend(f"- {path}" for path in result.diff_summary.changed_files)
    else:
        lines.append("- None")

    lines.extend(["", "## Timeline"])
    if result.timeline:
        lines.extend(f"{event.order}. {event.message}" for event in result.timeline)
    else:
        lines.append("- None")

    lines.extend(["", "## Command Events"])
    if result.report_paths.command_log is not None:
        lines.append(f"Command log: {result.report_paths.command_log}")
    if result.command_events:
        for event in result.command_events:
            if event.blocked:
                status = "blocked"
            elif event.executed:
                status = "executed"
            else:
                status = "simulated"
            lines.append(f"- [{status}] {event.command_text}{_event_flags(event)}")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Reports",
            f"- JSON: {result.report_paths.json}",
            f"- Markdown: {result.report_paths.markdown}",
            "",
        ]
    )
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path
