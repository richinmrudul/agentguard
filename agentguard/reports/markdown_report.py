from pathlib import Path

from agentguard.core.result import BenchmarkResult


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


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
            lines.append(f"- [{status}] {event.command_text}")
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
