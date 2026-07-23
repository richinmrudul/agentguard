from pathlib import Path

from agentguard.core.result import CheckResult, CiResult
from agentguard.reports.markdown import markdown_inline_code, markdown_text


def _format_check(check: CheckResult) -> str:
    return (
        f"- [{markdown_text(check.severity)}] {markdown_text(check.name)}: "
        f"{markdown_text(check.message)}"
    )


def _file_lines(label: str, paths: list[str], limit: int = 10) -> list[str]:
    lines = [f"- {markdown_text(label)}: {len(paths)}"]
    for path in paths[:limit]:
        lines.append(f"  - {markdown_inline_code(path)}")
    remaining = len(paths) - limit
    if remaining > 0:
        lines.append(f"  - ...and {remaining} more")
    return lines


def write_github_step_summary(result: CiResult, summary_path: Path) -> Path:
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    failed_checks = [
        check
        for check in result.check_results
        if not check.passed and check.severity in {"error", "critical"}
    ]
    warning_checks = [
        check for check in result.check_results if not check.passed and check.severity == "warning"
    ]

    lines = [
        "## AgentGuard CI Report",
        "",
        f"- Task: {markdown_inline_code(result.task_id)}",
        f"- Result: **{markdown_text(result.result)}**",
        f"- Score: **{result.score}/100**",
        "",
        "### Failed Checks",
    ]
    if failed_checks:
        lines.extend(_format_check(check) for check in failed_checks)
    else:
        lines.append("- None")

    lines.append("")
    lines.append("### Warning Checks")
    if warning_checks:
        lines.extend(_format_check(check) for check in warning_checks)
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "### Changed Files",
            *_file_lines("Modified", result.diff_summary.modified_files),
            *_file_lines("Added", result.diff_summary.added_files),
            *_file_lines("Deleted", result.diff_summary.deleted_files),
            "",
            "### Reports",
            f"- JSON: {markdown_inline_code(result.report_paths.json)}",
            f"- Markdown: {markdown_inline_code(result.report_paths.markdown)}",
        ]
    )
    if result.report_paths.command_log is not None:
        lines.append(
            f"- Command log: {markdown_inline_code(result.report_paths.command_log)}"
        )

    with summary_path.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    return summary_path
