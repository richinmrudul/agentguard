from pathlib import Path

from agentguard.core.result import CheckResult, CiResult
from agentguard.reports.markdown import markdown_inline_code, markdown_text

MAX_CHECKS_PER_SECTION = 20
MAX_SUMMARY_FIELD_CHARS = 500


def _bounded(value: object) -> str:
    text = str(value)
    if len(text) <= MAX_SUMMARY_FIELD_CHARS:
        return text
    return text[: MAX_SUMMARY_FIELD_CHARS - len("...[truncated]")] + "...[truncated]"


def _portable_report_path(result: CiResult, path: Path) -> str:
    try:
        return path.resolve().relative_to(result.repo_dir.resolve()).as_posix()
    except ValueError:
        return path.name


def _format_check(check: CheckResult) -> str:
    return (
        f"- [{markdown_text(_bounded(check.severity))}] "
        f"{markdown_text(_bounded(check.name))}: "
        f"{markdown_text(_bounded(check.message))}"
    )


def _file_lines(label: str, paths: list[str], limit: int = 10) -> list[str]:
    lines = [f"- {markdown_text(label)}: {len(paths)}"]
    for path in paths[:limit]:
        lines.append(f"  - {markdown_inline_code(_bounded(path))}")
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
        lines.extend(
            _format_check(check) for check in failed_checks[:MAX_CHECKS_PER_SECTION]
        )
        if len(failed_checks) > MAX_CHECKS_PER_SECTION:
            lines.append(f"- ...and {len(failed_checks) - MAX_CHECKS_PER_SECTION} more")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("### Warning Checks")
    if warning_checks:
        lines.extend(
            _format_check(check) for check in warning_checks[:MAX_CHECKS_PER_SECTION]
        )
        if len(warning_checks) > MAX_CHECKS_PER_SECTION:
            lines.append(f"- ...and {len(warning_checks) - MAX_CHECKS_PER_SECTION} more")
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
            f"- JSON: {markdown_inline_code(_portable_report_path(result, result.report_paths.json))}",
            f"- Markdown: {markdown_inline_code(_portable_report_path(result, result.report_paths.markdown))}",
        ]
    )
    if result.report_paths.command_log is not None:
        lines.append(
            "- Command log: "
            f"{markdown_inline_code(_portable_report_path(result, result.report_paths.command_log))}"
        )

    with summary_path.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")

    return summary_path
