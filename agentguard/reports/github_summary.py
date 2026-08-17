import os
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


def github_step_summary_markdown(result: CiResult) -> str:
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

    return "\n".join(lines) + "\n"


def append_github_step_summary(summary_path: Path, content: str) -> Path:
    """Append one complete summary payload, rolling back partial writes when safe."""
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    descriptor = os.open(summary_path, flags, 0o666)
    initial_size = os.fstat(descriptor).st_size
    payload = content.encode("utf-8")
    written = 0
    try:
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise OSError("step-summary write made no progress")
            written += count
    except OSError:
        try:
            if os.fstat(descriptor).st_size == initial_size + written:
                os.ftruncate(descriptor, initial_size)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)

    return summary_path


def write_github_step_summary(result: CiResult, summary_path: Path) -> Path:
    append_github_step_summary(summary_path, github_step_summary_markdown(result))

    return summary_path
