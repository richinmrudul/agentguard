from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent


class DiffSizeCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[CommandEvent],
    ) -> CheckResult:
        evidence: list[str] = []
        files_changed = len(diff_summary.changed_files)
        limits = config.diff_limits

        line_limit_configured = (
            limits.max_lines_added is not None or limits.max_lines_deleted is not None
        )
        count_status = getattr(diff_summary, "line_count_status", "exact")
        count_complete = getattr(diff_summary, "line_count_complete", True)
        count_error = getattr(diff_summary, "line_count_error", None)
        known_statuses = {
            "exact",
            "over_limit",
            "presentation_capped",
            "incomplete",
            "binary",
            "malformed",
            "unavailable",
            "not_applicable",
        }
        if (
            line_limit_configured
            and (not count_complete or count_status not in known_statuses)
            and count_status != "not_applicable"
        ):
            reason = count_error or count_status or "unavailable"
            evidence.append(
                "Diff line count evidence is incomplete or unavailable; "
                f"failing closed for configured line limits ({reason})."
            )
        if (
            limits.max_files_changed is not None
            and files_changed > limits.max_files_changed
        ):
            evidence.append(
                f"Changed {files_changed} files; limit is {limits.max_files_changed}."
            )
        if (
            limits.max_lines_added is not None
            and diff_summary.lines_added > limits.max_lines_added
        ):
            evidence.append(
                f"Added {diff_summary.lines_added} lines; "
                f"limit is {limits.max_lines_added}."
            )
        if (
            limits.max_lines_deleted is not None
            and diff_summary.lines_deleted > limits.max_lines_deleted
        ):
            evidence.append(
                f"Deleted {diff_summary.lines_deleted} lines; "
                f"limit is {limits.max_lines_deleted}."
            )
        passed = not evidence
        return CheckResult(
            name="Diff size",
            passed=passed,
            severity=config.severity_for("diff_size", "warning"),
            message="Diff size stayed within configured limits."
            if passed
            else "Diff size exceeded configured limits.",
            evidence=evidence,
        )
