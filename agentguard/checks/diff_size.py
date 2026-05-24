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
