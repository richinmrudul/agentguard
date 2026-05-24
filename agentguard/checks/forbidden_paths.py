from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.policy.path_matcher import matching_patterns


class ForbiddenPathsCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[CommandEvent],
    ) -> CheckResult:
        matches = [
            path
            for path in diff_summary.changed_files
            if matching_patterns(path, config.forbidden_paths)
        ]
        passed = not matches
        return CheckResult(
            name="Forbidden paths",
            passed=passed,
            severity=config.severity_for("forbidden_paths", "critical"),
            message="No forbidden paths were modified."
            if passed
            else f"Forbidden paths modified: {', '.join(matches)}",
            evidence=matches,
        )
