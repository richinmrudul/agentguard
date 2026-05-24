from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.policy.path_matcher import matching_patterns


class TestTamperingCheck(Check):
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
            if matching_patterns(path, config.test_paths)
        ]
        passed = not matches
        return CheckResult(
            name="Test tampering",
            passed=passed,
            severity=config.severity_for("test_tampering", "error"),
            message="No test files were modified."
            if passed
            else f"Modified test files: {', '.join(matches)}",
            evidence=matches,
        )
