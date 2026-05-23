from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary


class TestsPassCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[str],
    ) -> CheckResult:
        passed = test_result.exit_code == 0
        return CheckResult(
            name="Tests passed",
            passed=passed,
            severity="error",
            message="Configured test command passed."
            if passed
            else "Configured test command failed.",
            evidence=[f"{test_result.command} exited {test_result.exit_code}"],
        )
