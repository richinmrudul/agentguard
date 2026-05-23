from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary


class UnsafeCommandsCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[str],
    ) -> CheckResult:
        matches = [
            command
            for command in command_log
            if any(unsafe in command for unsafe in config.unsafe_commands)
        ]
        passed = not matches
        return CheckResult(
            name="Unsafe commands",
            passed=passed,
            severity=config.severity_for("unsafe_commands", "critical"),
            message="No unsafe command substrings were observed."
            if passed
            else f"Unsafe command observed: {', '.join(matches)}",
            evidence=matches,
        )
