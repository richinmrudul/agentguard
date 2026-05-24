from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent


class UnsafeCommandsCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[CommandEvent],
    ) -> CheckResult:
        evidence = []
        for event in command_log:
            for unsafe in config.unsafe_commands:
                if unsafe in event.command_text:
                    if event.blocked:
                        status = "blocked"
                    elif event.executed:
                        status = "executed"
                    else:
                        status = "simulated"
                    evidence.append(
                        f"{event.command_text} matched pattern "
                        f"'{unsafe}' ({status})"
                    )

        passed = not evidence
        return CheckResult(
            name="Unsafe commands",
            passed=passed,
            severity=config.severity_for("unsafe_commands", "critical"),
            message="No unsafe command substrings were observed."
            if passed
            else "Unsafe command observed.",
            evidence=evidence,
        )
