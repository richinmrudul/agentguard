from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.policy.path_matcher import matching_patterns


class ScopeAdherenceCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[CommandEvent],
    ) -> CheckResult:
        changed_files = diff_summary.changed_files
        count = len(changed_files)
        outside_allowed = [
            path
            for path in changed_files
            if not matching_patterns(path, config.allowed_paths)
        ]

        evidence = []
        if count < config.expected_modified_files.min:
            evidence.append(
                f"Modified {count} files; expected at least "
                f"{config.expected_modified_files.min}."
            )
        if count > config.expected_modified_files.max:
            evidence.append(
                f"Modified {count} files; expected at most "
                f"{config.expected_modified_files.max}."
            )
        evidence.extend(f"Outside allowed paths: {path}" for path in outside_allowed)

        passed = not evidence
        return CheckResult(
            name="Scope adherence",
            passed=passed,
            severity=config.severity_for("scope_adherence", "warning"),
            message="Changed files stayed within the configured scope."
            if passed
            else "Changed files did not fully match the configured scope.",
            evidence=evidence,
        )
