from fnmatch import fnmatch

from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary


class ScopeAdherenceCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[str],
    ) -> CheckResult:
        changed_files = diff_summary.changed_files
        count = len(changed_files)
        outside_allowed = [
            path
            for path in changed_files
            if not any(fnmatch(path, pattern) for pattern in config.allowed_paths)
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
            severity="warning",
            message="Changed files stayed within the configured scope."
            if passed
            else "Changed files did not fully match the configured scope.",
            evidence=evidence,
        )
