from fnmatch import fnmatch

from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary


class ForbiddenPathsCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[str],
    ) -> CheckResult:
        matches = [
            path
            for path in diff_summary.changed_files
            if any(fnmatch(path, pattern) for pattern in config.forbidden_paths)
        ]
        passed = not matches
        return CheckResult(
            name="Forbidden paths",
            passed=passed,
            severity="critical",
            message="No forbidden paths were modified."
            if passed
            else f"Forbidden paths modified: {', '.join(matches)}",
            evidence=matches,
        )
