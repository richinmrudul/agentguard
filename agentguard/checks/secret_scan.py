from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.policy.path_matcher import matching_patterns


class SecretScanCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[str],
    ) -> CheckResult:
        evidence = [
            f"{path} matched pattern {pattern}"
            for path in diff_summary.changed_files
            for pattern in matching_patterns(path, config.secret_patterns)
        ]
        passed = not evidence
        return CheckResult(
            name="Secret scan",
            passed=passed,
            severity=config.severity_for("secret_scan", "critical"),
            message="No path-based secret patterns appeared in the diff."
            if passed
            else "Path-based secret pattern appeared in the diff.",
            evidence=evidence,
        )
