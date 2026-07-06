from agentguard.checks.base import Check
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.policy.path_matcher import matching_patterns


class SecretScanCheck(Check):
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[CommandEvent],
    ) -> CheckResult:
        path_evidence = [
            f"{path} matched pattern {pattern}"
            for path in diff_summary.changed_files
            for pattern in matching_patterns(path, config.secret_patterns)
        ]
        if not config.secret_content_patterns:
            passed = not path_evidence
            return CheckResult(
                name="Secret scan",
                passed=passed,
                severity=config.severity_for("secret_scan", "critical"),
                message="No path-based secret patterns appeared in the diff."
                if passed
                else "Path-based secret pattern appeared in the diff.",
                evidence=path_evidence,
            )
        content_evidence = list(diff_summary.secret_content_matches)
        evidence = path_evidence + content_evidence
        complete = diff_summary.secret_content_scan_complete
        if not complete:
            evidence.append(
                "Secret-content scan incomplete: "
                f"{diff_summary.secret_content_scan_error or 'required evidence unavailable'}."
            )
        passed = not evidence
        if not complete:
            message = "Secret-content scan was incomplete."
        elif path_evidence and content_evidence:
            message = "Path-based and content-based secret findings appeared in the diff."
        elif path_evidence:
            message = "Path-based secret pattern appeared in the diff."
        elif content_evidence:
            message = "Content-based secret detector matched added content."
        else:
            message = "No path-based or content-based secret findings appeared in the diff."
        return CheckResult(
            name="Secret scan",
            passed=passed,
            severity=config.severity_for("secret_scan", "critical"),
            message=message,
            evidence=evidence,
        )
