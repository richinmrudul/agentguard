from dataclasses import dataclass
from typing import Optional

from agentguard.checks.registry import instantiate_checks, registered_checks
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent


@dataclass(frozen=True)
class PolicyEvaluationContext:
    config: AgentGuardConfig
    test_result: CommandResult
    diff_summary: DiffSummary
    command_events: list[CommandEvent]


def evaluate_policy_checks(
    context: PolicyEvaluationContext,
    *,
    enabled_identifiers: Optional[list[str]] = None,
) -> list[CheckResult]:
    known = {registration.identifier for registration in registered_checks()}
    enabled = set(enabled_identifiers) if enabled_identifiers is not None else known
    unsupported = sorted(enabled - known)
    if unsupported:
        raise ValueError(
            "Unsupported replay check identifier(s): " + ", ".join(unsupported)
        )
    return [
        check.run(
            context.config,
            context.test_result,
            context.diff_summary,
            context.command_events,
        )
        for check in instantiate_checks(disabled_identifiers=known - enabled)
    ]
