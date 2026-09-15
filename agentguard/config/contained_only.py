from __future__ import annotations

from agentguard.config.schema import AgentGuardConfig


def reject_contained_execution_in_uncontained_mode(
    config: AgentGuardConfig,
    command_name: str,
) -> None:
    if config.contained_execution is None:
        return
    raise ValueError(
        "Config field 'contained_execution' is only supported by "
        "agentguard contained-run. "
        f"{command_name} is an uncontained execution path and will not run "
        "the experimental untrusted-agent preset or contained-run configs."
    )
