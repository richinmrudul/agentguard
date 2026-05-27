from dataclasses import dataclass


@dataclass(frozen=True)
class CommandPolicyDecision:
    allowed: bool
    mode: str
    matched_patterns: list[str]
    message: str


def evaluate_command_policy(
    command_text: str,
    unsafe_patterns: list[str],
    mode: str,
) -> CommandPolicyDecision:
    matched_patterns = [
        pattern for pattern in unsafe_patterns if pattern and pattern in command_text
    ]
    if not matched_patterns:
        return CommandPolicyDecision(
            allowed=True,
            mode=mode,
            matched_patterns=[],
            message="Command preflight policy allowed execution.",
        )
    if mode == "audit":
        return CommandPolicyDecision(
            allowed=True,
            mode=mode,
            matched_patterns=matched_patterns,
            message=(
                "Command preflight policy matched unsafe pattern(s) "
                "in audit mode; execution allowed."
            ),
        )
    return CommandPolicyDecision(
        allowed=False,
        mode=mode,
        matched_patterns=matched_patterns,
        message="Command blocked by preflight policy.",
    )
