from agentguard.policy.command_policy import evaluate_command_policy


def test_command_policy_no_match_allows() -> None:
    decision = evaluate_command_policy(
        command_text="python agent_scripts/safe_agent.py",
        unsafe_patterns=["rm -rf"],
        mode="enforce",
    )

    assert decision.allowed is True
    assert decision.matched_patterns == []


def test_command_policy_audit_match_allows_and_records_pattern() -> None:
    decision = evaluate_command_policy(
        command_text='python -c "print(\'rm -rf\')"',
        unsafe_patterns=["rm -rf"],
        mode="audit",
    )

    assert decision.allowed is True
    assert decision.mode == "audit"
    assert decision.matched_patterns == ["rm -rf"]
    assert "audit mode" in decision.message


def test_command_policy_enforce_match_blocks_and_records_pattern() -> None:
    decision = evaluate_command_policy(
        command_text="rm -rf /tmp/agentguard-demo",
        unsafe_patterns=["rm -rf"],
        mode="enforce",
    )

    assert decision.allowed is False
    assert decision.mode == "enforce"
    assert decision.matched_patterns == ["rm -rf"]
    assert "blocked" in decision.message
