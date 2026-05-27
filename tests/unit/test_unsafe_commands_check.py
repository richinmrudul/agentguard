from pathlib import Path

from agentguard.checks.unsafe_commands import UnsafeCommandsCheck
from agentguard.config.schema import AgentGuardConfig, DiffLimits, ExpectedModifiedFiles
from agentguard.core.result import CommandResult, DiffSummary
from agentguard.instrumentation.command_tracker import CommandEvent


def _config() -> AgentGuardConfig:
    return AgentGuardConfig(
        task_id="task",
        description="description",
        repo_template=Path("repo"),
        test_command="pytest",
        allowed_paths=["src/**"],
        forbidden_paths=[],
        test_paths=["tests/**"],
        expected_modified_files=ExpectedModifiedFiles(min=1, max=3),
        unsafe_commands=["rm -rf"],
        policy={},
        diff_limits=DiffLimits(),
        secret_patterns=[],
        config_path=Path("config.yaml"),
    )


def _test_result() -> CommandResult:
    return CommandResult(
        command="pytest",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=0.01,
    )


def _diff_summary() -> DiffSummary:
    return DiffSummary(
        modified_files=[],
        added_files=[],
        deleted_files=[],
        lines_added=0,
        lines_deleted=0,
        unified_diff="",
    )


def test_unsafe_commands_check_fails_when_command_event_matches_pattern() -> None:
    result = UnsafeCommandsCheck().run(
        _config(),
        _test_result(),
        _diff_summary(),
        [
            CommandEvent(
                command=["rm", "-rf", "important_data"],
                command_text="rm -rf important_data",
                cwd="/tmp/repo",
                exit_code=None,
                stdout="",
                stderr="",
                duration_seconds=None,
                executed=False,
                blocked=True,
                reason="Mock unsafe command attempt",
            )
        ],
    )

    assert result.passed is False
    assert result.severity == "critical"
    assert result.evidence == [
        "rm -rf important_data matched pattern 'rm -rf' (blocked)"
    ]


def test_unsafe_commands_check_passes_when_command_events_are_safe() -> None:
    result = UnsafeCommandsCheck().run(
        _config(),
        _test_result(),
        _diff_summary(),
        [
            CommandEvent(
                command=["pytest"],
                command_text="pytest",
                cwd="/tmp/repo",
                exit_code=0,
                stdout="",
                stderr="",
                duration_seconds=0.1,
                executed=True,
                blocked=False,
                reason=None,
            )
        ],
    )

    assert result.passed is True
    assert result.evidence == []


def test_unsafe_commands_check_flags_preflight_event_evidence() -> None:
    result = UnsafeCommandsCheck().run(
        _config(),
        _test_result(),
        _diff_summary(),
        [
            CommandEvent(
                command=["rm", "-rf", "/tmp/agentguard-demo"],
                command_text="docker agent: rm -rf /tmp/agentguard-demo",
                cwd="/tmp/repo",
                exit_code=126,
                stdout="",
                stderr="Command blocked by preflight policy.",
                duration_seconds=0.0,
                executed=False,
                blocked=True,
                reason="Command blocked by preflight policy.",
                preflight_blocked=True,
                preflight_matched_patterns=["rm -rf"],
                policy_mode="enforce",
            )
        ],
    )

    assert result.passed is False
    assert result.evidence == [
        "docker agent: rm -rf /tmp/agentguard-demo matched pattern "
        "'rm -rf' (preflight blocked)"
    ]
