from dataclasses import replace
from pathlib import Path

from agentguard.checks.diff_size import DiffSizeCheck
from agentguard.config.schema import AgentGuardConfig, DiffLimits, ExpectedModifiedFiles
from agentguard.core.result import CommandResult, DiffSummary


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
        unsafe_commands=[],
        policy={},
        diff_limits=DiffLimits(
            max_files_changed=1,
            max_lines_added=10,
            max_lines_deleted=5,
        ),
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


def test_diff_size_check_fails_with_evidence_for_exceeded_limits() -> None:
    result = DiffSizeCheck().run(
        _config(),
        _test_result(),
        DiffSummary(
            modified_files=["src/a.py", "src/b.py"],
            added_files=[],
            deleted_files=[],
            lines_added=12,
            lines_deleted=6,
            unified_diff="",
        ),
        [],
    )

    assert result.passed is False
    assert result.severity == "warning"
    assert result.evidence == [
        "Changed 2 files; limit is 1.",
        "Added 12 lines; limit is 10.",
        "Deleted 6 lines; limit is 5.",
    ]


def test_diff_size_check_uses_policy_severity() -> None:
    config = replace(_config(), policy={"diff_size": "error"})

    result = DiffSizeCheck().run(
        config,
        _test_result(),
        DiffSummary(
            modified_files=["src/a.py", "src/b.py"],
            added_files=[],
            deleted_files=[],
            lines_added=1,
            lines_deleted=1,
            unified_diff="",
        ),
        [],
    )

    assert result.severity == "error"
