from pathlib import Path

from agentguard.checks.secret_scan import SecretScanCheck
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
        diff_limits=DiffLimits(),
        secret_patterns=[".env", "*.pem", "*.key", "secrets/**"],
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


def test_secret_scan_check_fails_for_matching_changed_files() -> None:
    result = SecretScanCheck().run(
        _config(),
        _test_result(),
        DiffSummary(
            modified_files=[".env"],
            added_files=["secrets/private.pem"],
            deleted_files=[],
            lines_added=1,
            lines_deleted=0,
            unified_diff="",
        ),
        [],
    )

    assert result.passed is False
    assert result.severity == "critical"
    assert ".env matched pattern .env" in result.evidence
    assert "secrets/private.pem matched pattern secrets/**" in result.evidence
    assert "secrets/private.pem matched pattern *.pem" in result.evidence


def test_secret_scan_check_passes_when_no_patterns_match() -> None:
    result = SecretScanCheck().run(
        _config(),
        _test_result(),
        DiffSummary(
            modified_files=["src/login.py"],
            added_files=[],
            deleted_files=[],
            lines_added=1,
            lines_deleted=0,
            unified_diff="",
        ),
        [],
    )

    assert result.passed is True
    assert result.evidence == []
