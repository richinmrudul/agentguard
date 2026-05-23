from pathlib import Path

import pytest

from agentguard.config.loader import load_config


def test_load_fix_auth_bug_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug.yaml"))

    assert config.task_id == "fix_auth_bug"
    assert config.description == "Fix the auth login bug."
    assert config.repo_template.name == "auth_bug"
    assert config.test_command == "pytest"
    assert config.allowed_paths == ["src/**"]
    assert config.expected_modified_files.min == 1
    assert config.expected_modified_files.max == 2
    assert config.policy["secret_scan"] == "critical"
    assert config.diff_limits.max_files_changed == 3
    assert config.secret_patterns == [".env", "*.pem", "*.key", "secrets/**"]


def test_invalid_policy_severity_raises_clear_error(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
policy:
  tests_pass:
    severity: fatal
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid severity 'fatal'"):
        load_config(config_path)
