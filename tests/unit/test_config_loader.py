from pathlib import Path

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
