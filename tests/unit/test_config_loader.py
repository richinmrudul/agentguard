from pathlib import Path

import pytest

from agentguard.config.loader import load_config


def test_load_fix_auth_bug_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug.yaml"))

    assert config.task_id == "fix_auth_bug"
    assert config.description == "Fix the auth login bug."
    assert config.mode == "benchmark"
    assert config.repo_template is not None
    assert config.repo_template.name == "auth_bug"
    assert config.test_command == "pytest"
    assert config.sandbox.type == "local"
    assert config.allowed_paths == ["src/**"]
    assert config.expected_modified_files.min == 1
    assert config.expected_modified_files.max == 2
    assert config.policy["secret_scan"] == "critical"
    assert config.diff_limits.max_files_changed == 3
    assert config.secret_patterns == [".env", "*.pem", "*.key", "secrets/**"]
    assert config.command_timeout_seconds == 60
    assert config.max_output_bytes == 200000
    assert config.command_policy.mode == "audit"


def test_load_fix_auth_bug_docker_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_docker.yaml"))

    assert config.agent_command is None
    assert config.sandbox.type == "docker"
    assert config.sandbox.image == "python:3.11-slim"
    assert config.sandbox.workdir == "/workspace"
    assert config.sandbox.network == "none"
    assert config.sandbox.timeout_seconds == 60


def test_load_docker_command_agent_config() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_docker_command_safe.yaml"))

    assert config.agent_command == "python agent_scripts/safe_agent.py"
    assert config.sandbox.type == "docker"
    assert config.sandbox.network == "none"
    assert config.sandbox.memory == "512m"
    assert config.sandbox.cpus == 1.0
    assert config.sandbox.read_only is False


def test_config_rejects_invalid_docker_network(tmp_path: Path) -> None:
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
sandbox:
  type: docker
  image: python:3.11-slim
  docker:
    network: host
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.docker.network"):
        load_config(config_path)


def test_config_rejects_non_positive_docker_cpus(tmp_path: Path) -> None:
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
sandbox:
  type: docker
  image: python:3.11-slim
  docker:
    cpus: 0
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.docker.cpus"):
        load_config(config_path)


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


def test_load_ci_config_without_repo_template() -> None:
    config = load_config(Path("examples/configs/ci_basic.yaml"))

    assert config.mode == "ci"
    assert config.task_id == "pr_safety_check"
    assert config.repo_template is None
    assert config.allowed_paths == ["agentguard/**", "tests/**", "examples/**"]


def test_config_accepts_command_limit_defaults_for_null_values(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
command_timeout_seconds:
max_output_bytes:
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.command_timeout_seconds == 60
    assert config.max_output_bytes == 200000


def test_config_rejects_non_positive_command_timeout(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
command_timeout_seconds: 0
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="command_timeout_seconds"):
        load_config(config_path)


def test_config_rejects_non_positive_max_output_bytes(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
max_output_bytes: 0
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="max_output_bytes"):
        load_config(config_path)


def test_config_rejects_invalid_command_policy_mode(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
command_policy:
  mode: monitor
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="command_policy.mode"):
        load_config(config_path)
