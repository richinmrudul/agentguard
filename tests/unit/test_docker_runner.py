from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentguard.agents.custom_command_agent import CustomCommandAgent
from agentguard.config.loader import load_config
from agentguard.config.schema import SandboxConfig
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.sandbox.docker_runner import (
    DockerCommandRunner,
    DockerTestRunner,
    _docker_test_argv,
)


def test_docker_command_includes_expected_container_options(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerTestRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            workdir="/workspace",
            network="none",
            timeout_seconds=30,
        ),
    )

    command = runner._docker_command(repo_dir, ["pytest"])

    assert command[:3] == ["docker", "run", "--rm"]
    assert "-v" in command
    assert f"{repo_dir.resolve()}:/workspace" in command
    assert command[command.index("-w") + 1] == "/workspace"
    assert command[command.index("-e") + 1] == "PYTHONPATH=/workspace/src"
    assert command[command.index("--network") + 1] == "none"
    assert "python:3.11-slim" in command
    assert command[-1] == "pytest"


def test_docker_command_sets_pythonpath_for_custom_workdir(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerTestRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            workdir="/app",
        ),
    )

    command = runner._docker_command(repo_dir, ["python", "-m", "tests"])

    assert f"{repo_dir.resolve()}:/app" in command
    assert command[command.index("-w") + 1] == "/app"
    assert command[command.index("-e") + 1] == "PYTHONPATH=/app/src"


def test_docker_command_runner_records_readable_agent_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_run(command, **kwargs):
        return SimpleNamespace(returncode=0, stdout="agent ok", stderr="")

    monkeypatch.setattr("agentguard.sandbox.docker_runner.subprocess.run", fake_run)
    tracker = CommandTracker()
    runner = DockerCommandRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )

    result = runner.run_argv(
        repo_dir=repo_dir,
        inner_command=["python", "agent_scripts/safe_agent.py"],
        command_text="docker agent: python agent_scripts/safe_agent.py",
    )

    assert result.exit_code == 0
    assert tracker.commands == ["docker agent: python agent_scripts/safe_agent.py"]


def test_docker_runner_records_install_and_test_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("agentguard.sandbox.docker_runner.subprocess.run", fake_run)
    tracker = CommandTracker()
    runner = DockerTestRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )

    result = runner.run(repo_dir, "pytest")

    assert result.exit_code == 0
    assert len(calls) == 2
    assert calls[0][0][-7:] == [
        "python",
        "-m",
        "pip",
        "install",
        "--no-build-isolation",
        "-e",
        ".",
    ]
    assert calls[1][0][-3:] == ["python", "-m", "pytest"]
    assert tracker.commands == [
        "docker: python -m pip install --no-build-isolation -e .",
        "docker: pytest",
    ]


def test_docker_test_argv_normalizes_pytest_command() -> None:
    assert _docker_test_argv("pytest") == ["python", "-m", "pytest"]


def test_docker_test_argv_preserves_pytest_args() -> None:
    assert _docker_test_argv("pytest -q") == ["python", "-m", "pytest", "-q"]


def test_docker_test_argv_preserves_non_pytest_command() -> None:
    assert _docker_test_argv("python -m auth_example.mini_pytest") == [
        "python",
        "-m",
        "auth_example.mini_pytest",
    ]


def test_docker_runner_surfaces_missing_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_run(command, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("agentguard.sandbox.docker_runner.subprocess.run", fake_run)
    tracker = CommandTracker()
    runner = DockerTestRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )

    result = runner.run(repo_dir, "pytest")

    assert result.exit_code == 127
    assert "Docker is not installed" in result.stderr
    assert (
        tracker.events[0].command_text
        == "docker: python -m pip install --no-build-isolation -e ."
    )


def test_custom_command_agent_requires_agent_command(tmp_path: Path) -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_docker.yaml"))
    agent = CustomCommandAgent(config)

    with pytest.raises(ValueError, match="requires config field 'agent_command'"):
        agent.run(tmp_path, CommandTracker())


def test_custom_command_agent_runs_in_docker_with_readable_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_command="python agent_scripts/safe_agent.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="agent ok", stderr="")

    monkeypatch.setattr("agentguard.sandbox.docker_runner.subprocess.run", fake_run)
    tracker = CommandTracker()

    CustomCommandAgent(config).run(repo_dir, tracker)

    assert calls[0][:3] == ["docker", "run", "--rm"]
    assert f"{repo_dir.resolve()}:/workspace" in calls[0]
    assert calls[0][calls[0].index("-w") + 1] == "/workspace"
    assert calls[0][calls[0].index("-e") + 1] == "PYTHONPATH=/workspace/src"
    assert calls[0][calls[0].index("--network") + 1] == "none"
    assert calls[0][-2:] == ["python", "agent_scripts/safe_agent.py"]
    assert tracker.commands == ["docker agent: python agent_scripts/safe_agent.py"]


def test_sandbox_defaults_to_local(tmp_path: Path) -> None:
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
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.sandbox.type == "local"
    assert config.sandbox.workdir == "/workspace"
    assert config.sandbox.network == "none"
    assert config.sandbox.timeout_seconds == 60


def test_docker_sandbox_requires_image(tmp_path: Path) -> None:
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
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.image"):
        load_config(config_path)


def test_invalid_sandbox_type_raises_clear_error(tmp_path: Path) -> None:
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
  type: vm
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.type"):
        load_config(config_path)
