from dataclasses import replace
from pathlib import Path
import sys

from agentguard.agents.agent_command_agent import AgentCommandAgent
from agentguard.config.loader import load_config
from agentguard.instrumentation.command_tracker import CommandTracker


def _config(**overrides):
    return replace(
        load_config(Path("examples/configs/fix_auth_bug_agent_command_safe.yaml")),
        **overrides,
    )


def test_agent_command_string_is_split_safely(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()
    command = (
        f'{sys.executable} -c "from pathlib import Path; '
        "Path('quoted output.txt').write_text('ok', encoding='utf-8')\""
    )

    AgentCommandAgent(_config(agent_command=command)).run(repo_dir, tracker)

    event = tracker.events[0]
    assert (repo_dir / "quoted output.txt").read_text(encoding="utf-8") == "ok"
    assert event.command == [
        sys.executable,
        "-c",
        "from pathlib import Path; "
        "Path('quoted output.txt').write_text('ok', encoding='utf-8')",
    ]
    assert event.command_text == f"agent command: {command}"
    assert event.exit_code == 0


def test_agent_command_list_is_used_directly(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()
    argv = [
        sys.executable,
        "-c",
        "from pathlib import Path; Path('list-output').write_text('ok')",
    ]

    AgentCommandAgent(_config(agent_command=argv)).run(repo_dir, tracker)

    event = tracker.events[0]
    assert (repo_dir / "list-output").read_text(encoding="utf-8") == "ok"
    assert event.command == argv
    assert event.command_text.startswith("agent command:")


def test_agent_command_environment_is_passed(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()
    command = (
        "import os; from pathlib import Path; "
        "Path('env-output').write_text(os.environ['AGENTGUARD_VALUE'])"
    )

    AgentCommandAgent(
        _config(
            agent_command=[sys.executable, "-c", command],
            agent_environment={"AGENTGUARD_VALUE": "present"},
        )
    ).run(repo_dir, tracker)

    assert (repo_dir / "env-output").read_text(encoding="utf-8") == "present"


def test_agent_command_default_workdir_is_repo_root(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()

    AgentCommandAgent(
        _config(
            agent_command=[
                sys.executable,
                "-c",
                "from pathlib import Path; Path('repo-root-marker').write_text('ok')",
            ],
        )
    ).run(repo_dir, tracker)

    assert (repo_dir / "repo-root-marker").exists()
    assert tracker.events[0].cwd == str(repo_dir)


def test_agent_command_config_dir_workdir(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    config_path = config_dir / "agentguard.yaml"
    config_path.write_text("task_id: placeholder\n", encoding="utf-8")
    tracker = CommandTracker()

    AgentCommandAgent(
        _config(
            agent_command=[
                sys.executable,
                "-c",
                "from pathlib import Path; Path('config-dir-marker').write_text('ok')",
            ],
            agent_workdir="config_dir",
            config_path=config_path,
        )
    ).run(repo_dir, tracker)

    assert (config_dir / "config-dir-marker").exists()
    assert not (repo_dir / "config-dir-marker").exists()
    assert tracker.events[0].cwd == str(config_dir)


def test_agent_command_preflight_enforce_blocks_before_execution(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()

    AgentCommandAgent(
        _config(
            agent_command=[
                sys.executable,
                "-c",
                "from pathlib import Path; Path('should-not-run').write_text('no')",
            ],
            unsafe_commands=[sys.executable],
            command_policy=replace(_config().command_policy, mode="enforce"),
            agent_name="blocked-demo-agent",
        )
    ).run(repo_dir, tracker)

    event = tracker.events[0]
    assert not (repo_dir / "should-not-run").exists()
    assert event.preflight_blocked is True
    assert event.executed is False
    assert event.exit_code == 126
    assert event.preflight_matched_patterns == [sys.executable]
    assert event.policy_mode == "enforce"
    assert event.agent_name == "blocked-demo-agent"
