from dataclasses import replace
from pathlib import Path
import sys

import pytest

from agentguard.agents.local_command_agent import LocalCommandAgent
from agentguard.config.loader import load_config
from agentguard.instrumentation.command_tracker import CommandTracker


def _config(**overrides):
    return replace(
        load_config(Path("examples/configs/fix_auth_bug_local_command_safe.yaml")),
        **overrides,
    )


def test_local_command_agent_runs_harmless_command_in_repo(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()
    command = (
        f'{sys.executable} -c "from pathlib import Path; '
        "Path('agent-output.txt').write_text('ok', encoding='utf-8')\""
    )

    LocalCommandAgent(_config(agent_command=command)).run(repo_dir, tracker)

    assert (repo_dir / "agent-output.txt").read_text(encoding="utf-8") == "ok"
    assert tracker.events[0].command_text == f"local agent: {command}"
    assert tracker.events[0].exit_code == 0
    assert tracker.events[0].executed is True


def test_local_command_agent_records_command_event(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()

    LocalCommandAgent(
        _config(agent_command=f'{sys.executable} -c "print(123)"')
    ).run(repo_dir, tracker)

    event = tracker.events[0]
    assert event.command[0] == sys.executable
    assert event.cwd == str(repo_dir)
    assert event.stdout.strip() == "123"
    assert event.stderr == ""
    assert event.duration_seconds is not None


def test_local_command_agent_timeout_records_controlled_event(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()

    LocalCommandAgent(
        _config(
            agent_command=f'{sys.executable} -c "import time; time.sleep(2)"',
            command_timeout_seconds=1,
        )
    ).run(repo_dir, tracker)

    event = tracker.events[0]
    assert event.exit_code == 124
    assert event.timed_out is True
    assert "Local command timed out after 1 seconds." in event.stderr


def test_local_command_agent_preflight_enforce_blocks_before_execution(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()
    command = (
        f'{sys.executable} -c "from pathlib import Path; '
        "Path('should-not-run').write_text('no')\""
    )

    LocalCommandAgent(
        _config(
            agent_command=command,
            unsafe_commands=[sys.executable],
            command_policy=replace(_config().command_policy, mode="enforce"),
        )
    ).run(repo_dir, tracker)

    assert not (repo_dir / "should-not-run").exists()
    event = tracker.events[0]
    assert event.preflight_blocked is True
    assert event.executed is False
    assert event.exit_code == 126
    assert event.preflight_matched_patterns == [sys.executable]
    assert event.policy_mode == "enforce"


def test_local_command_agent_requires_agent_command(tmp_path: Path) -> None:
    agent = LocalCommandAgent(_config(agent_command=None))

    with pytest.raises(ValueError, match="requires config field 'agent_command'"):
        agent.run(tmp_path, CommandTracker())
