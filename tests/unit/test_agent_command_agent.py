from dataclasses import replace
import os
from pathlib import Path
import sys
import time

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


def test_agent_command_timeout_cleans_up_child_process(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    child_pid = tmp_path / "child.pid"
    tracker = CommandTracker()
    script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "\"import time; time.sleep(30)\"])\n"
        f"Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        "time.sleep(30)\n"
    )

    AgentCommandAgent(
        _config(
            agent_command=[sys.executable, "-c", script],
            command_timeout_seconds=1,
        )
    ).run(repo_dir, tracker)

    pid = _read_pid(child_pid)
    assert _process_exited(pid), f"child process still running: {pid}"
    event = tracker.events[0]
    assert event.timed_out is True
    assert event.process_cleanup_attempted is True
    assert event.process_cleanup_complete is True


def _read_pid(path: Path) -> int:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.exists():
            return int(path.read_text(encoding="utf-8"))
        time.sleep(0.02)
    raise AssertionError("child pid was not written")


def _process_exited(pid: int) -> bool:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False
