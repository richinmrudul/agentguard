from dataclasses import replace
import os
import shlex
from pathlib import Path
import sys
import time

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


def test_local_command_agent_bounds_large_stdout_and_stderr(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    tracker = CommandTracker()
    script = (
        "import sys; "
        "sys.stdout.write('out-start' + 'o' * 2000000 + 'out-end'); "
        "sys.stderr.write('err-start' + 'e' * 2000000 + 'err-end')"
    )

    LocalCommandAgent(
        _config(
            agent_command=shlex.join([sys.executable, "-c", script]),
            max_output_bytes=128,
        )
    ).run(repo_dir, tracker)

    event = tracker.events[0]
    assert event.stdout_truncated is True
    assert event.stderr_truncated is True
    assert len(event.stdout.encode("utf-8")) <= 128
    assert len(event.stderr.encode("utf-8")) <= 128
    assert event.stdout.endswith("out-end")
    assert event.stderr.endswith("err-end")


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
    assert event.process_cleanup_attempted is True
    assert event.process_cleanup_complete is True


def test_local_command_agent_timeout_cleans_up_child_process(
    tmp_path: Path,
) -> None:
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

    LocalCommandAgent(
        _config(
            agent_command=shlex.join([sys.executable, "-c", script]),
            command_timeout_seconds=1,
        )
    ).run(repo_dir, tracker)

    pid = _read_pid(child_pid)
    assert _process_exited(pid), f"child process still running: {pid}"
    event = tracker.events[0]
    assert event.timed_out is True
    assert event.process_cleanup_complete is True


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
