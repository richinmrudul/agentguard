import os
import sys
from pathlib import Path

from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import _build_test_env
from agentguard.instrumentation.test_runner import TestRunner as AgentGuardTestRunner


def test_build_test_env_uses_absolute_src_pythonpath(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = tmp_path / "repo"
    src_dir = repo_dir / "src"
    src_dir.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", "existing-path")

    env = _build_test_env(Path("repo"))
    pythonpath_entries = env["PYTHONPATH"].split(os.pathsep)

    assert pythonpath_entries[0] == str(src_dir.resolve())
    assert Path(pythonpath_entries[0]).is_absolute()
    assert pythonpath_entries[1] == "existing-path"


def test_test_runner_times_out_sleeping_command(tmp_path: Path) -> None:
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker, timeout_seconds=1)

    result = runner.run(
        tmp_path,
        f"{sys.executable} -c \"import time; time.sleep(2)\"",
    )

    assert result.exit_code == 124
    assert result.timed_out is True
    assert "timed out after 1 seconds" in result.stderr
    assert tracker.events[0].timed_out is True


def test_test_runner_truncates_large_stdout(tmp_path: Path) -> None:
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker, max_output_bytes=80)

    result = runner.run(
        tmp_path,
        f"{sys.executable} -c \"print('start' + 'x' * 200 + 'end')\"",
    )

    assert result.exit_code == 0
    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 80
    assert result.stdout.startswith("[agentguard] Output truncated")
    assert "end" in result.stdout
    assert "start" not in result.stdout
    assert tracker.events[0].stdout_truncated is True
