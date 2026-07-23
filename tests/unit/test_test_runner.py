import os
import shlex
import sys
import time
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
    assert result.process_cleanup_attempted is True
    assert result.process_cleanup_complete is True


def test_test_runner_timeout_cleans_up_child_process(tmp_path: Path) -> None:
    child_pid = tmp_path / "child.pid"
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker, timeout_seconds=1)
    script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        "\"import time; time.sleep(30)\"])\n"
        f"Path({str(child_pid)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        "time.sleep(30)\n"
    )

    result = runner.run(tmp_path, shlex.join([sys.executable, "-c", script]))

    pid = _read_pid(child_pid)
    assert _process_exited(pid), f"child process still running: {pid}"
    assert result.timed_out is True
    assert tracker.events[0].process_cleanup_complete is True


def test_test_runner_timeout_keeps_large_output_bounded(tmp_path: Path) -> None:
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(
        tracker,
        timeout_seconds=1,
        max_output_bytes=160,
    )
    script = (
        "import sys, time; "
        "sys.stdout.write('o' * 2000000); sys.stdout.flush(); "
        "sys.stderr.write('e' * 2000000); sys.stderr.flush(); "
        "time.sleep(30)"
    )

    result = runner.run(tmp_path, shlex.join([sys.executable, "-c", script]))

    assert result.timed_out is True
    assert result.stdout_truncated is True
    assert result.stderr_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 160
    assert len(result.stderr.encode("utf-8")) <= 160
    assert "timed out after 1 seconds" in result.stderr
    assert result.process_cleanup_complete is True


def test_test_runner_truncates_large_stdout(tmp_path: Path) -> None:
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker, max_output_bytes=80)

    result = runner.run(
        tmp_path,
        f"{sys.executable} -c \"print('start' + 'x' * 2000000 + 'end')\"",
    )

    assert result.exit_code == 0
    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 80
    assert result.stdout.startswith("[agentguard] Output truncated")
    assert "end" in result.stdout
    assert "start" not in result.stdout
    assert tracker.events[0].stdout_truncated is True


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
