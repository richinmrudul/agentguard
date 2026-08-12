import os
import signal
import shlex
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import (
    _build_test_env,
    _go_test_env,
    _is_pytest_argv,
)
from agentguard.instrumentation.test_runner import TestRunner as AgentGuardTestRunner
from agentguard.repo.git_diff import collect_diff


def test_build_test_env_uses_isolated_absolute_src_pythonpath(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = tmp_path / "repo"
    src_dir = repo_dir / "src"
    src_dir.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", "existing-path")
    monkeypatch.setenv("AGENTGUARD_AUDIT_CANARY", "must-not-be-forwarded")

    env = _build_test_env(Path("repo"))

    assert env["PYTHONPATH"] == str(src_dir.resolve())
    assert Path(env["PYTHONPATH"]).is_absolute()
    assert "existing-path" not in env["PYTHONPATH"]
    assert "AGENTGUARD_AUDIT_CANARY" not in env
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["RUFF_CACHE_DIR"] == str(
        repo_dir.resolve() / ".git" / "agentguard-cache" / "ruff"
    )
    assert "PYTEST_ADDOPTS" not in env
    assert "GOCACHE" not in env
    assert "GOMODCACHE" not in env


def test_pytest_detection_covers_supported_command_forms() -> None:
    assert _is_pytest_argv(["pytest", "-q"])
    assert _is_pytest_argv([sys.executable, "-m", "pytest", "-q"])
    assert not _is_pytest_argv([sys.executable, "-c", "print('pytest')"])


def test_pytest_cache_option_is_appended_without_replacing_options(
    tmp_path: Path,
) -> None:
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker)

    result = runner.run(tmp_path, "pytest --version")

    assert result.exit_code == 0
    assert tracker.events[0].command[:2] == [sys.executable, "-m"]
    assert tracker.events[0].command[-2:] == [
        "-o",
        f"cache_dir={tmp_path / '.git' / 'agentguard-cache' / 'pytest'}",
    ]


def test_pytest_keeps_attacker_cache_evidence_and_contains_owned_cache(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--template="], cwd=repo, check=True)
    attacker_cache = repo / ".pytest_cache" / "attacker.txt"
    attacker_cache.parent.mkdir()
    attacker_cache.write_text("baseline\n", encoding="utf-8")
    test_file = repo / "test_cache.py"
    test_file.write_text(
        "def test_cache_fixture(cache):\n"
        "    cache.set('agentguard/test', 'ok')\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.local",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "Baseline",
        ],
        cwd=repo,
        check=True,
    )
    attacker_cache.write_text("agent changed\n", encoding="utf-8")

    result = AgentGuardTestRunner(CommandTracker()).run(repo, "pytest -q")

    assert result.exit_code == 0
    assert attacker_cache.read_text(encoding="utf-8") == "agent changed\n"
    assert not (repo / "__pycache__").exists()
    assert not (repo / ".pytest_cache" / "v").exists()
    assert (repo / ".git" / "agentguard-cache" / "pytest" / "v").is_dir()


def test_go_test_env_uses_contained_caches_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "Go repo café"
    repo_dir.mkdir()

    env = _go_test_env(repo_dir)

    assert env["GOCACHE"] == str(repo_dir / ".git/agentguard-cache/go-build")
    assert env["GOMODCACHE"] == str(repo_dir / ".git/agentguard-cache/go-mod")
    assert env["GOENV"] == "off"
    assert env["GOTOOLCHAIN"] == "local"

    outside = tmp_path / "outside"
    outside.mkdir()
    (repo_dir / ".git").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="not a safe directory"):
        _go_test_env(repo_dir)


def test_runner_caches_do_not_hide_attacker_owned_lookalikes(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "--template="], cwd=repo, check=True)
    (repo / "sample_module.py").write_text("VALUE = 1\n", encoding="utf-8")
    attacker_paths = [
        repo / ".agentguard" / "cache" / "payload.txt",
        repo / ".ruff_cache" / "payload.txt",
        repo / "__pycache__" / "payload.pyc",
        repo / "attacker.pyc",
    ]
    for path in attacker_paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=test@example.local",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "Baseline",
        ],
        cwd=repo,
        check=True,
    )
    for path in attacker_paths:
        path.write_text("agent changed\n", encoding="utf-8")

    python_result = AgentGuardTestRunner(CommandTracker()).run(
        repo,
        shlex.join(
            [
                sys.executable,
                "-c",
                "import sample_module; assert sample_module.VALUE == 1",
            ]
        ),
    )
    ruff_result = AgentGuardTestRunner(CommandTracker()).run(
        repo,
        shlex.join(
            [str(Path(sys.executable).with_name("ruff")), "check", "sample_module.py"]
        ),
    )
    diff = collect_diff(repo)

    assert python_result.exit_code == 0
    assert ruff_result.exit_code == 0
    assert set(diff.modified_files) == {
        path.relative_to(repo).as_posix() for path in attacker_paths
    }
    assert all(
        path.read_text(encoding="utf-8") == "agent changed\n"
        for path in attacker_paths
    )
    assert not (repo / "__pycache__" / "sample_module.pyc").exists()
    assert not (repo / ".ruff_cache" / "CACHEDIR.TAG").exists()
    assert not (repo / ".agentguard" / "cache" / "go-build").exists()


def test_test_runner_excludes_ambient_environment_from_captured_output(
    tmp_path: Path,
    monkeypatch,
) -> None:
    canary = "AGENTGUARD_AMBIENT_CANARY_116"
    monkeypatch.setenv("AGENTGUARD_AMBIENT_SECRET", canary)
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker)
    script = (
        "import os; "
        "print(os.environ.get('AGENTGUARD_AMBIENT_SECRET', 'absent'))"
    )

    result = runner.run(tmp_path, shlex.join([sys.executable, "-c", script]))

    assert result.exit_code == 0
    assert result.stdout.strip() == "absent"
    assert canary not in result.stdout
    assert tracker.events[0].stdout.strip() == "absent"


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


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_test_runner_timeout_bounds_retained_pipes_and_prevents_late_write(
    tmp_path: Path,
) -> None:
    child_pid_path = tmp_path / "retained-pipe-child.pid"
    child_ready_path = tmp_path / "retained-pipe-child.ready"
    late_write = tmp_path / "late-write.txt"
    child_script = (
        "import signal, sys, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"Path({str(child_ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        "sys.stdout.write('child-out\\n'); sys.stdout.flush()\n"
        "sys.stderr.write('child-err\\n'); sys.stderr.flush()\n"
        "time.sleep(2.8)\n"
        f"Path({str(late_write)!r}).write_text('survived', encoding='utf-8')\n"
        "time.sleep(1.2)\n"
    )
    leader_script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_script!r}])\n"
        f"Path({str(child_pid_path)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        f"deadline = time.monotonic() + 0.8\n"
        f"ready = Path({str(child_ready_path)!r})\n"
        "while not ready.exists() and time.monotonic() < deadline: time.sleep(0.01)\n"
        "time.sleep(10)\n"
    )
    tracker = CommandTracker()
    runner = AgentGuardTestRunner(tracker, timeout_seconds=1)
    started = time.monotonic()
    child_pid = None

    try:
        result = runner.run(
            tmp_path,
            shlex.join([sys.executable, "-c", leader_script]),
        )
        elapsed = time.monotonic() - started
        child_pid = _read_pid(child_pid_path)
        time.sleep(max(0.0, 3.0 - elapsed))

        assert elapsed < 2.75
        assert result.timed_out is True
        assert result.process_cleanup_attempted is True
        assert result.process_cleanup_complete is True
        assert "command timed out and process tree was terminated" in result.stderr
        assert _process_exited(child_pid)
        assert not late_write.exists()
    finally:
        if child_pid is not None and not _process_exited(child_pid):
            os.kill(child_pid, signal.SIGKILL)


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


def test_test_runner_interrupt_after_spawn_cleans_up_and_preserves_interrupt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    process = object()
    cleanup_calls = []
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.BoundedProcessOutput",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            KeyboardInterrupt("capture interrupted")
        ),
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.processes.terminate_process_tree",
        lambda owned: cleanup_calls.append(owned),
    )

    with pytest.raises(KeyboardInterrupt, match="capture interrupted"):
        AgentGuardTestRunner(CommandTracker()).run(tmp_path, "python -V")

    assert cleanup_calls == [process]


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_test_runner_interrupt_cleans_real_descendant(
    tmp_path: Path,
    monkeypatch,
) -> None:
    child_pid_path = tmp_path / "interrupt-child.pid"
    late_write = tmp_path / "late-write.txt"
    child_script = (
        "import time\n"
        "from pathlib import Path\n"
        "time.sleep(0.8)\n"
        f"Path({str(late_write)!r}).write_text('survived')\n"
        "time.sleep(20)\n"
    )
    script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        "child = subprocess.Popen([sys.executable, '-c', "
        f"{child_script!r}])\n"
        f"Path({str(child_pid_path)!r}).write_text(str(child.pid))\n"
        "time.sleep(20)\n"
    )
    original_wait = AgentGuardTestRunner.run.__globals__["BoundedProcessOutput"].wait
    original_popen = AgentGuardTestRunner.run.__globals__["popen_with_process_group"]
    spawned = []
    first_wait = True

    def capture_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        spawned.append(process)
        return process

    def interrupt_wait(capture, timeout=None):
        nonlocal first_wait
        if first_wait:
            first_wait = False
            _read_pid(child_pid_path)
            raise KeyboardInterrupt("test interrupt")
        return original_wait(capture, timeout)

    monkeypatch.setattr(
        "agentguard.instrumentation.output_limits.BoundedProcessOutput.wait",
        interrupt_wait,
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.popen_with_process_group",
        capture_popen,
    )

    started = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt, match="test interrupt"):
            AgentGuardTestRunner(CommandTracker()).run(
                tmp_path,
                shlex.join([sys.executable, "-c", script]),
            )
        child_pid = _read_pid(child_pid_path)
        time.sleep(1)

        assert time.monotonic() - started < 2.5
        assert _process_exited(child_pid)
        assert not late_write.exists()
    finally:
        for process in spawned:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_test_runner_finish_exception_cleans_up_and_preserves_exception(
    tmp_path: Path,
    monkeypatch,
) -> None:
    process = object()
    cleanup_calls = []

    class FinishFailure:
        def __init__(self, *_args):
            pass

        def wait(self, timeout=None):
            return 0

        def finish(self, timeout=None):
            raise RuntimeError("finish processing failed")

    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.BoundedProcessOutput",
        FinishFailure,
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.processes.terminate_process_tree",
        lambda owned: cleanup_calls.append(owned),
    )

    with pytest.raises(RuntimeError, match="finish processing failed"):
        AgentGuardTestRunner(CommandTracker()).run(tmp_path, "python -V")

    assert cleanup_calls == [process]


def test_test_runner_timeout_cleanup_failures_remain_controlled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    class TimeoutCapture:
        def __init__(self, *_args):
            pass

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("test", timeout)

        def finish(self, timeout=None):
            raise RuntimeError("finish failed")

    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.popen_with_process_group",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.BoundedProcessOutput",
        TimeoutCapture,
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.test_runner.terminate_process_tree",
        lambda _process: (_ for _ in ()).throw(RuntimeError("cleanup failed")),
    )

    result = AgentGuardTestRunner(CommandTracker(), timeout_seconds=1).run(
        tmp_path, "python -V"
    )

    assert result.exit_code == 124
    assert result.timed_out is True
    assert result.process_cleanup_complete is False


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
