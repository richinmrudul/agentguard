import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agentguard.instrumentation import processes
from agentguard.instrumentation.processes import (
    PROCESS_CLEANUP_INCOMPLETE_MESSAGE,
    cleanup_process_after_exception,
    popen_with_process_group,
    terminate_process_tree,
)


def test_exception_cleanup_preserves_original_when_cleanup_steps_raise(
    monkeypatch,
) -> None:
    class Capture:
        def wait(self, timeout=None):
            raise RuntimeError("drain failed")

        def finish(self, timeout=None):
            raise RuntimeError("finish failed")

    calls = []
    monkeypatch.setattr(
        processes,
        "terminate_process_tree",
        lambda _process: (_ for _ in ()).throw(RuntimeError("terminate failed")),
    )

    with pytest.raises(KeyboardInterrupt, match="original interrupt"):
        try:
            raise KeyboardInterrupt("original interrupt")
        except KeyboardInterrupt:
            cleanup_process_after_exception(
                object(),
                Capture(),
                extra_cleanup=lambda: calls.append("extra"),
            )
            raise

    assert calls == ["extra"]


def test_exception_cleanup_runs_extra_cleanup_without_process() -> None:
    calls = []

    cleanup_process_after_exception(
        None,
        None,
        extra_cleanup=lambda: calls.append("extra"),
    )

    assert calls == ["extra"]


def test_exception_cleanup_preserves_cancellation_style_base_exception(
    monkeypatch,
) -> None:
    class Cancelled(BaseException):
        pass

    cleanup_calls = []
    monkeypatch.setattr(
        processes,
        "terminate_process_tree",
        lambda process: cleanup_calls.append(process),
    )

    with pytest.raises(Cancelled, match="cancelled"):
        try:
            raise Cancelled("cancelled")
        except BaseException:
            cleanup_process_after_exception(object(), None)
            raise

    assert len(cleanup_calls) == 1


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_termination_escalates_and_verifies_term_ignoring_descendant(
    tmp_path: Path,
) -> None:
    child_pid_path = tmp_path / "child.pid"
    child_ready_path = tmp_path / "child.ready"
    late_write = tmp_path / "late-write.txt"
    child_script = (
        "import signal, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"Path({str(child_ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        "time.sleep(0.8)\n"
        f"Path({str(late_write)!r}).write_text('survived', encoding='utf-8')\n"
        "time.sleep(10)\n"
    )
    leader_script = (
        "import subprocess, sys, time\n"
        "from pathlib import Path\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_script!r}])\n"
        f"Path({str(child_pid_path)!r}).write_text(str(child.pid), encoding='utf-8')\n"
        "time.sleep(10)\n"
    )
    process = popen_with_process_group(
        [sys.executable, "-c", leader_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child_pid = _read_pid(child_pid_path)
    _wait_for_path(child_ready_path)

    try:
        result = terminate_process_tree(process)
        time.sleep(0.9)

        assert result.attempted is True
        assert result.kill_required is True
        assert result.complete is True
        assert not _process_exists(child_pid)
        assert not late_write.exists()
    finally:
        _kill_group_if_present(process.pid)


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_termination_uses_captured_group_after_leader_exits(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    child_ready_path = tmp_path / "child.ready"
    child_script = (
        "import signal, time\n"
        "from pathlib import Path\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        f"Path({str(child_ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        "time.sleep(10)\n"
    )
    leader_script = (
        "import subprocess, sys\n"
        "from pathlib import Path\n"
        f"child = subprocess.Popen([sys.executable, '-c', {child_script!r}])\n"
        f"Path({str(child_pid_path)!r}).write_text(str(child.pid), encoding='utf-8')\n"
    )
    process = popen_with_process_group(
        [sys.executable, "-c", leader_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child_pid = _read_pid(child_pid_path)
    _wait_for_path(child_ready_path)
    process.wait(timeout=2)

    try:
        result = terminate_process_tree(process)

        assert result.attempted is True
        assert result.kill_required is True
        assert result.complete is True
        assert not _process_exists(child_pid)
    finally:
        _kill_group_if_present(process.pid)


def test_windows_backend_does_not_claim_descendant_verification(monkeypatch) -> None:
    class ExitedProcess:
        pid = 1234

        @staticmethod
        def poll():
            return 0

    monkeypatch.setattr(processes.os, "name", "nt")

    result = terminate_process_tree(ExitedProcess())

    assert result.attempted is True
    assert result.complete is False
    assert result.kill_required is False
    assert result.message == PROCESS_CLEANUP_INCOMPLETE_MESSAGE


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_already_exited_owned_group_requires_no_cleanup() -> None:
    process = popen_with_process_group(
        [sys.executable, "-c", "pass"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    process.wait(timeout=2)

    result = terminate_process_tree(process)

    assert result.attempted is False
    assert result.complete is True
    assert result.kill_required is False
    assert result.message is None


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_graceful_process_group_exit_does_not_require_kill() -> None:
    process = popen_with_process_group(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        result = terminate_process_tree(process)

        assert result.attempted is True
        assert result.complete is True
        assert result.kill_required is False
    finally:
        _kill_group_if_present(process.pid)


def test_zero_deadlines_are_bounded_and_report_incomplete(monkeypatch) -> None:
    class RunningProcess:
        pid = 1234

        @staticmethod
        def poll():
            return None

    monkeypatch.setattr(processes.os, "name", "posix")
    monkeypatch.setattr(processes, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(processes, "_signal_process_tree", lambda *_args: None)
    started = time.monotonic()

    result = terminate_process_tree(
        RunningProcess(),
        terminate_timeout_seconds=0,
        kill_timeout_seconds=0,
    )

    assert time.monotonic() - started < 0.1
    assert result.complete is False
    assert result.kill_required is True


def test_incomplete_cleanup_uses_fixed_message(monkeypatch) -> None:
    class RunningProcess:
        pid = 1234

        @staticmethod
        def poll():
            return None

        @staticmethod
        def terminate():
            return None

        @staticmethod
        def kill():
            return None

    monkeypatch.setattr(processes.os, "name", "nt")

    result = terminate_process_tree(
        RunningProcess(),
        terminate_timeout_seconds=0,
        kill_timeout_seconds=0,
    )

    assert result.complete is False
    assert result.kill_required is True
    assert result.message == PROCESS_CLEANUP_INCOMPLETE_MESSAGE


def _read_pid(path: Path) -> int:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.exists():
            return int(path.read_text(encoding="utf-8"))
        time.sleep(0.01)
    raise AssertionError("child pid was not written")


def _wait_for_path(path: Path) -> None:
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"path was not written: {path.name}")


def _process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _kill_group_if_present(process_group_id: int) -> None:
    try:
        os.killpg(process_group_id, signal.SIGKILL)
    except ProcessLookupError:
        pass
