import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


PROCESS_TERMINATE_TIMEOUT_SECONDS = 0.5
PROCESS_KILL_TIMEOUT_SECONDS = 0.5
PROCESS_CLEANUP_COMPLETE_MESSAGE = "process tree terminated"
PROCESS_CLEANUP_INCOMPLETE_MESSAGE = (
    "process cleanup incomplete: child process did not exit before kill deadline"
)
PROCESS_TIMEOUT_TERMINATED_MESSAGE = (
    "command timed out and process tree was terminated"
)


@dataclass(frozen=True)
class ProcessCleanupResult:
    attempted: bool = False
    complete: bool = True
    kill_required: bool = False
    message: Optional[str] = None


def popen_with_process_group(
    argv: list[str],
    **kwargs,
) -> subprocess.Popen:
    if os.name == "posix":
        kwargs.setdefault("start_new_session", True)
    return subprocess.Popen(argv, **kwargs)


def terminate_process_tree(
    process: subprocess.Popen,
    *,
    terminate_timeout_seconds: float = PROCESS_TERMINATE_TIMEOUT_SECONDS,
    kill_timeout_seconds: float = PROCESS_KILL_TIMEOUT_SECONDS,
) -> ProcessCleanupResult:
    if process.poll() is not None:
        return ProcessCleanupResult(
            attempted=False,
            complete=True,
            kill_required=False,
            message=None,
        )

    _signal_process_tree(process, signal.SIGTERM)
    if _wait_until_exited(process, terminate_timeout_seconds):
        return ProcessCleanupResult(
            attempted=True,
            complete=True,
            kill_required=False,
            message=PROCESS_CLEANUP_COMPLETE_MESSAGE,
        )

    _signal_process_tree(process, signal.SIGKILL)
    complete = _wait_until_exited(process, kill_timeout_seconds)
    return ProcessCleanupResult(
        attempted=True,
        complete=complete,
        kill_required=True,
        message=(
            PROCESS_CLEANUP_COMPLETE_MESSAGE
            if complete
            else PROCESS_CLEANUP_INCOMPLETE_MESSAGE
        ),
    )


def append_cleanup_message(stderr: str, cleanup: ProcessCleanupResult) -> str:
    if not cleanup.attempted or not cleanup.message:
        return stderr
    return f"{stderr}\n{cleanup.message}".strip()


def _signal_process_tree(process: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, sig)
        elif sig == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()
    except ProcessLookupError:
        return
    except OSError:
        if sig == signal.SIGTERM:
            try:
                process.terminate()
            except OSError:
                return
        else:
            try:
                process.kill()
            except OSError:
                return


def _wait_until_exited(process: subprocess.Popen, timeout_seconds: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    return process.poll() is not None
