import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Optional


PROCESS_TERMINATE_TIMEOUT_SECONDS = 0.5
PROCESS_KILL_TIMEOUT_SECONDS = 0.5
PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS = 0.5
PROCESS_CLEANUP_COMPLETE_MESSAGE = "process tree terminated"
PROCESS_CLEANUP_INCOMPLETE_MESSAGE = (
    "process cleanup incomplete: process-tree exit could not be confirmed"
)
PROCESS_TIMEOUT_TERMINATED_MESSAGE = (
    "command timed out and process tree was terminated"
)
PROCESS_TIMEOUT_CLEANUP_INCOMPLETE_MESSAGE = (
    "command timed out and process-tree cleanup could not be confirmed"
)

_OWNED_PROCESS_GROUP_ATTRIBUTE = "_agentguard_owned_process_group_id"


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
    process = subprocess.Popen(argv, **kwargs)
    if os.name == "posix" and kwargs.get("start_new_session"):
        # Capture ownership while the leader is alive. Looking it up during
        # cleanup is racy because the leader may already have exited while a
        # descendant still owns an inherited pipe or mutates the workspace.
        setattr(process, _OWNED_PROCESS_GROUP_ATTRIBUTE, process.pid)
    return process


def terminate_process_tree(
    process: subprocess.Popen,
    *,
    terminate_timeout_seconds: float = PROCESS_TERMINATE_TIMEOUT_SECONDS,
    kill_timeout_seconds: float = PROCESS_KILL_TIMEOUT_SECONDS,
) -> ProcessCleanupResult:
    process_group_id = _owned_process_group_id(process)
    leader_exited = process.poll() is not None
    if os.name == "posix" and process_group_id is not None:
        tree_exited = leader_exited and not _process_group_exists(process_group_id)
    else:
        # Without a Windows Job Object, Popen can verify only the direct child.
        # Never turn that weaker observation into a process-tree guarantee.
        tree_exited = False

    if tree_exited:
        return ProcessCleanupResult(
            attempted=False,
            complete=True,
            kill_required=False,
            message=None,
        )

    if leader_exited and (os.name != "posix" or process_group_id is None):
        return ProcessCleanupResult(
            attempted=True,
            complete=False,
            kill_required=False,
            message=PROCESS_CLEANUP_INCOMPLETE_MESSAGE,
        )

    _signal_process_tree(process, signal.SIGTERM, process_group_id)
    if os.name != "posix" or process_group_id is None:
        if _wait_until_leader_exited(process, terminate_timeout_seconds):
            return ProcessCleanupResult(
                attempted=True,
                complete=False,
                kill_required=False,
                message=PROCESS_CLEANUP_INCOMPLETE_MESSAGE,
            )
        _signal_process_tree(process, signal.SIGKILL, process_group_id)
        _wait_until_leader_exited(process, kill_timeout_seconds)
        return ProcessCleanupResult(
            attempted=True,
            complete=False,
            kill_required=True,
            message=PROCESS_CLEANUP_INCOMPLETE_MESSAGE,
        )

    if _wait_until_tree_exited(
        process,
        process_group_id,
        terminate_timeout_seconds,
    ):
        return ProcessCleanupResult(
            attempted=True,
            complete=True,
            kill_required=False,
            message=PROCESS_CLEANUP_COMPLETE_MESSAGE,
        )

    _signal_process_tree(process, signal.SIGKILL, process_group_id)
    complete = _wait_until_tree_exited(
        process,
        process_group_id,
        kill_timeout_seconds,
    )
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


def process_timeout_message(cleanup: ProcessCleanupResult) -> str:
    if cleanup.complete:
        return PROCESS_TIMEOUT_TERMINATED_MESSAGE
    return PROCESS_TIMEOUT_CLEANUP_INCOMPLETE_MESSAGE


def _owned_process_group_id(process: subprocess.Popen) -> Optional[int]:
    value = getattr(process, _OWNED_PROCESS_GROUP_ATTRIBUTE, None)
    return int(value) if value is not None else None


def _signal_process_tree(
    process: subprocess.Popen,
    sig: signal.Signals,
    process_group_id: Optional[int],
) -> None:
    try:
        if os.name == "posix" and process_group_id is not None:
            os.killpg(process_group_id, sig)
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


def _wait_until_tree_exited(
    process: subprocess.Popen,
    process_group_id: int,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        leader_exited = process.poll() is not None
        if os.name == "posix":
            if leader_exited and not _process_group_exists(process_group_id):
                return True
        elif leader_exited:
            # The direct child is gone, but descendants are not owned or
            # observable without a Job Object.
            return False

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        # Conservatively avoid claiming cleanup when the platform cannot
        # establish that the owned group is gone.
        return True
    return True


def _wait_until_leader_exited(
    process: subprocess.Popen,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    while True:
        if process.poll() is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))
