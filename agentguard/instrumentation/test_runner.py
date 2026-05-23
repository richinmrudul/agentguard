import shlex
import subprocess
import sys
import time
from pathlib import Path

from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker


def _argv(command: str) -> list[str]:
    parts = shlex.split(command)
    if parts and parts[0] == "pytest":
        return [sys.executable, "-m", "pytest", *parts[1:]]
    return parts


class TestRunner:
    def __init__(self, command_tracker: CommandTracker) -> None:
        self.command_tracker = command_tracker

    def run(self, repo_dir: Path, command: str) -> CommandResult:
        argv = _argv(command)
        if not argv:
            raise ValueError("Test command cannot be empty.")

        self.command_tracker.record(command)
        started = time.monotonic()
        completed = subprocess.run(
            argv,
            cwd=repo_dir,
            check=False,
            capture_output=True,
            text=True,
        )
        return CommandResult(
            command=command,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=time.monotonic() - started,
        )
