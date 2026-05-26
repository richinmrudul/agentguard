import os
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


def _build_test_env(repo_dir: Path) -> dict[str, str]:
    env = os.environ.copy()
    src_path = (repo_dir / "src").resolve()
    if src_path.exists():
        existing_pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            str(src_path)
            if not existing_pythonpath
            else f"{src_path}{os.pathsep}{existing_pythonpath}"
        )
    return env


class TestRunner:
    def __init__(self, command_tracker: CommandTracker) -> None:
        self.command_tracker = command_tracker

    def run(self, repo_dir: Path, command: str) -> CommandResult:
        argv = _argv(command)
        if not argv:
            raise ValueError("Test command cannot be empty.")

        env = _build_test_env(repo_dir)

        started = time.monotonic()
        completed = subprocess.run(
            argv,
            cwd=repo_dir,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        duration_seconds = time.monotonic() - started
        self.command_tracker.record_executed(
            command=argv,
            command_text=command,
            cwd=repo_dir,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=duration_seconds,
        )
        return CommandResult(
            command=command,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            duration_seconds=duration_seconds,
        )
