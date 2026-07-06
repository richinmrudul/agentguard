import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.output_limits import limit_output
from agentguard.instrumentation.processes import (
    PROCESS_TIMEOUT_TERMINATED_MESSAGE,
    ProcessCleanupResult,
    append_cleanup_message,
    popen_with_process_group,
    terminate_process_tree,
)


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
    def __init__(
        self,
        command_tracker: CommandTracker,
        timeout_seconds: int = 60,
        max_output_bytes: int = 200000,
    ) -> None:
        self.command_tracker = command_tracker
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def run(self, repo_dir: Path, command: str) -> CommandResult:
        argv = _argv(command)
        if not argv:
            raise ValueError("Test command cannot be empty.")

        env = _build_test_env(repo_dir)

        started = time.monotonic()
        timed_out = False
        cleanup = ProcessCleanupResult()
        try:
            process = popen_with_process_group(
                argv,
                cwd=repo_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            stdout, stderr = process.communicate(timeout=self.timeout_seconds)
            exit_code = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            cleanup = terminate_process_tree(process)
            stdout, stderr = process.communicate()
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            stderr = (
                f"{stderr}\nCommand timed out after "
                f"{self.timeout_seconds} seconds."
                f"\n{PROCESS_TIMEOUT_TERMINATED_MESSAGE}"
            ).strip()
            stderr = append_cleanup_message(stderr, cleanup)
        duration_seconds = time.monotonic() - started
        limited_stdout = limit_output(stdout, self.max_output_bytes)
        limited_stderr = limit_output(stderr, self.max_output_bytes)
        self.command_tracker.record_executed(
            command=argv,
            command_text=command,
            cwd=repo_dir,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=limited_stdout.truncated,
            stderr_truncated=limited_stderr.truncated,
            process_cleanup_attempted=cleanup.attempted,
            process_cleanup_complete=cleanup.complete,
            process_cleanup_message=cleanup.message,
        )
        return CommandResult(
            command=command,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=limited_stdout.truncated,
            stderr_truncated=limited_stderr.truncated,
            process_cleanup_attempted=cleanup.attempted,
            process_cleanup_complete=cleanup.complete,
            process_cleanup_message=cleanup.message,
        )
