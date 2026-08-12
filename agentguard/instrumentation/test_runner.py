import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.output_limits import (
    BoundedProcessOutput,
    LimitedOutput,
    ProcessOutput,
    limit_output,
)
from agentguard.instrumentation.processes import (
    PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS,
    PROCESS_CLEANUP_INCOMPLETE_MESSAGE,
    ProcessCleanupResult,
    append_cleanup_message,
    cleanup_process_after_exception,
    popen_with_process_group,
    process_timeout_message,
    terminate_process_tree,
)

INHERITED_SUBPROCESS_ENV_NAMES = (
    "COLORTERM",
    "COMSPEC",
    "FORCE_COLOR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "NO_COLOR",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TERM",
    "TMP",
    "TMPDIR",
    "VIRTUAL_ENV",
    "WINDIR",
)


def _argv(command: str) -> list[str]:
    parts = shlex.split(command)
    if parts and parts[0] == "pytest":
        return [sys.executable, "-m", "pytest", *parts[1:]]
    return parts


def _build_subprocess_env(repo_dir: Path) -> dict[str, str]:
    env = {
        name: os.environ[name]
        for name in INHERITED_SUBPROCESS_ENV_NAMES
        if name in os.environ
    }
    src_path = (repo_dir / "src").resolve()
    if src_path.exists():
        env["PYTHONPATH"] = str(src_path)
    return env


def _build_test_env(repo_dir: Path) -> dict[str, str]:
    env = _build_subprocess_env(repo_dir)
    cache_root = repo_dir.resolve() / ".git" / "agentguard-cache"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["RUFF_CACHE_DIR"] = str(cache_root / "ruff")
    return env


def _is_pytest_argv(argv: list[str]) -> bool:
    return Path(argv[0]).name in {"pytest", "py.test"} or argv[1:3] == [
        "-m",
        "pytest",
    ]


def _go_test_env(repo_dir: Path) -> dict[str, str]:
    root = repo_dir.resolve()
    git_root = root / ".git"
    artifact_root = git_root / "agentguard-cache"
    for path in (
        git_root,
        artifact_root,
        artifact_root / "go-build",
        artifact_root / "go-mod",
    ):
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError(
                "Go test cache path is not a safe directory beneath the repository: "
                f"{path.relative_to(root)}"
            )
    return {
        "GOCACHE": str(artifact_root / "go-build"),
        "GOENV": "off",
        "GOMODCACHE": str(artifact_root / "go-mod"),
        "GOTOOLCHAIN": "local",
    }


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
        if _is_pytest_argv(argv):
            # The test run is trusted, but a repository-local cache name is not.
            # Avoid generating standard pytest/Python caches rather than hiding
            # same-named attacker-controlled content from benchmark evidence.
            cache_dir = repo_dir / ".git" / "agentguard-cache" / "pytest"
            argv.extend(["-o", f"cache_dir={cache_dir}"])
        if Path(argv[0]).name == "go":
            env.update(_go_test_env(repo_dir))

        started = time.monotonic()
        timed_out = False
        cleanup = ProcessCleanupResult()
        process = None
        capture = None
        cleanup_started = False
        try:
            process = popen_with_process_group(
                argv,
                cwd=repo_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            capture = BoundedProcessOutput(process, self.max_output_bytes)
            exit_code = capture.wait(timeout=self.timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            cleanup_started = True
            try:
                cleanup = terminate_process_tree(process)
            except BaseException:
                cleanup = ProcessCleanupResult(
                    attempted=True,
                    complete=False,
                    message=PROCESS_CLEANUP_INCOMPLETE_MESSAGE,
                )
            try:
                capture.wait(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
            except BaseException:
                pass
        except BaseException:
            cleanup_process_after_exception(
                process,
                capture,
                cleanup_started=cleanup_started,
            )
            raise
        try:
            captured = capture.finish(
                timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS if timed_out else None
            )
        except BaseException:
            if timed_out:
                captured = ProcessOutput(
                    stdout=LimitedOutput(text="", truncated=False),
                    stderr=LimitedOutput(text="", truncated=False),
                )
            else:
                cleanup_process_after_exception(
                    process,
                    capture,
                    cleanup_started=cleanup_started,
                )
                raise
        stdout = captured.stdout.text
        stderr = captured.stderr.text
        if timed_out:
            stderr = (
                f"{stderr}\nCommand timed out after "
                f"{self.timeout_seconds} seconds."
                f"\n{process_timeout_message(cleanup)}"
            ).strip()
            stderr = append_cleanup_message(stderr, cleanup)
        duration_seconds = time.monotonic() - started
        limited_stdout = limit_output(stdout, self.max_output_bytes)
        limited_stderr = limit_output(stderr, self.max_output_bytes)
        stdout_truncated = captured.stdout.truncated or limited_stdout.truncated
        stderr_truncated = captured.stderr.truncated or limited_stderr.truncated
        self.command_tracker.record_executed(
            command=argv,
            command_text=command,
            cwd=repo_dir,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
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
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            process_cleanup_attempted=cleanup.attempted,
            process_cleanup_complete=cleanup.complete,
            process_cleanup_message=cleanup.message,
        )
