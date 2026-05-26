import shlex
import subprocess
import time
from pathlib import Path

from agentguard.config.schema import SandboxConfig
from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker


INSTALL_COMMAND = [
    "python",
    "-m",
    "pip",
    "install",
    "--no-build-isolation",
    "-e",
    ".",
]


def _docker_test_argv(command: str) -> list[str]:
    parts = shlex.split(command)
    if parts and parts[0] == "pytest":
        return ["python", "-m", "pytest", *parts[1:]]
    return parts


def docker_available() -> bool:
    try:
        completed = subprocess.run(
            ["docker", "info"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return False
    return completed.returncode == 0


class DockerTestRunner:
    def __init__(
        self,
        command_tracker: CommandTracker,
        sandbox: SandboxConfig,
    ) -> None:
        self.sandbox = sandbox
        self.command_runner = DockerCommandRunner(command_tracker, sandbox)

    def _docker_command(self, repo_dir: Path, inner_command: list[str]) -> list[str]:
        return self.command_runner.build_command(repo_dir, inner_command)

    def _run_inner_command(
        self,
        repo_dir: Path,
        inner_command: list[str],
        command_text: str,
    ) -> CommandResult:
        return self.command_runner.run_argv(repo_dir, inner_command, command_text)

    def run(self, repo_dir: Path, command: str) -> CommandResult:
        test_argv = _docker_test_argv(command)
        if not test_argv:
            raise ValueError("Test command cannot be empty.")

        install_result = self._run_inner_command(
            repo_dir=repo_dir,
            inner_command=INSTALL_COMMAND,
            command_text="docker: python -m pip install --no-build-isolation -e .",
        )
        if install_result.exit_code != 0:
            return CommandResult(
                command=command,
                exit_code=install_result.exit_code,
                stdout=install_result.stdout,
                stderr=install_result.stderr,
                duration_seconds=install_result.duration_seconds,
            )

        test_result = self._run_inner_command(
            repo_dir=repo_dir,
            inner_command=test_argv,
            command_text=f"docker: {command}",
        )
        return CommandResult(
            command=command,
            exit_code=test_result.exit_code,
            stdout=test_result.stdout,
            stderr=test_result.stderr,
            duration_seconds=install_result.duration_seconds
            + test_result.duration_seconds,
        )


class DockerCommandRunner:
    def __init__(
        self,
        command_tracker: CommandTracker,
        sandbox: SandboxConfig,
    ) -> None:
        self.command_tracker = command_tracker
        self.sandbox = sandbox

    def build_command(self, repo_dir: Path, inner_command: list[str]) -> list[str]:
        if self.sandbox.type != "docker":
            raise ValueError("DockerCommandRunner requires sandbox.type='docker'.")
        if not self.sandbox.image:
            raise ValueError("Docker sandbox requires an image.")
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{repo_dir.resolve()}:{self.sandbox.workdir}",
            "-w",
            self.sandbox.workdir,
            "-e",
            f"PYTHONPATH={self.sandbox.workdir}/src",
            "--network",
            self.sandbox.network,
            self.sandbox.image,
            *inner_command,
        ]

    def run_argv(
        self,
        repo_dir: Path,
        inner_command: list[str],
        command_text: str,
    ) -> CommandResult:
        docker_command = self.build_command(repo_dir, inner_command)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                docker_command,
                check=False,
                capture_output=True,
                text=True,
                timeout=self.sandbox.timeout_seconds,
            )
            exit_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except FileNotFoundError:
            exit_code = 127
            stdout = ""
            stderr = "Docker is not installed or is not available on PATH."
        except subprocess.TimeoutExpired as error:
            exit_code = 124
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            stderr = (
                f"{stderr}\nDocker command timed out after "
                f"{self.sandbox.timeout_seconds} seconds."
            ).strip()
        duration_seconds = time.monotonic() - started

        self.command_tracker.record_executed(
            command=docker_command,
            command_text=command_text,
            cwd=repo_dir,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration_seconds,
        )
        return CommandResult(
            command=command_text,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration_seconds,
        )
