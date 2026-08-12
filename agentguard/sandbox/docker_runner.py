import shlex
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.config.schema import SandboxConfig
from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.output_limits import BoundedProcessOutput, limit_output
from agentguard.instrumentation.processes import (
    PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS,
    ProcessCleanupResult,
    append_cleanup_message,
    popen_with_process_group,
    process_timeout_message,
    terminate_process_tree,
)


INSTALL_COMMAND = [
    "python",
    "-m",
    "pip",
    "install",
    "--no-build-isolation",
    "-e",
    ".",
]
DOCKER_CLEANUP_COMPLETE_MESSAGE = "docker container removed after timeout"
DOCKER_CLEANUP_INCOMPLETE_MESSAGE = (
    "docker cleanup incomplete: container removal failed"
)
OWNED_TEST_ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "RUFF_CACHE_DIR": "/workspace/.git/agentguard-cache/ruff",
    "GOCACHE": "/workspace/.git/agentguard-cache/go-build",
    "GOMODCACHE": "/workspace/.git/agentguard-cache/go-mod",
    "GOENV": "off",
    "GOTOOLCHAIN": "local",
}


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
        timeout_seconds: Optional[int] = None,
        max_output_bytes: int = 200000,
    ) -> None:
        self.sandbox = sandbox
        self.command_runner = DockerCommandRunner(
            command_tracker,
            sandbox,
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def _docker_command(self, repo_dir: Path, inner_command: list[str]) -> list[str]:
        return self.command_runner.build_command(repo_dir, inner_command)

    def run(self, repo_dir: Path, command: str) -> CommandResult:
        test_argv = _docker_test_argv(command)
        if not test_argv:
            raise ValueError("Test command cannot be empty.")
        if test_argv[:3] == ["python", "-m", "pytest"]:
            test_argv.extend(
                [
                    "-o",
                    f"cache_dir={self.sandbox.workdir}/.git/agentguard-cache/pytest",
                ]
            )

        owned_environment = {
            name: value.replace("/workspace", self.sandbox.workdir)
            for name, value in OWNED_TEST_ENVIRONMENT.items()
        }
        install_result = self.command_runner.run_argv(
            repo_dir=repo_dir,
            inner_command=INSTALL_COMMAND,
            command_text="docker: python -m pip install --no-build-isolation -e .",
            environment=owned_environment,
        )
        if install_result.exit_code != 0:
            return CommandResult(
                command=command,
                exit_code=install_result.exit_code,
                stdout=install_result.stdout,
                stderr=install_result.stderr,
                duration_seconds=install_result.duration_seconds,
                timed_out=install_result.timed_out,
                stdout_truncated=install_result.stdout_truncated,
                stderr_truncated=install_result.stderr_truncated,
                process_cleanup_attempted=install_result.process_cleanup_attempted,
                process_cleanup_complete=install_result.process_cleanup_complete,
                process_cleanup_message=install_result.process_cleanup_message,
            )

        test_result = self.command_runner.run_argv(
            repo_dir=repo_dir,
            inner_command=test_argv,
            command_text=f"docker: {command}",
            environment=owned_environment,
        )
        return CommandResult(
            command=command,
            exit_code=test_result.exit_code,
            stdout=test_result.stdout,
            stderr=test_result.stderr,
            duration_seconds=install_result.duration_seconds
            + test_result.duration_seconds,
            timed_out=test_result.timed_out,
            stdout_truncated=test_result.stdout_truncated,
            stderr_truncated=test_result.stderr_truncated,
            process_cleanup_attempted=test_result.process_cleanup_attempted,
            process_cleanup_complete=test_result.process_cleanup_complete,
            process_cleanup_message=test_result.process_cleanup_message,
        )


class DockerCommandRunner:
    def __init__(
        self,
        command_tracker: CommandTracker,
        sandbox: SandboxConfig,
        timeout_seconds: Optional[int] = None,
        max_output_bytes: int = 200000,
    ) -> None:
        self.command_tracker = command_tracker
        self.sandbox = sandbox
        self.timeout_seconds = (
            sandbox.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        self.max_output_bytes = max_output_bytes

    def build_command(
        self,
        repo_dir: Path,
        inner_command: list[str],
        *,
        container_name: Optional[str] = None,
        environment: Optional[dict[str, str]] = None,
    ) -> list[str]:
        if self.sandbox.type != "docker":
            raise ValueError("DockerCommandRunner requires sandbox.type='docker'.")
        if not self.sandbox.image:
            raise ValueError("Docker sandbox requires an image.")
        validate_docker_image_reference(self.sandbox.image)
        command = [
            "docker",
            "run",
            "--rm",
        ]
        if container_name is not None:
            command.extend(["--name", container_name])
        command.extend([
            "-v",
            f"{repo_dir.resolve()}:{self.sandbox.workdir}",
            "-w",
            self.sandbox.workdir,
            "-e",
            f"PYTHONPATH={self.sandbox.workdir}/src",
        ])
        for name, value in sorted((environment or {}).items()):
            command.extend(["-e", f"{name}={value}"])
        command.extend(["--network", self.sandbox.network])
        if self.sandbox.memory is not None:
            command.extend(["--memory", self.sandbox.memory])
        if self.sandbox.cpus is not None:
            command.extend(["--cpus", str(self.sandbox.cpus)])
        if self.sandbox.read_only:
            command.extend(["--read-only", "--tmpfs", "/tmp"])
        command.extend(["--", self.sandbox.image, *inner_command])
        return command

    def run_argv(
        self,
        repo_dir: Path,
        inner_command: list[str],
        command_text: str,
        preflight_matched_patterns: Optional[list[str]] = None,
        policy_mode: Optional[str] = None,
        environment: Optional[dict[str, str]] = None,
    ) -> CommandResult:
        container_name = self._container_name()
        docker_command = self.build_command(
            repo_dir,
            inner_command,
            container_name=container_name,
            environment=environment,
        )
        started = time.monotonic()
        timed_out = False
        cleanup = ProcessCleanupResult()
        try:
            process = popen_with_process_group(
                docker_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            capture = BoundedProcessOutput(process, self.max_output_bytes)
            exit_code = capture.wait(timeout=self.timeout_seconds)
            captured = capture.finish()
            stdout = captured.stdout.text
            stderr = captured.stderr.text
        except FileNotFoundError:
            exit_code = 127
            stdout = ""
            stderr = "Docker is not installed or is not available on PATH."
            captured = None
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            cleanup = terminate_process_tree(process)
            docker_cleanup = self._remove_container(container_name)
            cleanup = self._combine_cleanup(cleanup, docker_cleanup)
            try:
                capture.wait(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                pass
            captured = capture.finish(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
            stdout = captured.stdout.text
            stderr = captured.stderr.text
            stderr = (
                f"{stderr}\nDocker command timed out after "
                f"{self.timeout_seconds} seconds."
                f"\n{process_timeout_message(cleanup)}"
            ).strip()
            stderr = append_cleanup_message(stderr, cleanup)
        duration_seconds = time.monotonic() - started
        limited_stdout = limit_output(stdout, self.max_output_bytes)
        limited_stderr = limit_output(stderr, self.max_output_bytes)
        stdout_truncated = (
            captured is not None and captured.stdout.truncated
        ) or limited_stdout.truncated
        stderr_truncated = (
            captured is not None and captured.stderr.truncated
        ) or limited_stderr.truncated

        self.command_tracker.record_executed(
            command=docker_command,
            command_text=command_text,
            cwd=repo_dir,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            preflight_matched_patterns=preflight_matched_patterns,
            policy_mode=policy_mode,
            process_cleanup_attempted=cleanup.attempted,
            process_cleanup_complete=cleanup.complete,
            process_cleanup_message=cleanup.message,
        )
        return CommandResult(
            command=command_text,
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

    def _container_name(self) -> str:
        return f"agentguard-{uuid.uuid4().hex[:12]}"

    def _remove_container(self, container_name: str) -> ProcessCleanupResult:
        try:
            completed = subprocess.run(
                ["docker", "rm", "-f", container_name],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return ProcessCleanupResult(
                attempted=True,
                complete=False,
                kill_required=False,
                message=DOCKER_CLEANUP_INCOMPLETE_MESSAGE,
            )
        return ProcessCleanupResult(
            attempted=True,
            complete=completed.returncode == 0,
            kill_required=False,
            message=(
                DOCKER_CLEANUP_COMPLETE_MESSAGE
                if completed.returncode == 0
                else DOCKER_CLEANUP_INCOMPLETE_MESSAGE
            ),
        )

    def _combine_cleanup(
        self,
        process_cleanup: ProcessCleanupResult,
        docker_cleanup: ProcessCleanupResult,
    ) -> ProcessCleanupResult:
        if not process_cleanup.attempted and not docker_cleanup.attempted:
            return ProcessCleanupResult()
        return ProcessCleanupResult(
            attempted=process_cleanup.attempted or docker_cleanup.attempted,
            complete=process_cleanup.complete and docker_cleanup.complete,
            kill_required=process_cleanup.kill_required,
            message=(
                docker_cleanup.message
                if not docker_cleanup.complete
                else docker_cleanup.message or process_cleanup.message
            ),
        )
