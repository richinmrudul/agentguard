import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Optional

from agentguard.agents.base import Agent
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CommandResult
from agentguard.guard.filesystem import ProcessController
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
from agentguard.instrumentation.test_runner import _build_subprocess_env
from agentguard.policy.command_policy import evaluate_command_policy
from agentguard.provenance.manifest import sanitize_arguments, sanitize_text


class AgentCommandAgent(Agent):
    name = "agent-command"

    def __init__(self, config: AgentGuardConfig) -> None:
        self.config = config

    def run(
        self,
        repo_dir: Path,
        command_tracker: Optional[CommandTracker] = None,
        process_controller: Optional[ProcessController] = None,
    ) -> None:
        if not self.config.agent_command:
            raise ValueError(
                "Agent 'agent-command' requires config field 'agent_command'."
            )
        if command_tracker is None:
            raise ValueError("Agent 'agent-command' requires command tracking.")

        argv = self._argv()
        if not argv:
            raise ValueError("Config field 'agent_command' cannot be empty.")

        raw_command_text = self._raw_command_text()
        raw_display_argv = list(self.config.agent_display_command or argv)
        display_argv = sanitize_arguments(
            raw_display_argv,
            [
                value
                for value in self.config.agent_environment.values()
                if value
            ],
        )
        if self.config.agent_display_command is not None:
            profile_name = self.config.agent_metadata.get(
                "profile_name",
                self.config.agent_name or "external agent",
            )
            profile_id = self.config.agent_metadata.get(
                "profile_id",
                self.config.agent_name or "unknown",
            )
            command_text = (
                f"agent profile {profile_name} ({profile_id}): "
                f"{shlex.join(display_argv)}"
            )
        else:
            command_text = f"agent command: {shlex.join(display_argv)}"
        workdir = self._workdir(repo_dir)
        decision = evaluate_command_policy(
            command_text=(
                shlex.join(raw_display_argv)
                if self.config.agent_display_command is not None
                else raw_command_text
            ),
            unsafe_patterns=self.config.unsafe_commands,
            mode=self.config.command_policy.mode,
        )
        if not decision.allowed:
            command_tracker.record_preflight_blocked(
                command=display_argv,
                command_text=command_text,
                cwd=workdir,
                matched_patterns=decision.matched_patterns,
                policy_mode=decision.mode,
                message=decision.message,
                agent_name=self.config.agent_name,
            )
            return

        self._run_argv(
            repo_dir=repo_dir,
            workdir=workdir,
            argv=argv,
            display_argv=display_argv,
            command_text=command_text,
            command_tracker=command_tracker,
            preflight_matched_patterns=decision.matched_patterns,
            policy_mode=decision.mode if decision.matched_patterns else None,
            process_controller=process_controller,
        )

    def _argv(self) -> list[str]:
        command = self.config.agent_command
        if isinstance(command, str):
            return shlex.split(command)
        if command is None:
            return []
        return list(command)

    def _raw_command_text(self) -> str:
        command = self.config.agent_command
        if isinstance(command, str):
            return command
        if command is None:
            return ""
        return shlex.join(command)

    def _workdir(self, repo_dir: Path) -> Path:
        if self.config.agent_workdir_path is not None:
            return self.config.agent_workdir_path
        if self.config.agent_workdir == "config_dir":
            return self.config.config_path.parent
        return repo_dir

    def _env(self, repo_dir: Path) -> dict[str, str]:
        if self.config.agent_environment_isolated:
            env = {"PATH": os.environ.get("PATH", os.defpath)}
            env.update(self.config.agent_environment)
            src_path = (repo_dir / "src").resolve()
            if src_path.exists():
                env["PYTHONPATH"] = str(src_path)
            return env
        env = _build_subprocess_env(repo_dir)
        env.update(self.config.agent_environment)
        return env

    def _run_argv(
        self,
        repo_dir: Path,
        workdir: Path,
        argv: list[str],
        display_argv: list[str],
        command_text: str,
        command_tracker: CommandTracker,
        preflight_matched_patterns: list[str],
        policy_mode: Optional[str],
        process_controller: Optional[ProcessController] = None,
    ) -> CommandResult:
        started = time.monotonic()
        timed_out = False
        cleanup = ProcessCleanupResult()
        process: Optional[subprocess.Popen] = None
        capture = None
        cleanup_started = False
        try:
            process = popen_with_process_group(
                argv,
                cwd=workdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env(repo_dir),
            )
            capture = BoundedProcessOutput(process, self.config.max_output_bytes)
            if process_controller is not None:
                process_controller.attach(process)
            exit_code = capture.wait(timeout=self.config.command_timeout_seconds)
            captured = capture.finish()
            stdout = captured.stdout.text
            stderr = captured.stderr.text
            if (
                process_controller is not None
                and process_controller.termination_requested
            ):
                cleanup = process_controller.termination_cleanup_result()
                reason = (
                    process_controller.termination_reason
                    or "policy violation"
                )
                label = (
                    "online filesystem guard"
                    if "filesystem" in reason
                    else "online guard"
                )
                stderr = (
                    f"{stderr}\nAgent terminated by {label}: {reason}"
                ).strip()
        except FileNotFoundError as error:
            if process is not None:
                cleanup_process_after_exception(process, capture)
                raise
            exit_code = 127
            stdout = ""
            stderr = f"Agent command executable not found: {error.filename}"
            captured = None
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            if process is not None:
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
            try:
                captured = capture.finish(
                    timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS
                )
            except BaseException:
                captured = ProcessOutput(
                    stdout=LimitedOutput(text="", truncated=False),
                    stderr=LimitedOutput(text="", truncated=False),
                )
            stdout = captured.stdout.text
            stderr = captured.stderr.text
            stderr = (
                f"{stderr}\nAgent command timed out after "
                f"{self.config.command_timeout_seconds} seconds."
                f"\n{process_timeout_message(cleanup)}"
            ).strip()
            stderr = append_cleanup_message(stderr, cleanup)
        except BaseException:
            cleanup_process_after_exception(
                process,
                capture,
                cleanup_started=cleanup_started,
            )
            raise

        duration_seconds = time.monotonic() - started
        sensitive_values = [
            value for value in self.config.agent_environment.values() if value
        ]
        if self.config.agent_environment_isolated and os.environ.get("PATH"):
            sensitive_values.append(os.environ["PATH"])
        if self.config.agent_display_command is not None:
            sensitive_values.extend(
                actual
                for actual, displayed in zip(argv, self.config.agent_display_command)
                if actual != displayed
            )
        stdout = sanitize_text(stdout, sensitive_values)
        stderr = sanitize_text(stderr, sensitive_values)
        limited_stdout = limit_output(stdout, self.config.max_output_bytes)
        limited_stderr = limit_output(stderr, self.config.max_output_bytes)
        stdout_truncated = (
            captured is not None and captured.stdout.truncated
        ) or limited_stdout.truncated
        stderr_truncated = (
            captured is not None and captured.stderr.truncated
        ) or limited_stderr.truncated
        command_tracker.record_executed(
            command=display_argv,
            command_text=command_text,
            cwd=workdir,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            preflight_matched_patterns=preflight_matched_patterns,
            policy_mode=policy_mode,
            agent_name=self.config.agent_name,
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
