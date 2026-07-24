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
from agentguard.instrumentation.output_limits import BoundedProcessOutput, limit_output
from agentguard.instrumentation.processes import (
    PROCESS_TIMEOUT_TERMINATED_MESSAGE,
    ProcessCleanupResult,
    append_cleanup_message,
    popen_with_process_group,
    terminate_process_tree,
)
from agentguard.instrumentation.test_runner import _build_test_env
from agentguard.policy.command_policy import evaluate_command_policy
from agentguard.provenance.manifest import sanitize_text


class LocalCommandAgent(Agent):
    name = "local-command"

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
                "Agent 'local-command' requires config field 'agent_command'."
            )
        if command_tracker is None:
            raise ValueError("Agent 'local-command' requires command tracking.")

        raw_command = self.config.agent_command
        if isinstance(raw_command, str):
            argv = shlex.split(raw_command)
            raw_command_text = raw_command
        else:
            argv = list(raw_command)
            raw_command_text = shlex.join(argv)
        if not argv:
            raise ValueError("Config field 'agent_command' cannot be empty.")

        command_text = f"local agent: {raw_command_text}"
        decision = evaluate_command_policy(
            command_text=raw_command_text,
            unsafe_patterns=self.config.unsafe_commands,
            mode=self.config.command_policy.mode,
        )
        if not decision.allowed:
            command_tracker.record_preflight_blocked(
                command=argv,
                command_text=command_text,
                cwd=repo_dir,
                matched_patterns=decision.matched_patterns,
                policy_mode=decision.mode,
                message=decision.message,
            )
            return

        self._run_argv(
            repo_dir=repo_dir,
            argv=argv,
            command_text=command_text,
            command_tracker=command_tracker,
            preflight_matched_patterns=decision.matched_patterns,
            policy_mode=decision.mode if decision.matched_patterns else None,
            process_controller=process_controller,
        )

    def _run_argv(
        self,
        repo_dir: Path,
        argv: list[str],
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
        try:
            process = popen_with_process_group(
                argv,
                cwd=repo_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    **_build_test_env(repo_dir),
                    **self.config.agent_environment,
                },
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
            exit_code = 127
            stdout = ""
            stderr = f"Local command executable not found: {error.filename}"
            captured = None
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            if process is not None and process.poll() is None:
                cleanup = terminate_process_tree(process)
            capture.wait()
            captured = capture.finish()
            stdout = captured.stdout.text
            stderr = captured.stderr.text
            stderr = (
                f"{stderr}\nLocal command timed out after "
                f"{self.config.command_timeout_seconds} seconds."
                f"\n{PROCESS_TIMEOUT_TERMINATED_MESSAGE}"
            ).strip()
            stderr = append_cleanup_message(stderr, cleanup)

        duration_seconds = time.monotonic() - started
        sensitive_values = [
            value for value in self.config.agent_environment.values() if value
        ]
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
            command=argv,
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
