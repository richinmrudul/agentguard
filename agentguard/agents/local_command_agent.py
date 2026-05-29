import shlex
import subprocess
import time
from pathlib import Path
from typing import Optional

from agentguard.agents.base import Agent
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.output_limits import limit_output
from agentguard.instrumentation.test_runner import _build_test_env
from agentguard.policy.command_policy import evaluate_command_policy


class LocalCommandAgent(Agent):
    name = "local-command"

    def __init__(self, config: AgentGuardConfig) -> None:
        self.config = config

    def run(
        self,
        repo_dir: Path,
        command_tracker: Optional[CommandTracker] = None,
    ) -> None:
        if not self.config.agent_command:
            raise ValueError(
                "Agent 'local-command' requires config field 'agent_command'."
            )
        if command_tracker is None:
            raise ValueError("Agent 'local-command' requires command tracking.")

        argv = shlex.split(self.config.agent_command)
        if not argv:
            raise ValueError("Config field 'agent_command' cannot be empty.")

        command_text = f"local agent: {self.config.agent_command}"
        decision = evaluate_command_policy(
            command_text=self.config.agent_command,
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
        )

    def _run_argv(
        self,
        repo_dir: Path,
        argv: list[str],
        command_text: str,
        command_tracker: CommandTracker,
        preflight_matched_patterns: list[str],
        policy_mode: Optional[str],
    ) -> CommandResult:
        started = time.monotonic()
        timed_out = False
        try:
            completed = subprocess.run(
                argv,
                cwd=repo_dir,
                check=False,
                capture_output=True,
                text=True,
                env=_build_test_env(repo_dir),
                timeout=self.config.command_timeout_seconds,
            )
            exit_code = completed.returncode
            stdout = completed.stdout
            stderr = completed.stderr
        except FileNotFoundError as error:
            exit_code = 127
            stdout = ""
            stderr = f"Local command executable not found: {error.filename}"
        except subprocess.TimeoutExpired as error:
            timed_out = True
            exit_code = 124
            stdout = error.stdout or ""
            stderr = error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            stderr = (
                f"{stderr}\nLocal command timed out after "
                f"{self.config.command_timeout_seconds} seconds."
            ).strip()

        duration_seconds = time.monotonic() - started
        limited_stdout = limit_output(stdout, self.config.max_output_bytes)
        limited_stderr = limit_output(stderr, self.config.max_output_bytes)
        command_tracker.record_executed(
            command=argv,
            command_text=command_text,
            cwd=repo_dir,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=limited_stdout.truncated,
            stderr_truncated=limited_stderr.truncated,
            preflight_matched_patterns=preflight_matched_patterns,
            policy_mode=policy_mode,
        )
        return CommandResult(
            command=command_text,
            exit_code=exit_code,
            stdout=limited_stdout.text,
            stderr=limited_stderr.text,
            duration_seconds=duration_seconds,
            timed_out=timed_out,
            stdout_truncated=limited_stdout.truncated,
            stderr_truncated=limited_stderr.truncated,
        )
