import shlex
from pathlib import Path
from typing import Optional

from agentguard.agents.base import Agent
from agentguard.config.schema import AgentGuardConfig
from agentguard.guard.filesystem import ProcessController
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.output_limits import limit_output
from agentguard.policy.command_policy import evaluate_command_policy
from agentguard.provenance.manifest import (
    sanitize_arguments,
    sanitize_text,
    sensitive_values_for_config,
)
from agentguard.sandbox.docker_runner import DockerCommandRunner
from agentguard.terminal import sanitize_terminal_text


class CustomCommandAgent(Agent):
    name = "custom-command"

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
                "Agent 'custom-command' requires config field 'agent_command'."
            )
        if self.config.sandbox.type != "docker":
            raise ValueError("Agent 'custom-command' currently requires docker sandbox.")
        if command_tracker is None:
            raise ValueError("Agent 'custom-command' requires command tracking.")

        argv = shlex.split(self.config.agent_command)
        if not argv:
            raise ValueError("Config field 'agent_command' cannot be empty.")
        sensitive_values = self._sensitive_values(repo_dir)
        command_text = "docker agent: " + shlex.join(
            sanitize_arguments(argv, sensitive_values)
        )
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
            self._sanitize_last_event(command_tracker, sensitive_values)
            return

        try:
            result = DockerCommandRunner(
                command_tracker,
                self.config.sandbox,
                timeout_seconds=self.config.command_timeout_seconds,
                max_output_bytes=self.config.max_output_bytes,
            ).run_argv(
                repo_dir=repo_dir,
                inner_command=argv,
                command_text=command_text,
                preflight_matched_patterns=decision.matched_patterns,
                policy_mode=decision.mode if decision.matched_patterns else None,
            )
        except OSError as error:
            raise ValueError(
                "Docker could not launch the custom agent container."
            ) from error
        self._sanitize_last_event(command_tracker, sensitive_values)
        if result.exit_code == 127 and result.stderr.startswith(
            "Docker is not installed"
        ):
            raise ValueError(
                "Docker is unavailable; the custom agent container did not start."
            )
        if result.exit_code == 125:
            raise ValueError(
                "Docker could not start the custom agent container."
            )

    def _sensitive_values(
        self,
        repo_dir: Path,
    ) -> list[str]:
        return sensitive_values_for_config(
            self.config,
            [str(repo_dir), str(repo_dir.resolve())],
        )

    def _sanitize_last_event(
        self,
        command_tracker: CommandTracker,
        sensitive_values: list[str],
    ) -> None:
        events = command_tracker.events
        if not events:
            return
        event = events[-1]
        event.command = [
            sanitize_terminal_text(value, preserve_newlines=False)
            for value in sanitize_arguments(event.command, sensitive_values)
        ]
        event.command_text = sanitize_terminal_text(
            sanitize_text(event.command_text, sensitive_values),
            preserve_newlines=False,
        )
        event.cwd = "[REPOSITORY]"
        stdout = limit_output(
            sanitize_terminal_text(sanitize_text(event.stdout, sensitive_values)),
            self.config.max_output_bytes,
        )
        stderr = limit_output(
            sanitize_terminal_text(sanitize_text(event.stderr, sensitive_values)),
            self.config.max_output_bytes,
        )
        event.stdout = stdout.text
        event.stderr = stderr.text
        event.stdout_truncated = event.stdout_truncated or stdout.truncated
        event.stderr_truncated = event.stderr_truncated or stderr.truncated
        if event.process_cleanup_message is not None:
            event.process_cleanup_message = sanitize_terminal_text(
                sanitize_text(event.process_cleanup_message, sensitive_values)
            )
