import shlex
from pathlib import Path
from typing import Optional

from agentguard.agents.base import Agent
from agentguard.config.schema import AgentGuardConfig
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.sandbox.docker_runner import DockerCommandRunner


class CustomCommandAgent(Agent):
    name = "custom-command"

    def __init__(self, config: AgentGuardConfig) -> None:
        self.config = config

    def run(
        self,
        repo_dir: Path,
        command_tracker: Optional[CommandTracker] = None,
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

        result = DockerCommandRunner(command_tracker, self.config.sandbox).run_argv(
            repo_dir=repo_dir,
            inner_command=argv,
            command_text=f"docker agent: {self.config.agent_command}",
        )
        if result.exit_code != 0:
            stderr_tail = result.stderr[-500:]
            raise RuntimeError(
                "Custom command agent failed with exit code "
                f"{result.exit_code}: {stderr_tail}"
            )
