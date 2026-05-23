from abc import ABC, abstractmethod

from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary


class Check(ABC):
    @abstractmethod
    def run(
        self,
        config: AgentGuardConfig,
        test_result: CommandResult,
        diff_summary: DiffSummary,
        command_log: list[str],
    ) -> CheckResult:
        """Evaluate evidence and return a structured check result."""
