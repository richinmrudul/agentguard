from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from agentguard.instrumentation.command_tracker import CommandTracker


class Agent(ABC):
    name: str

    @abstractmethod
    def run(
        self,
        repo_dir: Path,
        command_tracker: Optional[CommandTracker] = None,
    ) -> None:
        """Modify the copied benchmark repository."""
