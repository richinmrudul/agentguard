from abc import ABC, abstractmethod
from pathlib import Path


class Agent(ABC):
    name: str

    @abstractmethod
    def run(self, repo_dir: Path) -> None:
        """Modify the copied benchmark repository."""
