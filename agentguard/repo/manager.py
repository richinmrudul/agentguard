import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agentguard.config.schema import AgentGuardConfig


@dataclass(frozen=True)
class PreparedRepo:
    run_id: str
    run_dir: Path
    repo_dir: Path


class RepoManager:
    def __init__(self, runs_root: Path = Path(".agentguard/runs")) -> None:
        self.runs_root = runs_root

    def prepare(self, config: AgentGuardConfig, agent_name: str) -> PreparedRepo:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        run_id = f"{config.task_id}-{agent_name}-{timestamp}"
        run_dir = self.runs_root / run_id
        repo_dir = run_dir / "repo"

        if config.repo_template is None:
            raise ValueError("Benchmark mode requires repo_template.")

        run_dir.mkdir(parents=True, exist_ok=False)
        shutil.copytree(config.repo_template, repo_dir)
        self._git(repo_dir, "init")
        self._git(repo_dir, "add", ".")
        self._git(
            repo_dir,
            "-c",
            "user.email=agentguard@example.local",
            "-c",
            "user.name=AgentGuard",
            "commit",
            "-m",
            "Initial benchmark state",
        )
        return PreparedRepo(run_id=run_id, run_dir=run_dir, repo_dir=repo_dir)

    @staticmethod
    def _git(repo_dir: Path, *args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
        )
