import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from agentguard.artifact_paths import artifact_directory
from agentguard.config.schema import AgentGuardConfig


@dataclass(frozen=True)
class PreparedRepo:
    run_id: str
    run_dir: Path
    repo_dir: Path
    baseline_commit: str


class RepoManager:
    def __init__(self, runs_root: Path = Path(".agentguard/runs")) -> None:
        self.runs_root = runs_root

    def prepare(self, config: AgentGuardConfig, agent_name: str) -> PreparedRepo:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        run_id = f"{config.task_id}-{agent_name}-{timestamp}-{uuid4().hex[:8]}"
        run_dir = artifact_directory(self.runs_root, run_id)
        repo_dir = run_dir / "repo"

        if config.repo_template is None:
            raise ValueError("Benchmark mode requires repo_template.")

        template = config.repo_template.resolve()
        self._validate_template(template, repo_dir, reject_git_control=False)

        run_dir.mkdir(parents=True, exist_ok=False)
        try:
            shutil.copytree(
                template,
                repo_dir,
                symlinks=True,
                ignore=self._ignore_git_control_entries,
            )
            self._validate_template(repo_dir, None, reject_git_control=True)
            self._git(repo_dir, "init", "--template=")
            git_dir = repo_dir / ".git"
            if not git_dir.is_dir() or git_dir.is_symlink():
                raise RuntimeError("Prepared repository did not receive fresh Git metadata.")
            self._git(repo_dir, "add", ".")
            self._git(
                repo_dir,
                "-c",
                "user.email=agentguard@example.local",
                "-c",
                "user.name=AgentGuard",
                "-c",
                f"core.hooksPath={os.devnull}",
                "commit",
                "-m",
                "Initial benchmark state",
            )
            baseline_commit = self._git_output(repo_dir, "rev-parse", "HEAD")
        except Exception:
            try:
                shutil.rmtree(run_dir)
            except OSError as cleanup_error:
                raise RuntimeError(
                    f"Repository preparation failed and cleanup was incomplete; "
                    f"partial artifacts remain at {run_dir}."
                ) from cleanup_error
            raise
        return PreparedRepo(
            run_id=run_id,
            run_dir=run_dir,
            repo_dir=repo_dir,
            baseline_commit=baseline_commit,
        )

    @staticmethod
    def _ignore_git_control_entries(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name.casefold() == ".git"}

    @staticmethod
    def _validate_template(
        template: Path,
        destination: Optional[Path],
        *,
        reject_git_control: bool,
    ) -> None:
        if not template.is_dir():
            raise ValueError("Benchmark repo_template must be a directory.")

        template_root = template.resolve()
        if destination is not None:
            try:
                destination.resolve().relative_to(template_root)
            except ValueError:
                pass
            else:
                raise ValueError(
                    "Benchmark run directory must be outside repo_template."
                )

        for directory, directory_names, file_names in os.walk(
            template_root, followlinks=False
        ):
            current = Path(directory)
            for name in (*directory_names, *file_names):
                entry = current / name
                if name.casefold() == ".git":
                    if reject_git_control:
                        raise ValueError(
                            "Copied benchmark content contains Git control metadata."
                        )
                    if entry.is_symlink():
                        raise ValueError(
                            "Benchmark repo_template contains a symlink named .git: "
                            f"{entry.relative_to(template_root)}"
                        )
                    continue
                if not entry.is_symlink():
                    continue
                target = entry.readlink()
                if target.is_absolute():
                    raise ValueError(
                        f"Benchmark repo_template contains an absolute symlink: "
                        f"{entry.relative_to(template_root)}"
                    )
                try:
                    resolved_target = entry.resolve()
                    relative_target = resolved_target.relative_to(template_root)
                except (OSError, RuntimeError, ValueError) as error:
                    raise ValueError(
                        f"Benchmark repo_template contains an escaping or invalid "
                        f"symlink: {entry.relative_to(template_root)}"
                    ) from error
                if any(part.casefold() == ".git" for part in relative_target.parts):
                    raise ValueError(
                        f"Benchmark repo_template contains a symlink to Git control "
                        f"metadata: {entry.relative_to(template_root)}"
                    )

    @staticmethod
    def _git(repo_dir: Path, *args: str) -> None:
        RepoManager._run_git(repo_dir, *args)

    @staticmethod
    def _git_output(repo_dir: Path, *args: str) -> str:
        return RepoManager._run_git(repo_dir, *args).stdout.strip()

    @staticmethod
    def _run_git(repo_dir: Path, *args: str) -> subprocess.CompletedProcess[str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("GIT_")
        }
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            }
        )
        return subprocess.run(
            ["git", *args],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
