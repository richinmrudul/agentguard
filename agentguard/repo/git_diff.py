import subprocess
from pathlib import Path

from agentguard.core.result import DiffSummary


def _git(repo_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _numstat(repo_dir: Path) -> tuple[int, int]:
    added = 0
    deleted = 0
    for line in _git(repo_dir, "diff", "--numstat").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        if parts[0].isdigit():
            added += int(parts[0])
        if parts[1].isdigit():
            deleted += int(parts[1])
    return added, deleted


def collect_diff(repo_dir: Path) -> DiffSummary:
    modified_files = _git(repo_dir, "diff", "--name-only", "--diff-filter=M").splitlines()
    added_files = _git(repo_dir, "diff", "--name-only", "--diff-filter=A").splitlines()
    deleted_files = _git(repo_dir, "diff", "--name-only", "--diff-filter=D").splitlines()
    lines_added, lines_deleted = _numstat(repo_dir)

    return DiffSummary(
        modified_files=modified_files,
        added_files=added_files,
        deleted_files=deleted_files,
        lines_added=lines_added,
        lines_deleted=lines_deleted,
        unified_diff=_git(repo_dir, "diff"),
    )
