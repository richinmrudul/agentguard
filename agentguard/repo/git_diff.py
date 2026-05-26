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
    return _numstat_for_diff(repo_dir, "HEAD")


def _numstat_for_diff(repo_dir: Path, *diff_args: str) -> tuple[int, int]:
    added = 0
    deleted = 0
    for line in _git(repo_dir, "diff", *diff_args, "--numstat").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        if parts[0].isdigit():
            added += int(parts[0])
        if parts[1].isdigit():
            deleted += int(parts[1])
    return added, deleted


def _classify_name_status(
    name_status: str,
) -> tuple[list[str], list[str], list[str]]:
    modified_files: list[str] = []
    added_files: list[str] = []
    deleted_files: list[str] = []

    for line in name_status.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status = parts[0]
        path = parts[-1]
        status_type = status[0]
        if status_type == "A":
            added_files.append(path)
        elif status_type == "D":
            deleted_files.append(path)
        elif status_type == "R":
            modified_files.append(path)
        elif status_type == "M":
            modified_files.append(path)

    return modified_files, added_files, deleted_files


def _untracked_files(repo_dir: Path) -> list[str]:
    return [
        path
        for path in _git(
            repo_dir,
            "ls-files",
            "--others",
            "--exclude-standard",
        ).splitlines()
        if not _is_generated_artifact(path)
    ]


def _is_generated_artifact(path: str) -> bool:
    return (
        "__pycache__/" in path
        or path.endswith(".pyc")
        or path.startswith(".pytest_cache/")
    )


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except UnicodeDecodeError:
        return 0


def collect_diff(repo_dir: Path) -> DiffSummary:
    modified_files = _git(
        repo_dir,
        "diff",
        "HEAD",
        "--name-only",
        "--diff-filter=M",
    ).splitlines()
    added_files = _git(
        repo_dir,
        "diff",
        "HEAD",
        "--name-only",
        "--diff-filter=A",
    ).splitlines()
    untracked_files = _untracked_files(repo_dir)
    added_files.extend(path for path in untracked_files if path not in added_files)
    deleted_files = _git(
        repo_dir,
        "diff",
        "HEAD",
        "--name-only",
        "--diff-filter=D",
    ).splitlines()
    lines_added, lines_deleted = _numstat(repo_dir)
    lines_added += sum(_line_count(repo_dir / path) for path in untracked_files)

    return DiffSummary(
        modified_files=modified_files,
        added_files=added_files,
        deleted_files=deleted_files,
        lines_added=lines_added,
        lines_deleted=lines_deleted,
        unified_diff=_git(repo_dir, "diff", "HEAD"),
    )


def collect_diff_between_refs(
    repo_dir: Path,
    base_ref: str,
    head_ref: str,
) -> DiffSummary:
    diff_ref = f"{base_ref}...{head_ref}"
    modified_files, added_files, deleted_files = _classify_name_status(
        _git(repo_dir, "diff", diff_ref, "--name-status")
    )
    lines_added, lines_deleted = _numstat_for_diff(repo_dir, diff_ref)

    return DiffSummary(
        modified_files=modified_files,
        added_files=added_files,
        deleted_files=deleted_files,
        lines_added=lines_added,
        lines_deleted=lines_deleted,
        unified_diff=_git(repo_dir, "diff", diff_ref),
    )
