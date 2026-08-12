import subprocess
from pathlib import Path

from agentguard.core.result import DiffSummary
from agentguard.repo.internal_artifacts import (
    git_exclusion_pathspecs,
    is_internal_artifact,
)


def _git(repo_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _numstat(repo_dir: Path, baseline_ref: str = "HEAD") -> tuple[int, int]:
    return _numstat_for_diff(repo_dir, baseline_ref)


def _numstat_for_diff(repo_dir: Path, *diff_args: str) -> tuple[int, int]:
    added = 0
    deleted = 0
    for line in _git(repo_dir, "diff", *diff_args, "--numstat").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        if is_internal_artifact(parts[-1]):
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

    fields = name_status.split("\0")
    index = 0
    while index < len(fields):
        status = fields[index]
        index += 1
        if not status:
            continue
        status_type = status[0]
        path_count = 2 if status_type in {"C", "R"} else 1
        paths = fields[index : index + path_count]
        index += path_count
        visible_paths = [
            path for path in paths if path and not is_internal_artifact(path)
        ]
        if status_type == "A":
            added_files.extend(visible_paths)
        elif status_type == "D":
            deleted_files.extend(visible_paths)
        elif status_type in {"C", "M", "R", "T", "U", "X"}:
            modified_files.extend(visible_paths)

    return modified_files, added_files, deleted_files


def _untracked_files(repo_dir: Path, *, include_ignored: bool = False) -> list[str]:
    args = ["ls-files", "--others"]
    if not include_ignored:
        args.append("--exclude-standard")
    args.append("-z")
    return sorted(
        [
            path
            for path in _git(repo_dir, *args).split("\0")
            if path
            if not is_internal_artifact(path)
        ]
    )


def _line_count(path: Path) -> int:
    if path.is_symlink() or not path.is_file():
        return 0
    try:
        return len(path.read_text(encoding="utf-8").splitlines())
    except (OSError, UnicodeDecodeError):
        return 0


def _require_baseline_commit(repo_dir: Path, baseline_ref: str) -> None:
    try:
        _git(repo_dir, "cat-file", "-e", f"{baseline_ref}^{{commit}}")
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(
            "The prepared benchmark baseline commit is unavailable; "
            "post-run evidence cannot be collected safely."
        ) from error


def collect_diff(
    repo_dir: Path,
    baseline_ref: str = "HEAD",
    *,
    include_ignored: bool = False,
) -> DiffSummary:
    _require_baseline_commit(repo_dir, baseline_ref)
    modified_files, added_files, deleted_files = _classify_name_status(
        _git(
            repo_dir,
            "diff",
            baseline_ref,
            "--find-renames",
            "--name-status",
            "-z",
        )
    )
    untracked_files = _untracked_files(repo_dir, include_ignored=include_ignored)
    added_files.extend(path for path in untracked_files if path not in added_files)
    lines_added, lines_deleted = _numstat(repo_dir, baseline_ref)
    lines_added += sum(_line_count(repo_dir / path) for path in untracked_files)

    return DiffSummary(
        modified_files=modified_files,
        added_files=added_files,
        deleted_files=deleted_files,
        lines_added=lines_added,
        lines_deleted=lines_deleted,
        unified_diff=_git(
            repo_dir,
            "diff",
            baseline_ref,
            "--",
            ".",
            *git_exclusion_pathspecs(),
        ),
    )


def collect_diff_between_refs(
    repo_dir: Path,
    base_ref: str,
    head_ref: str,
) -> DiffSummary:
    diff_ref = f"{base_ref}...{head_ref}"
    modified_files, added_files, deleted_files = _classify_name_status(
        _git(repo_dir, "diff", diff_ref, "--find-renames", "--name-status", "-z")
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
