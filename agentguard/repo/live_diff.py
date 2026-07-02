import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


MAX_LIVE_DIFF_FILE_BYTES = 1_000_000
MAX_LIVE_DIFF_TOTAL_BYTES = 8_000_000
MAX_LIVE_DIFF_FILES = 1_000


@dataclass(frozen=True)
class LiveDiffCandidate:
    path: str
    baseline_size: Optional[int]
    current_size: Optional[int]


@dataclass(frozen=True)
class LiveLineMeasurement:
    lines_added: int = 0
    lines_deleted: int = 0
    complete: bool = True
    skipped_files: int = 0
    error: Optional[str] = None


def measure_live_line_diff(
    repo_dir: Path,
    candidates: list[LiveDiffCandidate],
    baseline_ref: Optional[str] = "HEAD",
    *,
    max_file_bytes: int = MAX_LIVE_DIFF_FILE_BYTES,
    max_total_bytes: int = MAX_LIVE_DIFF_TOTAL_BYTES,
    max_files: int = MAX_LIVE_DIFF_FILES,
) -> LiveLineMeasurement:
    if baseline_ref is None:
        return _live_measurement(
            0,
            0,
            len(candidates),
            git_unavailable=True,
        )
    selected: list[LiveDiffCandidate] = []
    skipped = 0
    total_bytes = 0
    for candidate in sorted(candidates, key=lambda item: item.path):
        sizes = [
            size
            for size in (candidate.baseline_size, candidate.current_size)
            if size is not None
        ]
        largest_file_version = max(sizes, default=0)
        candidate_bytes = sum(sizes)
        if (
            len(selected) >= max_files
            or largest_file_version > max_file_bytes
            or total_bytes + candidate_bytes > max_total_bytes
        ):
            skipped += 1
            continue
        selected.append(candidate)
        total_bytes += candidate_bytes

    if not selected:
        return _live_measurement(
            0,
            0,
            skipped,
            bounds_exceeded=bool(skipped),
        )

    pathspecs = [f":(literal){candidate.path}" for candidate in selected]
    try:
        tracked = {
            os.fsdecode(path)
            for path in _git_bytes(
                repo_dir,
                "ls-files",
                "-z",
                "--",
                *pathspecs,
            ).split(b"\0")
            if path
        }
        untracked = {
            os.fsdecode(path)
            for path in _git_bytes(
                repo_dir,
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                *pathspecs,
            ).split(b"\0")
            if path
        }
    except (OSError, subprocess.SubprocessError):
        return _live_measurement(
            0,
            0,
            skipped + len(selected),
            git_unavailable=True,
            bounds_exceeded=bool(skipped),
        )

    tracked_candidates = [
        candidate
        for candidate in selected
        if candidate.path in tracked or candidate.baseline_size is not None
    ]
    untracked_candidates = [
        candidate
        for candidate in selected
        if candidate.path in untracked
        and candidate.path not in tracked
        and candidate.baseline_size is None
    ]
    classified_paths = {
        candidate.path
        for candidate in [*tracked_candidates, *untracked_candidates]
    }

    added = 0
    deleted = 0
    binary_or_malformed = 0
    read_failures = len(selected) - len(classified_paths)
    for candidate in untracked_candidates:
        line_count = _bounded_untracked_line_count(
            repo_dir / candidate.path,
            max_file_bytes=max_file_bytes,
        )
        if line_count is None:
            read_failures += 1
        else:
            added += line_count

    git_unavailable = False
    if tracked_candidates:
        tracked_pathspecs = [
            f":(literal){candidate.path}" for candidate in tracked_candidates
        ]
        try:
            output = _git_bytes(
                repo_dir,
                "diff",
                baseline_ref,
                "--numstat",
                "-z",
                "--",
                *tracked_pathspecs,
            )
            tracked_added, tracked_deleted, incomplete_entries = (
                _parse_numstat_bytes(output)
            )
            added += tracked_added
            deleted += tracked_deleted
            binary_or_malformed += incomplete_entries
        except (OSError, subprocess.SubprocessError):
            git_unavailable = True

    skipped_total = skipped + binary_or_malformed + read_failures
    return _live_measurement(
        added,
        deleted,
        skipped_total,
        bounds_exceeded=bool(skipped),
        binary_or_unreadable=bool(binary_or_malformed or read_failures),
        git_unavailable=git_unavailable,
    )


def resolve_live_diff_baseline(repo_dir: Path) -> Optional[str]:
    try:
        value = _git_bytes(repo_dir, "rev-parse", "--verify", "HEAD").strip()
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if len(decoded) not in {40, 64} or any(
        character not in "0123456789abcdefABCDEF" for character in decoded
    ):
        return None
    return decoded


def _git_bytes(repo_dir: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
    )
    return result.stdout


def _bounded_untracked_line_count(
    path: Path,
    *,
    max_file_bytes: int,
) -> Optional[int]:
    try:
        file_stat = path.lstat()
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_size > max_file_bytes
        ):
            return None
        with path.open("rb") as file:
            content = file.read(max_file_bytes + 1)
    except OSError:
        return None
    if len(content) > max_file_bytes or b"\x00" in content:
        return None
    return len(content.splitlines())


def _parse_numstat_bytes(output: bytes) -> tuple[int, int, int]:
    added = 0
    deleted = 0
    incomplete = 0
    fields = output.split(b"\0")
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if not record:
            continue
        parts = record.split(b"\t", 2)
        if len(parts) != 3:
            incomplete += 1
            continue
        added_value, deleted_value, path = parts
        if not path:
            index += 2
        if added_value.isdigit() and deleted_value.isdigit():
            added += int(added_value)
            deleted += int(deleted_value)
        else:
            incomplete += 1
    return added, deleted, incomplete


def _live_measurement(
    added: int,
    deleted: int,
    skipped_files: int,
    *,
    bounds_exceeded: bool = False,
    binary_or_unreadable: bool = False,
    git_unavailable: bool = False,
) -> LiveLineMeasurement:
    reasons = []
    if bounds_exceeded:
        reasons.append("processing bounds exceeded")
    if binary_or_unreadable:
        reasons.append("binary or unreadable files skipped")
    if git_unavailable:
        reasons.append("Git diff unavailable")
    error = (
        "Line measurement incomplete: " + "; ".join(reasons) + "."
        if reasons
        else None
    )
    return LiveLineMeasurement(
        lines_added=max(0, added),
        lines_deleted=max(0, deleted),
        complete=not reasons,
        skipped_files=max(0, skipped_files),
        error=error,
    )
