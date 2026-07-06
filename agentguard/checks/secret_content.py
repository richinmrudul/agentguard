import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

from agentguard.config.schema import SecretContentPattern
from agentguard.core.result import DiffSummary


MAX_SECRET_SCAN_FILES = 256
MAX_SECRET_SCAN_BYTES_PER_FILE = 1_000_000
MAX_SECRET_SCAN_TOTAL_BYTES = 8_000_000
MAX_SECRET_SCAN_LINE_BYTES = 16_384
MAX_SECRET_SCAN_MATCHES = 100
MAX_SECRET_SCAN_MATCHES_PER_DETECTOR_FILE = 5


@dataclass(frozen=True)
class SecretContentScanResult:
    matches: list[str]
    complete: bool
    error: Optional[str] = None


def _safe_path(raw_path: str) -> Optional[str]:
    if any(ord(character) < 32 or ord(character) == 127 for character in raw_path):
        return None
    path = PurePosixPath(raw_path.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        return None
    normalized = path.as_posix()
    return normalized if normalized not in {"", "."} else None


def _added_lines(
    unified_diff: str,
) -> tuple[list[tuple[str, int, str]], set[str], Optional[str]]:
    additions: list[tuple[str, int, str]] = []
    represented_paths: set[str] = set()
    current_path: Optional[str] = None
    current_line: Optional[int] = None
    total_bytes = 0
    section_bytes = 0
    for line in unified_diff.splitlines():
        line_bytes = len(line.encode("utf-8", errors="replace")) + 1
        total_bytes += line_bytes
        if total_bytes > MAX_SECRET_SCAN_TOTAL_BYTES:
            return additions, represented_paths, "diff byte limit exceeded"
        if line.startswith("diff --git "):
            current_path = None
            current_line = None
            section_bytes = 0
            continue
        if current_line is None and line.startswith("+++ "):
            raw_path = line[4:]
            if raw_path == "/dev/null":
                current_path = None
            elif raw_path.startswith(("a/", "b/")):
                current_path = _safe_path(raw_path[2:])
            else:
                current_path = _safe_path(raw_path)
            if current_path is not None:
                represented_paths.add(current_path)
            current_line = None
            section_bytes = 0
            continue
        section_bytes += line_bytes
        if section_bytes > MAX_SECRET_SCAN_BYTES_PER_FILE:
            return additions, represented_paths, "diff section byte limit exceeded"
        if line.startswith("@@ "):
            try:
                new_range = line.split(" ")[2][1:]
                current_line = int(new_range.split(",", 1)[0])
            except (IndexError, ValueError):
                return additions, represented_paths, "diff metadata unavailable"
            continue
        if current_path is None or current_line is None:
            continue
        if line.startswith("+"):
            content = line[1:]
            if len(content.encode("utf-8", errors="replace")) > MAX_SECRET_SCAN_LINE_BYTES:
                return additions, represented_paths, "line byte limit exceeded"
            additions.append((current_path, current_line, content))
            current_line += 1
        elif not line.startswith("-") and not line.startswith("\\"):
            current_line += 1
    return additions, represented_paths, None


def _markdown_path(path: str) -> str:
    escaped = path
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "(", ")", "<", ">", "#"):
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _git_blob(repo_dir: Path, path: str) -> Optional[bytes]:
    try:
        result = subprocess.run(
            ["git", "show", f"HEAD:{path}"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout


def _is_exact_rename(
    repo_dir: Path,
    content: bytes,
    deleted_files: list[str],
) -> bool:
    for deleted_path in deleted_files:
        baseline = _git_blob(repo_dir, deleted_path)
        if baseline is not None and baseline == content:
            return True
    return False


def scan_secret_content(
    repo_dir: Path,
    diff_summary: DiffSummary,
    patterns: list[SecretContentPattern],
) -> SecretContentScanResult:
    if not patterns:
        return SecretContentScanResult(matches=[], complete=True)
    additions, represented_paths, diff_error = _added_lines(
        diff_summary.unified_diff
    )
    if diff_error is not None:
        return SecretContentScanResult([], False, diff_error)

    candidate_paths = sorted(represented_paths | set(diff_summary.added_files))
    if len(candidate_paths) > MAX_SECRET_SCAN_FILES:
        return SecretContentScanResult([], False, "candidate file limit exceeded")

    total_bytes = sum(
        len(content.encode("utf-8", errors="replace"))
        for _, _, content in additions
    )
    for raw_path in sorted(set(diff_summary.added_files) - represented_paths):
        path = _safe_path(raw_path)
        if path is None:
            return SecretContentScanResult([], False, "unsafe path encountered")
        target = repo_dir / path
        try:
            if target.is_symlink() or not target.is_file():
                continue
            content = target.read_bytes()
        except OSError:
            return SecretContentScanResult([], False, "file content unavailable")
        if len(content) > MAX_SECRET_SCAN_BYTES_PER_FILE:
            return SecretContentScanResult([], False, "file byte limit exceeded")
        total_bytes += len(content)
        if total_bytes > MAX_SECRET_SCAN_TOTAL_BYTES:
            return SecretContentScanResult([], False, "total byte limit exceeded")
        if b"\0" in content:
            continue
        if _is_exact_rename(repo_dir, content, diff_summary.deleted_files):
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            return SecretContentScanResult([], False, "text decoding unavailable")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if len(line.encode("utf-8")) > MAX_SECRET_SCAN_LINE_BYTES:
                return SecretContentScanResult(
                    [], False, "line byte limit exceeded"
                )
            additions.append((path, line_number, line))

    retained: list[tuple[str, int, str]] = []
    omitted = 0
    per_detector_file: dict[tuple[str, str], int] = {}
    for path, line_number, content in additions:
        for pattern in patterns:
            if pattern.contains not in content:
                continue
            key = (path, pattern.id)
            count = per_detector_file.get(key, 0)
            if count >= MAX_SECRET_SCAN_MATCHES_PER_DETECTOR_FILE:
                omitted += 1
                continue
            per_detector_file[key] = count + 1
            retained.append((path, line_number, pattern.id))
    retained.sort()
    omitted += max(0, len(retained) - MAX_SECRET_SCAN_MATCHES)
    retained = retained[:MAX_SECRET_SCAN_MATCHES]
    matches = [
        f"{_markdown_path(path)}:{line_number} matched secret-content detector {detector_id}"
        for path, line_number, detector_id in retained
    ]
    if omitted:
        matches.append(f"{omitted} additional secret-content match(es) omitted")
    return SecretContentScanResult(matches=matches, complete=True)


def with_secret_content_scan(
    repo_dir: Path,
    diff_summary: DiffSummary,
    patterns: list[SecretContentPattern],
) -> DiffSummary:
    from dataclasses import replace

    result = scan_secret_content(repo_dir, diff_summary, patterns)
    return replace(
        diff_summary,
        secret_content_matches=result.matches,
        secret_content_scan_complete=result.complete,
        secret_content_scan_error=result.error,
    )
