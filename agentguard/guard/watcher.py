from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from agentguard.policy.path_matcher import matching_patterns


MAX_OBSERVED_FILES = 20000
MAX_INSPECTED_ENTRIES = MAX_OBSERVED_FILES * 2
IGNORED_DIR_NAMES = {
    ".git",
    ".agentguard",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "node_modules",
}
IGNORED_FILE_NAMES = {".agentguard_agent_events.jsonl"}


class FilesystemWatcherMode(str, Enum):
    AUTO = "auto"
    POLLING = "polling"
    DISABLED = "disabled"


@dataclass(frozen=True)
class FileState:
    kind: str
    mtime_ns: int
    size: int
    symlink_target: Optional[str] = None


@dataclass(frozen=True)
class FilesystemWatchEvent:
    path: str
    event_type: str
    observed_at_sequence: int
    source: str


@dataclass(frozen=True)
class FilesystemObservation:
    snapshot: dict[str, FileState]
    events: list[FilesystemWatchEvent]
    scan_complete: bool = True


@dataclass(frozen=True)
class FilesystemSnapshot:
    states: dict[str, FileState]
    complete: bool
    entries_inspected: int


class FilesystemSnapshotScanner:
    def __init__(
        self,
        *,
        repo_dir: Path,
        guard_ignore_paths: list[str],
    ) -> None:
        self.repo_dir = repo_dir.expanduser().resolve()
        self.guard_ignore_paths = list(guard_ignore_paths)

    def snapshot(self) -> dict[str, FileState]:
        """Return states for legacy callers; runtime guards use scan_snapshot()."""
        return self.scan_snapshot().states

    def scan_snapshot(self) -> FilesystemSnapshot:
        observed: dict[str, FileState] = {}
        stack = [self.repo_dir]
        inspected = 0
        complete = True
        while stack:
            directory = stack.pop()
            try:
                entries = os.scandir(directory)
            except OSError:
                continue
            with entries:
                for entry in entries:
                    inspected += 1
                    if inspected > MAX_INSPECTED_ENTRIES:
                        complete = False
                        stack.clear()
                        break
                    if entry.name in IGNORED_FILE_NAMES:
                        continue
                    rel = self.relative_path(Path(entry.path))
                    if rel is None:
                        continue
                    try:
                        stat = entry.stat(follow_symlinks=False)
                        is_symlink = entry.is_symlink()
                        is_dir = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        continue
                    target = None
                    kind = "file"
                    if is_symlink:
                        kind = "symlink"
                        try:
                            target = os.readlink(entry.path)
                        except OSError:
                            target = None
                        if not self.symlink_escapes(rel, target or "") and (
                            self.ignored_path(rel)
                        ):
                            continue
                    elif is_dir:
                        kind = "directory"
                        if self.built_in_ignored_path(rel):
                            continue
                        if self.configured_ignored_path(rel, is_directory=True):
                            if self.tree_contains_escaping_symlink(
                                Path(entry.path),
                                rel,
                            ):
                                stack.append(Path(entry.path))
                            continue
                        stack.append(Path(entry.path))
                        if self.configured_ignore_has_descendant(rel):
                            continue
                    elif self.ignored_path(rel):
                        continue
                    if len(observed) >= MAX_OBSERVED_FILES:
                        complete = False
                        stack.clear()
                        break
                    observed[rel] = FileState(
                        kind=kind,
                        mtime_ns=stat.st_mtime_ns,
                        size=stat.st_size,
                        symlink_target=target,
                    )
        return FilesystemSnapshot(
            states=dict(sorted(observed.items())),
            complete=complete,
            entries_inspected=inspected,
        )

    def changed_paths(
        self,
        baseline: dict[str, FileState],
        current: dict[str, FileState],
    ) -> list[str]:
        paths = set(baseline) | set(current)
        changed = []
        for path in sorted(paths):
            before = baseline.get(path)
            after = current.get(path)
            escaping_symlink = (
                after is not None
                and after.kind == "symlink"
                and self.symlink_escapes(path, after.symlink_target or "")
            )
            if self.ignored_path(path) and not escaping_symlink:
                continue
            if before != after:
                changed.append(path)
        return changed

    def ignored_path(self, path: str, *, is_directory: bool = False) -> bool:
        if self.built_in_ignored_path(path):
            return True
        return self.configured_ignored_path(path, is_directory=is_directory)

    def built_in_ignored_path(self, path: str) -> bool:
        return any(part in IGNORED_DIR_NAMES for part in Path(path).parts)

    def configured_ignored_path(
        self,
        path: str,
        *,
        is_directory: bool = False,
    ) -> bool:
        if matching_patterns(path, self.guard_ignore_paths):
            return True
        if is_directory:
            return any(
                pattern.endswith("/**")
                and pattern[: -len("/**")].rstrip("/") == path.rstrip("/")
                for pattern in self.guard_ignore_paths
            )
        return False

    def tree_contains_escaping_symlink(
        self,
        directory: Path,
        relative_directory: str,
    ) -> bool:
        stack = [(directory, relative_directory)]
        inspected = 0
        while stack and inspected < MAX_OBSERVED_FILES:
            current, current_relative = stack.pop()
            try:
                entries = os.scandir(current)
            except OSError:
                return True
            with entries:
                for entry in entries:
                    inspected += 1
                    if inspected >= MAX_OBSERVED_FILES:
                        return True
                    relative = f"{current_relative}/{entry.name}"
                    try:
                        if entry.is_symlink():
                            try:
                                target = os.readlink(entry.path)
                            except OSError:
                                return True
                            if self.symlink_escapes(relative, target):
                                return True
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append((Path(entry.path), relative))
                    except OSError:
                        return True
        return bool(stack)

    def configured_ignore_has_descendant(self, path: str) -> bool:
        prefix = path.rstrip("/") + "/"
        return any(pattern.startswith(prefix) for pattern in self.guard_ignore_paths)

    def relative_path(self, path: Path) -> Optional[str]:
        try:
            return path.relative_to(self.repo_dir).as_posix()
        except ValueError:
            try:
                return path.resolve(strict=False).relative_to(self.repo_dir).as_posix()
            except ValueError:
                return None

    def symlink_escapes(self, path: str, target: str) -> bool:
        if not target:
            return False
        link_path = self.repo_dir / path
        resolved = (link_path.parent / target).resolve(strict=False)
        try:
            resolved.relative_to(self.repo_dir)
        except ValueError:
            return True
        return False


class PollingFilesystemWatcher:
    def __init__(
        self,
        *,
        scanner: FilesystemSnapshotScanner,
        source: str = "polling",
    ) -> None:
        self.scanner = scanner
        self.source = source
        self._previous: dict[str, FileState] = {}
        self._sequence = 0
        self._last_emitted_by_path: dict[str, str] = {}

    def start(self, baseline: dict[str, FileState]) -> None:
        self._previous = dict(baseline)
        self._sequence = 0
        self._last_emitted_by_path = {}

    def poll(self) -> FilesystemObservation:
        result = self.scanner.scan_snapshot()
        if not result.complete:
            return FilesystemObservation(
                snapshot=result.states,
                events=[],
                scan_complete=False,
            )
        events = self._events_for(self._previous, result.states)
        self._previous = result.states
        return FilesystemObservation(
            snapshot=result.states,
            events=events,
            scan_complete=result.complete,
        )

    def _events_for(
        self,
        before: dict[str, FileState],
        after: dict[str, FileState],
    ) -> list[FilesystemWatchEvent]:
        events: list[FilesystemWatchEvent] = []
        for path in self.scanner.changed_paths(before, after):
            before_state = before.get(path)
            after_state = after.get(path)
            event_type = _event_type(before_state, after_state)
            if event_type is None:
                continue
            if (
                event_type == "modified"
                and self._last_emitted_by_path.get(path) == event_type
            ):
                continue
            self._sequence += 1
            events.append(
                FilesystemWatchEvent(
                    path=path,
                    event_type=event_type,
                    observed_at_sequence=self._sequence,
                    source=self.source,
                )
            )
            self._last_emitted_by_path[path] = event_type
        return events


def _event_type(
    before: Optional[FileState],
    after: Optional[FileState],
) -> Optional[str]:
    if before is None and after is None:
        return None
    before_is_symlink = before is not None and before.kind == "symlink"
    after_is_symlink = after is not None and after.kind == "symlink"
    if before is None and after is not None:
        return "symlink_created" if after_is_symlink else "created"
    if before is not None and after is None:
        return "symlink_deleted" if before_is_symlink else "deleted"
    if before_is_symlink or after_is_symlink:
        return "symlink_modified"
    return "modified"


def normalize_watcher_mode(mode: str) -> FilesystemWatcherMode:
    return FilesystemWatcherMode(mode)
