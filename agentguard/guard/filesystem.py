import math
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from agentguard.config.schema import AgentGuardConfig
from agentguard.policy.path_matcher import matching_patterns


DEFAULT_POLL_INTERVAL_SECONDS = 0.2
DEFAULT_GRACEFUL_TIMEOUT_SECONDS = 0.5
MAX_OBSERVED_FILES = 20000
IGNORED_DIR_NAMES = {
    ".git",
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


class GuardMode(str, Enum):
    OFF = "off"
    AUDIT = "audit"
    ENFORCE = "enforce"


def validate_guard_configuration(
    guard_mode: GuardMode,
    guard_poll_interval_seconds: float,
) -> tuple[GuardMode, float]:
    if not isinstance(guard_mode, GuardMode):
        guard_mode = GuardMode(str(guard_mode))
    if (
        isinstance(guard_poll_interval_seconds, bool)
        or not isinstance(guard_poll_interval_seconds, (int, float))
        or not math.isfinite(guard_poll_interval_seconds)
        or guard_poll_interval_seconds <= 0
    ):
        raise ValueError(
            "guard_poll_interval_seconds must be a finite positive number."
        )
    return guard_mode, float(guard_poll_interval_seconds)


@dataclass(frozen=True)
class FileState:
    kind: str
    mtime_ns: int
    size: int
    symlink_target: Optional[str] = None


@dataclass(frozen=True)
class LiveGuardViolation:
    violation_type: str
    path: str
    message: str
    action: str
    observed_at: float


@dataclass(frozen=True)
class LiveGuardSummary:
    mode: str = GuardMode.OFF.value
    triggered: bool = False
    first_violation_time: Optional[float] = None
    violations: list[LiveGuardViolation] = field(default_factory=list)
    files_observed: int = 0
    scan_count: int = 0
    monitor_duration_seconds: float = 0.0
    terminated_agent: bool = False
    kill_required: bool = False
    graceful_timeout_seconds: float = DEFAULT_GRACEFUL_TIMEOUT_SECONDS


class ProcessController:
    def __init__(
        self,
        *,
        graceful_timeout_seconds: float = DEFAULT_GRACEFUL_TIMEOUT_SECONDS,
    ) -> None:
        self.graceful_timeout_seconds = graceful_timeout_seconds
        self._lock = threading.Lock()
        self._process: Optional[subprocess.Popen] = None
        self.termination_requested = False
        self.kill_required = False
        self.termination_reason: Optional[str] = None

    def attach(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._process = process
            if self.termination_requested:
                self._terminate_locked()

    def request_termination(self, reason: str) -> None:
        with self._lock:
            if self.termination_requested:
                return
            self.termination_requested = True
            self.termination_reason = reason
            self._terminate_locked()

    def _terminate_locked(self) -> None:
        process = self._process
        if process is None or process.poll() is not None:
            return
        process.terminate()
        deadline = time.monotonic() + self.graceful_timeout_seconds
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if process.poll() is None:
            self.kill_required = True
            process.kill()


class RuntimeFilesystemGuard:
    def __init__(
        self,
        *,
        repo_dir: Path,
        config: AgentGuardConfig,
        mode: GuardMode,
        process_controller: Optional[ProcessController] = None,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        self.repo_dir = repo_dir.expanduser().resolve()
        self.config = config
        self.mode = mode
        self.process_controller = process_controller
        self.poll_interval_seconds = poll_interval_seconds
        self.time_source = time_source
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._baseline: dict[str, FileState] = {}
        self._summary = LiveGuardSummary(mode=mode.value)
        self._start_time: Optional[float] = None

    def start(self) -> None:
        if self.mode == GuardMode.OFF:
            return
        self._baseline = self._scan_tree()
        self._start_time = self.time_source()
        self._thread = threading.Thread(
            target=self._run,
            name="agentguard-filesystem-guard",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> LiveGuardSummary:
        if self.mode == GuardMode.OFF:
            return self._summary
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(self.poll_interval_seconds * 4, 1.0))
        return self.summary()

    def scan_once(self) -> list[LiveGuardViolation]:
        current = self._scan_tree()
        violations = self._violations_for_diff(current)
        self._record_scan(current, violations)
        return violations

    def summary(self) -> LiveGuardSummary:
        with self._lock:
            return self._summary

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval_seconds):
            self.scan_once()
            if self.summary().terminated_agent:
                return

    def _record_scan(
        self,
        current: dict[str, FileState],
        violations: list[LiveGuardViolation],
    ) -> None:
        with self._lock:
            existing = list(self._summary.violations)
            known = {(item.violation_type, item.path) for item in existing}
            new_violations = [
                item
                for item in violations
                if (item.violation_type, item.path) not in known
            ]
            all_violations = [*existing, *new_violations]
            triggered = bool(all_violations)
            first = self._summary.first_violation_time
            if first is None and new_violations:
                first = new_violations[0].observed_at
            terminated = self._summary.terminated_agent
            if (
                self.mode == GuardMode.ENFORCE
                and new_violations
                and self.process_controller is not None
            ):
                terminated = True
                first_violation = new_violations[0]
                self.process_controller.request_termination(
                    f"Online filesystem guard: {first_violation.message}"
                )
            duration = self._elapsed_seconds()
            self._summary = LiveGuardSummary(
                mode=self.mode.value,
                triggered=triggered,
                first_violation_time=first,
                violations=all_violations,
                files_observed=max(self._summary.files_observed, len(current)),
                scan_count=self._summary.scan_count + 1,
                monitor_duration_seconds=duration,
                terminated_agent=terminated,
                kill_required=(
                    self.process_controller.kill_required
                    if self.process_controller is not None
                    else False
                ),
                graceful_timeout_seconds=(
                    self.process_controller.graceful_timeout_seconds
                    if self.process_controller is not None
                    else DEFAULT_GRACEFUL_TIMEOUT_SECONDS
                ),
            )

    def _scan_tree(self) -> dict[str, FileState]:
        observed: dict[str, FileState] = {}
        stack = [self.repo_dir]
        while stack and len(observed) < MAX_OBSERVED_FILES:
            directory = stack.pop()
            try:
                entries = list(os.scandir(directory))
            except OSError:
                continue
            for entry in entries:
                if len(observed) >= MAX_OBSERVED_FILES:
                    break
                if entry.name in IGNORED_FILE_NAMES:
                    continue
                rel = self._relative_path(Path(entry.path))
                if rel is None or self._ignored_path(rel):
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
                elif is_dir:
                    kind = "directory"
                    if entry.name not in IGNORED_DIR_NAMES:
                        stack.append(Path(entry.path))
                observed[rel] = FileState(
                    kind=kind,
                    mtime_ns=stat.st_mtime_ns,
                    size=stat.st_size,
                    symlink_target=target,
                )
        return observed

    def _violations_for_diff(
        self,
        current: dict[str, FileState],
    ) -> list[LiveGuardViolation]:
        violations: list[LiveGuardViolation] = []
        changed = self._changed_paths(current)
        for path in changed:
            state = current.get(path)
            previous = self._baseline.get(path)
            change = "deleted" if state is None else "changed"
            if matching_patterns(path, self.config.forbidden_paths):
                violations.append(
                    self._violation(
                        "forbidden_path",
                        path,
                        f"Forbidden path {change}: {path}",
                    )
                )
            if matching_patterns(path, self.config.test_paths):
                violations.append(
                    self._violation(
                        "test_tampering",
                        path,
                        f"Test path {change}: {path}",
                    )
                )
            if not matching_patterns(path, self.config.allowed_paths):
                violations.append(
                    self._violation(
                        "out_of_scope_path",
                        path,
                        f"Path outside allowed scope {change}: {path}",
                    )
                )
            secret_patterns = matching_patterns(path, self.config.secret_patterns)
            for pattern in secret_patterns:
                violations.append(
                    self._violation(
                        "secret_like_path",
                        path,
                        f"Secret-like path matched {pattern}: {path}",
                    )
                )
            if state is None and previous is not None and previous.kind == "file":
                violations.append(
                    self._violation(
                        "protected_deletion",
                        path,
                        f"Existing file deleted during agent execution: {path}",
                    )
                )
            if state is not None and state.kind == "symlink":
                target = state.symlink_target or ""
                if self._symlink_escapes(path, target):
                    violations.append(
                        self._violation(
                            "symlink_escape",
                            path,
                            f"Symlink escapes workspace: {path}",
                        )
                    )
        if (
            self.config.diff_limits.max_files_changed is not None
            and len(changed) > self.config.diff_limits.max_files_changed
        ):
            violations.append(
                self._violation(
                    "diff_size",
                    "(workspace)",
                    "Changed "
                    f"{len(changed)} files; live limit is "
                    f"{self.config.diff_limits.max_files_changed}.",
                )
            )
        return violations

    def _changed_paths(self, current: dict[str, FileState]) -> list[str]:
        paths = set(self._baseline) | set(current)
        changed = []
        for path in sorted(paths):
            if self._ignored_path(path):
                continue
            before = self._baseline.get(path)
            after = current.get(path)
            if before != after:
                changed.append(path)
        return changed

    def _violation(
        self,
        violation_type: str,
        path: str,
        message: str,
    ) -> LiveGuardViolation:
        action = (
            "terminated"
            if self.mode == GuardMode.ENFORCE and self.process_controller is not None
            else "recorded"
        )
        return LiveGuardViolation(
            violation_type=violation_type,
            path=path,
            message=message,
            action=action,
            observed_at=self._elapsed_seconds(),
        )

    def _elapsed_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        return self.time_source() - self._start_time

    def _ignored_path(self, path: str) -> bool:
        parts = Path(path).parts
        return any(part in IGNORED_DIR_NAMES for part in parts)

    def _relative_path(self, path: Path) -> Optional[str]:
        try:
            return path.relative_to(self.repo_dir).as_posix()
        except ValueError:
            try:
                return path.resolve(strict=False).relative_to(self.repo_dir).as_posix()
            except ValueError:
                return None

    def _symlink_escapes(self, path: str, target: str) -> bool:
        if not target:
            return False
        link_path = self.repo_dir / path
        resolved = (link_path.parent / target).resolve(strict=False)
        try:
            resolved.relative_to(self.repo_dir)
        except ValueError:
            return True
        return False
