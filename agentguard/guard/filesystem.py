import math
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from agentguard.checks.secret_content import (
    MAX_SECRET_SCAN_BYTES_PER_FILE,
    MAX_SECRET_SCAN_FILES,
    MAX_SECRET_SCAN_LINE_BYTES,
    MAX_SECRET_SCAN_MATCHES,
    MAX_SECRET_SCAN_MATCHES_PER_DETECTOR_FILE,
    MAX_SECRET_SCAN_TOTAL_BYTES,
    SecretContentMatch,
    match_secret_content_line,
)
from agentguard.config.schema import AgentGuardConfig
from agentguard.guard.watcher import (
    FileState,
    FilesystemSnapshotScanner,
    FilesystemWatchEvent,
    FilesystemWatcherMode,
    PollingFilesystemWatcher,
)
from agentguard.instrumentation.processes import (
    ProcessCleanupResult,
    terminate_process_tree,
)
from agentguard.policy.path_matcher import matching_patterns
from agentguard.repo.live_diff import (
    LiveDiffCandidate,
    LiveLineMeasurement,
    measure_live_line_diff,
    resolve_live_diff_baseline,
)


DEFAULT_POLL_INTERVAL_SECONDS = 0.2
DEFAULT_GRACEFUL_TIMEOUT_SECONDS = 0.5
MAX_RETAINED_WATCHER_EVENTS = 200


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
    configured_ignore_patterns: list[str] = field(default_factory=list)
    live_lines_added: int = 0
    live_lines_deleted: int = 0
    line_measurement_complete: bool = True
    line_measurement_skipped_files: int = 0
    line_measurement_error: Optional[str] = None
    watcher_mode: str = FilesystemWatcherMode.AUTO.value
    watcher_events_observed: int = 0
    watcher_events: list[FilesystemWatchEvent] = field(default_factory=list)
    watcher_event_limit_exceeded: bool = False
    watcher_event_error: Optional[str] = None


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
        self._cleanup_result = ProcessCleanupResult()
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

    def termination_cleanup_result(self) -> ProcessCleanupResult:
        with self._lock:
            return self._cleanup_result

    def _terminate_locked(self) -> None:
        process = self._process
        if process is None:
            return
        self._cleanup_result = terminate_process_tree(
            process,
            terminate_timeout_seconds=self.graceful_timeout_seconds,
        )
        self.kill_required = self._cleanup_result.kill_required


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
        line_measurer: Callable[..., LiveLineMeasurement] = measure_live_line_diff,
    ) -> None:
        self.repo_dir = repo_dir.expanduser().resolve()
        self.config = config
        self.mode = mode
        self.process_controller = process_controller
        self.poll_interval_seconds = poll_interval_seconds
        self.time_source = time_source
        self.line_measurer = line_measurer
        has_line_limits = (
            config.diff_limits.max_lines_added is not None
            or config.diff_limits.max_lines_deleted is not None
        )
        self._line_baseline_ref = (
            resolve_live_diff_baseline(self.repo_dir)
            if has_line_limits
            else None
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._scanner = FilesystemSnapshotScanner(
            repo_dir=self.repo_dir,
            guard_ignore_paths=list(config.guard_ignore_paths),
        )
        self._watcher_mode = FilesystemWatcherMode(config.filesystem_watcher.mode)
        self._watcher = (
            PollingFilesystemWatcher(scanner=self._scanner)
            if self._watcher_mode
            in {FilesystemWatcherMode.AUTO, FilesystemWatcherMode.POLLING}
            else None
        )
        self._baseline: dict[str, FileState] = {}
        self._baseline_secret_content_matches: set[tuple[str, int, str]] = set()
        self._secret_content_baseline_error: Optional[str] = None
        self._summary = LiveGuardSummary(
            mode=mode.value,
            configured_ignore_patterns=list(config.guard_ignore_paths),
            watcher_mode=self._watcher_mode.value,
        )
        self._start_time: Optional[float] = None

    def start(self) -> None:
        if self.mode == GuardMode.OFF:
            return
        self._baseline = self._scanner.snapshot()
        if self._watcher is not None:
            self._watcher.start(self._baseline)
        (
            self._baseline_secret_content_matches,
            self._secret_content_baseline_error,
        ) = self._scan_secret_content_baseline()
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
        if self._watcher is not None:
            observation = self._watcher.poll()
            current = observation.snapshot
            watcher_events = observation.events
        else:
            current = self._scanner.snapshot()
            watcher_events = []
        changed = self._scanner.changed_paths(self._baseline, current)
        line_measurement = self._measure_lines(current, changed)
        violations = self._violations_for_diff(
            current,
            changed=changed,
            line_measurement=line_measurement,
        )
        self._record_scan(current, violations, line_measurement, watcher_events)
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
        line_measurement: LiveLineMeasurement,
        watcher_events: list[FilesystemWatchEvent],
    ) -> None:
        with self._lock:
            existing = list(self._summary.violations)
            known = {
                (item.violation_type, item.path, item.message)
                for item in existing
            }
            new_violations = [
                item
                for item in violations
                if (item.violation_type, item.path, item.message) not in known
            ]
            all_violations = [*existing, *new_violations]
            triggered = bool(all_violations)
            first = self._summary.first_violation_time
            if first is None and new_violations:
                first = new_violations[0].observed_at
            previous_watcher_events = list(self._summary.watcher_events)
            candidate_watcher_events = [
                *previous_watcher_events,
                *watcher_events,
            ]
            watcher_limit_exceeded = (
                self._summary.watcher_event_limit_exceeded
                or len(candidate_watcher_events) > MAX_RETAINED_WATCHER_EVENTS
            )
            retained_watcher_events = candidate_watcher_events[
                :MAX_RETAINED_WATCHER_EVENTS
            ]
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
                configured_ignore_patterns=list(self.config.guard_ignore_paths),
                live_lines_added=line_measurement.lines_added,
                live_lines_deleted=line_measurement.lines_deleted,
                line_measurement_complete=line_measurement.complete,
                line_measurement_skipped_files=line_measurement.skipped_files,
                line_measurement_error=line_measurement.error,
                watcher_mode=self._watcher_mode.value,
                watcher_events_observed=(
                    self._summary.watcher_events_observed + len(watcher_events)
                ),
                watcher_events=retained_watcher_events,
                watcher_event_limit_exceeded=watcher_limit_exceeded,
                watcher_event_error=(
                    "filesystem watcher event limit exceeded"
                    if watcher_limit_exceeded
                    else None
                ),
            )

    def _violations_for_diff(
        self,
        current: dict[str, FileState],
        *,
        changed: Optional[list[str]] = None,
        line_measurement: Optional[LiveLineMeasurement] = None,
    ) -> list[LiveGuardViolation]:
        violations: list[LiveGuardViolation] = []
        changed = (
            changed
            if changed is not None
            else self._scanner.changed_paths(self._baseline, current)
        )
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
                if self._scanner.symlink_escapes(path, target):
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
        measurement = line_measurement or LiveLineMeasurement()
        if (
            self.config.diff_limits.max_lines_added is not None
            and measurement.lines_added
            > self.config.diff_limits.max_lines_added
        ):
            violations.append(
                self._violation(
                    "diff_lines_added",
                    "(workspace)",
                    f"Added {measurement.lines_added} lines; live limit is "
                    f"{self.config.diff_limits.max_lines_added}.",
                )
            )
        if (
            self.config.diff_limits.max_lines_deleted is not None
            and measurement.lines_deleted
            > self.config.diff_limits.max_lines_deleted
        ):
            violations.append(
                self._violation(
                    "diff_lines_deleted",
                    "(workspace)",
                    f"Deleted {measurement.lines_deleted} lines; live limit is "
                    f"{self.config.diff_limits.max_lines_deleted}.",
                )
            )
        violations.extend(self._secret_content_violations(current, changed))
        return violations

    def _secret_content_violations(
        self,
        current: dict[str, FileState],
        changed: list[str],
    ) -> list[LiveGuardViolation]:
        if not self.config.secret_content_patterns:
            return []
        candidates = [
            path
            for path in changed
            if (
                (state := current.get(path)) is not None
                and state.kind == "file"
            )
        ]
        matches, error = self._scan_secret_content_candidates(current, candidates)
        violations = [
            self._violation(
                "secret_content_detected",
                match.path,
                f"secret-content detector {match.detector_id} matched in "
                f"{match.path}"
                + (
                    f":{match.line_number}"
                    if match.line_number is not None
                    else ""
                ),
            )
            for match in matches
        ]
        if error is not None:
            violations.append(
                self._violation(
                    "secret_content_scan_incomplete",
                    "(workspace)",
                    f"secret-content live scan incomplete: {error}",
                )
            )
        return violations

    def _scan_secret_content_baseline(
        self,
    ) -> tuple[set[tuple[str, int, str]], Optional[str]]:
        if not self.config.secret_content_patterns:
            return set(), None
        paths = [
            path
            for path, state in self._baseline.items()
            if state.kind == "file"
        ]
        matches, error = self._scan_secret_content_candidates(
            self._baseline,
            paths,
            baseline_keys=set(),
        )
        return {
            (match.path, match.line_number or 0, match.detector_id)
            for match in matches
            if match.line_number is not None
        }, error

    def _scan_secret_content_candidates(
        self,
        states: dict[str, FileState],
        candidates: list[str],
        baseline_keys: Optional[set[tuple[str, int, str]]] = None,
    ) -> tuple[list[SecretContentMatch], Optional[str]]:
        baseline_keys = (
            self._baseline_secret_content_matches
            if baseline_keys is None
            else baseline_keys
        )
        selected = sorted(set(candidates))
        if len(selected) > MAX_SECRET_SCAN_FILES:
            return [], "candidate file limit exceeded"
        retained: list[SecretContentMatch] = []
        per_detector_file: dict[tuple[str, str], int] = {}
        total_bytes = 0
        omitted = 0
        for path in selected:
            state = states.get(path)
            if state is None or state.kind != "file":
                continue
            if state.size > MAX_SECRET_SCAN_BYTES_PER_FILE:
                return retained, "file byte limit exceeded"
            total_bytes += state.size
            if total_bytes > MAX_SECRET_SCAN_TOTAL_BYTES:
                return retained, "total byte limit exceeded"
            target = self.repo_dir / path
            try:
                file_stat = target.lstat()
                if target.is_symlink() or not target.is_file():
                    continue
                content = target.read_bytes()
            except OSError:
                return retained, "file content unavailable"
            if len(content) > MAX_SECRET_SCAN_BYTES_PER_FILE:
                return retained, "file byte limit exceeded"
            if b"\0" in content:
                continue
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                return retained, "text decoding unavailable"
            if file_stat.st_size != len(content):
                total_bytes += max(0, len(content) - state.size)
                if total_bytes > MAX_SECRET_SCAN_TOTAL_BYTES:
                    return retained, "total byte limit exceeded"
            for line_number, line in enumerate(text.splitlines(), start=1):
                if len(line.encode("utf-8")) > MAX_SECRET_SCAN_LINE_BYTES:
                    return retained, "line byte limit exceeded"
                for match in match_secret_content_line(
                    path=path,
                    line_number=line_number,
                    text=line,
                    patterns=self.config.secret_content_patterns,
                ):
                    key = (match.path, match.line_number or 0, match.detector_id)
                    if key in baseline_keys:
                        continue
                    detector_file = (match.path, match.detector_id)
                    count = per_detector_file.get(detector_file, 0)
                    if count >= MAX_SECRET_SCAN_MATCHES_PER_DETECTOR_FILE:
                        omitted += 1
                        continue
                    if len(retained) >= MAX_SECRET_SCAN_MATCHES:
                        omitted += 1
                        continue
                    per_detector_file[detector_file] = count + 1
                    retained.append(match)
        if omitted:
            return retained, "match limit exceeded"
        return retained, None

    def _measure_lines(
        self,
        current: dict[str, FileState],
        changed: list[str],
    ) -> LiveLineMeasurement:
        limits = self.config.diff_limits
        if (
            limits.max_lines_added is None
            and limits.max_lines_deleted is None
        ):
            return LiveLineMeasurement()
        candidates = []
        for path in changed:
            before = self._baseline.get(path)
            after = current.get(path)
            before_is_file = before is not None and before.kind == "file"
            after_is_file = after is not None and after.kind == "file"
            if not before_is_file and not after_is_file:
                continue
            candidates.append(
                LiveDiffCandidate(
                    path=path,
                    baseline_size=before.size if before_is_file else None,
                    current_size=after.size if after_is_file else None,
                )
            )
        if not candidates:
            return LiveLineMeasurement()
        try:
            return self.line_measurer(
                self.repo_dir,
                candidates,
                self._line_baseline_ref,
            )
        except Exception:
            return LiveLineMeasurement(
                complete=False,
                skipped_files=len(candidates),
                error="Line measurement incomplete: measurement unavailable.",
            )

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

    def _scan_tree(self) -> dict[str, FileState]:
        return self._scanner.snapshot()

    def _changed_paths(self, current: dict[str, FileState]) -> list[str]:
        return self._scanner.changed_paths(self._baseline, current)
