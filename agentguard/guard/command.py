import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from agentguard.config.schema import AgentGuardConfig
from agentguard.guard.filesystem import (
    DEFAULT_GRACEFUL_TIMEOUT_SECONDS,
    DEFAULT_POLL_INTERVAL_SECONDS,
    GuardMode,
    ProcessController,
)
from agentguard.instrumentation.agent_event_reader import (
    DEFAULT_AGENT_EVENT_FILE,
    AgentEventStreamReader,
)
from agentguard.policy.command_policy import evaluate_command_policy


MAX_RETAINED_COMMAND_VIOLATIONS = 100


@dataclass(frozen=True)
class CommandGuardViolation:
    violation_type: str
    command_text: str
    matched_patterns: list[str]
    message: str
    action: str
    observed_at: float


@dataclass(frozen=True)
class CommandGuardSummary:
    mode: str = GuardMode.OFF.value
    triggered: bool = False
    first_violation_time: Optional[float] = None
    violations: list[CommandGuardViolation] = field(default_factory=list)
    events_observed: int = 0
    scan_count: int = 0
    monitor_duration_seconds: float = 0.0
    terminated_agent: bool = False
    kill_required: bool = False
    graceful_timeout_seconds: float = DEFAULT_GRACEFUL_TIMEOUT_SECONDS
    event_file: str = DEFAULT_AGENT_EVENT_FILE
    instrumentation_incomplete: bool = False
    instrumentation_diagnostic: Optional[str] = None
    events_dropped: int = 0
    violations_dropped: int = 0


class RuntimeCommandGuard:
    def __init__(
        self,
        *,
        repo_dir: Path,
        config: AgentGuardConfig,
        mode: GuardMode,
        process_controller: Optional[ProcessController] = None,
        poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
        event_file_name: str = DEFAULT_AGENT_EVENT_FILE,
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        self.repo_dir = repo_dir.expanduser().resolve()
        self.config = config
        self.mode = mode
        self.process_controller = process_controller
        self.poll_interval_seconds = poll_interval_seconds
        self.event_file_name = event_file_name
        self.time_source = time_source
        self._reader = AgentEventStreamReader(
            self.repo_dir,
            event_file_name,
        )
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._summary = CommandGuardSummary(
            mode=mode.value,
            event_file=event_file_name,
        )
        self._start_time: Optional[float] = None

    def start(self) -> None:
        if self.mode == GuardMode.OFF:
            return
        self._start_time = self.time_source()
        self._thread = threading.Thread(
            target=self._run,
            name="agentguard-command-guard",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> CommandGuardSummary:
        if self.mode == GuardMode.OFF:
            return self._summary
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(self.poll_interval_seconds * 4, 1.0))
        self.scan_once()
        return self.summary()

    def scan_once(self) -> list[CommandGuardViolation]:
        batch = self._reader.read_new()
        events = batch.events
        violations = self._violations_for_events(events)
        self._record_scan(
            len(events),
            violations,
            instrumentation_diagnostic=batch.diagnostic,
            events_dropped=batch.events_dropped,
        )
        return violations

    def summary(self) -> CommandGuardSummary:
        with self._lock:
            return self._summary

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval_seconds):
            self.scan_once()
            if self.summary().terminated_agent:
                return

    def _violations_for_events(
        self,
        events: list[dict[str, object]],
    ) -> list[CommandGuardViolation]:
        violations: list[CommandGuardViolation] = []
        for event in events:
            command_text = event.get("command_text")
            if not isinstance(command_text, str) or not command_text:
                continue
            decision = evaluate_command_policy(
                command_text=command_text,
                unsafe_patterns=self.config.unsafe_commands,
                mode="audit",
            )
            if not decision.matched_patterns:
                continue
            action = (
                "terminated"
                if self.mode == GuardMode.ENFORCE
                else "recorded"
            )
            patterns = ", ".join(decision.matched_patterns)
            violations.append(
                CommandGuardViolation(
                    violation_type="unsafe_command",
                    command_text=command_text,
                    matched_patterns=decision.matched_patterns,
                    message=(
                        "Unsafe command event observed live: "
                        f"{patterns}"
                    ),
                    action=action,
                    observed_at=self._elapsed_seconds(),
                )
            )
        return violations

    def _record_scan(
        self,
        event_count: int,
        violations: list[CommandGuardViolation],
        *,
        instrumentation_diagnostic: Optional[str],
        events_dropped: int,
    ) -> None:
        with self._lock:
            existing = list(self._summary.violations)
            known = {
                (item.violation_type, item.command_text, tuple(item.matched_patterns))
                for item in existing
            }
            candidate_violations = [
                item
                for item in violations
                if (
                    item.violation_type,
                    item.command_text,
                    tuple(item.matched_patterns),
                )
                not in known
            ]
            available = max(
                0,
                MAX_RETAINED_COMMAND_VIOLATIONS - len(existing),
            )
            new_violations = candidate_violations[:available]
            violations_dropped = (
                self._summary.violations_dropped
                + len(candidate_violations)
                - len(new_violations)
            )
            all_violations = [*existing, *new_violations]
            triggered = bool(all_violations or candidate_violations)
            first = self._summary.first_violation_time
            if first is None and candidate_violations:
                first = candidate_violations[0].observed_at
            terminated = self._summary.terminated_agent
            if (
                self.mode == GuardMode.ENFORCE
                and candidate_violations
                and self.process_controller is not None
            ):
                terminated = True
                self.process_controller.request_termination(
                    f"Online command guard: {candidate_violations[0].message}"
                )
            self._summary = CommandGuardSummary(
                mode=self.mode.value,
                triggered=triggered,
                first_violation_time=first,
                violations=all_violations,
                events_observed=self._summary.events_observed + event_count,
                scan_count=self._summary.scan_count + 1,
                monitor_duration_seconds=self._elapsed_seconds(),
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
                event_file=self.event_file_name,
                instrumentation_incomplete=instrumentation_diagnostic is not None,
                instrumentation_diagnostic=instrumentation_diagnostic,
                events_dropped=events_dropped,
                violations_dropped=violations_dropped,
            )

    def _elapsed_seconds(self) -> float:
        if self._start_time is None:
            return 0.0
        return max(0.0, self.time_source() - self._start_time)
