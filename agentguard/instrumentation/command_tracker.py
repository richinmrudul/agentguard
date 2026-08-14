from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional, Union

from agentguard.sandbox.docker_identity import DockerImageIdentity

from agentguard.io import atomic_write_json


MAX_EXTENDED_COMMAND_EVENTS = 201


@dataclass
class CommandEvent:
    command: list[str]
    command_text: str
    cwd: str
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_seconds: Optional[float]
    executed: bool
    blocked: bool
    reason: Optional[str]
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    preflight_blocked: bool = False
    preflight_matched_patterns: list[str] = field(default_factory=list)
    policy_mode: Optional[str] = None
    agent_name: Optional[str] = None
    process_cleanup_attempted: bool = False
    process_cleanup_complete: bool = True
    process_cleanup_message: Optional[str] = None
    docker_image: Optional[DockerImageIdentity] = None


@dataclass
class CommandTracker:
    _events: list[CommandEvent] = field(default_factory=list)

    def record(self, command: str) -> None:
        self.record_blocked_or_simulated(
            command=[command],
            command_text=command,
            cwd="",
            blocked=False,
            reason=None,
        )

    @property
    def events(self) -> list[CommandEvent]:
        return list(self._events)

    @property
    def commands(self) -> list[str]:
        return [event.command_text for event in self._events]

    def extend(self, events: list[CommandEvent]) -> None:
        self._events.extend(events[:MAX_EXTENDED_COMMAND_EVENTS])

    def record_executed(
        self,
        command: list[str],
        command_text: str,
        cwd: Path,
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_seconds: float,
        timed_out: bool = False,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
        preflight_matched_patterns: Optional[list[str]] = None,
        policy_mode: Optional[str] = None,
        agent_name: Optional[str] = None,
        process_cleanup_attempted: bool = False,
        process_cleanup_complete: bool = True,
        process_cleanup_message: Optional[str] = None,
        docker_image: Optional[DockerImageIdentity] = None,
    ) -> CommandEvent:
        event = CommandEvent(
            command=command,
            command_text=command_text,
            cwd=str(cwd),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_seconds=duration_seconds,
            executed=True,
            blocked=False,
            reason=None,
            timed_out=timed_out,
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            preflight_matched_patterns=preflight_matched_patterns or [],
            policy_mode=policy_mode,
            agent_name=agent_name,
            process_cleanup_attempted=process_cleanup_attempted,
            process_cleanup_complete=process_cleanup_complete,
            process_cleanup_message=process_cleanup_message,
            docker_image=docker_image,
        )
        self._events.append(event)
        return event

    def record_preflight_blocked(
        self,
        command: list[str],
        command_text: str,
        cwd: Union[Path, str],
        matched_patterns: list[str],
        policy_mode: str,
        message: str,
        agent_name: Optional[str] = None,
    ) -> CommandEvent:
        event = CommandEvent(
            command=command,
            command_text=command_text,
            cwd=str(cwd),
            exit_code=126,
            stdout="",
            stderr=message,
            duration_seconds=0.0,
            executed=False,
            blocked=True,
            reason=message,
            preflight_blocked=True,
            preflight_matched_patterns=matched_patterns,
            policy_mode=policy_mode,
            agent_name=agent_name,
        )
        self._events.append(event)
        return event

    def record_blocked_or_simulated(
        self,
        command: list[str],
        command_text: str,
        cwd: Union[Path, str],
        blocked: bool,
        reason: Optional[str],
    ) -> CommandEvent:
        event = CommandEvent(
            command=command,
            command_text=command_text,
            cwd=str(cwd),
            exit_code=None,
            stdout="",
            stderr="",
            duration_seconds=None,
            executed=False,
            blocked=blocked,
            reason=reason,
        )
        self._events.append(event)
        return event

    def write_json(self, run_dir: Path) -> Path:
        path = run_dir / "command_log.json"
        atomic_write_json(path, [asdict(event) for event in self._events])
        return path
