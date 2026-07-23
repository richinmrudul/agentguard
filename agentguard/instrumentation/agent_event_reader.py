import json
import os
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from agentguard.instrumentation.command_tracker import CommandEvent


DEFAULT_AGENT_EVENT_FILE = ".agentguard_agent_events.jsonl"
MAX_AGENT_EVENT_BYTES = 1024 * 1024
MAX_AGENT_EVENT_LINE_BYTES = 8192
MAX_AGENT_EVENTS = 200
AGENT_EVENT_READ_CHUNK_BYTES = 8192
INSTRUMENTATION_INCOMPLETE = "Agent event instrumentation incomplete"


@dataclass(frozen=True)
class AgentEventBatch:
    events: list[dict[str, object]]
    diagnostic: Optional[str] = None
    events_dropped: int = 0


def _safe_event_path(repo_dir: Path, event_file_name: str) -> Optional[Path]:
    if (
        not event_file_name
        or "/" in event_file_name
        or "\\" in event_file_name
        or any(ord(character) < 32 for character in event_file_name)
    ):
        return None
    name = Path(event_file_name)
    if name.is_absolute() or name.name != event_file_name:
        return None
    return repo_dir / name


def _open_regular_file(path: Path) -> tuple[Optional[int], Optional[str]]:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, f"{INSTRUMENTATION_INCOMPLETE}: event source is unavailable."
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        return (
            None,
            f"{INSTRUMENTATION_INCOMPLETE}: event source is not a regular file.",
        )

    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None, f"{INSTRUMENTATION_INCOMPLETE}: event source was rejected."

    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
        identities = {
            (before.st_dev, before.st_ino),
            (opened.st_dev, opened.st_ino),
            (after.st_dev, after.st_ino),
        }
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(after.st_mode)
            or opened.st_nlink != 1
            or after.st_nlink != 1
            or len(identities) != 1
        ):
            raise ValueError
    except (OSError, ValueError):
        os.close(descriptor)
        return (
            None,
            f"{INSTRUMENTATION_INCOMPLETE}: event source changed while opening.",
        )
    return descriptor, None


class AgentEventStreamReader:
    def __init__(
        self,
        repo_dir: Path,
        event_file_name: str = DEFAULT_AGENT_EVENT_FILE,
        *,
        max_total_bytes: int = MAX_AGENT_EVENT_BYTES,
        max_line_bytes: int = MAX_AGENT_EVENT_LINE_BYTES,
        max_events: int = MAX_AGENT_EVENTS,
    ) -> None:
        self.repo_dir = repo_dir.expanduser().resolve()
        self.event_path = _safe_event_path(self.repo_dir, event_file_name)
        self.max_total_bytes = max_total_bytes
        self.max_line_bytes = max_line_bytes
        self.max_events = max_events
        self.offset = 0
        self.total_bytes = 0
        self.events_observed = 0
        self.events_dropped = 0
        self.partial_line_bytes = 0
        self._line = bytearray()
        self._discarding_line = False
        self._source_identity: Optional[tuple[int, int]] = None
        self._diagnostic: Optional[str] = None
        self._terminal = False

    def read_new(self, *, finalize: bool = False) -> AgentEventBatch:
        if self._terminal:
            return self._batch([])
        if self.event_path is None:
            self._fail(
                f"{INSTRUMENTATION_INCOMPLETE}: event file name is not portable."
            )
            return self._batch([])

        descriptor, diagnostic = _open_regular_file(self.event_path)
        if descriptor is None:
            if diagnostic is not None:
                self._fail(diagnostic)
            return self._batch([])

        events: list[dict[str, object]] = []
        try:
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
            if self._source_identity is None:
                self._source_identity = identity
            elif self._source_identity != identity or opened.st_size < self.offset:
                self._fail(
                    f"{INSTRUMENTATION_INCOMPLETE}: event source was replaced."
                )
                return self._batch(events)

            os.lseek(descriptor, self.offset, os.SEEK_SET)
            while not self._terminal:
                remaining = self.max_total_bytes - self.total_bytes
                if remaining <= 0:
                    if opened.st_size > self.offset:
                        self._fail(
                            f"{INSTRUMENTATION_INCOMPLETE}: total byte limit exceeded."
                        )
                    break
                chunk = os.read(
                    descriptor,
                    min(AGENT_EVENT_READ_CHUNK_BYTES, remaining),
                )
                if not chunk:
                    break
                self.offset += len(chunk)
                self.total_bytes += len(chunk)
                self._consume(chunk, events)

            if (
                not self._terminal
                and self.total_bytes >= self.max_total_bytes
                and opened.st_size > self.offset
            ):
                self._fail(
                    f"{INSTRUMENTATION_INCOMPLETE}: total byte limit exceeded."
                )
            if finalize and not self._terminal and self._line:
                self._complete_line(events)
        except OSError:
            self._fail(f"{INSTRUMENTATION_INCOMPLETE}: event source read failed.")
        finally:
            os.close(descriptor)
        return self._batch(events)

    def _consume(
        self,
        chunk: bytes,
        events: list[dict[str, object]],
    ) -> None:
        start = 0
        while start < len(chunk) and not self._terminal:
            newline = chunk.find(b"\n", start)
            complete = newline >= 0
            end = newline if complete else len(chunk)
            fragment = chunk[start:end]
            self._append_fragment(fragment, complete, events)
            start = end + 1 if complete else end

    def _append_fragment(
        self,
        fragment: bytes,
        complete: bool,
        events: list[dict[str, object]],
    ) -> None:
        if self._discarding_line:
            if complete:
                self._discarding_line = False
            return
        if len(self._line) + len(fragment) > self.max_line_bytes:
            self._line.clear()
            self.partial_line_bytes = 0
            self._discarding_line = not complete
            self._note(
                f"{INSTRUMENTATION_INCOMPLETE}: event line byte limit exceeded."
            )
            return
        self._line.extend(fragment)
        self.partial_line_bytes = len(self._line)
        if complete:
            self._complete_line(events)

    def _complete_line(self, events: list[dict[str, object]]) -> None:
        line = bytes(self._line)
        self._line.clear()
        self.partial_line_bytes = 0
        if not line:
            return
        try:
            data = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(data, dict) or data.get("type") != "command_attempt":
            return
        if self.events_observed >= self.max_events:
            self.events_dropped += 1
            self._fail(f"{INSTRUMENTATION_INCOMPLETE}: event count limit exceeded.")
            return
        self.events_observed += 1
        events.append(data)

    def _note(self, diagnostic: str) -> None:
        if self._diagnostic is None:
            self._diagnostic = diagnostic

    def _fail(self, diagnostic: str) -> None:
        self._note(diagnostic)
        self._terminal = True
        self._line.clear()
        self.partial_line_bytes = 0

    def _batch(self, events: list[dict[str, object]]) -> AgentEventBatch:
        return AgentEventBatch(
            events=events,
            diagnostic=self._diagnostic,
            events_dropped=self.events_dropped,
        )


def _string_list(value: Any) -> Optional[list[str]]:
    if not isinstance(value, list):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return value


def _command_attempt_event(
    data: dict[str, Any],
    repo_dir: Path,
) -> Optional[CommandEvent]:
    command_text = data.get("command_text")
    if not isinstance(command_text, str) or not command_text:
        return None

    if "command" in data:
        command = _string_list(data["command"])
        if command is None:
            return None
    else:
        try:
            command = shlex.split(command_text)
        except ValueError:
            return None

    blocked = data.get("blocked", False)
    if not isinstance(blocked, bool):
        blocked = False

    reason = data.get("reason")
    if reason is not None and not isinstance(reason, str):
        reason = None

    return CommandEvent(
        command=command,
        command_text=command_text,
        cwd=str(repo_dir),
        exit_code=None,
        stdout="",
        stderr="",
        duration_seconds=None,
        executed=not blocked,
        blocked=blocked,
        reason=reason,
    )


def _diagnostic_event(repo_dir: Path, diagnostic: str) -> CommandEvent:
    return CommandEvent(
        command=[],
        command_text=INSTRUMENTATION_INCOMPLETE,
        cwd=str(repo_dir),
        exit_code=None,
        stdout="",
        stderr="",
        duration_seconds=None,
        executed=False,
        blocked=False,
        reason=diagnostic,
    )


def read_agent_events(
    repo_dir: Path,
    event_file_name: str = DEFAULT_AGENT_EVENT_FILE,
) -> list[CommandEvent]:
    batch = AgentEventStreamReader(repo_dir, event_file_name).read_new(finalize=True)
    events = [
        event
        for data in batch.events
        if (event := _command_attempt_event(data, repo_dir)) is not None
    ]
    if batch.diagnostic is not None:
        events.append(_diagnostic_event(repo_dir, batch.diagnostic))
    return events
