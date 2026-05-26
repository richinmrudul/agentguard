import json
import shlex
from pathlib import Path
from typing import Any, Optional

from agentguard.instrumentation.command_tracker import CommandEvent


DEFAULT_AGENT_EVENT_FILE = ".agentguard_agent_events.jsonl"


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

    command = _string_list(data.get("command"))
    if command is None:
        command = shlex.split(command_text)

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


def read_agent_events(
    repo_dir: Path,
    event_file_name: str = DEFAULT_AGENT_EVENT_FILE,
) -> list[CommandEvent]:
    event_path = repo_dir / event_file_name
    if not event_path.exists():
        return []

    events: list[CommandEvent] = []
    with event_path.open("r", encoding="utf-8") as file:
        for line in file:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                # Cooperative instrumentation should not be able to crash the run.
                continue
            if not isinstance(data, dict):
                continue
            if data.get("type") != "command_attempt":
                continue
            event = _command_attempt_event(data, repo_dir)
            if event is not None:
                events.append(event)
    return events
