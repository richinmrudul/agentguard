import json
from pathlib import Path

from agentguard.instrumentation.agent_event_reader import read_agent_events


def test_missing_agent_event_file_returns_empty_list(tmp_path: Path) -> None:
    assert read_agent_events(tmp_path) == []


def test_valid_blocked_command_attempt_becomes_command_event(tmp_path: Path) -> None:
    event_file = tmp_path / ".agentguard_agent_events.jsonl"
    event_file.write_text(
        json.dumps(
            {
                "type": "command_attempt",
                "command": ["rm", "-rf", "important_data"],
                "command_text": "rm -rf important_data",
                "blocked": True,
                "reason": "Unsafe command attempt reported by custom agent",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = read_agent_events(tmp_path)

    assert len(events) == 1
    assert events[0].command == ["rm", "-rf", "important_data"]
    assert events[0].command_text == "rm -rf important_data"
    assert events[0].blocked is True
    assert events[0].executed is False
    assert events[0].exit_code is None
    assert events[0].cwd == str(tmp_path)
    assert events[0].reason == "Unsafe command attempt reported by custom agent"


def test_missing_command_list_uses_shlex_split(tmp_path: Path) -> None:
    (tmp_path / ".agentguard_agent_events.jsonl").write_text(
        json.dumps(
            {
                "type": "command_attempt",
                "command_text": "python -m pytest -q",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = read_agent_events(tmp_path)

    assert events[0].command == ["python", "-m", "pytest", "-q"]
    assert events[0].executed is True
    assert events[0].blocked is False


def test_malformed_json_line_is_ignored(tmp_path: Path) -> None:
    (tmp_path / ".agentguard_agent_events.jsonl").write_text(
        "{not json}\n"
        + json.dumps(
            {
                "type": "command_attempt",
                "command_text": "echo ok",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = read_agent_events(tmp_path)

    assert [event.command_text for event in events] == ["echo ok"]


def test_unsupported_event_type_is_ignored(tmp_path: Path) -> None:
    (tmp_path / ".agentguard_agent_events.jsonl").write_text(
        json.dumps({"type": "note", "message": "hello"}) + "\n",
        encoding="utf-8",
    )

    assert read_agent_events(tmp_path) == []
