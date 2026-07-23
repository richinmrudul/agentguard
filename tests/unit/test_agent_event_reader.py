import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from agentguard.instrumentation.agent_event_reader import (
    INSTRUMENTATION_INCOMPLETE,
    AgentEventStreamReader,
    _open_regular_file,
    read_agent_events,
)
from agentguard.instrumentation.command_tracker import CommandTracker


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


def _event(command_text: str) -> str:
    return json.dumps(
        {"type": "command_attempt", "command_text": command_text}
    )


def test_symlink_event_source_is_rejected_without_following(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text(_event("AGENTGUARD_EVENT_CANARY_OUTSIDE") + "\n")
    event_path = tmp_path / ".agentguard_agent_events.jsonl"
    event_path.symlink_to(outside)

    events = read_agent_events(tmp_path)

    assert [event.command_text for event in events] == [INSTRUMENTATION_INCOMPLETE]
    assert "not a regular file" in (events[0].reason or "")
    assert "AGENTGUARD_EVENT_CANARY_OUTSIDE" not in repr(events)


def test_online_reader_rejects_symlink_replacement(tmp_path: Path) -> None:
    event_path = tmp_path / ".agentguard_agent_events.jsonl"
    event_path.write_text(_event("echo safe") + "\n")
    reader = AgentEventStreamReader(tmp_path)

    first = reader.read_new()
    event_path.unlink()
    outside = tmp_path / "outside.jsonl"
    outside.write_text(_event("AGENTGUARD_EVENT_CANARY_REPLACED") + "\n")
    event_path.symlink_to(outside)
    second = reader.read_new()

    assert [event["command_text"] for event in first.events] == ["echo safe"]
    assert second.events == []
    assert "not a regular file" in (second.diagnostic or "")
    assert "AGENTGUARD_EVENT_CANARY_REPLACED" not in repr(second)


def test_hard_linked_event_source_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside.jsonl"
    outside.write_text(_event("AGENTGUARD_EVENT_CANARY_HARDLINK") + "\n")
    os.link(outside, tmp_path / ".agentguard_agent_events.jsonl")

    events = read_agent_events(tmp_path)

    assert [event.command_text for event in events] == [INSTRUMENTATION_INCOMPLETE]
    assert "not a regular file" in (events[0].reason or "")
    assert "AGENTGUARD_EVENT_CANARY_HARDLINK" not in repr(events)


@pytest.mark.parametrize(
    "file_type",
    [
        stat.S_IFDIR,
        stat.S_IFIFO,
        stat.S_IFSOCK,
        stat.S_IFCHR,
        stat.S_IFBLK,
    ],
)
def test_nonregular_event_types_are_rejected_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    file_type: int,
) -> None:
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda self: SimpleNamespace(
            st_mode=file_type,
            st_dev=1,
            st_ino=1,
            st_nlink=1,
        ),
    )
    monkeypatch.setattr(
        os,
        "open",
        lambda *args, **kwargs: pytest.fail("non-regular source was opened"),
    )

    descriptor, diagnostic = _open_regular_file(tmp_path / "event")

    assert descriptor is None
    assert "not a regular file" in (diagnostic or "")


def test_oversized_line_is_dropped_but_later_valid_event_survives(
    tmp_path: Path,
) -> None:
    event_path = tmp_path / ".agentguard_agent_events.jsonl"
    event_path.write_bytes(
        b'{"type":"command_attempt","command_text":"'
        + b"x" * 100
        + b'"}\n'
        + _event("echo safe").encode()
        + b"\n"
    )
    reader = AgentEventStreamReader(tmp_path, max_line_bytes=64)

    batch = reader.read_new(finalize=True)

    assert [event["command_text"] for event in batch.events] == ["echo safe"]
    assert "line byte limit exceeded" in (batch.diagnostic or "")
    assert reader.partial_line_bytes == 0


def test_unterminated_line_buffer_is_bounded_and_recovers(tmp_path: Path) -> None:
    event_path = tmp_path / ".agentguard_agent_events.jsonl"
    event_path.write_bytes(b"x" * 100)
    reader = AgentEventStreamReader(tmp_path, max_line_bytes=80)

    first = reader.read_new()
    with event_path.open("ab") as file:
        file.write(b"\n" + _event("echo recovered").encode() + b"\n")
    second = reader.read_new()

    assert first.events == []
    assert "line byte limit exceeded" in (first.diagnostic or "")
    assert reader.partial_line_bytes == 0
    assert [event["command_text"] for event in second.events] == [
        "echo recovered"
    ]


def test_total_byte_limit_stops_incremental_read(tmp_path: Path) -> None:
    (tmp_path / ".agentguard_agent_events.jsonl").write_bytes(b"x" * 1024)
    reader = AgentEventStreamReader(tmp_path, max_total_bytes=64)

    batch = reader.read_new()

    assert reader.total_bytes == 64
    assert reader.partial_line_bytes == 0
    assert "total byte limit exceeded" in (batch.diagnostic or "")


def test_event_overflow_and_command_log_size_are_bounded(tmp_path: Path) -> None:
    event_path = tmp_path / ".agentguard_agent_events.jsonl"
    event_path.write_text(
        "".join(
            _event(f"echo AGENTGUARD_EVENT_CANARY_{index:03d}") + "\n"
            for index in range(500)
        ),
        encoding="utf-8",
    )

    events = read_agent_events(tmp_path)
    tracker = CommandTracker()
    tracker.extend(events)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    command_log = tracker.write_json(run_dir)

    assert len(events) == 201
    assert events[-1].command_text == INSTRUMENTATION_INCOMPLETE
    assert "event count limit exceeded" in (events[-1].reason or "")
    assert command_log.stat().st_size < 500_000
    assert "AGENTGUARD_EVENT_CANARY_499" not in command_log.read_text(
        encoding="utf-8"
    )
