import json
from pathlib import Path

from agentguard.instrumentation.command_tracker import CommandTracker


def test_command_tracker_records_executed_command_event(tmp_path: Path) -> None:
    tracker = CommandTracker()

    tracker.record_executed(
        command=["pytest"],
        command_text="pytest",
        cwd=tmp_path,
        exit_code=0,
        stdout="ok",
        stderr="",
        duration_seconds=0.12,
    )

    event = tracker.events[0]
    assert event.command == ["pytest"]
    assert event.command_text == "pytest"
    assert event.cwd == str(tmp_path)
    assert event.exit_code == 0
    assert event.stdout == "ok"
    assert event.executed is True
    assert event.blocked is False
    assert event.timed_out is False
    assert event.stdout_truncated is False
    assert event.stderr_truncated is False


def test_command_tracker_records_blocked_or_simulated_command_event(
    tmp_path: Path,
) -> None:
    tracker = CommandTracker()

    tracker.record_blocked_or_simulated(
        command=["rm", "-rf", "important_data"],
        command_text="rm -rf important_data",
        cwd=tmp_path,
        blocked=True,
        reason="Mock unsafe command attempt",
    )

    event = tracker.events[0]
    assert event.executed is False
    assert event.blocked is True
    assert event.reason == "Mock unsafe command attempt"


def test_command_tracker_writes_valid_json(tmp_path: Path) -> None:
    tracker = CommandTracker()
    tracker.record_blocked_or_simulated(
        command=["rm", "-rf", "important_data"],
        command_text="rm -rf important_data",
        cwd=tmp_path,
        blocked=True,
        reason="Mock unsafe command attempt",
    )

    path = tracker.write_json(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert path == tmp_path / "command_log.json"
    assert data[0]["command_text"] == "rm -rf important_data"
    assert data[0]["blocked"] is True
    assert data[0]["timed_out"] is False
    assert data[0]["stdout_truncated"] is False
    assert data[0]["stderr_truncated"] is False
