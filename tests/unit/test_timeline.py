import json
from dataclasses import asdict

from agentguard.core.timeline import TimelineRecorder


def test_timeline_recorder_assigns_increasing_order() -> None:
    recorder = TimelineRecorder()

    first = recorder.add("run_started", "Run started")
    second = recorder.add("run_completed", "Run completed")

    assert first.order == 1
    assert second.order == 2
    assert [event.order for event in recorder.events] == [1, 2]


def test_timeline_event_serializes_cleanly() -> None:
    recorder = TimelineRecorder()
    event = recorder.add(
        "tests_completed",
        "Tests completed with exit code 0",
        {"test_exit_code": 0, "modified_files": ["src/auth_example/login.py"]},
    )

    assert json.loads(json.dumps(asdict(event))) == {
        "order": 1,
        "event_type": "tests_completed",
        "message": "Tests completed with exit code 0",
        "metadata": {
            "test_exit_code": 0,
            "modified_files": ["src/auth_example/login.py"],
        },
    }
