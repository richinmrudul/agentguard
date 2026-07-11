import os
from pathlib import Path

import pytest

from agentguard.guard.watcher import (
    FilesystemSnapshotScanner,
    PollingFilesystemWatcher,
)


def test_polling_watcher_captures_create_modify_delete_events(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    (repo / "src").mkdir()
    created = repo / "src/app.py"
    created.write_text("one\n", encoding="utf-8")
    first = watcher.poll()

    created.write_text("two\n", encoding="utf-8")
    second = watcher.poll()

    created.unlink()
    third = watcher.poll()

    events = [*first.events, *second.events, *third.events]
    event_pairs = [(event.event_type, event.path) for event in events]
    assert event_pairs[:2] == [
        ("created", "src"),
        ("created", "src/app.py"),
    ]
    assert ("modified", "src/app.py") in event_pairs
    assert event_pairs[-1] == ("deleted", "src/app.py")
    assert [event.observed_at_sequence for event in events] == list(
        range(1, len(events) + 1)
    )
    assert {event.source for event in events} == {"polling"}
    assert all(not Path(event.path).is_absolute() for event in events)


def test_snapshot_scanner_respects_guard_ignore_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "coverage").mkdir()
    (repo / "src/app.py").write_text("ok\n", encoding="utf-8")
    (repo / "coverage/report.txt").write_text("ignored\n", encoding="utf-8")

    scanner = FilesystemSnapshotScanner(
        repo_dir=repo,
        guard_ignore_paths=["coverage/**"],
    )
    snapshot = scanner.snapshot()

    assert "src/app.py" in snapshot
    assert "coverage" not in snapshot
    assert "coverage/report.txt" not in snapshot


def test_snapshot_scanner_ignores_internal_agentguard_artifacts(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / ".agentguard").mkdir(parents=True)
    (repo / ".agentguard/runtime.json").write_text("{}", encoding="utf-8")

    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])

    assert scanner.snapshot() == {}


def test_snapshot_scanner_keeps_escaping_symlink_inside_ignored_tree(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support unavailable")
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    (repo / "ignored").mkdir(parents=True)
    outside.mkdir()
    try:
        os.symlink(outside, repo / "ignored/link")
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")

    scanner = FilesystemSnapshotScanner(
        repo_dir=repo,
        guard_ignore_paths=["ignored/**"],
    )
    snapshot = scanner.snapshot()

    assert "ignored/link" in snapshot
    assert snapshot["ignored/link"].kind == "symlink"
    assert scanner.symlink_escapes("ignored/link", str(outside)) is True


def test_polling_watcher_ignores_internal_command_event_file(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    (repo / ".agentguard_agent_events.jsonl").write_text(
        "{}\n",
        encoding="utf-8",
    )

    assert watcher.poll().events == []
