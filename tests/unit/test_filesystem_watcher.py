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


def test_polling_watcher_records_escaping_symlink_inside_ignored_tree(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support unavailable")
    repo = tmp_path / "repo"
    outside = tmp_path / "outside"
    (repo / "ignored").mkdir(parents=True)
    outside.mkdir()
    scanner = FilesystemSnapshotScanner(
        repo_dir=repo,
        guard_ignore_paths=["ignored/**"],
    )
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())
    try:
        os.symlink(outside, repo / "ignored/link")
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")

    events = watcher.poll().events

    assert [(event.event_type, event.path) for event in events] == [
        ("symlink_created", "ignored/link")
    ]
    assert str(outside) not in "\n".join(
        f"{event.event_type} {event.path}" for event in events
    )


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


def test_polling_watcher_represents_rename_as_delete_and_create(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    original = repo / "old.txt"
    original.write_text("same\n", encoding="utf-8")
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    original.rename(repo / "new.txt")

    assert [(event.event_type, event.path) for event in watcher.poll().events] == [
        ("created", "new.txt"),
        ("deleted", "old.txt"),
    ]


def test_polling_watcher_documents_transient_create_delete_limit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    transient = repo / "transient.txt"
    transient.write_text("short lived\n", encoding="utf-8")
    transient.unlink()

    observation = watcher.poll()

    assert observation.events == []
    assert "transient.txt" not in observation.snapshot


def test_polling_watcher_documents_transient_create_modify_delete_limit(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    transient = repo / "transient.txt"
    transient.write_text("one\n", encoding="utf-8")
    transient.write_text("two\n", encoding="utf-8")
    transient.unlink()

    observation = watcher.poll()

    assert observation.events == []
    assert "transient.txt" not in observation.snapshot


def test_polling_watcher_deduplicates_consecutive_modify_events(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    target = repo / "app.py"
    target.write_text("one\n", encoding="utf-8")
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    target.write_text("two\n", encoding="utf-8")
    first = watcher.poll()
    target.write_text("three\n", encoding="utf-8")
    second = watcher.poll()

    assert [(event.event_type, event.path) for event in first.events] == [
        ("modified", "app.py")
    ]
    assert second.events == []


def test_polling_watcher_records_symlink_create_modify_delete(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support unavailable")
    repo = tmp_path / "repo"
    repo.mkdir()
    outside_one = tmp_path / "outside-one"
    outside_two = tmp_path / "outside-two"
    outside_one.mkdir()
    outside_two.mkdir()
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    link = repo / "escape"
    try:
        os.symlink(outside_one, link)
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")
    created = watcher.poll()

    link.unlink()
    os.symlink(outside_two, link)
    modified = watcher.poll()

    link.unlink()
    deleted = watcher.poll()

    assert [(event.event_type, event.path) for event in created.events] == [
        ("symlink_created", "escape")
    ]
    assert [(event.event_type, event.path) for event in modified.events] == [
        ("symlink_modified", "escape")
    ]
    assert [(event.event_type, event.path) for event in deleted.events] == [
        ("symlink_deleted", "escape")
    ]
    combined = "\n".join(
        f"{event.event_type} {event.path}"
        for event in [*created.events, *modified.events, *deleted.events]
    )
    assert str(outside_one) not in combined
    assert str(outside_two) not in combined


def test_polling_watcher_records_file_symlink_replacements(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support unavailable")
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = repo / "switch"
    target.write_text("file\n", encoding="utf-8")
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    target.unlink()
    try:
        os.symlink(outside, target)
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")
    symlink_replacement = watcher.poll()

    target.unlink()
    target.write_text("file again\n", encoding="utf-8")
    file_replacement = watcher.poll()

    assert [
        (event.event_type, event.path)
        for event in symlink_replacement.events
    ] == [("symlink_modified", "switch")]
    assert [(event.event_type, event.path) for event in file_replacement.events] == [
        ("symlink_modified", "switch")
    ]


def test_polling_watcher_ignores_safe_symlink_inside_ignored_path(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlink support unavailable")
    repo = tmp_path / "repo"
    (repo / "ignored").mkdir(parents=True)
    (repo / "target").mkdir()
    scanner = FilesystemSnapshotScanner(
        repo_dir=repo,
        guard_ignore_paths=["ignored/**"],
    )
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start(scanner.snapshot())

    try:
        os.symlink("../target", repo / "ignored/link")
    except OSError as error:
        pytest.skip(f"symlink unavailable: {error}")

    assert watcher.poll().events == []
