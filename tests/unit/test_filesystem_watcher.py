import os
from pathlib import Path

import pytest

from agentguard.guard.watcher import (
    MAX_OBSERVED_FILES,
    FilesystemSnapshotScanner,
    PollingFilesystemWatcher,
)


def test_snapshot_scan_reports_true_entry_cap_boundaries(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for index in range(MAX_OBSERVED_FILES + 1):
        descriptor = os.open(repo / f"f-{index:05d}", os.O_CREAT | os.O_WRONLY)
        os.close(descriptor)
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])

    above = scanner.scan_snapshot()

    assert above.complete is False
    assert above.entries_inspected == MAX_OBSERVED_FILES + 1
    assert len(above.states) == MAX_OBSERVED_FILES

    (repo / f"f-{MAX_OBSERVED_FILES:05d}").unlink()
    (repo / ".git").mkdir()
    (repo / ".git/config").touch()
    (repo / ".agentguard").mkdir()
    (repo / ".agentguard/runtime.json").touch()
    exact = scanner.scan_snapshot()

    assert exact.complete is True
    assert exact.entries_inspected == MAX_OBSERVED_FILES + 2
    assert len(exact.states) == MAX_OBSERVED_FILES
    assert list(exact.states) == sorted(exact.states)

    (repo / f"f-{MAX_OBSERVED_FILES - 1:05d}").unlink()
    below = scanner.scan_snapshot()

    assert below.complete is True
    assert below.entries_inspected == MAX_OBSERVED_FILES + 1
    assert len(below.states) == MAX_OBSERVED_FILES - 1


def test_polling_watcher_propagates_incomplete_scan(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in ("a", "b", "c"):
        (repo / name).touch()
    monkeypatch.setattr("agentguard.guard.watcher.MAX_OBSERVED_FILES", 2)
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])
    watcher = PollingFilesystemWatcher(scanner=scanner)
    watcher.start({})

    observation = watcher.poll()

    assert observation.scan_complete is False
    assert len(observation.snapshot) == 2


def test_nested_snapshot_reports_overflow_after_exact_cap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = tmp_path / "repo"
    nested = repo / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "three").touch()
    monkeypatch.setattr("agentguard.guard.watcher.MAX_OBSERVED_FILES", 3)
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])

    exact = scanner.scan_snapshot()
    (nested / "four").touch()
    above = scanner.scan_snapshot()

    assert exact.complete is True
    assert list(exact.states) == ["one", "one/two", "one/two/three"]
    assert above.complete is False
    assert len(above.states) == 3


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


def test_snapshot_scanner_observes_git_ignored_repository_files(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (repo / "agent-created.log").write_text("evidence\n", encoding="utf-8")
    scanner = FilesystemSnapshotScanner(repo_dir=repo, guard_ignore_paths=[])

    snapshot = scanner.scan_snapshot()

    assert snapshot.complete is True
    assert "agent-created.log" in snapshot.states


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
