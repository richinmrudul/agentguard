import json
import os
import subprocess
from pathlib import Path

import pytest

from agentguard.sandbox.contained_workspace import (
    ContainedWorkspaceError,
    ContainedWorkspaceLimits,
    ContainedWorkspaceMutationError,
    _hash_regular_file,
    _open_validated_regular_file,
    prepare_contained_workspace,
)


PRIVATE_CANARY = "/Users/private/AGENTGUARD_PATH_CANARY"
CREDENTIAL_CANARY = "ghp_AGENTGUARD_SECRET_CANARY_1234567890"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _init_repo(repo: Path) -> str:
    repo.mkdir()
    _git(repo, "init", "--template=")
    _git(repo, "config", "user.email", "test@example.local")
    _git(repo, "config", "user.name", "Test")
    (repo / "tracked.txt").write_text("tracked\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return _git(repo, "rev-parse", "HEAD")


def _metadata(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _paths(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))


def test_prepare_contained_workspace_copies_regular_content_without_git_metadata(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    head = _init_repo(source)
    (source / "tracked.txt").write_text("dirty tracked\n", encoding="utf-8")
    (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    (source / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (source / "ignored.txt").write_text("ignored\n", encoding="utf-8")

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="ordinary",
    )

    assert prepared.workspace_dir != source
    assert not (prepared.workspace_dir / ".git").exists()
    assert (prepared.workspace_dir / "tracked.txt").read_text(encoding="utf-8") == (
        "dirty tracked\n"
    )
    assert (prepared.workspace_dir / "untracked.txt").is_file()
    assert (prepared.workspace_dir / "ignored.txt").is_file()
    assert prepared.evidence_dir.is_dir()
    assert not prepared.workspace_dir.is_relative_to(source)
    assert prepared.metadata.baseline.git_head == head
    assert prepared.metadata.baseline.source_kind == "git"
    assert prepared.metadata.agentguard_evidence == "evidence"
    assert prepared.metadata.cleanup_targets == (".",)


def test_prepare_records_tracked_untracked_ignored_deleted_and_renamed_evidence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _init_repo(source)
    (source / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (source / "old.txt").write_text("old\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "baseline")
    (source / "tracked.txt").write_text("modified\n", encoding="utf-8")
    (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    (source / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    (source / "old.txt").unlink()
    _git(source, "mv", "tracked.txt", "renamed.txt")

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="status",
    )

    status = {
        (entry.status, entry.path, entry.source_path)
        for entry in prepared.metadata.baseline.git_status
    }
    assert ("RM", "renamed.txt", "tracked.txt") in status
    assert ("D ", "old.txt", None) in status
    assert ("??", "untracked.txt", None) in status
    assert ("!!", "ignored.txt", None) in status
    assert (prepared.workspace_dir / "renamed.txt").is_file()
    assert not (prepared.workspace_dir / "old.txt").exists()


def test_baseline_is_fixed_after_source_head_moves(tmp_path: Path) -> None:
    source = tmp_path / "source"
    first_head = _init_repo(source)

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="fixed-baseline",
    )
    (source / "later.txt").write_text("later\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "later")

    assert _git(source, "rev-parse", "HEAD") != first_head
    assert prepared.metadata.baseline.git_head == first_head
    assert not (prepared.workspace_dir / "later.txt").exists()


def test_empty_git_repo_and_non_git_directory_are_deterministic(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    _git(empty, "init", "--template=")
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "hello.txt").write_text("hello\n", encoding="utf-8")

    empty_prepared = prepare_contained_workspace(
        empty,
        tmp_path / "lifecycle",
        workspace_id="empty",
    )
    plain_one = prepare_contained_workspace(
        plain,
        tmp_path / "lifecycle",
        workspace_id="plain-one",
    )
    plain_two = prepare_contained_workspace(
        plain,
        tmp_path / "lifecycle",
        workspace_id="plain-two",
    )

    assert empty_prepared.metadata.baseline.source_kind == "git-empty"
    assert empty_prepared.metadata.baseline.git_head is None
    assert plain_one.metadata.baseline.source_kind == "directory"
    assert plain_one.metadata.baseline.digest == plain_two.metadata.baseline.digest
    first = plain_one.metadata.to_dict()
    second = plain_two.metadata.to_dict()
    first["workspace_id"] = "normalized"
    second["workspace_id"] = "normalized"
    assert first == second


@pytest.mark.parametrize(
    "writable_paths",
    [
        (".git",),
        (".agentguard",),
        ("nested/.agentguard",),
        (".", "src"),
        ("src", "src/generated"),
        ("src", "src"),
        ("src/", "src"),
    ],
)
def test_agent_visible_writable_paths_reject_ambiguous_ownership(
    tmp_path: Path,
    writable_paths: tuple[str, ...],
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")

    with pytest.raises(ContainedWorkspaceError):
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="writable-paths",
            agent_visible_writable_paths=writable_paths,
        )

    assert not (tmp_path / "lifecycle" / "writable-paths").exists()


def test_agent_visible_writable_root_is_allowed_as_sole_path(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="writable-root",
        agent_visible_writable_paths=(".",),
    )

    assert prepared.metadata.agent_visible_writable_paths == (".",)


@pytest.mark.parametrize(
    "relative_path",
    [
        ".agentguard/report.json",
        "nested/.agentguard/report.json",
        ".agentguard_agent_events.jsonl",
        ".agentguard-cache/report.json",
    ],
)
def test_reserved_and_nested_spoofing_are_rejected(
    tmp_path: Path,
    relative_path: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    path = source / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("spoof\n", encoding="utf-8")

    with pytest.raises(ContainedWorkspaceError, match="reserved path"):
        prepare_contained_workspace(source, tmp_path / "lifecycle", workspace_id="bad")

    assert not (tmp_path / "lifecycle" / "bad").exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
def test_safe_unicode_and_space_paths_preserve_relative_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "dir with spaces").mkdir()
    (source / "dir with spaces" / "unicodé.txt").write_text(
        "content\n",
        encoding="utf-8",
    )
    (source / "link").symlink_to("dir with spaces/unicodé.txt")

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="unicode",
    )

    assert (prepared.workspace_dir / "dir with spaces" / "unicodé.txt").is_file()
    assert (prepared.workspace_dir / "link").is_symlink()
    assert (prepared.workspace_dir / "link").readlink() == Path(
        "dir with spaces/unicodé.txt"
    )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
@pytest.mark.parametrize("target", ["../outside.txt", "missing.txt"])
def test_symlink_escape_and_dangling_links_are_rejected(
    tmp_path: Path,
    target: str,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")
    (source / "link").symlink_to(target)

    with pytest.raises(ContainedWorkspaceError, match="symlink"):
        prepare_contained_workspace(source, tmp_path / "lifecycle", workspace_id="link")


def test_hardlink_boundary_is_rejected_without_copying_external_content(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    os.link(outside, source / "linked.txt")

    with pytest.raises(ContainedWorkspaceError, match="hardlink"):
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="hardlink",
        )

    assert not (tmp_path / "lifecycle" / "hardlink").exists()


def test_bounded_large_and_many_behavior(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "large.txt").write_bytes(b"x" * 12)

    with pytest.raises(ContainedWorkspaceError, match="too large"):
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="large",
            limits=ContainedWorkspaceLimits(max_file_bytes=8),
        )

    (source / "large.txt").unlink()
    for index in range(3):
        (source / f"{index}.txt").write_text("x\n", encoding="utf-8")
    with pytest.raises(ContainedWorkspaceError, match="entry limit"):
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="many",
            limits=ContainedWorkspaceLimits(max_entries=2),
        )


def test_partial_copy_failure_rolls_back_without_private_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")

    def fail_copy(*_args, **_kwargs):
        raise OSError(f"copy failed at {PRIVATE_CANARY} token={CREDENTIAL_CANARY}")

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._copy_regular_file",
        fail_copy,
    )

    with pytest.raises(ContainedWorkspaceError) as caught:
        prepare_contained_workspace(source, tmp_path / "lifecycle", workspace_id="copy")

    assert PRIVATE_CANARY not in str(caught.value)
    assert CREDENTIAL_CANARY not in str(caught.value)
    assert "lifecycle-owned setup" in str(caught.value)
    assert not (tmp_path / "lifecycle" / "copy").exists()
    assert not (tmp_path / "lifecycle" / "copy.preparing").exists()


def test_metadata_write_failure_rolls_back_without_private_diagnostics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")

    def fail_metadata(*_args, **_kwargs):
        raise OSError(f"metadata failed at {PRIVATE_CANARY} token={CREDENTIAL_CANARY}")

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._write_metadata",
        fail_metadata,
    )

    with pytest.raises(ContainedWorkspaceError) as caught:
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="metadata-fails",
        )

    assert PRIVATE_CANARY not in str(caught.value)
    assert CREDENTIAL_CANARY not in str(caught.value)
    assert "lifecycle-owned setup" in str(caught.value)
    assert not (tmp_path / "lifecycle" / "metadata-fails").exists()
    assert not (tmp_path / "lifecycle" / "metadata-fails.preparing").exists()


def test_regular_file_replacement_during_copy_fails_closed_without_swapped_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    victim = source / "victim.txt"
    victim.write_text("original\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("swapped secret\n", encoding="utf-8")
    original_open = _open_validated_regular_file
    swapped = False

    def swap_before_open(path: Path, expected: os.stat_result) -> int:
        nonlocal swapped
        if path == victim and not swapped:
            swapped = True
            path.unlink()
            path.symlink_to(outside)
        return original_open(path, expected)

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._open_validated_regular_file",
        swap_before_open,
    )

    with pytest.raises(ContainedWorkspaceError, match="source changed"):
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="copy-race",
        )

    assert swapped
    assert not (tmp_path / "lifecycle" / "copy-race").exists()
    assert not (tmp_path / "lifecycle" / "copy-race.preparing").exists()
    assert not (tmp_path / "lifecycle" / "copy-race" / "workspace" / "victim.txt").exists()


def test_regular_file_replacement_during_baseline_hash_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    victim = source / "victim.txt"
    victim.write_text("original\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text(f"swapped {PRIVATE_CANARY} {CREDENTIAL_CANARY}\n", encoding="utf-8")
    original_hash = _hash_regular_file
    swapped = False

    def swap_before_hash(path: Path, expected: os.stat_result) -> str:
        nonlocal swapped
        if path == victim and not swapped:
            swapped = True
            path.unlink()
            path.symlink_to(outside)
        return original_hash(path, expected)

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._hash_regular_file",
        swap_before_hash,
    )

    with pytest.raises(ContainedWorkspaceError) as caught:
        prepare_contained_workspace(
            source,
            tmp_path / "lifecycle",
            workspace_id="hash-race",
        )

    assert swapped
    assert PRIVATE_CANARY not in str(caught.value)
    assert CREDENTIAL_CANARY not in str(caught.value)
    assert "source changed" in str(caught.value)
    assert not (tmp_path / "lifecycle" / "hash-race").exists()
    assert not (tmp_path / "lifecycle" / "hash-race.preparing").exists()


def test_cleanup_success_and_user_owned_path_preservation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    user_owned = tmp_path / "user-owned"
    user_owned.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="cleanup",
    )

    result = prepared.cleanup()

    assert result.complete
    assert not prepared.run_dir.exists()
    assert user_owned.is_dir()


def test_cleanup_failure_evidence_is_sanitized_without_deleting_user_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    user_owned = tmp_path / "user-owned"
    user_owned.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="cleanup-fails",
    )

    def fail_rmtree(_path):
        raise OSError(f"denied {PRIVATE_CANARY} password={CREDENTIAL_CANARY}")

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace.shutil.rmtree",
        fail_rmtree,
    )

    result = prepared.cleanup()

    assert not result.complete
    assert PRIVATE_CANARY not in result.message
    assert CREDENTIAL_CANARY not in result.message
    assert "OSError" in result.message
    assert prepared.run_dir.exists()
    assert user_owned.is_dir()


def test_metadata_file_is_deterministic_and_omits_private_absolute_paths(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="metadata",
    )
    metadata = _metadata(prepared.evidence_dir / "workspace-metadata.json")

    assert metadata == prepared.metadata.to_dict()
    encoded = json.dumps(metadata, sort_keys=True)
    assert str(tmp_path) not in encoded
    assert PRIVATE_CANARY not in encoded
    assert CREDENTIAL_CANARY not in encoded
    assert metadata["baseline"]["digest"] == prepared.metadata.baseline.digest


def test_preparation_cleanup_failure_diagnostic_is_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")

    def fail_copy(*_args, **_kwargs):
        raise OSError("copy failed")

    def fail_rmtree(_path):
        raise OSError(f"cleanup failed at {PRIVATE_CANARY} api_key={CREDENTIAL_CANARY}")

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._copy_regular_file",
        fail_copy,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace.shutil.rmtree",
        fail_rmtree,
    )

    with pytest.raises(RuntimeError) as caught:
        prepare_contained_workspace(source, tmp_path / "lifecycle", workspace_id="bad")

    assert "partial lifecycle-owned artifacts remain" in str(caught.value)
    assert PRIVATE_CANARY not in str(caught.value)
    assert CREDENTIAL_CANARY not in str(caught.value)


def test_git_control_metadata_is_excluded_recursively(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".git" / "objects").mkdir(parents=True)
    (source / ".git" / "config").write_text("root git\n", encoding="utf-8")
    (source / "nested" / ".git" / "objects").mkdir(parents=True)
    (source / "nested" / ".git" / "HEAD").write_text("nested git\n", encoding="utf-8")
    (source / "nested" / "file.txt").write_text("kept\n", encoding="utf-8")

    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="no-git",
    )

    assert ".git" not in _paths(prepared.workspace_dir)
    assert "nested/.git" not in _paths(prepared.workspace_dir)
    assert (prepared.workspace_dir / "nested" / "file.txt").is_file()


def test_capture_mutations_classifies_modified_added_deleted_and_renamed_files(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "modified.txt").write_text("before\n", encoding="utf-8")
    (source / "deleted.txt").write_text("delete me\n", encoding="utf-8")
    (source / "renamed.txt").write_text("same content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="mutations",
    )

    (prepared.workspace_dir / "modified.txt").write_text("after\n", encoding="utf-8")
    (prepared.workspace_dir / "deleted.txt").unlink()
    (prepared.workspace_dir / "added.txt").write_text("new\n", encoding="utf-8")
    (prepared.workspace_dir / "renamed.txt").rename(
        prepared.workspace_dir / "renamed-now.txt"
    )

    mutations = prepared.capture_mutations()

    assert mutations.modified_files == ("modified.txt",)
    assert mutations.added_files == ("added.txt",)
    assert mutations.deleted_files == ("deleted.txt",)
    assert mutations.renamed_files == (("renamed.txt", "renamed-now.txt"),)
    assert mutations.changed_files == (
        "added.txt",
        "deleted.txt",
        "modified.txt",
        "renamed-now.txt",
        "renamed.txt",
    )


def test_capture_excludes_agentguard_evidence_outside_workspace(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-evidence",
    )
    (prepared.evidence_dir / ".agentguard_agent_events.jsonl").write_text(
        "{}\n",
        encoding="utf-8",
    )
    (prepared.evidence_dir / "extra.json").write_text("{}\n", encoding="utf-8")

    mutations = prepared.capture_mutations()

    assert mutations.changed_files == ()


def test_capture_uses_fixed_baseline_after_source_head_moves(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    _init_repo(source)
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-fixed",
    )
    baseline_head = prepared.metadata.baseline.git_head

    (source / "source-only.txt").write_text("source changed\n", encoding="utf-8")
    _git(source, "add", ".")
    _git(source, "commit", "-m", "source head moved")
    (prepared.workspace_dir / "tracked.txt").write_text("agent edit\n", encoding="utf-8")
    (prepared.workspace_dir / "agent-only.txt").write_text("new\n", encoding="utf-8")

    mutations = prepared.capture_mutations()

    assert prepared.metadata.baseline.git_head == baseline_head
    assert mutations.modified_files == ("tracked.txt",)
    assert mutations.added_files == ("agent-only.txt",)
    assert mutations.deleted_files == ()


def test_capture_rejects_agent_created_git_control_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _init_repo(source)
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-git",
    )
    _git(prepared.workspace_dir, "init", "--template=")

    with pytest.raises(ContainedWorkspaceMutationError, match="reserved path"):
        prepared.capture_mutations()


def test_capture_rejects_reserved_path_spoofing(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-reserved",
    )
    (prepared.workspace_dir / ".agentguard").mkdir()
    (prepared.workspace_dir / ".agentguard" / "report.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(ContainedWorkspaceMutationError) as caught:
        prepared.capture_mutations()

    assert "reserved path" in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
def test_capture_rejects_unsafe_symlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-symlink",
    )
    (prepared.workspace_dir / "escape").symlink_to("../outside.txt")

    with pytest.raises(ContainedWorkspaceMutationError, match="symlink"):
        prepared.capture_mutations()


def test_capture_rejects_unsafe_hardlink(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-hardlink",
    )
    os.link(outside, prepared.workspace_dir / "linked.txt")

    with pytest.raises(ContainedWorkspaceMutationError, match="hardlink"):
        prepared.capture_mutations()


def test_capture_bounded_scan_behavior(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-bounds",
        limits=ContainedWorkspaceLimits(max_entries=4),
    )
    for index in range(5):
        (prepared.workspace_dir / f"{index}.txt").write_text("x\n", encoding="utf-8")

    with pytest.raises(ContainedWorkspaceMutationError, match="entry limit"):
        prepared.capture_mutations()


def test_capture_diagnostics_omit_private_paths_and_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_text("content\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-diagnostics",
    )

    def fail_hash(_path):
        raise OSError(f"failed at {PRIVATE_CANARY} token={CREDENTIAL_CANARY}")

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._hash_regular_file",
        fail_hash,
    )

    with pytest.raises(ContainedWorkspaceMutationError) as caught:
        prepared.capture_mutations()

    assert PRIVATE_CANARY not in str(caught.value)
    assert CREDENTIAL_CANARY not in str(caught.value)
    assert "bounded scan" in str(caught.value)


def test_regular_file_replacement_during_capture_hash_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "victim.txt").write_text("original\n", encoding="utf-8")
    prepared = prepare_contained_workspace(
        source,
        tmp_path / "lifecycle",
        workspace_id="capture-hash-race",
    )
    victim = prepared.workspace_dir / "victim.txt"
    outside = tmp_path / "outside.txt"
    outside.write_text(f"swapped {PRIVATE_CANARY} {CREDENTIAL_CANARY}\n", encoding="utf-8")
    original_hash = _hash_regular_file
    swapped = False

    def swap_before_hash(path: Path, expected: os.stat_result) -> str:
        nonlocal swapped
        if path == victim and not swapped:
            swapped = True
            path.unlink()
            path.symlink_to(outside)
        return original_hash(path, expected)

    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._hash_regular_file",
        swap_before_hash,
    )

    with pytest.raises(ContainedWorkspaceMutationError) as caught:
        prepared.capture_mutations()

    assert swapped
    assert PRIVATE_CANARY not in str(caught.value)
    assert CREDENTIAL_CANARY not in str(caught.value)
    assert "source changed" in str(caught.value)
