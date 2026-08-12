import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.repo.manager import RepoManager


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _config_for(repo: Path):
    return replace(
        load_config(Path("examples/configs/fix_auth_bug.yaml")),
        repo_template=repo,
    )


def _init_repo(repo: Path) -> str:
    repo.mkdir(parents=True)
    _git(repo, "init", "--template=")
    _git(repo, "config", "user.email", "test@example.local")
    _git(repo, "config", "user.name", "Test")
    (repo / "tracked.txt").write_text("initial\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "initial")
    return _git(repo, "rev-parse", "HEAD")


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def test_prepare_preserves_repository_symlinks(tmp_path: Path) -> None:
    source_symlink = Path(
        "examples/repos/symlink_path_traversal/linked_secrets"
    )
    if not source_symlink.is_symlink():
        pytest.skip("Repository symlinks are unavailable on this platform.")

    config = load_config(
        Path("examples/configs/symlink_path_traversal_safe.yaml")
    )
    prepared = RepoManager(tmp_path / "runs").prepare(config, "custom-command")

    copied_symlink = prepared.repo_dir / "linked_secrets"
    assert copied_symlink.is_symlink()
    assert copied_symlink.readlink() == Path("secrets")


def test_prepare_excludes_git_metadata_recursively_and_preserves_similar_names(
    tmp_path: Path,
) -> None:
    template = tmp_path / "template"
    template.mkdir()
    (template / ".git" / "hooks").mkdir(parents=True)
    (template / ".git" / "config").write_text("untrusted\n", encoding="utf-8")
    (template / "nested" / ".GIT").mkdir(parents=True)
    (template / "nested" / ".GIT" / "HEAD").write_text(
        "untrusted\n", encoding="utf-8"
    )
    (template / "legit.git").write_text("kept\n", encoding="utf-8")
    (template / ".github").mkdir()
    (template / ".github" / "kept.txt").write_text("kept\n", encoding="utf-8")
    (template / "git-notes.txt").write_text("kept\n", encoding="utf-8")

    prepared = RepoManager(tmp_path / "runs").prepare(
        _config_for(template), "custom-command"
    )

    assert (prepared.repo_dir / ".git").is_dir()
    assert not (prepared.repo_dir / "nested" / ".GIT").exists()
    assert (prepared.repo_dir / "legit.git").read_text(encoding="utf-8") == "kept\n"
    assert (prepared.repo_dir / ".github" / "kept.txt").is_file()
    assert (prepared.repo_dir / "git-notes.txt").is_file()
    assert _git(prepared.repo_dir, "status", "--porcelain") == ""


def test_prepare_flattens_nested_repository_without_creating_gitlink(
    tmp_path: Path,
) -> None:
    template = tmp_path / "template"
    _init_repo(template)
    nested = template / "nested"
    _init_repo(nested)
    nested_head = _git(nested, "rev-parse", "HEAD")
    source_head = _git(template, "rev-parse", "HEAD")
    source_bytes = _tree_bytes(template)

    prepared = RepoManager(tmp_path / "runs").prepare(
        _config_for(template), "custom-command"
    )

    assert _tree_bytes(template) == source_bytes
    assert _git(template, "rev-parse", "HEAD") == source_head
    assert _git(nested, "rev-parse", "HEAD") == nested_head
    assert not (prepared.repo_dir / "nested" / ".git").exists()
    index_entry = _git(
        prepared.repo_dir, "ls-files", "--stage", "nested/tracked.txt"
    )
    assert index_entry.startswith("100644 ")


def test_prepare_linked_worktree_uses_fresh_metadata_without_mutating_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    source_head = _init_repo(source)
    worktree = tmp_path / "linked"
    _git(source, "worktree", "add", "-b", "linked-branch", str(worktree))
    (worktree / "tracked.txt").write_text("dirty worktree\n", encoding="utf-8")
    pointer = (worktree / ".git").read_bytes()
    status = _git(worktree, "status", "--porcelain=v1")
    source_bytes = _tree_bytes(source)
    worktree_bytes = _tree_bytes(worktree)

    prepared = RepoManager(tmp_path / "runs").prepare(
        _config_for(worktree), "custom-command"
    )

    assert (worktree / ".git").read_bytes() == pointer
    assert _tree_bytes(source) == source_bytes
    assert _tree_bytes(worktree) == worktree_bytes
    assert _git(worktree, "rev-parse", "HEAD") == source_head
    assert _git(worktree, "status", "--porcelain=v1") == status
    assert (prepared.repo_dir / ".git").is_dir()
    assert not (prepared.repo_dir / ".git").is_symlink()
    assert _git(prepared.repo_dir, "rev-parse", "--git-dir") == ".git"
    assert _git(prepared.repo_dir, "rev-parse", "--git-common-dir") == ".git"
    assert (prepared.repo_dir / "tracked.txt").read_text(encoding="utf-8") == (
        "dirty worktree\n"
    )


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
def test_prepare_rejects_git_named_symlink_without_creating_artifacts(
    tmp_path: Path,
) -> None:
    template = tmp_path / "template"
    metadata = template / "metadata"
    metadata.mkdir(parents=True)
    (metadata / "config").write_text("untrusted\n", encoding="utf-8")
    (template / ".git").symlink_to("metadata", target_is_directory=True)
    (template / "source.txt").write_text("safe\n", encoding="utf-8")

    runs_root = tmp_path / "runs"

    with pytest.raises(ValueError, match="symlink named .git"):
        RepoManager(runs_root).prepare(_config_for(template), "custom-command")

    assert not runs_root.exists()


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
@pytest.mark.parametrize("target", [".git", "../outside"])
def test_prepare_rejects_symlink_to_metadata_or_outside_template(
    tmp_path: Path, target: str
) -> None:
    template = tmp_path / "template"
    (template / ".git").mkdir(parents=True)
    (tmp_path / "outside").mkdir()
    (template / "unsafe-link").symlink_to(target, target_is_directory=True)
    runs_root = tmp_path / "runs"

    with pytest.raises(ValueError, match="symlink"):
        RepoManager(runs_root).prepare(_config_for(template), "custom-command")

    assert not runs_root.exists()


def test_prepare_does_not_copy_or_invoke_source_hooks(tmp_path: Path) -> None:
    template = tmp_path / "template"
    _init_repo(template)
    marker = tmp_path / "hook-ran"
    hook = template / ".git" / "hooks" / "post-commit"
    hook.parent.mkdir()
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    hook.chmod(0o755)
    alternates = template / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str(template / ".git" / "objects") + "\n", encoding="utf-8")
    (template / "tracked.txt").write_text("dirty\n", encoding="utf-8")
    source_head = _git(template, "rev-parse", "HEAD")

    prepared = RepoManager(tmp_path / "runs").prepare(
        _config_for(template), "custom-command"
    )

    assert not marker.exists()
    assert _git(template, "rev-parse", "HEAD") == source_head
    assert not (prepared.repo_dir / ".git" / "hooks" / "post-commit").exists()
    assert not (prepared.repo_dir / ".git" / "objects" / "info" / "alternates").exists()


def test_prepare_ignores_git_environment_redirection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source_head = _init_repo(source)
    template = tmp_path / "template"
    template.mkdir()
    (template / "new.txt").write_text("new\n", encoding="utf-8")
    monkeypatch.setenv("GIT_DIR", str(source / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(source))

    prepared = RepoManager(tmp_path / "runs").prepare(
        _config_for(template), "custom-command"
    )
    monkeypatch.delenv("GIT_DIR")
    monkeypatch.delenv("GIT_WORK_TREE")

    assert _git(source, "rev-parse", "HEAD") == source_head
    assert (prepared.repo_dir / ".git").is_dir()
    assert _git(prepared.repo_dir, "status", "--porcelain") == ""


def test_prepare_cleans_partial_artifacts_after_copy_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = tmp_path / "template"
    template.mkdir()
    (template / "source.txt").write_text("source\n", encoding="utf-8")
    runs_root = tmp_path / "runs"

    def fail_copy(_source, destination, **_kwargs):
        Path(destination).mkdir()
        (Path(destination) / "partial.txt").write_text(
            "partial\n", encoding="utf-8"
        )
        raise OSError("copy failed")

    monkeypatch.setattr("agentguard.repo.manager.shutil.copytree", fail_copy)

    with pytest.raises(OSError, match="copy failed"):
        RepoManager(runs_root).prepare(_config_for(template), "custom-command")

    assert list(runs_root.iterdir()) == []


def test_prepare_reports_partial_artifacts_when_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    template = tmp_path / "template"
    template.mkdir()
    runs_root = tmp_path / "runs"

    def fail_copy(_source, destination, **_kwargs):
        Path(destination).mkdir()
        (Path(destination) / "partial.txt").write_text(
            "partial\n", encoding="utf-8"
        )
        raise OSError("unrelated sensitive preparation detail")

    def fail_cleanup(_path):
        raise OSError("cleanup denied")

    monkeypatch.setattr("agentguard.repo.manager.shutil.copytree", fail_copy)
    monkeypatch.setattr("agentguard.repo.manager.shutil.rmtree", fail_cleanup)

    with pytest.raises(RuntimeError, match="cleanup was incomplete") as caught:
        RepoManager(runs_root).prepare(_config_for(template), "custom-command")

    remaining = list(runs_root.iterdir())
    assert len(remaining) == 1
    partial_run_dir = remaining[0]
    assert str(caught.value) == (
        "Repository preparation failed and cleanup was incomplete; "
        f"partial artifacts remain at {partial_run_dir}."
    )
    assert "sensitive" not in str(caught.value)
    assert isinstance(caught.value.__cause__, OSError)
    assert str(caught.value.__cause__) == "cleanup denied"
    assert (partial_run_dir / "repo" / "partial.txt").is_file()


def test_prepare_rejects_run_directory_inside_template(tmp_path: Path) -> None:
    template = tmp_path / "template"
    template.mkdir()
    runs_root = template / ".agentguard" / "runs"

    with pytest.raises(ValueError, match="outside repo_template"):
        RepoManager(runs_root).prepare(_config_for(template), "custom-command")

    assert not runs_root.exists()
