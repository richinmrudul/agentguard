import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.checks.forbidden_paths import ForbiddenPathsCheck
from agentguard.checks.scope_adherence import ScopeAdherenceCheck
from agentguard.checks.secret_scan import SecretScanCheck
from agentguard.checks.test_tampering import TestTamperingCheck
from agentguard.config.loader import load_config
from agentguard.core.result import CommandResult
from agentguard.repo.git_diff import collect_diff, collect_diff_between_refs
from agentguard.repo.internal_artifacts import is_internal_artifact


def _git(repo_dir: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _command_result() -> CommandResult:
    return CommandResult(
        command="pytest",
        exit_code=0,
        stdout="",
        stderr="",
        duration_seconds=0.0,
    )


def test_collect_diff_between_refs_classifies_committed_changes(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init")
    _git(repo_dir, "branch", "-M", "main")
    _write(repo_dir / "src" / "app.py", "VALUE = 1\n")
    _write(repo_dir / "src" / "old.py", "OLD = True\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Initial state",
    )

    _git(repo_dir, "checkout", "-b", "feature")
    _write(repo_dir / "src" / "app.py", "VALUE = 2\nEXTRA = True\n")
    _write(repo_dir / "src" / "new.py", "NEW = True\n")
    (repo_dir / "src" / "old.py").unlink()
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Feature changes",
    )

    diff = collect_diff_between_refs(repo_dir, "main", "HEAD")

    assert diff.modified_files == ["src/app.py"]
    assert diff.added_files == ["src/new.py"]
    assert diff.deleted_files == ["src/old.py"]
    assert diff.lines_added >= 2
    assert diff.lines_deleted >= 1
    assert "src/app.py" in diff.unified_diff


def test_internal_artifact_matcher_identifies_generated_paths() -> None:
    assert is_internal_artifact(".agentguard_agent_events.jsonl")
    assert is_internal_artifact(".agentguard/runs/x/report.json")
    assert is_internal_artifact("tests/__pycache__/x.pyc")
    assert is_internal_artifact(".pytest_cache/v/cache/nodeids")
    assert not is_internal_artifact("src/auth_example/login.py")


def test_collect_diff_excludes_internal_artifacts_and_keeps_source_files(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init")
    _git(repo_dir, "branch", "-M", "main")
    _write(repo_dir / "src" / "app.py", "VALUE = 1\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Initial state",
    )

    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    _write(repo_dir / ".agentguard_agent_events.jsonl", "{}\n")
    _write(repo_dir / ".pytest_cache" / "v" / "cache" / "nodeids", "[]\n")
    _write(repo_dir / "tests" / "__pycache__" / "x.pyc", "bytecode\n")
    _write(repo_dir / "tests" / "test_app.py", "def test_app():\n    pass\n")

    diff = collect_diff(repo_dir)

    assert diff.modified_files == ["src/app.py"]
    assert diff.added_files == ["tests/test_app.py"]
    assert diff.deleted_files == []
    assert ".agentguard_agent_events.jsonl" not in diff.changed_files
    assert ".agentguard_agent_events.jsonl" not in diff.unified_diff
    assert "src/app.py" in diff.unified_diff


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="Symlinks unavailable")
def test_collect_diff_includes_ignored_paths_without_following_symlinks(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init", "--template=")
    _write(
        repo_dir / ".gitignore",
        "ignored/**\nnested/*.secret\n.agentguard/**\n*.pyc\n",
    )
    _write(repo_dir / "ignored" / "modified.txt", "baseline\n")
    _write(repo_dir / "ignored" / "deleted.txt", "delete me\n")
    _write(repo_dir / "ignored" / "renamed.txt", "rename me\n")
    _git(repo_dir, "add", "--all", "--force", "--", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Baseline",
    )

    _write(repo_dir / "ignored" / "modified.txt", "changed\n")
    (repo_dir / "ignored" / "deleted.txt").unlink()
    (repo_dir / "ignored" / "renamed.txt").rename(
        repo_dir / "ignored" / "renamed-new.txt"
    )
    _write(repo_dir / "nested" / "new.secret", "new ignored\n")
    (repo_dir / "ignored" / "link.secret").symlink_to("../modified.txt")
    _write(repo_dir / "ignored" / "nested" / ".git" / "config", "control\n")
    _write(repo_dir / ".agentguard" / "runs" / "report.json", "{}\n")
    _write(repo_dir / "generated.pyc", "bytecode\n")

    legacy = collect_diff(repo_dir)
    first = collect_diff(repo_dir, include_ignored=True)
    second = collect_diff(repo_dir, include_ignored=True)

    assert legacy.added_files == []
    assert first == second
    assert first.modified_files == ["ignored/modified.txt"]
    assert first.added_files == [
        "ignored/link.secret",
        "ignored/renamed-new.txt",
        "nested/new.secret",
    ]
    assert first.deleted_files == [
        "ignored/deleted.txt",
        "ignored/renamed.txt",
    ]
    assert first.lines_added == 3
    assert first.lines_deleted == 3
    assert all(".git" not in path.split("/") for path in first.changed_files)
    assert "ignored/nested/.git/config" not in first.changed_files
    assert ".agentguard/runs/report.json" not in first.changed_files
    assert "generated.pyc" not in first.changed_files
    assert "ignored/modified.txt" in first.unified_diff


def test_collect_diff_staged_renames_include_both_paths_for_policy_checks(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init")
    _git(repo_dir, "branch", "-M", "main")
    _write(repo_dir / "tests" / "old_test.py", "def test_old():\n    pass\n")
    _write(repo_dir / "secrets" / "old.txt", "not a credential\n")
    _write(
        repo_dir / "src" / "original.py",
        "\n".join(f"LINE_{index} = {index}" for index in range(12)) + "\n",
    )
    unusual_old = "src/odd\tname\nold.py"
    unusual_new = "src/odd\tname\nnew.py"
    _write(repo_dir / unusual_old, "VALUE = 1\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Initial state",
    )
    _git(repo_dir, "checkout", "-b", "feature")
    _git(repo_dir, "mv", "tests/old_test.py", "src/moved_test.py")
    _git(repo_dir, "mv", "secrets/old.txt", "src/recovered.txt")
    _git(repo_dir, "mv", "src/original.py", "secrets/renamed.py")
    _write(
        repo_dir / "secrets" / "renamed.py",
        "\n".join(
            "LINE_5 = 'edited'" if index == 5 else f"LINE_{index} = {index}"
            for index in range(12)
        )
        + "\n",
    )
    _git(repo_dir, "add", "secrets/renamed.py")
    _git(repo_dir, "mv", unusual_old, unusual_new)

    working_diff = collect_diff(repo_dir)

    expected_rename_paths = {
        "tests/old_test.py",
        "src/moved_test.py",
        "secrets/old.txt",
        "src/recovered.txt",
        "src/original.py",
        "secrets/renamed.py",
        unusual_old,
        unusual_new,
    }
    assert set(working_diff.modified_files) == expected_rename_paths
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug.yaml")),
        test_paths=["tests/**"],
        forbidden_paths=["secrets/**"],
        secret_patterns=["secrets/**"],
        allowed_paths=["src/**"],
    )
    test_tampering = TestTamperingCheck().run(
        config,
        _command_result(),
        working_diff,
        [],
    )
    forbidden = ForbiddenPathsCheck().run(
        config,
        _command_result(),
        working_diff,
        [],
    )
    secrets = SecretScanCheck().run(
        config,
        _command_result(),
        working_diff,
        [],
    )
    scope = ScopeAdherenceCheck().run(
        config,
        _command_result(),
        working_diff,
        [],
    )
    assert test_tampering.passed is False
    assert test_tampering.evidence == ["tests/old_test.py"]
    assert forbidden.passed is False
    assert set(forbidden.evidence) == {"secrets/old.txt", "secrets/renamed.py"}
    assert secrets.passed is False
    assert any("secrets/old.txt" in evidence for evidence in secrets.evidence)
    assert any("secrets/renamed.py" in evidence for evidence in secrets.evidence)
    assert scope.passed is False
    assert "Outside allowed paths: tests/old_test.py" in scope.evidence
    assert "Outside allowed paths: secrets/renamed.py" in scope.evidence

    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-am",
        "Rename files",
    )
    ref_diff = collect_diff_between_refs(repo_dir, "main", "HEAD")

    assert set(ref_diff.modified_files) == expected_rename_paths
    assert set(ref_diff.changed_files) == set(working_diff.changed_files)


def test_collect_diff_unstaged_rename_exposes_source_and_destination(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init")
    _git(repo_dir, "branch", "-M", "main")
    old_path = repo_dir / "tests" / "old_test.py"
    new_path = repo_dir / "src" / "moved_test.py"
    _write(old_path, "def test_old():\n    pass\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Initial state",
    )
    new_path.parent.mkdir()
    old_path.rename(new_path)

    diff = collect_diff(repo_dir)

    assert diff.deleted_files == ["tests/old_test.py"]
    assert diff.added_files == ["src/moved_test.py"]
    assert set(diff.changed_files) == {"tests/old_test.py", "src/moved_test.py"}


def test_collect_diff_fixed_baseline_combines_committed_index_and_worktree(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init", "--template=")
    _git(repo_dir, "branch", "-M", "main")
    _write(repo_dir / "src" / "app.py", "VALUE = 1\n")
    _write(repo_dir / "src" / "remove.py", "REMOVE = True\n")
    _write(repo_dir / "tests" / "test_app.py", "def test_app():\n    pass\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Baseline",
    )
    baseline_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    _git(repo_dir, "checkout", "-b", "agent-work")
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    _write(repo_dir / "secrets" / "committed.key", "api_key=committedsecret\n")
    _git(repo_dir, "rm", "src/remove.py")
    _git(repo_dir, "mv", "tests/test_app.py", "tests/test_renamed.py")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Agent commit one",
    )
    _write(repo_dir / "src" / "second.py", "SECOND = True\n")
    _git(repo_dir, "add", "src/second.py")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Agent commit two",
    )
    _git(repo_dir, "checkout", "--detach")
    _write(repo_dir / "src" / "staged.py", "STAGED = True\n")
    _git(repo_dir, "add", "src/staged.py")
    _write(repo_dir / "src" / "app.py", "VALUE = 3\n")
    _write(repo_dir / "src" / "untracked.py", "UNTRACKED = True\n")

    diff = collect_diff(repo_dir, baseline_commit)

    assert set(diff.modified_files) == {
        "src/app.py",
        "tests/test_app.py",
        "tests/test_renamed.py",
    }
    assert set(diff.added_files) == {
        "secrets/committed.key",
        "src/second.py",
        "src/staged.py",
        "src/untracked.py",
    }
    assert diff.deleted_files == ["src/remove.py"]
    assert diff.lines_added >= 5
    assert diff.lines_deleted >= 2
    assert "secrets/committed.key" in diff.unified_diff
    assert diff == collect_diff(repo_dir, baseline_commit)


def test_collect_diff_fixed_baseline_detects_clean_agent_commit(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init", "--template=")
    _write(repo_dir / "tracked.txt", "baseline\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Baseline",
    )
    baseline_commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _write(repo_dir / "tracked.txt", "committed agent change\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Agent commit",
    )

    assert collect_diff(repo_dir).changed_files == []
    assert collect_diff(repo_dir, baseline_commit).modified_files == ["tracked.txt"]


def test_collect_diff_fixed_baseline_fails_closed_when_commit_is_unavailable(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init", "--template=")

    with pytest.raises(RuntimeError, match="baseline commit is unavailable"):
        collect_diff(repo_dir, "0" * 40)
