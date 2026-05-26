import subprocess
from pathlib import Path

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
