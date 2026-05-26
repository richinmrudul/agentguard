import subprocess
from pathlib import Path

from agentguard.repo.git_diff import collect_diff_between_refs


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
