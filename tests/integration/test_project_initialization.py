import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.ci import run_ci
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner as CommandTestRunner


runner = CliRunner()


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )


def _repository(root: Path) -> None:
    root.mkdir()
    _git(root, "init")
    _git(root, "branch", "-M", "main")
    (root / "src.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(root, "add", "src.py")
    _git(
        root,
        "-c",
        "user.name=AgentGuard",
        "-c",
        "user.email=agentguard@example.local",
        "commit",
        "-m",
        "Initial state",
    )


def test_initialized_repository_can_run_first_ci_evaluation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _repository(root)

    initialized = runner.invoke(
        app,
        [
            "init",
            str(root),
            "--no-ci",
            "--test-command",
            f"{sys.executable} -c \"raise SystemExit(0)\"",
        ],
    )
    (root / "src.py").write_text("VALUE = 2\n", encoding="utf-8")
    result = run_ci(
        root / "agentguard.yaml",
        repo_dir=root,
        ci_root=tmp_path / "ci-results",
    )

    assert initialized.exit_code == 0, initialized.output
    assert result.result == "PASS"
    assert result.test_result.exit_code == 0
    assert result.report_paths.json.exists()
    assert result.report_paths.markdown.exists()


def test_parent_directory_initialization_produces_reusable_strict_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    parent = tmp_path / "parent"
    root = parent / "project café"
    parent.mkdir()
    root.mkdir()
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    monkeypatch.chdir(parent)

    result = runner.invoke(app, ["init", root.name, "--ci", "github"])
    config = load_config(root / "agentguard.yaml")

    assert result.exit_code == 0, result.output
    assert config.test_command == "python -m pytest"
    assert (root / ".github/workflows/agentguard.yml").is_file()


def test_explicit_test_command_metacharacters_are_not_shell_injectable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    marker = root / "injected"
    command = (
        f"{sys.executable} -c \"raise SystemExit(0)\" ; "
        f"touch {marker}"
    )

    initialized = runner.invoke(
        app,
        ["init", str(root), "--no-ci", "--test-command", command],
    )
    config = load_config(root / "agentguard.yaml")
    test_result = CommandTestRunner(CommandTracker()).run(root, config.test_command)

    assert initialized.exit_code == 0, initialized.output
    assert test_result.exit_code == 0
    assert not marker.exists()
