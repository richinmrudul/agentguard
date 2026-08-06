import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.ci import run_ci
from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner as CommandTestRunner
from agentguard.presets import get_preset, preset_names


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


def test_all_presets_load_and_evaluate_through_production_ci_path(
    tmp_path: Path,
) -> None:
    for preset_name in preset_names():
        root = tmp_path / preset_name
        _repository(root)
        initialized = runner.invoke(
            app,
            [
                "init",
                str(root),
                "--no-ci",
                "--preset",
                preset_name,
                "--test-command",
                f'{sys.executable} -c "raise SystemExit(0)"',
            ],
        )
        config = load_config(root / "agentguard.yaml")
        result = run_ci(
            root / "agentguard.yaml",
            repo_dir=root,
            ci_root=tmp_path / "ci-results" / preset_name,
        )

        assert initialized.exit_code == 0, initialized.output
        assert result.result == "PASS"
        assert config.command_timeout_seconds == get_preset(
            preset_name
        ).settings.command_timeout_seconds
        assert result.report_paths.json.exists()


def test_preset_thresholds_change_actual_ci_validation_behavior(
    tmp_path: Path,
) -> None:
    outcomes = {}
    for preset_name in preset_names():
        root = tmp_path / preset_name
        _repository(root)
        initialized = runner.invoke(
            app,
            [
                "init",
                str(root),
                "--no-ci",
                "--preset",
                preset_name,
                "--test-command",
                f'{sys.executable} -c "raise SystemExit(0)"',
            ],
        )
        assert initialized.exit_code == 0, initialized.output
        _git(root, "add", "agentguard.yaml", ".gitignore")
        _git(
            root,
            "-c",
            "user.name=AgentGuard",
            "-c",
            "user.email=agentguard@example.local",
            "commit",
            "-m",
            "Add AgentGuard",
        )
        for index in range(60):
            (root / f"change-{index:02d}.txt").write_text("change\n", encoding="utf-8")
        result = run_ci(
            root / "agentguard.yaml",
            repo_dir=root,
            ci_root=tmp_path / "threshold-results" / preset_name,
        )
        outcomes[preset_name] = {
            check.name: (check.passed, check.severity)
            for check in result.check_results
        }

    assert outcomes["minimal"]["Scope adherence"] == (True, "warning")
    assert outcomes["minimal"]["Diff size"] == (True, "warning")
    assert outcomes["recommended"]["Scope adherence"] == (False, "warning")
    assert outcomes["recommended"]["Diff size"] == (False, "warning")
    assert outcomes["strict"]["Scope adherence"] == (False, "error")
    assert outcomes["strict"]["Diff size"] == (False, "error")


def test_generated_execution_limits_are_consumed_by_ci_test_runner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    observed = []

    class RecordingTestRunner:
        def __init__(self, tracker, timeout_seconds: int, max_output_bytes: int):
            observed.append((timeout_seconds, max_output_bytes))

        def run(self, repo_dir: Path, command: str) -> CommandResult:
            return CommandResult(
                command=command,
                exit_code=0,
                stdout="",
                stderr="",
                duration_seconds=0.0,
            )

    monkeypatch.setattr("agentguard.core.ci.TestRunner", RecordingTestRunner)
    for preset_name in preset_names():
        root = tmp_path / preset_name
        _repository(root)
        initialized = runner.invoke(
            app,
            [
                "init",
                str(root),
                "--no-ci",
                "--preset",
                preset_name,
                "--test-command",
                "python -m pytest",
            ],
        )
        assert initialized.exit_code == 0, initialized.output
        run_ci(
            root / "agentguard.yaml",
            repo_dir=root,
            ci_root=tmp_path / "runner-results" / preset_name,
        )

    assert observed == [
        (
            get_preset(name).settings.command_timeout_seconds,
            get_preset(name).settings.max_output_bytes,
        )
        for name in preset_names()
    ]


def test_strict_builtin_detectors_change_actual_ci_secret_validation(
    tmp_path: Path,
) -> None:
    outcomes = {}
    for preset_name in ("recommended", "strict"):
        root = tmp_path / preset_name
        _repository(root)
        initialized = runner.invoke(
            app,
            [
                "init",
                str(root),
                "--no-ci",
                "--preset",
                preset_name,
                "--test-command",
                f'{sys.executable} -c "raise SystemExit(0)"',
            ],
        )
        assert initialized.exit_code == 0, initialized.output
        _git(root, "add", "agentguard.yaml", ".gitignore")
        _git(
            root,
            "-c",
            "user.name=AgentGuard",
            "-c",
            "user.email=agentguard@example.local",
            "commit",
            "-m",
            "Add AgentGuard",
        )
        fake_token = "ghp_" + ("A" * 24)
        (root / "client.py").write_text(
            f'TOKEN = "{fake_token}"\n', encoding="utf-8"
        )
        result = run_ci(
            root / "agentguard.yaml",
            repo_dir=root,
            ci_root=tmp_path / "secret-results" / preset_name,
        )
        secret_check = next(
            check for check in result.check_results if check.name == "Secret scan"
        )
        outcomes[preset_name] = secret_check

    assert outcomes["recommended"].passed is True
    assert outcomes["strict"].passed is False
    assert "github-token-shape" in " ".join(outcomes["strict"].evidence)
