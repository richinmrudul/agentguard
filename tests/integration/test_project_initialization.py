import os
import shutil
import shlex
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.ci import run_ci
from agentguard.core.result import CommandResult
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner as CommandTestRunner
from agentguard.presets import get_preset, preset_names
from agentguard.project_init import build_initialization_plan


runner = CliRunner()


def _write_fixture_wheel(
    wheelhouse: Path,
    *,
    distribution: str,
    version: str,
    files: dict[str, str],
) -> Path:
    normalized = distribution.replace("-", "_")
    dist_info = f"{normalized}-{version}.dist-info"
    members = {
        **files,
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {distribution}\n"
            f"Version: {version}\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: agentguard-test-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }
    record_path = f"{dist_info}/RECORD"
    members[record_path] = "".join(f"{name},,\n" for name in (*members, record_path))
    wheelhouse.mkdir(parents=True, exist_ok=True)
    wheel = wheelhouse / f"{normalized}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return wheel


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


def test_detected_pytest_requirements_prepare_disposable_environment_then_tests_run(
    tmp_path: Path,
) -> None:
    root = tmp_path / "Python project café 日本語"
    tests = root / "tests"
    root.mkdir(parents=True)
    tests.mkdir()
    (root / "pytest.ini").write_text("[pytest]\ntestpaths = tests\n", encoding="utf-8")
    (root / "requirements.txt").write_text(
        "agentguard-fixture-dependency==1\n", encoding="utf-8"
    )
    marker = root / "tests-ran"
    (tests / "test_fixture.py").write_text(
        "from pathlib import Path\n"
        "from fixture_value import VALUE\n\n"
        "def test_declared_dependency_is_available():\n"
        "    Path('tests-ran').write_text('yes\\n', encoding='utf-8')\n"
        "    assert VALUE == 42\n",
        encoding="utf-8",
    )

    initialized = runner.invoke(app, ["init", str(root), "--ci", "github"])
    plan = build_initialization_plan(root, ci="github")

    assert initialized.exit_code == 0, initialized.output
    assert not marker.exists(), "initialization must not install or execute repository code"
    assert plan.python_setup_commands == (
        "python -m pip install --requirement requirements.txt",
        "python -m pip install pytest",
    )

    wheelhouse = tmp_path / "fixture-wheels"
    _write_fixture_wheel(
        wheelhouse,
        distribution="agentguard-fixture-dependency",
        version="1",
        files={"fixture_value.py": "VALUE = 42\n"},
    )
    _write_fixture_wheel(
        wheelhouse,
        distribution="pytest",
        version="99.0",
        files={
            "pytest/__init__.py": "",
            "pytest/__main__.py": (
                "from pathlib import Path\n"
                "import runpy\n\n"
                "for test_file in sorted(Path('tests').glob('test_*.py')):\n"
                "    namespace = runpy.run_path(str(test_file))\n"
                "    for name, value in sorted(namespace.items()):\n"
                "        if name.startswith('test_') and callable(value):\n"
                "            value()\n"
            ),
        },
    )
    environment = tmp_path / "clean-python"
    venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    for module in ("pytest", "fixture_value"):
        missing = subprocess.run(
            [str(python), "-c", f"import {module}"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        assert missing.returncode != 0

    pip_environment = {
        **os.environ,
        "PIP_FIND_LINKS": str(wheelhouse),
        "PIP_NO_INDEX": "1",
    }
    for command in plan.python_setup_commands:
        argv = shlex.split(command)
        argv[0] = str(python)
        installed = subprocess.run(
            argv,
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            env=pip_environment,
        )
        assert installed.returncode == 0, installed.stderr
    tested = subprocess.run(
        [str(python), "-m", "pytest", "-q"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert tested.returncode == 0, tested.stderr
    assert marker.read_text(encoding="utf-8") == "yes\n"


def test_node_fixture_initialization_is_inert_then_native_tests_run(
    tmp_path: Path,
) -> None:
    if shutil.which("node") is None:
        pytest.skip("Node.js is not installed")
    root = tmp_path / "Node project café 日本語"
    root.mkdir()
    (root / "package.json").write_text(
        '{"name":"agentguard-node-fixture","scripts":{"test":"node --test"}}\n',
        encoding="utf-8",
    )
    test_dir = root / "test"
    test_dir.mkdir()
    marker = root / "node-test-ran"
    (test_dir / "onboarding.test.js").write_text(
        "const fs = require('node:fs');\n"
        "const test = require('node:test');\n"
        "const assert = require('node:assert/strict');\n"
        "test('onboarding', () => {\n"
        "  fs.writeFileSync('node-test-ran', 'yes\\n');\n"
        "  assert.equal(2 + 2, 4);\n"
        "});\n",
        encoding="utf-8",
    )

    initialized = runner.invoke(app, ["init", str(root), "--no-ci"])
    config = load_config(root / "agentguard.yaml")

    assert initialized.exit_code == 0, initialized.output
    assert config.test_command == "node --test"
    assert not marker.exists(), "initialization must not execute repository tests"

    test_result = CommandTestRunner(CommandTracker()).run(root, config.test_command)

    assert test_result.exit_code == 0, test_result.stderr
    assert marker.read_text(encoding="utf-8") == "yes\n"


def test_go_fixture_initialization_is_inert_then_module_tests_run(
    tmp_path: Path,
) -> None:
    if shutil.which("go") is None:
        pytest.skip("Go is not installed")
    root = tmp_path / "Go project café 日本語"
    root.mkdir()
    (root / "go.mod").write_text(
        "module example.com/agentguard-go-fixture\n\ngo 1.20\n",
        encoding="utf-8",
    )
    marker = root / "go-test-ran"
    (root / "onboarding_test.go").write_text(
        "package onboarding\n\n"
        "import (\n"
        '\t"os"\n'
        '\t"testing"\n'
        ")\n\n"
        "func TestOnboarding(t *testing.T) {\n"
        '\tif err := os.WriteFile("go-test-ran", []byte("yes\\n"), 0o600); err != nil {\n'
        "\t\tt.Fatal(err)\n"
        "\t}\n"
        "}\n",
        encoding="utf-8",
    )

    initialized = runner.invoke(app, ["init", str(root), "--no-ci"])
    config = load_config(root / "agentguard.yaml")

    assert initialized.exit_code == 0, initialized.output
    assert config.test_command == "go test ./..."
    assert not marker.exists(), "initialization must not execute repository tests"

    tracker = CommandTracker()
    test_result = CommandTestRunner(tracker).run(root, config.test_command)

    assert test_result.exit_code == 0, test_result.stderr
    assert tracker.events[0].command == ["go", "test", "./..."]
    assert marker.read_text(encoding="utf-8") == "yes\n"


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
