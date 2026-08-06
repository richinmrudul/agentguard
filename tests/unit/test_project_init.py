import re
import subprocess
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.project_init import (
    CONFIG_PATH,
    GITHUB_WORKFLOW_PATH,
    UNKNOWN_TEST_COMMAND,
)


runner = CliRunner()
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
ANSI_STYLE = re.compile(r"\x1b\[[0-9;]*m")


def _invoke(root: Path, *args: str):
    return runner.invoke(app, ["init", str(root), *args])


def _python_project(root: Path) -> None:
    root.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\n\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n",
        encoding="utf-8",
    )


def _workflow(root: Path) -> dict:
    return yaml.safe_load((root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8"))


def test_init_basic_python_project_generates_strict_valid_config(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _python_project(root)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    config = load_config(root / CONFIG_PATH)
    assert config.mode == "ci"
    assert config.test_command == "python -m pytest"
    assert "Detected project type: Python" in result.output
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert (root / ".gitignore").read_text(encoding="utf-8") == ".agentguard/\n"


def test_explicit_test_command_is_preserved_as_one_yaml_value(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    command = "python -m pytest -k \"safe or quoted\"; echo $TOKEN && touch /tmp/no"

    result = _invoke(root, "--test-command", command, "--no-ci")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == command
    assert command not in result.output
    assert "Test command: supplied with --test-command" in result.output


def test_unknown_project_uses_failing_customization_placeholder(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND
    assert "No safe test command was detected" in (
        root / CONFIG_PATH
    ).read_text(encoding="utf-8")
    assert "Detected project type: unknown" in result.output


def test_github_workflow_is_valid_least_privilege_and_pinned(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _python_project(root)

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 0, result.output
    workflow = _workflow(root)
    assert workflow["permissions"] == {"contents": "read"}
    assert "pull_request_target" not in workflow
    assert "pull_request" in workflow.get("on", workflow.get(True))
    steps = workflow["jobs"]["agentguard"]["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert uses
    assert all(FULL_SHA.fullmatch(item.rsplit("@", 1)[1]) for item in uses)
    source = (root / GITHUB_WORKFLOW_PATH).read_text(encoding="utf-8")
    assert "agentguard-evals==0.2.2" in source
    assert "agentguard ci --config agentguard.yaml" in source
    assert "--base \"$AGENTGUARD_BASE_SHA\" --head HEAD --github-summary" in source
    assert "secrets." not in source
    assert "id-token" not in source


def test_no_ci_does_not_generate_workflow(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert "rerun with --ci github" in result.output


def test_dry_run_leaves_project_byte_for_byte_unchanged(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    existing = root / "keep.txt"
    existing.write_bytes(b"\x00original\n")
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*")}

    result = _invoke(root, "--dry-run", "--ci", "github")

    after = {path.relative_to(root): path.read_bytes() for path in root.rglob("*")}
    assert result.exit_code == 0, result.output
    assert before == after
    assert "Would create:" in result.output
    assert "Dry run complete" in result.output


def test_default_refuses_nonidentical_existing_config_without_partial_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    config = root / CONFIG_PATH
    config.write_text("user: config\n", encoding="utf-8")

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 1
    assert config.read_text(encoding="utf-8") == "user: config\n"
    assert not (root / ".gitignore").exists()
    assert not (root / GITHUB_WORKFLOW_PATH).exists()
    assert "Conflict:\n- agentguard.yaml" in result.output


def test_force_replaces_only_owned_targets(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / CONFIG_PATH).write_text("user: config\n", encoding="utf-8")
    workflow = root / GITHUB_WORKFLOW_PATH
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: user workflow\n", encoding="utf-8")
    unrelated = root / ".github/workflows/build.yml"
    unrelated.write_text("name: keep me\n", encoding="utf-8")
    readme = root / "README.md"
    readme.write_text("keep me\n", encoding="utf-8")

    result = _invoke(root, "--force", "--ci", "github", "--test-command", "pytest")

    assert result.exit_code == 0, result.output
    assert load_config(root / CONFIG_PATH).test_command == "pytest"
    assert "agentguard-evals==0.2.2" in workflow.read_text(encoding="utf-8")
    assert unrelated.read_text(encoding="utf-8") == "name: keep me\n"
    assert readme.read_text(encoding="utf-8") == "keep me\n"


def test_identical_rerun_is_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    _python_project(root)
    first = _invoke(root, "--ci", "github")
    before = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}

    second = _invoke(root, "--ci", "github")

    after = {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}
    assert first.exit_code == second.exit_code == 0
    assert before == after
    assert "Already current:" in second.output


def test_gitignore_is_preserved_and_entry_is_deduplicated(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ignore = root / ".gitignore"
    ignore.write_text("dist/\n.agentguard/\ncustom/\n", encoding="utf-8")

    first = _invoke(root, "--no-ci")
    second = _invoke(root, "--no-ci")

    assert first.exit_code == second.exit_code == 0
    assert ignore.read_text(encoding="utf-8") == "dist/\n.agentguard/\ncustom/\n"
    assert ignore.read_text(encoding="utf-8").count(".agentguard/") == 1


def test_gitignore_addition_preserves_unrelated_content_without_force(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    ignore = root / ".gitignore"
    ignore.write_text("dist/\ncustom/\n", encoding="utf-8")

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert ignore.read_text(encoding="utf-8") == "dist/\ncustom/\n.agentguard/\n"
    assert "Updated:\n- .gitignore" in result.output


def test_existing_user_workflow_is_not_overwritten_without_force(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    workflow = root / GITHUB_WORKFLOW_PATH
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: custom\n", encoding="utf-8")

    result = _invoke(root, "--ci", "github")

    assert result.exit_code == 1
    assert workflow.read_text(encoding="utf-8") == "name: custom\n"


def test_symlink_escape_is_rejected_without_writing_outside(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / ".github").symlink_to(outside, target_is_directory=True)

    result = _invoke(root, "--ci", "github", "--force")

    assert result.exit_code == 2
    assert "escapes project root" in result.output
    assert not (outside / "workflows/agentguard.yml").exists()
    assert not (root / CONFIG_PATH).exists()


def test_dangling_parent_symlink_is_rejected_without_partial_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".github").symlink_to(tmp_path / "missing", target_is_directory=True)

    result = _invoke(root, "--ci", "github", "--force")

    assert result.exit_code == 2
    assert "unsafe parent symlink" in result.output
    assert not (root / CONFIG_PATH).exists()


def test_escaping_symlink_file_is_rejected_even_with_force(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("keep\n", encoding="utf-8")
    (root / CONFIG_PATH).symlink_to(outside)

    result = _invoke(root, "--force", "--no-ci")

    assert result.exit_code == 2
    assert outside.read_text(encoding="utf-8") == "keep\n"


def test_detection_does_not_follow_project_signal_symlink_outside_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside-pyproject.toml"
    outside.write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (root / "pyproject.toml").symlink_to(outside)

    result = _invoke(root, "--no-ci")

    assert result.exit_code == 0, result.output
    assert "Detected project type: unknown" in result.output
    assert load_config(root / CONFIG_PATH).test_command == UNKNOWN_TEST_COMMAND


def test_spaces_unicode_and_parent_directory_path_work(tmp_path: Path, monkeypatch) -> None:
    parent = tmp_path / "parent"
    root = parent / "space café 日本語"
    parent.mkdir()
    root.mkdir()
    monkeypatch.chdir(parent)

    result = runner.invoke(app, ["init", root.name, "--no-ci", "--test-command", "pytest"])

    assert result.exit_code == 0, result.output
    assert (root / CONFIG_PATH).exists()
    assert root.name in result.output


def test_init_from_target_directory_uses_current_directory(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)

    result = runner.invoke(app, ["init", "--no-ci", "--test-command", "pytest"])

    assert result.exit_code == 0, result.output
    assert (root / CONFIG_PATH).exists()
    assert "Initialized AgentGuard in ." in result.output


def test_detection_never_executes_repository_commands(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repo"
    _python_project(root)
    (root / "setup.py").write_text("raise SystemExit('must not execute')\n", encoding="utf-8")

    def fail(*args, **kwargs):
        raise AssertionError(f"unexpected command execution: {args!r} {kwargs!r}")

    monkeypatch.setattr(subprocess, "run", fail)

    result = _invoke(root, "--dry-run", "--ci", "github")

    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("--ci", "gitlab"), "supports only 'github'"),
        (("--ci", "github", "--no-ci"), "cannot be used together"),
        (("--test-command", "   "), "non-empty"),
    ],
)
def test_invalid_options_have_concise_errors_without_tracebacks(
    tmp_path: Path,
    args: tuple[str, ...],
    message: str,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()

    result = _invoke(root, *args)

    assert result.exit_code == 2
    assert message in result.output
    assert "Traceback" not in result.output


def test_help_documents_final_interface() -> None:
    result = runner.invoke(app, ["init", "--help"])

    assert result.exit_code == 0
    help_text = ANSI_STYLE.sub("", result.output)
    assert "path" in help_text.lower()
    for option in ("--dry-run", "--force", "--ci", "--no-ci", "--test-command"):
        assert option in help_text
