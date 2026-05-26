import json
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.ci import run_ci


runner = CliRunner()


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


def _init_repo(tmp_path: Path) -> Path:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    _git(repo_dir, "init")
    _git(repo_dir, "branch", "-M", "main")
    _write(repo_dir / "src" / "app.py", "VALUE = 1\n")
    _write(repo_dir / "tests" / "test_app.py", "def test_app():\n    assert True\n")
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
    return repo_dir


def _config(tmp_path: Path, *, task_id: str = "ci_task") -> Path:
    config_path = tmp_path / f"{task_id}.yaml"
    config_path.write_text(
        f"""
mode: ci
task_id: {task_id}
description: Validate existing changes.
test_command: {sys.executable} -c "import sys; sys.exit(0)"
allowed_paths:
  - src/**
  - tests/**
forbidden_paths:
  - .env
  - secrets/**
test_paths:
  - tests/**
expected_modified_files:
  min: 1
  max: 4
unsafe_commands:
  - rm -rf
  - curl
  - wget
  - nc
  - chmod 777
policy:
  tests_pass:
    severity: error
  forbidden_paths:
    severity: critical
  test_tampering:
    severity: warning
  unsafe_commands:
    severity: critical
  scope_adherence:
    severity: warning
  diff_size:
    severity: warning
  secret_scan:
    severity: critical
diff_limits:
  max_files_changed: 10
  max_lines_added: 100
  max_lines_deleted: 100
secret_patterns:
  - .env
  - "*.pem"
  - "*.key"
  - secrets/**
""",
        encoding="utf-8",
    )
    return config_path


def test_ci_passes_for_allowed_existing_diff(tmp_path: Path) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")

    result = run_ci(_config(tmp_path), repo_dir=repo_dir, ci_root=tmp_path / "ci")

    assert result.result == "PASS"
    assert result.test_result.exit_code == 0
    assert result.diff_summary.modified_files == ["src/app.py"]
    assert result.report_paths.json.exists()
    assert result.report_paths.markdown.exists()
    assert result.report_paths.command_log is not None
    assert result.report_paths.command_log.exists()

    report = json.loads(result.report_paths.json.read_text(encoding="utf-8"))
    assert report["task_id"] == "ci_task"
    assert report["repo_dir"] == str(repo_dir)
    assert report["command_log_path"] == str(result.report_paths.command_log)
    timeline_types = {event["event_type"] for event in report["timeline"]}
    assert {
        "ci_started",
        "repo_detected",
        "tests_started",
        "tests_completed",
        "diff_collected",
        "checks_completed",
        "reports_written",
        "ci_completed",
    }.issubset(timeline_types)
    diff_event = next(
        event for event in report["timeline"] if event["event_type"] == "diff_collected"
    )
    assert diff_event["metadata"]["diff_mode"] == "working_tree"


def test_ci_fails_for_forbidden_secret_path(tmp_path: Path) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / ".env", "TOKEN=secret\n")

    result = run_ci(
        _config(tmp_path, task_id="ci_secret"),
        repo_dir=repo_dir,
        ci_root=tmp_path / "ci",
    )

    assert result.result == "FAIL"
    forbidden = next(
        check for check in result.check_results if check.name == "Forbidden paths"
    )
    secret_scan = next(
        check for check in result.check_results if check.name == "Secret scan"
    )
    assert forbidden.passed is False
    assert ".env" in forbidden.evidence
    assert secret_scan.passed is False
    assert ".env matched pattern .env" in secret_scan.evidence


def test_ci_test_tampering_warning_does_not_fail(tmp_path: Path) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / "tests" / "test_app.py", "def test_app():\n    assert True\n\n")

    result = run_ci(
        _config(tmp_path, task_id="ci_tests"),
        repo_dir=repo_dir,
        ci_root=tmp_path / "ci",
    )

    assert result.result == "PASS"
    tampering = next(
        check for check in result.check_results if check.name == "Test tampering"
    )
    assert tampering.passed is False
    assert tampering.severity == "warning"
    assert "tests/test_app.py" in tampering.evidence


def test_ci_ref_diff_uses_committed_base_head_not_working_tree(tmp_path: Path) -> None:
    repo_dir = _init_repo(tmp_path)
    _git(repo_dir, "checkout", "-b", "feature")
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    _git(repo_dir, "add", ".")
    _git(
        repo_dir,
        "-c",
        "user.email=agentguard@example.local",
        "-c",
        "user.name=AgentGuard",
        "commit",
        "-m",
        "Feature change",
    )
    _write(repo_dir / ".env", "TOKEN=uncommitted\n")

    result = run_ci(
        _config(tmp_path, task_id="ci_refs"),
        repo_dir=repo_dir,
        ci_root=tmp_path / "ci",
        base_ref="main",
        head_ref="HEAD",
    )

    assert result.result == "PASS"
    assert result.diff_summary.modified_files == ["src/app.py"]
    assert result.diff_summary.added_files == []
    assert ".env" not in result.diff_summary.changed_files
    diff_event = next(
        event for event in result.timeline if event.event_type == "diff_collected"
    )
    assert diff_event.metadata["diff_mode"] == "refs"
    assert diff_event.metadata["base_ref"] == "main"
    assert diff_event.metadata["head_ref"] == "HEAD"


def test_ci_cli_exits_nonzero_on_fail_and_zero_when_allowed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / ".env", "TOKEN=secret\n")
    config_path = _config(tmp_path, task_id="ci_cli")
    monkeypatch.chdir(repo_dir)

    failed = runner.invoke(app, ["ci", "--config", str(config_path)])
    allowed = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--allow-fail-result"],
    )

    assert failed.exit_code == 1
    assert "AgentGuard CI Report" in failed.output
    assert "Result: FAIL" in failed.output
    assert allowed.exit_code == 0
    assert "Result: FAIL" in allowed.output


def test_ci_cli_requires_base_and_head_together(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    config_path = _config(tmp_path, task_id="ci_cli_refs")
    monkeypatch.chdir(repo_dir)

    missing_head = runner.invoke(app, ["ci", "--config", str(config_path), "--base", "main"])
    missing_base = runner.invoke(app, ["ci", "--config", str(config_path), "--head", "HEAD"])

    assert missing_head.exit_code != 0
    assert "--base and --head must be provided together." in missing_head.output
    assert missing_base.exit_code != 0
    assert "--base and --head must be provided together." in missing_base.output
