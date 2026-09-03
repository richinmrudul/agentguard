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
    assert report["repo_dir"] == "${REPOSITORY_ROOT}"
    assert report["command_log_path"] == "${RUN_ROOT}/command_log.json"
    assert str(tmp_path) not in result.report_paths.json.read_text(encoding="utf-8")
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


def test_ci_cli_writes_github_step_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / ".env", "TOKEN=secret\n")
    config_path = _config(tmp_path, task_id="ci_summary")
    summary_path = tmp_path / "github summary ü" / "summary file.md"
    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    result = runner.invoke(
        app,
        [
            "ci",
            "--config",
            str(config_path),
            "--github-summary",
            "--allow-fail-result",
        ],
    )

    assert result.exit_code == 0
    assert "GitHub summary: written." in result.output
    assert summary_path.exists()
    summary = summary_path.read_text(encoding="utf-8")
    assert "## AgentGuard CI Report" in summary
    assert "- Result: **FAIL**" in summary
    assert "- [critical] Forbidden paths:" in summary


def test_ci_cli_reports_summary_directory_failure_after_pass_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    config_path = _config(tmp_path, task_id="ci_summary_directory")
    private_path = tmp_path / "private hostile\nsummary"
    private_path.mkdir()
    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(private_path))

    result = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--github-summary"],
    )

    assert result.exit_code == 2
    assert "AgentGuard CI Report" in result.output
    assert "Result: PASS" in result.output
    assert "GitHub step summary could not be written" in result.output
    assert "was not published to the step summary" in result.output
    assert "GitHub summary: written." not in result.output
    assert str(private_path) not in result.output
    assert "Traceback" not in result.output


def test_ci_cli_summary_failure_preserves_fail_result_visibility(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / ".env", "TOKEN=secret\n")
    config_path = _config(tmp_path, task_id="ci_summary_failed_gate")
    summary_directory = tmp_path / "summary-directory"
    summary_directory.mkdir()
    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_directory))

    result = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--github-summary"],
    )

    assert result.exit_code == 2
    assert "Result: FAIL" in result.output
    assert "GitHub step summary could not be written" in result.output
    assert "Traceback" not in result.output


def test_ci_cli_rejects_empty_summary_destination(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    config_path = _config(tmp_path, task_id="ci_summary_empty")
    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", "")

    result = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--github-summary"],
    )

    assert result.exit_code == 2
    assert "Result: PASS" in result.output
    assert "GitHub step summary could not be written" in result.output
    assert "GITHUB_STEP_SUMMARY is not set" not in result.output
    assert "Traceback" not in result.output


def test_ci_cli_prepares_one_combined_summary_append(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    config_path = _config(tmp_path, task_id="ci_summary_second_append")
    summary_path = tmp_path / "summary.md"
    summary_path.write_text("Existing summary\n", encoding="utf-8")
    original_open = Path.open
    summary_opens = 0

    def fail_second_summary_open(
        path: Path,
        *args: object,
        **kwargs: object,
    ):
        nonlocal summary_opens
        if path == summary_path and args and args[0] == "a":
            summary_opens += 1
            if summary_opens == 2:
                raise OSError("second append failed at /private/hostile")
        return original_open(path, *args, **kwargs)

    monkeypatch.chdir(repo_dir)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.setattr(Path, "open", fail_second_summary_open)

    result = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--github-summary"],
    )

    assert result.exit_code == 0
    assert summary_opens == 0
    summary = summary_path.read_text(encoding="utf-8")
    assert summary.startswith("Existing summary\n")
    assert "## AgentGuard CI Report" in summary
    assert "## AgentGuard baseline comparison" in summary
    assert "Result: PASS" in result.output
    assert "/private/hostile" not in result.output
    assert "Traceback" not in result.output


def test_ci_cli_warns_when_github_summary_env_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / "src" / "app.py", "VALUE = 2\n")
    config_path = _config(tmp_path, task_id="ci_missing_summary")
    monkeypatch.chdir(repo_dir)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    result = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--github-summary"],
    )

    assert result.exit_code == 0
    assert (
        "Warning: --github-summary was provided but GITHUB_STEP_SUMMARY is not set."
        in result.output
    )
    assert "AgentGuard CI Report" in result.output


def test_ci_cli_compares_actual_report_and_preserves_conservative_gate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / ".env", "TOKEN=secret\n")
    config_path = _config(tmp_path, task_id="ci_baseline_pr")
    baseline_result = run_ci(
        config_path,
        repo_dir=repo_dir,
        ci_root=tmp_path / "baseline-run",
    )
    _write(repo_dir / "secrets" / "new.key", "not-a-real-secret\n")
    output = tmp_path / "pr-report.json"
    monkeypatch.chdir(repo_dir)

    gated = runner.invoke(
        app,
        [
            "ci",
            "--config",
            str(config_path),
            "--baseline-report",
            str(baseline_result.report_paths.json),
            "--pr-report",
            str(output),
        ],
    )

    assert gated.exit_code == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["baseline"]["status"] == "available"
    assert report["counts"]["new"] > 0
    assert report["counts"]["existing"] > 0
    assert report["gate"] == "all-blocking-findings"
    assert "Baseline findings: available" in gated.output


def test_ci_cli_invalid_baseline_is_reported_but_does_not_mask_result(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    _write(repo_dir / ".env", "TOKEN=secret\n")
    config_path = _config(tmp_path, task_id="ci_invalid_baseline")
    invalid = tmp_path / "baseline.json"
    invalid.write_text("{", encoding="utf-8")
    output = tmp_path / "pr-report.json"
    monkeypatch.chdir(repo_dir)

    result = runner.invoke(
        app,
        [
            "ci",
            "--config",
            str(config_path),
            "--baseline-report",
            str(invalid),
            "--pr-report",
            str(output),
        ],
    )

    assert result.exit_code == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["baseline"]["status"] == "invalid"
    assert report["counts"]["new"] == 0
    assert report["counts"]["unclassified"] > 0


def test_ci_cli_requires_base_and_head_together(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_dir = _init_repo(tmp_path)
    config_path = _config(tmp_path, task_id="ci_cli_refs")
    monkeypatch.chdir(repo_dir)

    missing_head = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--base", "main"],
    )
    missing_base = runner.invoke(
        app,
        ["ci", "--config", str(config_path), "--head", "HEAD"],
    )

    assert missing_head.exit_code == 2
    assert "--base and --head must be provided together." in missing_head.output
    assert missing_base.exit_code == 2
    assert "--base and --head must be provided together." in missing_base.output
