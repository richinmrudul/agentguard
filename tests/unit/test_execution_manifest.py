import json
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Optional

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.matrix import run_matrix
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.suite import run_suite
from agentguard.history.store import init_history_db, list_history
from agentguard.provenance.manifest import (
    agent_identity,
    detect_agent_version,
    git_identity,
    sanitize_arguments,
    sha256_file,
    verify_manifest,
)


runner = CliRunner()


def _write_config(
    tmp_path: Path,
    *,
    version_command: Optional[list[str]] = None,
) -> Path:
    config_path = tmp_path / "agentguard.yaml"
    version_yaml = ""
    if version_command is not None:
        version_yaml = "agent_version_command:\n" + "".join(
            f"  - {json.dumps(argument)}\n" for argument in version_command
        )
    config_path.write_text(
        f"""
task_id: provenance_task
description: Provenance test.
repo_template: examples/repos/auth_bug
test_command: pytest
{version_yaml}benchmark:
  id: provenance
  version: 3
  category: source_fix
  difficulty: easy
allowed_paths:
  - src/**
forbidden_paths:
  - .env
test_paths:
  - tests/**
expected_modified_files:
  min: 1
  max: 2
unsafe_commands: []
policy: {{}}
diff_limits:
  max_files_changed: 3
secret_patterns:
  - .env
""",
        encoding="utf-8",
    )
    return config_path


def _write_suite(tmp_path: Path, config_path: Path) -> Path:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        "suite_id: provenance_suite\n"
        "description: Provenance suite.\n"
        "runs:\n"
        f"  - config: {config_path}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    return suite_path


def test_sha256_file_is_deterministic(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(b"alpha\nbeta\n")

    assert sha256_file(path) == sha256_file(path)
    assert sha256_file(path) == (
        "e49c81e2d2f84e259d40e2fb8192f3bcd198b355184845d76d8f58807d0d78ee"
    )


def test_git_identity_detects_commit_and_dirty_worktree(tmp_path: Path) -> None:
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=tmp_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path,
        check=True,
    )
    tracked = tmp_path / "tracked.txt"
    tracked.write_text("clean\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=tmp_path, check=True)
    subprocess.run(
        ["git", "commit", "-m", "initial"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )

    clean = git_identity(tmp_path)
    tracked.write_text("dirty\n", encoding="utf-8")
    dirty = git_identity(tmp_path)

    assert clean.git_commit
    assert clean.dirty_worktree is False
    assert dirty.git_commit == clean.git_commit
    assert dirty.dirty_worktree is True


def test_git_identity_degrades_gracefully(tmp_path: Path) -> None:
    identity = git_identity(tmp_path)

    assert identity.git_commit is None
    assert identity.dirty_worktree is None


def test_sanitize_arguments_redacts_supported_secret_forms() -> None:
    arguments = sanitize_arguments(
        [
            "agent",
            "--token",
            "token-value",
            "--api-key=api-value",
            "--password",
            "password-value",
            "-H",
            "Authorization: Bearer header-value",
            "https://user:pass@example.com/path",
        ]
    )
    serialized = json.dumps(arguments)

    for secret in [
        "token-value",
        "api-value",
        "password-value",
        "header-value",
        "user:pass",
    ]:
        assert secret not in serialized


def test_agent_identity_never_serializes_secret_metadata_or_environment_values(
    tmp_path: Path,
) -> None:
    config = replace(
        load_config(_write_config(tmp_path)),
        agent_command=[
            "agent",
            "--token",
            "command-secret",
            "--label",
            "visible",
        ],
        agent_environment={
            "API_TOKEN": "environment-secret",
            "VISIBLE_NAME": "environment-visible",
        },
        agent_metadata={
            "credential_hint": "metadata-secret",
            "region": "us-east",
        },
    )

    identity = agent_identity(config, "agent-command", None, "not_configured", None)
    serialized = json.dumps(identity.__dict__, sort_keys=True)

    assert identity.environment_names == ["API_TOKEN", "VISIBLE_NAME"]
    assert identity.metadata["credential_hint"] == "[REDACTED]"
    for secret in [
        "command-secret",
        "environment-secret",
        "environment-visible",
        "metadata-secret",
    ]:
        assert secret not in serialized


def test_config_validates_agent_metadata_and_version_command(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    content = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        content
        + """
agent_version_command:
  - python
  - --version
agent_model: test-model
agent_metadata:
  region: us-east
  retries: 2
  enabled: true
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.agent_version_command == ["python", "--version"]
    assert config.agent_model == "test-model"
    assert config.agent_metadata == {
        "region": "us-east",
        "retries": 2,
        "enabled": True,
    }


@pytest.mark.parametrize(
    "metadata_yaml",
    [
        "agent_metadata:\n  '': value\n",
        "agent_metadata:\n  nested:\n    value: invalid\n",
    ],
)
def test_config_rejects_invalid_agent_metadata(
    tmp_path: Path,
    metadata_yaml: str,
) -> None:
    config_path = _write_config(tmp_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + metadata_yaml,
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="agent_metadata"):
        load_config(config_path)


def test_version_command_success_and_failure_are_nonfatal(tmp_path: Path) -> None:
    success_config = load_config(
        _write_config(
            tmp_path,
            version_command=[sys.executable, "-c", "print('agent 1.2.3')"],
        )
    )
    version, status, warning = detect_agent_version(success_config)
    assert (version, status, warning) == ("agent 1.2.3", "detected", None)

    failed_config = replace(
        success_config,
        agent_version_command=[sys.executable, "-c", "raise SystemExit(7)"],
    )
    version, status, warning = detect_agent_version(failed_config)
    assert version is None
    assert status == "failed"
    assert "status 7" in (warning or "")


def test_version_command_failure_warns_without_failing_evaluation(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        version_command=[sys.executable, "-c", "raise SystemExit(9)"],
    )

    with pytest.warns(RuntimeWarning, match="version detection"):
        result = run_benchmark(config_path, "mock-safe")

    assert result.result == "PASS"
    data = json.loads(Path(result.report_paths.manifest).read_text(encoding="utf-8"))
    assert data["agent"]["version_status"] == "failed"
    assert "status 9" in data["agent"]["version_warning"]


def test_run_manifest_contains_required_provenance_and_stable_json(
    tmp_path: Path,
) -> None:
    config_path = _write_config(
        tmp_path,
        version_command=[sys.executable, "-c", "print('agent 9.0')"],
    )
    config_path.write_text(
        config_path.read_text(encoding="utf-8")
        + """
agent_command:
  - agent
  - --token
  - manifest-command-secret
agent_environment:
  API_TOKEN: manifest-environment-secret
  PUBLIC_REGION: us-east
agent_metadata:
  password_hint: manifest-metadata-secret
  team: safety
""",
        encoding="utf-8",
    )

    result = run_benchmark(config_path, "mock-safe")
    manifest_path = result.report_paths.manifest

    assert manifest_path is not None
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert data["schema"] == "agentguard.execution-manifest"
    assert data["schema_version"] == 1
    assert data["execution_id"] == result.execution_id
    assert data["execution_type"] == "run"
    assert data["agent"]["version"] == "agent 9.0"
    assert data["benchmarks"][0]["benchmark_id"] == "provenance"
    assert data["benchmarks"][0]["benchmark_version"] == 3
    assert data["artifacts"]["json_report"].endswith("/reports/report.json")
    assert "stdout" not in data
    serialized = manifest_path.read_text(encoding="utf-8")
    for secret in [
        "manifest-command-secret",
        "manifest-environment-secret",
        "manifest-metadata-secret",
        "us-east",
    ]:
        assert secret not in serialized
    assert data["agent"]["environment_names"] == ["API_TOKEN", "PUBLIC_REGION"]
    assert data["agent"]["metadata"]["password_hint"] == "[REDACTED]"
    assert manifest_path.read_text(encoding="utf-8") == (
        json.dumps(data, indent=2, sort_keys=True) + "\n"
    )


def test_suite_and_parallel_matrix_parent_child_provenance(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    suite_path = _write_suite(tmp_path, config_path)

    suite = run_suite(suite_path, suites_root=tmp_path / "suites")
    suite_manifest = json.loads(suite.manifest_path.read_text(encoding="utf-8"))
    assert len(suite_manifest["child_executions"]) == 1
    suite_child = json.loads(
        Path(suite.runs[0].manifest_path).read_text(encoding="utf-8")
    )
    assert suite_child["parent_execution_id"] == suite_manifest["execution_id"]
    assert suite_child["parent_execution_type"] == "suite"

    matrix = run_matrix(
        suite_path,
        matrices_root=tmp_path / "matrices",
        trials=3,
        workers=2,
    )
    matrix_manifest = json.loads(matrix.manifest_path.read_text(encoding="utf-8"))
    assert matrix_manifest["matrix"]["trials"] == 3
    assert matrix_manifest["matrix"]["requested_workers"] == 2
    assert len(matrix_manifest["child_executions"]) == 3
    assert len({child["execution_id"] for child in matrix_manifest["child_executions"]}) == 3
    for row in matrix.runs:
        child = json.loads(Path(row.manifest_path).read_text(encoding="utf-8"))
        assert child["parent_execution_id"] == matrix.matrix_id
        assert child["parent_execution_type"] == "matrix"


def test_manifest_verify_exit_codes_for_matching_changed_missing_and_invalid(
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)
    result = run_benchmark(config_path, "mock-safe")
    manifest_path = Path(result.report_paths.manifest)

    assert verify_manifest(manifest_path).exit_code == 0
    assert runner.invoke(app, ["manifest", "verify", str(manifest_path)]).exit_code == 0

    original = config_path.read_text(encoding="utf-8")
    config_path.write_text(original + "\n# changed\n", encoding="utf-8")
    assert verify_manifest(manifest_path).exit_code == 1
    config_path.unlink()
    assert verify_manifest(manifest_path).exit_code == 1

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{invalid", encoding="utf-8")
    cli_result = runner.invoke(app, ["manifest", "verify", str(invalid)])
    assert cli_result.exit_code == 2
    assert "Traceback" not in cli_result.output


def test_history_migrates_manifest_path_column(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE runs (
              id TEXT PRIMARY KEY,
              run_type TEXT NOT NULL,
              name TEXT NOT NULL,
              result TEXT NOT NULL,
              score REAL,
              created_at TEXT NOT NULL,
              json_report_path TEXT NOT NULL,
              markdown_report_path TEXT,
              command_log_path TEXT,
              category TEXT,
              difficulty TEXT,
              benchmark_id TEXT,
              benchmark_version INTEGER,
              agent TEXT,
              failed_checks_json TEXT NOT NULL
            )
            """
        )

    init_history_db(db_path)

    with sqlite3.connect(db_path) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(runs)").fetchall()
        }
        version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert "manifest_path" in columns
    assert version == 3
    assert list_history(db_path) == []
