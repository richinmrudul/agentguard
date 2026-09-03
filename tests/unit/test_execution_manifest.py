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
    MANIFEST_SCHEMA,
    agent_identity,
    detect_agent_version,
    git_identity,
    load_manifest,
    manifest_trusted_roots,
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


def test_version_command_bounds_large_output(tmp_path: Path) -> None:
    config = load_config(
        _write_config(
            tmp_path,
            version_command=[
                sys.executable,
                "-c",
                "print('agent 1.2.3'); print('x' * 2000000)",
            ],
        )
    )

    version, status, warning = detect_agent_version(config)

    assert (version, status, warning) == ("agent 1.2.3", "detected", None)


def test_version_command_interrupt_cleans_up_and_preserves_interrupt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = load_config(
        _write_config(tmp_path, version_command=[sys.executable, "--version"])
    )
    process = object()
    cleanup_calls = []

    class InterruptingCapture:
        def __init__(self, *_args, **_kwargs):
            pass

        def wait(self, timeout=None):
            raise KeyboardInterrupt("version interrupted")

        def finish(self, timeout=None):
            return None

    monkeypatch.setattr(
        "agentguard.provenance.manifest.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agentguard.provenance.manifest.BoundedProcessOutput",
        InterruptingCapture,
    )
    monkeypatch.setattr(
        "agentguard.instrumentation.processes.terminate_process_tree",
        lambda owned: cleanup_calls.append(owned),
    )

    with pytest.raises(KeyboardInterrupt, match="version interrupted"):
        detect_agent_version(config)

    assert cleanup_calls == [process]


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


def test_run_artifacts_use_portable_references_for_known_local_roots(
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)

    result = run_benchmark(config_path, "mock-safe")

    artifact_paths = [
        result.report_paths.json,
        result.report_paths.markdown,
        result.report_paths.command_log,
        result.report_paths.manifest,
        result.report_paths.trace,
    ]
    serialized = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in artifact_paths
        if path is not None
    )

    assert str(tmp_path) not in serialized
    assert "${CONFIG_ROOT}/agentguard.yaml" in serialized
    assert "${RUN_ROOT}/reports/report.json" in serialized
    assert "${REPOSITORY_ROOT}" in serialized
    assert verify_manifest(
        Path(result.report_paths.manifest),
        trusted_roots=manifest_trusted_roots(config_root=config_path.parent),
    ).exit_code == 0


def test_manifest_verification_fails_closed_for_malformed_portable_reference(
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)
    result = run_benchmark(config_path, "mock-safe")
    manifest_path = Path(result.report_paths.manifest)
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data["configuration"]["path"] = "${CONFIG_ROOT}/../agentguard.yaml"
    manifest_path.write_text(json.dumps(data), encoding="utf-8")

    verification = verify_manifest(
        manifest_path,
        trusted_roots=manifest_trusted_roots(config_root=config_path.parent),
    )

    assert verification.exit_code == 1
    assert (
        "MISSING configuration: portable reference could not be resolved"
        in verification.messages
    )
    assert str(tmp_path) not in "\n".join(verification.messages)


def test_suite_and_parallel_matrix_parent_child_provenance(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path)
    suite_path = _write_suite(tmp_path, config_path)

    suite = run_suite(suite_path, suites_root=tmp_path / "suites")
    suite_manifest = json.loads(suite.manifest_path.read_text(encoding="utf-8"))
    assert len(suite_manifest["child_executions"]) == 1
    suite_artifacts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            suite.json_report_path,
            suite.markdown_report_path,
            suite.manifest_path,
        )
    )
    assert str(tmp_path) not in suite_artifacts
    assert "${CONFIG_ROOT}/suite.yaml" in suite_artifacts
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
    matrix_artifacts = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            matrix.json_report_path,
            matrix.markdown_report_path,
            matrix.manifest_path,
        )
    )
    assert str(tmp_path) not in matrix_artifacts
    assert "${CONFIG_ROOT}/suite.yaml" in matrix_artifacts
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

    detached = verify_manifest(manifest_path)
    assert detached.exit_code == 1
    assert detached.messages == [
        "MISSING configuration: portable reference could not be resolved"
    ]
    roots = {"CONFIG_ROOT": config_path.parent}
    assert verify_manifest(manifest_path, trusted_roots=roots).exit_code == 0
    assert (
        runner.invoke(
            app,
            [
                "manifest",
                "verify",
                str(manifest_path),
                "--config-root",
                str(config_path.parent),
            ],
        ).exit_code
        == 0
    )

    original = config_path.read_text(encoding="utf-8")
    config_path.write_text(original + "\n# changed\n", encoding="utf-8")
    assert verify_manifest(manifest_path, trusted_roots=roots).exit_code == 1
    config_path.unlink()
    assert verify_manifest(manifest_path, trusted_roots=roots).exit_code == 1

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{invalid", encoding="utf-8")
    cli_result = runner.invoke(app, ["manifest", "verify", str(invalid)])
    assert cli_result.exit_code == 2
    assert "Traceback" not in cli_result.output


def test_manifest_validation_rejects_non_object_and_invalid_structure(
    tmp_path: Path,
) -> None:
    non_object = tmp_path / "list.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="root must be an object"):
        load_manifest(non_object)

    invalid_schema = tmp_path / "invalid-schema.json"
    invalid_schema.write_text(
        json.dumps({"schema": f"{MANIFEST_SCHEMA}.invalid"}),
        encoding="utf-8",
    )
    result = verify_manifest(invalid_schema)

    assert result.status == "invalid"
    assert result.exit_code == 2
    assert result.messages == ["Invalid manifest schema identifier."]


def test_manifest_verification_reports_changed_and_missing_references(
    tmp_path: Path,
) -> None:
    config_path = _write_config(tmp_path)
    run = run_benchmark(config_path, "mock-safe")
    manifest_path = Path(run.report_paths.manifest)

    config_path.write_text(
        config_path.read_text(encoding="utf-8") + "\n# changed\n",
        encoding="utf-8",
    )
    changed = verify_manifest(
        manifest_path,
        trusted_roots={"CONFIG_ROOT": config_path.parent},
    )
    assert changed.status == "changed"
    assert any(
        message.startswith("CHANGED configuration:") for message in changed.messages
    )

    config_path.unlink()
    missing = verify_manifest(
        manifest_path,
        trusted_roots={"CONFIG_ROOT": config_path.parent},
    )
    assert missing.status == "changed"
    assert any(
        message.startswith("MISSING configuration:") for message in missing.messages
    )


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
    assert version == 4
    assert list_history(db_path) == []
