import json
import os
import stat
import subprocess
import unicodedata
from types import SimpleNamespace
from pathlib import Path
from typing import Optional

import pytest
import yaml

from agentguard.config.loader import load_config
from agentguard.core.ci import run_ci
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.contained_run import (
    EXIT_DOCKER,
    EXIT_POLICY,
    EXIT_PREFLIGHT,
    EXIT_TIMEOUT,
    ContainedCleanupResult,
    ContainedDockerExecution,
    ContainedRunFailure,
    run_contained_agent_command,
)
from agentguard.core import contained_run
from agentguard.core.result import CommandResult
from agentguard.sandbox import docker_preflight
from agentguard.sandbox.contained_workspace import (
    ContainedPathSnapshot,
    ContainedWorkspaceLimits,
    _collect_baseline_text_files,
    _measure_file,
)
from agentguard.sandbox.docker_preflight import DockerPreflightStatus


IMAGE = "example.com/team/agent@sha256:" + "a" * 64
CONTAINER_ID = "a" * 64
CONTAINER_NAME = "agentguard-owned"
OWNER_LABEL = "agentguard.contained-run.id=owned"


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source repo"
    source.mkdir()
    (source / "hello.txt").write_text("hello\n", encoding="utf-8")
    return source


def _config(tmp_path: Path, **updates) -> Path:
    data = {
        "task_id": "contained_issue_157",
        "description": "Contained run test.",
        "repo_template": str(_source(tmp_path)),
        "test_command": "true",
        "expected_modified_files": {"min": 0, "max": 2},
        "unsafe_commands": [],
        "sandbox": {
            "type": "docker",
            "image": IMAGE,
            "network": "none",
        },
        "contained_execution": {
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
        },
    }
    data.update(updates)
    path = tmp_path / "agentguard.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _cwd_config(tmp_path: Path, **updates) -> Path:
    data = {
        "task_id": updates.pop("task_id", "contained_default_artifacts"),
        "mode": "ci",
        "description": "Contained run current-working-directory source test.",
        "test_command": "true",
        "expected_modified_files": {"min": 0, "max": 5},
        "unsafe_commands": [],
        "sandbox": {
            "type": "docker",
            "image": IMAGE,
            "network": "none",
        },
        "contained_execution": {
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
        },
    }
    data.update(updates)
    path = tmp_path / f"{data['task_id']}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _run(config_path: Path, command: list[str], tmp_path: Path, **kwargs):
    return run_contained_agent_command(
        config_path,
        command,
        runs_root=tmp_path / "runs",
        **kwargs,
    )


def _preflight(_config, *, status=DockerPreflightStatus.SUPPORTED):
    return docker_preflight.DockerPreflightResult(
        status=status,
        claim_level=(
            "linux-docker-engine"
            if status != DockerPreflightStatus.EXPERIMENTAL
            else "docker-desktop-reduced"
        ),
        supported=status
        in {DockerPreflightStatus.SUPPORTED, DockerPreflightStatus.EXPERIMENTAL},
        checks=[],
    )


def _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
    return CommandResult(
        command="contained-run",
        exit_code=0,
        stdout="ok",
        stderr="",
        duration_seconds=0.01,
    )


def test_default_contained_run_artifacts_do_not_poison_cwd_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source repo"
    source.mkdir()
    (source / "hello.txt").write_text("hello\n", encoding="utf-8")
    config_path = _cwd_config(tmp_path)
    monkeypatch.chdir(source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    first = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )
    second = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )

    assert first.result == "PASS"
    assert second.result == "PASS"
    assert first.report_path.is_file()
    assert second.report_path.is_file()
    assert first.run_dir.resolve().is_relative_to(
        source / ".agentguard" / "contained-runs"
    )
    assert second.run_dir.resolve().is_relative_to(
        source / ".agentguard" / "contained-runs"
    )
    assert ".agentguard" not in second.diff_summary.changed_files
    assert second.mutations["changed_files"] == []
    assert not (source / "workspace-lifecycle").exists()


def test_default_prior_artifacts_do_not_change_mutation_totals_or_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "hello.txt").write_text("hello\n", encoding="utf-8")
    config_path = _cwd_config(
        tmp_path,
        forbidden_paths=[".agentguard/**"],
        secret_patterns=[".agentguard/**"],
        expected_modified_files={"min": 0, "max": 0},
    )
    monkeypatch.chdir(source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    first = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )
    second = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )

    assert first.result == "PASS"
    assert second.result == "PASS"
    assert second.diff_summary.added_files == []
    assert second.diff_summary.deleted_files == []
    assert second.diff_summary.modified_files == []
    assert second.mutations["changed_files"] == []
    assert all(check.passed for check in second.check_results)


def test_default_artifact_filter_preserves_ignored_and_untracked_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (source / "ignored.txt").write_text("ignored\n", encoding="utf-8")
    (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")
    config_path = _cwd_config(tmp_path)
    monkeypatch.chdir(source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )
    captured: dict[str, list[str]] = {}

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        captured["workspace"] = sorted(
            path.relative_to(cwd).as_posix()
            for path in cwd.rglob("*")
            if path.is_file()
        )
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=fake_executor,
    )

    assert result.result == "PASS"
    assert "ignored.txt" in captured["workspace"]
    assert "untracked.txt" in captured["workspace"]


def test_default_artifact_filter_rejects_attacker_agentguard_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    (source / ".agentguard").mkdir(parents=True)
    (source / ".agentguard" / "attacker.txt").write_text("owned by user\n", encoding="utf-8")
    config_path = _cwd_config(tmp_path)
    monkeypatch.chdir(source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )

    assert result.result == "FAIL"
    assert result.failure is not None
    assert result.failure.stage == "workspace_prep"
    assert "reserved path" in result.failure.message


def test_forged_default_artifact_metadata_is_not_excluded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source"
    forged = source / ".agentguard" / "contained-runs" / "forged-contained-20260101000000000000-deadbeef"
    forged.mkdir(parents=True)
    (forged / "agentguard-contained-run-artifact.json").write_text(
        json.dumps(
            {
                "schema": "agentguard.contained-run-artifact",
                "schema_version": 1,
                "owner": "agentguard",
                "artifact_kind": "contained-run",
                "run_id": forged.name,
                "lifecycle_state": "complete",
            }
        ),
        encoding="utf-8",
    )
    (forged / "payload.txt").write_text("attacker controlled\n", encoding="utf-8")
    config_path = _cwd_config(tmp_path)
    monkeypatch.chdir(source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )

    assert result.result == "FAIL"
    assert result.failure is not None
    assert "reserved path" in result.failure.message


def test_default_artifact_symlink_and_hardlink_are_not_trusted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("Symlinks are unavailable")
    source = tmp_path / "source"
    runs = source / ".agentguard" / "contained-runs"
    runs.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.txt").write_text("outside\n", encoding="utf-8")
    (runs / "linked-contained-20260101000000000000-deadbeef").symlink_to(outside)
    config_path = _cwd_config(tmp_path)
    monkeypatch.chdir(source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = run_contained_agent_command(
        config_path,
        ["true"],
        docker_executor=_successful_fake_executor,
    )

    assert result.result == "FAIL"
    assert result.failure is not None
    assert "reserved path" in result.failure.message


def test_contained_run_preserves_structured_argv_and_uses_docker_spec(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)
    captured = {}

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        captured["argv"] = argv
        captured["cwd"] = cwd
        captured["workspace_mode"] = stat.S_IMODE(cwd.stat().st_mode)
        (cwd / "new file.txt").write_text("created\n", encoding="utf-8")
        return CommandResult(
            command="contained-run",
            exit_code=0,
            stdout="ok",
            stderr="",
            duration_seconds=0.01,
        )

    command = [
        "python",
        "-c",
        "print('spaced value Δ \"quote\" $HOME ; rm -rf /')",
    ]
    result = _run(
        config_path,
        command,
        tmp_path,
        docker_executor=fake_executor,
    )

    assert result.exit_code == 0
    assert result.result == "PASS"
    assert captured["argv"][-len(command) :] == command
    assert "--" in captured["argv"]
    assert "--env" in captured["argv"]
    assert "HOME=/tmp/agentguard-home" in captured["argv"]
    assert "LANG=C.UTF-8" in captured["argv"]
    assert "LC_ALL=C.UTF-8" in captured["argv"]
    assert (
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        in captured["argv"]
    )
    assert "--network" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--network") + 1] == "none"
    assert "--read-only" in captured["argv"]
    assert "--cap-drop" in captured["argv"]
    assert "ALL" in captured["argv"]
    assert "--security-opt" in captured["argv"]
    assert "no-new-privileges" in captured["argv"]
    assert not captured["workspace_mode"] & stat.S_IWOTH
    assert "new file.txt" in result.diff_summary.added_files
    assert not (load_config(config_path).repo_template / "new file.txt").exists()
    source_mode = stat.S_IMODE(
        (load_config(config_path).repo_template / "hello.txt").stat().st_mode
    )
    assert not source_mode & stat.S_IWOTH
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert report["command"] == command
    assert "source repo" not in " ".join(report["docker_argv"])
    assert str(tmp_path) not in json.dumps(report, sort_keys=True)
    assert report["source_dir"] == "[REDACTED_PATH]"
    assert report["run_dir"] == "[REDACTED_PATH]"


def test_contained_run_preserves_child_argv_after_docker_image_boundary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)
    captured = {}
    command = [
        "-leading-executable",
        "--help",
        "-h",
        "--flag",
        "one",
        "--flag",
        "two",
        "--empty=",
        "--",
        "$HOME",
        "$(whoami)",
    ]

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        captured["argv"] = argv
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(
        config_path,
        command,
        tmp_path,
        docker_executor=fake_executor,
    )

    boundary = captured["argv"].index("--")
    assert result.exit_code == 0
    assert captured["argv"][boundary + 2 :] == command
    assert result.command == command
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert report["command"] == command


def test_contained_run_diff_size_uses_exact_mutation_line_counts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 2, "max_lines_deleted": 0},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "hello.txt").write_text("HELLO\nnew\n", encoding="utf-8")
        (cwd / "created.txt").write_text("tail", encoding="utf-8")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert result.diff_summary.lines_added == 3
    assert result.diff_summary.lines_deleted == 1
    assert result.diff_summary.line_count_status == "exact"
    assert result.diff_summary.line_count_complete is True
    assert result.diff_summary.unified_diff == ""
    assert result.diff_summary.unified_diff_status == "not_recorded"
    diff_size = next(check for check in result.check_results if check.name == "Diff size")
    assert diff_size.passed is False
    assert diff_size.evidence == [
        "Added 3 lines; limit is 2.",
        "Deleted 1 lines; limit is 0.",
    ]


def test_contained_run_diff_size_fails_closed_for_binary_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 100, "max_lines_deleted": 100},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "blob.bin").write_bytes(b"\0\1binary")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert result.diff_summary.line_count_status == "binary"
    assert result.diff_summary.line_count_complete is False
    assert result.diff_summary.line_count_error is not None
    assert "counted safely" in result.diff_summary.line_count_error
    diff_size = next(check for check in result.check_results if check.name == "Diff size")
    assert diff_size.passed is False
    assert diff_size.evidence == [
        "Diff line count evidence is incomplete or unavailable; "
        "failing closed for configured line limits "
        f"({result.diff_summary.line_count_error})."
    ]


def test_contained_run_diff_summary_records_counts_without_raw_diff_text(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 100, "max_lines_deleted": 100},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "many.txt").write_text(
            "".join(f"line {index}\n" for index in range(20)),
            encoding="utf-8",
        )
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.diff_summary.lines_added == 20
    assert result.diff_summary.lines_deleted == 0
    assert result.diff_summary.line_count_status == "exact"
    assert result.diff_summary.unified_diff == ""
    assert result.diff_summary.unified_diff_truncated is False
    assert result.diff_summary.unified_diff_status == "not_recorded"
    diff_size = next(check for check in result.check_results if check.name == "Diff size")
    assert diff_size.passed is True


def test_contained_run_diff_size_passes_exactly_at_line_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 2, "max_lines_deleted": 0},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "created.txt").write_text("one\ntwo\n", encoding="utf-8")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "PASS"
    assert result.diff_summary.lines_added == 2
    assert result.diff_summary.lines_deleted == 0
    assert result.diff_summary.line_count_status == "exact"


def test_contained_run_diff_size_counts_deletions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 0, "max_lines_deleted": 0},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "hello.txt").unlink()
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert result.diff_summary.lines_added == 0
    assert result.diff_summary.lines_deleted == 1
    diff_size = next(check for check in result.check_results if check.name == "Diff size")
    assert diff_size.evidence == ["Deleted 1 lines; limit is 0."]


def test_contained_run_diff_size_counts_added_file_without_final_newline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 0, "max_lines_deleted": 0},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "tail.txt").write_text("tail", encoding="utf-8")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert result.diff_summary.lines_added == 1
    assert result.diff_summary.lines_deleted == 0


def test_contained_run_diff_size_counts_large_single_line_from_snapshot(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 1, "max_lines_deleted": 0},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )
    monkeypatch.setattr(contained_run, "CONTAINED_DIFF_MAX_TEXT_BYTES", 4)

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "long.txt").write_text("abcdef", encoding="utf-8")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "PASS"
    assert result.diff_summary.lines_added == 1
    assert result.diff_summary.line_count_status == "exact"


def test_contained_run_diff_size_pure_rename_has_no_line_delta(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        expected_modified_files={"min": 0, "max": 3},
        diff_limits={"max_lines_added": 0, "max_lines_deleted": 0},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "hello.txt").rename(cwd / "moved.txt")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "PASS"
    assert result.diff_summary.renamed_files[0].source_path == "hello.txt"
    assert result.diff_summary.renamed_files[0].destination_path == "moved.txt"
    assert result.diff_summary.lines_added == 0
    assert result.diff_summary.lines_deleted == 0


def test_contained_diff_build_counts_rename_with_content_change(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "new.txt").write_text("new\nextra\n", encoding="utf-8")
    old_snapshot = ContainedPathSnapshot(
        path="old.txt",
        kind="file",
        size=4,
        sha256="old",
        mode=0o644,
        line_count=1,
        content_kind="text",
    )
    mutations = SimpleNamespace(
        modified_files=(),
        added_files=(),
        deleted_files=(),
        renamed_files=(("old.txt", "new.txt"),),
        baseline_files=(old_snapshot,),
        current_files=(),
        baseline_text_files={"old.txt": (b"old\n",)},
    )

    summary = contained_run._diff_summary_from_mutations(
        mutations,
        workspace_dir=workspace,
    )

    assert summary.renamed_files[0].source_path == "old.txt"
    assert summary.renamed_files[0].destination_path == "new.txt"
    assert summary.lines_added == 2
    assert summary.lines_deleted == 1
    assert summary.line_count_status == "exact"


def test_contained_diff_build_fails_closed_when_total_text_limit_exceeded(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "file.txt").write_text("new\n", encoding="utf-8")
    snapshot = ContainedPathSnapshot(
        path="file.txt",
        kind="file",
        size=4,
        sha256="old",
        mode=0o644,
        line_count=1,
        content_kind="text",
    )
    mutations = SimpleNamespace(
        modified_files=("file.txt",),
        added_files=(),
        deleted_files=(),
        renamed_files=(),
        baseline_files=(snapshot,),
        current_files=(),
        baseline_text_files={"file.txt": (b"old\n",)},
    )
    monkeypatch.setattr(contained_run, "CONTAINED_DIFF_MAX_TOTAL_TEXT_BYTES", 1)

    summary = contained_run._diff_summary_from_mutations(
        mutations,
        workspace_dir=workspace,
    )

    assert summary.line_count_status == "incomplete"
    assert summary.line_count_complete is False
    assert summary.line_count_error == "total diff byte limit exceeded"


def test_contained_run_diff_size_fails_closed_when_baseline_text_evidence_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        diff_limits={"max_lines_added": 100, "max_lines_deleted": 100},
        policy={"diff_size": {"severity": "error"}},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.contained_workspace._collect_baseline_text_files",
        lambda workspace_dir, files, limits: {},
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "hello.txt").write_text("changed\n", encoding="utf-8")
        return _successful_fake_executor(argv, cwd, timeout_seconds, max_output_bytes)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert result.diff_summary.line_count_status == "unavailable"
    assert result.diff_summary.line_count_complete is False
    assert result.diff_summary.line_count_error == "baseline text evidence unavailable"
    diff_size = next(check for check in result.check_results if check.name == "Diff size")
    assert diff_size.passed is False


def test_contained_diff_helpers_fail_closed_for_malformed_and_unavailable_paths(
    tmp_path: Path,
) -> None:
    missing = contained_run._read_contained_workspace_text(tmp_path, "missing.txt")
    malformed = contained_run._read_contained_workspace_text(tmp_path, "../escape.txt")

    assert isinstance(missing, contained_run._ContainedTextError)
    assert missing.status == "unavailable"
    assert isinstance(malformed, contained_run._ContainedTextError)
    assert malformed.status == "malformed"


def test_contained_diff_helpers_fail_closed_for_non_text_and_oversized_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    binary = tmp_path / "binary.bin"
    non_utf8 = tmp_path / "non-utf8.txt"
    large = tmp_path / "large.txt"
    binary.write_bytes(b"a\0b")
    non_utf8.write_bytes(b"\xff")
    large.write_text("abcde", encoding="utf-8")
    monkeypatch.setattr(contained_run, "CONTAINED_DIFF_MAX_TEXT_BYTES", 4)

    binary_result = contained_run._read_contained_workspace_text(tmp_path, "binary.bin")
    non_utf8_result = contained_run._read_contained_workspace_text(
        tmp_path,
        "non-utf8.txt",
    )
    large_result = contained_run._read_contained_workspace_text(tmp_path, "large.txt")

    assert isinstance(binary_result, contained_run._ContainedTextError)
    assert binary_result.status == "binary"
    assert isinstance(non_utf8_result, contained_run._ContainedTextError)
    assert non_utf8_result.status == "binary"
    assert isinstance(large_result, contained_run._ContainedTextError)
    assert large_result.status == "incomplete"


def test_contained_diff_accumulator_prefers_stronger_error() -> None:
    accumulator = contained_run._ContainedDiffAccumulator()

    accumulator.add_file_counts(
        added=contained_run._ContainedTextError("incomplete", "too large"),
        deleted=0,
    )
    accumulator.add_file_counts(
        added=contained_run._ContainedTextError("malformed", "bad evidence"),
        deleted=0,
    )
    result = accumulator.finish()

    assert result.line_count_status == "malformed"
    assert result.line_count_error == "bad evidence"


def test_contained_workspace_measure_file_classifies_binary_and_non_utf8(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "binary.bin"
    non_utf8 = tmp_path / "non-utf8.txt"
    text = tmp_path / "text.txt"
    binary.write_bytes(b"a\0b")
    non_utf8.write_bytes(b"\xff")
    text.write_text("one\ntwo", encoding="utf-8")

    assert _measure_file(binary, binary.lstat()) == (None, False, "binary")
    assert _measure_file(non_utf8, non_utf8.lstat()) == (None, False, "non_utf8")
    assert _measure_file(text, text.lstat()) == (2, True, "text")


def test_collect_baseline_text_files_is_bounded_and_skips_invalid_entries(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "one.txt").write_text("one\n", encoding="utf-8")
    (workspace / "two.txt").write_text("two\n", encoding="utf-8")
    (workspace / "binary.bin").write_bytes(b"\0")
    files = (
        ContainedPathSnapshot(
            path="one.txt",
            kind="file",
            size=4,
            sha256="a",
            mode=0o644,
            line_count=1,
            content_kind="text",
        ),
        ContainedPathSnapshot(
            path="binary.bin",
            kind="file",
            size=1,
            sha256="b",
            mode=0o644,
            line_count=None,
            line_count_complete=False,
            content_kind="binary",
        ),
        ContainedPathSnapshot(
            path="two.txt",
            kind="file",
            size=4,
            sha256="c",
            mode=0o644,
            line_count=1,
            content_kind="text",
        ),
    )

    collected = _collect_baseline_text_files(
        workspace,
        files,
        ContainedWorkspaceLimits(max_total_bytes=4),
    )

    assert collected == {"one.txt": (b"one\n",)}


def test_contained_run_fails_before_workspace_when_preflight_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config, status=DockerPreflightStatus.UNAVAILABLE),
    )

    def forbidden_prepare(*args, **kwargs):
        raise AssertionError("workspace must not be prepared after failed preflight")

    monkeypatch.setattr(
        "agentguard.core.contained_run.prepare_contained_workspace",
        forbidden_prepare,
    )

    result = _run(config_path, ["true"], tmp_path)

    assert result.failure is not None
    assert result.failure.exit_code == EXIT_PREFLIGHT
    assert result.report_path.is_file()


def test_contained_run_report_sanitizes_command_paths_with_spaces_and_unicode(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "source repo café 日本語"
    source.mkdir()
    (source / "input.txt").write_text("hello\n", encoding="utf-8")
    config_path = _config(tmp_path, repo_template=str(source))
    private_path = tmp_path / "private dir café" / "secret.txt"

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = _run(
        config_path,
        ["tool", str(private_path)],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: CommandResult(
            "contained-run",
            0,
            "",
            "",
            0.01,
        ),
    )

    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    assert "[REDACTED_PATH]" in report["command"]
    assert str(tmp_path) not in serialized
    assert "source repo café" not in serialized
    assert "private dir café" not in serialized


def _rename_config(tmp_path: Path, source: Path, **updates) -> Path:
    data = {
        "task_id": "contained_rename_policy",
        "description": "Contained rename policy regression.",
        "repo_template": str(source),
        "test_command": "true",
        "allowed_paths": ["src/**"],
        "forbidden_paths": ["secrets/**", ".agentguard/**"],
        "test_paths": ["tests/**"],
        "secret_patterns": ["secrets/**"],
        "expected_modified_files": {"min": 0, "max": 20},
        "policy": {"scope_adherence": {"severity": "error"}},
        "unsafe_commands": [],
        "sandbox": {
            "type": "docker",
            "image": IMAGE,
            "network": "none",
        },
        "contained_execution": {
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
        },
    }
    data.update(updates)
    path = tmp_path / f"{data['task_id']}.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _rename_source(tmp_path: Path) -> Path:
    source = tmp_path / "rename-source"
    (source / "src").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "secrets" / "nested").mkdir(parents=True)
    (source / "src" / "ok.txt").write_text("same\n", encoding="utf-8")
    (source / "src" / "space café.txt").write_text("unicode\n", encoding="utf-8")
    (source / "secrets" / "token.txt").write_text("secret\n", encoding="utf-8")
    (source / "secrets" / "nested" / "child.txt").write_text("child\n", encoding="utf-8")
    (source / "secrets" / "CaseOnly.txt").write_text("case\n", encoding="utf-8")
    return source


@pytest.mark.parametrize(
    ("source_path", "destination_path", "expected_result", "failed_checks", "evidence"),
    [
        ("src/ok.txt", "src/renamed.txt", "PASS", set(), set()),
        (
            "secrets/token.txt",
            "src/recovered.txt",
            "FAIL",
            {"Forbidden paths", "Scope adherence", "Secret scan"},
            {"secrets/token.txt"},
        ),
        (
            "src/ok.txt",
            "tests/ok.txt",
            "FAIL",
            {"Test tampering", "Scope adherence"},
            {"tests/ok.txt"},
        ),
        (
            "src/ok.txt",
            "secrets/ok.txt",
            "FAIL",
            {"Forbidden paths", "Scope adherence", "Secret scan"},
            {"secrets/ok.txt"},
        ),
        (
            "secrets/token.txt",
            "secrets/token-renamed.txt",
            "FAIL",
            {"Forbidden paths", "Scope adherence", "Secret scan"},
            {"secrets/token.txt", "secrets/token-renamed.txt"},
        ),
        (
            "secrets/CaseOnly.txt",
            "src/caseonly.txt",
            "FAIL",
            {"Forbidden paths", "Scope adherence", "Secret scan"},
            {"secrets/CaseOnly.txt"},
        ),
        (
            "src/space café.txt",
            "src/renamed café.txt",
            "PASS",
            set(),
            set(),
        ),
    ],
)
def test_contained_run_rename_endpoints_are_policy_inputs(
    tmp_path: Path,
    monkeypatch,
    source_path: str,
    destination_path: str,
    expected_result: str,
    failed_checks: set[str],
    evidence: set[str],
) -> None:
    source = _rename_source(tmp_path)
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        destination = cwd / destination_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        (cwd / source_path).rename(destination)
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == expected_result
    assert result.diff_summary.renamed_files[0].source_path == source_path
    assert result.diff_summary.renamed_files[0].destination_path == destination_path
    assert result.diff_summary.changed_files == [source_path, destination_path]
    assert (source / source_path).exists()
    assert not (source / destination_path).exists()
    observed_failures = {check.name for check in result.check_results if not check.passed}
    assert failed_checks <= observed_failures
    observed_evidence = {
        item
        for check in result.check_results
        for item in check.evidence
    }
    assert evidence <= observed_evidence

    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    rename = report["mutations"]["renamed_files"][0]
    assert rename["old"] == source_path
    assert rename["new"] == destination_path
    assert rename["source_path"] == source_path
    assert rename["destination_path"] == destination_path
    assert rename["change_type"] == "renamed"
    assert report["diff_summary"]["renamed_files"] == [
        {
            "source_path": source_path,
            "destination_path": destination_path,
            "change_type": "renamed",
        }
    ]
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    assert str(tmp_path) not in serialized


def test_contained_run_directory_rename_evaluates_protected_descendants(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = _rename_source(tmp_path)
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "src" / "moved-secrets").parent.mkdir(exist_ok=True)
        (cwd / "secrets").rename(cwd / "src" / "moved-secrets")
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    renamed = {
        (rename.source_path, rename.destination_path)
        for rename in result.diff_summary.renamed_files
    }
    assert ("secrets/nested/child.txt", "src/moved-secrets/nested/child.txt") in renamed
    forbidden = next(check for check in result.check_results if check.name == "Forbidden paths")
    assert forbidden.passed is False
    assert "secrets/nested/child.txt" in forbidden.evidence


def test_contained_run_rename_with_content_change_degrades_to_delete_add_policy(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = _rename_source(tmp_path)
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        destination = cwd / "tests" / "ok.txt"
        destination.write_text(
            (cwd / "src" / "ok.txt").read_text(encoding="utf-8") + "changed\n",
            encoding="utf-8",
        )
        (cwd / "src" / "ok.txt").unlink()
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.diff_summary.renamed_files == []
    assert result.diff_summary.deleted_files == ["src/ok.txt"]
    assert result.diff_summary.added_files == ["tests/ok.txt"]
    test_tampering = next(check for check in result.check_results if check.name == "Test tampering")
    assert test_tampering.passed is False
    assert test_tampering.evidence == ["tests/ok.txt"]


def test_contained_run_many_renames_are_bounded_and_deterministic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "many-renames"
    (source / "src").mkdir(parents=True)
    for index in range(12):
        (source / "src" / f"file-{index:02d}.txt").write_text(
            f"{index}\n",
            encoding="utf-8",
        )
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        for index in reversed(range(12)):
            (cwd / "src" / f"file-{index:02d}.txt").rename(
                cwd / "src" / f"renamed-{index:02d}.txt"
            )
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert len(result.diff_summary.renamed_files) == 12
    assert result.diff_summary.renamed_files[0].source_path == "src/file-00.txt"
    diff_size = next(check for check in result.check_results if check.name == "Diff size")
    assert diff_size.passed is True


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="Symlinks are unavailable")
def test_contained_run_symlink_rename_evaluates_link_path_without_following(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = _rename_source(tmp_path)
    (source / "secrets" / "link.txt").symlink_to("../src/ok.txt")
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        (cwd / "secrets" / "link.txt").rename(cwd / "src" / "link.txt")
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.diff_summary.renamed_files[0].source_path == "secrets/link.txt"
    forbidden = next(check for check in result.check_results if check.name == "Forbidden paths")
    assert forbidden.passed is False
    assert forbidden.evidence == ["secrets/link.txt"]


def test_contained_run_unicode_normalization_sensitive_rename_when_supported(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = tmp_path / "unicode-normalization"
    (source / "secrets").mkdir(parents=True)
    decomposed = unicodedata.normalize("NFD", "café")
    composed = unicodedata.normalize("NFC", "café")
    source_path = f"secrets/{decomposed}.txt"
    destination_path = f"src/{composed}.txt"
    (source / source_path).write_text("accent\n", encoding="utf-8")
    if not (source / source_path).exists():
        pytest.skip("filesystem normalizes Unicode paths before capture")
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        destination = cwd / destination_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        (cwd / source_path).rename(destination)
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.diff_summary.renamed_files[0].source_path == source_path
    forbidden = next(check for check in result.check_results if check.name == "Forbidden paths")
    assert forbidden.passed is False
    assert source_path in forbidden.evidence


def test_contained_run_reserved_agentguard_destination_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    source = _rename_source(tmp_path)
    config_path = _rename_config(tmp_path, source)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        destination = cwd / ".agentguard" / "report.json"
        destination.parent.mkdir()
        (cwd / "src" / "ok.txt").rename(destination)
        return CommandResult("contained-run", 0, "", "", 0.01)

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.result == "FAIL"
    assert result.failure is not None
    assert result.failure.stage == "workspace_prep"
    assert "reserved path" in result.failure.message


def test_contained_run_rejects_incompatible_bind_uid_gid_before_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    mismatched_uid = os.geteuid() + 1
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": mismatched_uid,
            "required_gid": os.getegid(),
        },
    )

    def forbidden_preflight(*args, **kwargs):
        raise AssertionError("preflight must not run with incompatible bind UID/GID")

    def forbidden_prepare(*args, **kwargs):
        raise AssertionError("workspace must not be prepared with incompatible bind UID/GID")

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        forbidden_preflight,
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.prepare_contained_workspace",
        forbidden_prepare,
    )

    with pytest.raises(ValueError, match="host bind mounts require"):
        _run(config_path, ["true"], tmp_path)


@pytest.mark.parametrize(
    ("runner_name", "agent_name"),
    [
        ("agentguard ci", None),
        ("agentguard run --agent local-command", "local-command"),
        ("agentguard run --agent agent-command", "agent-command"),
    ],
)
def test_uncontained_runners_reject_contained_execution_before_launch(
    tmp_path: Path,
    monkeypatch,
    runner_name: str,
    agent_name: Optional[str],
) -> None:
    config_path = _config(
        tmp_path,
        agent_command=["python", "-c", "raise SystemExit('must not run')"],
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("uncontained path must reject before launch")

    monkeypatch.setattr("agentguard.core.ci.detect_repo_dir", forbidden)
    monkeypatch.setattr("agentguard.core.orchestrator.RepoManager.prepare", forbidden)

    with pytest.raises(ValueError) as error:
        if agent_name is None:
            run_ci(config_path, repo_dir=tmp_path)
        else:
            run_benchmark(config_path, agent_name)

    message = str(error.value)
    assert "contained_execution" in message
    assert "agentguard contained-run" in message
    assert runner_name in message
    assert "uncontained execution path" in message


def test_contained_run_records_docker_desktop_experimental_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "docker-desktop-experimental",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
        },
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config, status=DockerPreflightStatus.EXPERIMENTAL),
    )

    result = _run(
        config_path,
        ["true"],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: CommandResult(
            "contained-run",
            0,
            "",
            "",
            0.01,
        ),
    )

    assert result.preflight.status == DockerPreflightStatus.EXPERIMENTAL
    assert result.failure is None


@pytest.mark.parametrize(
    ("command_result", "expected"),
    [
        (CommandResult("contained-run", 125, "", "create failed", 0.01), EXIT_DOCKER),
        (
            CommandResult(
                "contained-run",
                124,
                "",
                "timeout",
                0.01,
                timed_out=True,
            ),
            EXIT_TIMEOUT,
        ),
    ],
)
def test_contained_run_maps_docker_and_timeout_failures(
    tmp_path: Path,
    monkeypatch,
    command_result: CommandResult,
    expected: int,
) -> None:
    config_path = _config(tmp_path)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = _run(
        config_path,
        ["true"],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: command_result,
    )

    assert result.failure is not None
    assert result.failure.exit_code == expected


@pytest.mark.parametrize("exit_code", [126, 127])
def test_contained_agent_126_127_are_not_docker_failures(
    tmp_path: Path,
    monkeypatch,
    exit_code: int,
) -> None:
    config_path = _config(tmp_path)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = _run(
        config_path,
        ["sh", "-c", f"exit {exit_code}"],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: CommandResult(
            "contained-run",
            exit_code,
            "",
            "agent command failed",
            0.01,
        ),
    )

    assert result.failure is None
    assert result.command_result.exit_code == exit_code
    assert result.exit_code == 1


def test_contained_run_blocks_policy_before_docker_execution(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        unsafe_commands=["danger"],
        command_policy={"mode": "enforce"},
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    def forbidden_executor(*args, **kwargs):
        raise AssertionError("blocked command must not launch Docker")

    result = _run(
        config_path,
        ["danger"],
        tmp_path,
        docker_executor=forbidden_executor,
    )

    assert result.failure == ContainedRunFailure(
        stage="policy",
        exit_code=EXIT_POLICY,
        message="Command blocked by preflight policy.",
    )


def test_contained_run_cleans_workspace_on_nonzero_command(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )
    seen = {}

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        seen["run_dir"] = cwd.parent.parent
        return CommandResult("contained-run", 42, "nope", "", 0.01)

    result = _run(
        config_path,
        ["false"],
        tmp_path,
        docker_executor=fake_executor,
    )

    assert result.exit_code == 1
    assert result.cleanup_complete is True
    assert not (seen["run_dir"] / "agent-workspace").exists()


def test_container_cleanup_failure_is_reported(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "daemon refused cleanup"

    monkeypatch.setattr(contained_run.subprocess, "run", lambda *args, **kwargs: Completed())

    assert contained_run._remove_container("agentguard-test") == (
        "contained container cleanup failed."
    )


def test_missing_container_after_rm_is_not_cleanup_failure(monkeypatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "Error: No such container: agentguard-test"

    monkeypatch.setattr(contained_run.subprocess, "run", lambda *args, **kwargs: Completed())

    assert contained_run._remove_container("agentguard-test") is None


def _owned_identity():
    return contained_run.ContainedContainerIdentity(
        container_id=CONTAINER_ID,
        container_name=CONTAINER_NAME,
        owner_label=OWNER_LABEL,
    )


def _completed(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def _inspect_payload(*, running: bool) -> str:
    return json.dumps(
        {
            "Id": CONTAINER_ID,
            "Name": f"/{CONTAINER_NAME}",
            "Config": {
                "Labels": {
                    "agentguard.owner": "contained-run",
                    "agentguard.contained-run.id": "owned",
                }
            },
            "State": {"Running": running},
        }
    )


def test_cleanup_removes_only_exact_owned_container_id(monkeypatch) -> None:
    calls = []
    present = {"value": True}

    def fake_control(argv):
        calls.append(argv)
        if argv[1:3] == ["container", "inspect"]:
            if not present["value"]:
                return _completed(1, stderr="No such container")
            return _completed(stdout=_inspect_payload(running=False))
        if argv[1] == "rm":
            assert argv[-1] == CONTAINER_ID
            assert argv[-1] != CONTAINER_NAME
            present["value"] = False
            return _completed()
        raise AssertionError(f"unexpected docker command: {argv!r}")

    monkeypatch.setattr(contained_run, "_run_docker_control", fake_control)

    result = contained_run._cleanup_owned_container(_owned_identity())

    assert result.complete is True
    assert result.status == "removed"
    assert ["docker", "rm", CONTAINER_ID] in calls
    assert ["docker", "rm", CONTAINER_NAME] not in calls


def test_cleanup_graceful_stop_and_force_kill_statuses(monkeypatch) -> None:
    def run_case(still_running_after_stop: bool) -> ContainedCleanupResult:
        state = {"running": True, "present": True, "stopped_once": False}

        def fake_control(argv):
            if argv[1:3] == ["container", "inspect"]:
                if not state["present"]:
                    return _completed(1, stderr="No such container")
                return _completed(stdout=_inspect_payload(running=state["running"]))
            if argv[1] == "stop":
                state["stopped_once"] = True
                state["running"] = still_running_after_stop
                return _completed()
            if argv[1] == "kill":
                state["running"] = False
                return _completed()
            if argv[1] == "rm":
                state["present"] = False
                return _completed()
            raise AssertionError(f"unexpected docker command: {argv!r}")

        monkeypatch.setattr(contained_run, "_run_docker_control", fake_control)
        return contained_run._cleanup_owned_container(_owned_identity())

    graceful = run_case(False)
    forced = run_case(True)

    assert graceful.complete is True
    assert graceful.status == "cleanly_terminated"
    assert forced.complete is True
    assert forced.status == "force_killed"


def test_cleanup_failures_and_liveness_ambiguity_are_explicit(monkeypatch) -> None:
    def inspect_unavailable(argv):
        if argv[1:3] == ["container", "inspect"]:
            return _completed(1, stderr="daemon unavailable")
        raise AssertionError(f"unexpected docker command: {argv!r}")

    monkeypatch.setattr(contained_run, "_run_docker_control", inspect_unavailable)
    unavailable = contained_run._cleanup_owned_container(_owned_identity())
    assert unavailable.complete is False
    assert unavailable.status == "verification_unavailable"

    def remove_fails(argv):
        if argv[1:3] == ["container", "inspect"]:
            return _completed(stdout=_inspect_payload(running=False))
        if argv[1] == "rm":
            return _completed(1, stderr="permission denied")
        raise AssertionError(f"unexpected docker command: {argv!r}")

    monkeypatch.setattr(contained_run, "_run_docker_control", remove_fails)
    failed = contained_run._cleanup_owned_container(_owned_identity())
    assert failed.complete is False
    assert failed.status == "cleanup_incomplete"
    assert "removal failed" in failed.message


def test_cleanup_already_absent_is_idempotent(monkeypatch) -> None:
    calls = []

    def fake_control(argv):
        calls.append(argv)
        if argv[1:3] == ["container", "inspect"]:
            return _completed(1, stderr="No such container")
        raise AssertionError(f"unexpected docker command: {argv!r}")

    monkeypatch.setattr(contained_run, "_run_docker_control", fake_control)

    first = contained_run._cleanup_owned_container(_owned_identity())
    second = contained_run._cleanup_owned_container(_owned_identity())

    assert first.complete is True
    assert second.complete is True
    assert first.status == second.status == "already_absent"
    assert all(call[1] == "container" for call in calls)


def test_create_failure_after_container_appears_binds_identity_for_cleanup(
    monkeypatch,
) -> None:
    def fake_control(argv):
        if argv[1] == "create":
            return _completed(124, stderr="timeout")
        if argv[1:3] == ["container", "inspect"]:
            assert argv[-1] == CONTAINER_NAME
            return _completed(stdout=_inspect_payload(running=False))
        raise AssertionError(f"unexpected docker command: {argv!r}")

    monkeypatch.setattr(contained_run, "_run_docker_control", fake_control)

    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        CONTAINER_NAME,
        "--label",
        "agentguard.owner=contained-run",
        "--label",
        OWNER_LABEL,
        "--",
        IMAGE,
        "true",
    ]
    with pytest.raises(contained_run.DockerContainerCreatedError) as raised:
        contained_run._create_owned_container(argv)

    assert raised.value.identity.container_id == CONTAINER_ID


def test_docker_create_argv_preserves_agent_rm_argument_after_boundary() -> None:
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        CONTAINER_NAME,
        "--",
        IMAGE,
        "tool",
        "--rm",
        "target",
    ]

    create = contained_run._docker_create_argv(argv)

    assert create[:2] == ["docker", "create"]
    assert "--" not in create
    image_index = create.index(IMAGE)
    assert "--rm" not in create[:image_index]
    assert create[image_index + 1 :] == ["tool", "--rm", "target"]


def test_docker_create_failure_reports_bounded_sanitized_diagnostic(monkeypatch) -> None:
    canary_id = "b" * 64

    def fake_control(argv):
        if argv[1] == "create":
            return _completed(
                125,
                stdout=f"container {canary_id}",
                stderr=(
                    "invalid mount /Users/alice/private "
                    "agentguard-secret-name TOKEN=secret-value "
                    "agentguard.contained-run.id=private-run-id"
                ),
            )
        if argv[1:3] == ["container", "inspect"]:
            return _completed(1, stderr="No such container")
        raise AssertionError(f"unexpected docker command: {argv!r}")

    monkeypatch.setattr(contained_run, "_run_docker_control", fake_control)

    with pytest.raises(contained_run.DockerOperationalError) as raised:
        contained_run._create_owned_container(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                "agentguard-secret-name",
                "--label",
                "agentguard.owner=contained-run",
                "--label",
                "agentguard.contained-run.id=private-run-id",
                "--",
                IMAGE,
                "true",
            ]
        )

    diagnostic = raised.value.diagnostic
    assert "create failed" in diagnostic
    assert "identity inspect absent" in diagnostic
    assert "rc=125" in diagnostic
    assert canary_id not in diagnostic
    assert "agentguard-secret-name" not in diagnostic
    assert "private-run-id" not in diagnostic
    assert "secret-value" not in diagnostic
    assert "/Users/alice" not in diagnostic


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (
            {
                "Id": CONTAINER_ID,
                "Name": "/wrong-name",
                "Config": {
                    "Labels": {
                        "agentguard.owner": "contained-run",
                        "agentguard.contained-run.id": "owned",
                    }
                },
            },
            "identity name mismatch",
        ),
        (
            {
                "Id": CONTAINER_ID,
                "Name": f"/{CONTAINER_NAME}",
                "Config": {
                    "Labels": {
                        "agentguard.owner": "contained-run",
                        "agentguard.contained-run.id": "different",
                    }
                },
            },
            "identity run label mismatch",
        ),
    ],
)
def test_identity_binding_reports_mismatch_reason(monkeypatch, payload, reason) -> None:
    monkeypatch.setattr(
        contained_run,
        "_run_docker_control",
        lambda argv: _completed(stdout=json.dumps(payload)),
    )

    result = contained_run._bind_container_identity_detail(
        CONTAINER_ID,
        expected_name=CONTAINER_NAME,
        expected_owner_label=OWNER_LABEL,
    )

    assert result.identity is None
    assert result.reason == reason


def test_identity_binding_accepts_bounded_hosted_inspect_payload(monkeypatch) -> None:
    payload = {
        "Id": CONTAINER_ID,
        "Name": f"/{CONTAINER_NAME}",
        "Config": {
            "Labels": {
                "agentguard.owner": "contained-run",
                "agentguard.contained-run.id": "owned",
            },
            "Env": [f"FILLER_{index}={'x' * 60}" for index in range(120)],
        },
    }
    assert len(json.dumps(payload)) > contained_run.DOCKER_OUTPUT_MAX_BYTES
    assert len(json.dumps(payload)) < contained_run.DOCKER_INSPECT_MAX_BYTES
    monkeypatch.setattr(
        contained_run,
        "_run_docker_control",
        lambda argv: _completed(stdout=json.dumps(payload)),
    )

    result = contained_run._bind_container_identity_detail(
        CONTAINER_ID,
        expected_name=CONTAINER_NAME,
        expected_owner_label=OWNER_LABEL,
    )

    assert result.identity == _owned_identity()


def test_docker_start_failure_reports_sanitized_operational_diagnostic(monkeypatch) -> None:
    class FailedStartProcess:
        stdout = object()
        stderr = object()

        def wait(self, timeout=None):
            return 1

    class FailedStartCapture:
        def __init__(self, process, max_output_bytes):
            pass

        def wait(self, timeout=None):
            return 1

        def finish(self, timeout=None):
            return contained_run.ProcessOutput(
                stdout=contained_run.LimitedOutput(text="", truncated=False),
                stderr=contained_run.LimitedOutput(
                    text=(
                        "Error response from daemon: no such container "
                        f"{CONTAINER_ID} at /Users/alice/private"
                    ),
                    truncated=False,
                ),
            )

    monkeypatch.setattr(
        contained_run,
        "_create_owned_container",
        lambda _argv: _owned_identity(),
    )
    monkeypatch.setattr(
        contained_run.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FailedStartProcess(),
    )
    monkeypatch.setattr(contained_run, "BoundedProcessOutput", FailedStartCapture)
    monkeypatch.setattr(
        contained_run,
        "_cleanup_owned_container",
        lambda _identity: ContainedCleanupResult(
            attempted=True,
            complete=True,
            status="already_absent",
            message="contained container already absent",
        ),
    )

    execution = contained_run._execute_docker_argv(
        ["docker", "run", "--", IMAGE, "true"],
        Path("/tmp"),
        1,
        1024,
    )

    assert execution.command_result.exit_code == 125
    assert "start failed" in execution.command_result.stderr
    assert CONTAINER_ID not in execution.command_result.stderr
    assert "/Users/alice" not in execution.command_result.stderr


def test_interruption_after_container_creation_preserves_cleanup(monkeypatch) -> None:
    cleanup_calls = []

    class InterruptingProcess:
        stdout = object()
        stderr = object()

        def wait(self, timeout=None):
            raise KeyboardInterrupt("test interrupt")

    class InterruptingCapture:
        def __init__(self, process, max_output_bytes):
            self.process = process

        def wait(self, timeout=None):
            return self.process.wait(timeout=timeout)

        def finish(self, timeout=None):
            raise KeyboardInterrupt("test interrupt")

    monkeypatch.setattr(
        contained_run,
        "_create_owned_container",
        lambda _argv: _owned_identity(),
    )
    monkeypatch.setattr(
        contained_run.subprocess,
        "Popen",
        lambda *_args, **_kwargs: InterruptingProcess(),
    )
    monkeypatch.setattr(contained_run, "BoundedProcessOutput", InterruptingCapture)
    monkeypatch.setattr(contained_run, "cleanup_process_after_exception", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        contained_run,
        "_cleanup_owned_container",
        lambda identity: cleanup_calls.append(identity) or ContainedCleanupResult(
            attempted=True,
            complete=True,
            status="removed",
            message="contained container removed",
        ),
    )

    execution = contained_run._execute_docker_argv(
        ["docker", "run", "--", IMAGE, "true"],
        Path("/tmp"),
        1,
        1024,
    )

    assert cleanup_calls == [_owned_identity()]
    assert execution.command_result.exit_code == 125
    assert execution.command_result.process_cleanup_complete is True
    assert "interrupted" in execution.command_result.stderr


def test_timeout_cleans_container_before_terminating_attached_client(monkeypatch) -> None:
    events = []

    class TimeoutThenDrainedProcess:
        stdout = object()
        stderr = object()

        def wait(self, timeout=None):
            return 124

    class TimeoutThenDrainedCapture:
        def __init__(self, process, max_output_bytes):
            self.waits = 0

        def wait(self, timeout=None):
            self.waits += 1
            if self.waits == 1:
                events.append("timeout")
                raise subprocess.TimeoutExpired("docker start", timeout)
            events.append("drained")
            return 124

        def finish(self, timeout=None):
            events.append("finish")
            return contained_run.ProcessOutput(
                stdout=contained_run.LimitedOutput(text="", truncated=False),
                stderr=contained_run.LimitedOutput(text="", truncated=False),
            )

    monkeypatch.setattr(
        contained_run,
        "_create_owned_container",
        lambda _argv: _owned_identity(),
    )
    monkeypatch.setattr(
        contained_run.subprocess,
        "Popen",
        lambda *_args, **_kwargs: TimeoutThenDrainedProcess(),
    )
    monkeypatch.setattr(contained_run, "BoundedProcessOutput", TimeoutThenDrainedCapture)
    monkeypatch.setattr(
        contained_run,
        "_cleanup_owned_container",
        lambda identity: events.append("cleanup") or ContainedCleanupResult(
            attempted=True,
            complete=True,
            status="cleanly_terminated",
            message="contained container gracefully stopped and removed",
        ),
    )
    monkeypatch.setattr(
        contained_run,
        "terminate_process_tree",
        lambda process: events.append("terminate") or contained_run.ProcessCleanupResult(
            attempted=True,
            complete=True,
            message="process tree terminated",
        ),
    )

    execution = contained_run._execute_docker_argv(
        ["docker", "run", "--", IMAGE, "sleep", "20"],
        Path("/tmp"),
        1,
        1024,
    )

    assert events == ["timeout", "cleanup", "drained", "finish"]
    assert execution.command_result.timed_out is True
    assert execution.cleanup.complete is True
    assert execution.cleanup.status == "cleanly_terminated"


def test_cleanup_failure_preserves_primary_failure_and_retains_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )
    seen = {}

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        seen["run_dir"] = cwd.parent.parent
        return ContainedDockerExecution(
            CommandResult("contained-run", 125, "", "docker failed", 0.01),
            ContainedCleanupResult(
                attempted=True,
                complete=False,
                status="verification_unavailable",
                message="contained container liveness verification unavailable",
            ),
        )

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)

    assert result.exit_code == EXIT_DOCKER
    assert result.failure.exit_code == EXIT_DOCKER
    assert result.cleanup_failure.exit_code == contained_run.EXIT_CLEANUP
    assert result.result == "FAIL"
    assert result.cleanup_complete is False
    assert (seen["run_dir"] / "agent-workspace").exists()


def test_success_becomes_cleanup_failure_when_verification_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(tmp_path)
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = _run(
        config_path,
        ["true"],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: ContainedDockerExecution(
            CommandResult("contained-run", 0, "ok", "", 0.01),
            ContainedCleanupResult(
                attempted=True,
                complete=False,
                status="verification_unavailable",
                message="contained container liveness verification unavailable",
            ),
        ),
    )

    assert result.result == "FAIL"
    assert result.exit_code == contained_run.EXIT_CLEANUP
    assert result.failure.exit_code == contained_run.EXIT_CLEANUP
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert report["result"] == "FAIL"


def test_contained_run_bounds_output_and_sanitizes_canaries(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        max_output_bytes=80,
        agent_environment={"SECRET_TOKEN": "super-secret-value"},
    )
    source = load_config(config_path).repo_template
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = _run(
        config_path,
        ["true"],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: CommandResult(
            "contained-run",
            0,
            f"{source} super-secret-value " + ("x" * 500),
            "TOKEN=super-secret-value",
            0.01,
        ),
    )

    assert result.command_result.stdout_truncated
    assert str(source) not in result.command_result.stdout
    assert "super-secret-value" not in result.command_result.stdout
    assert "super-secret-value" not in result.command_result.stderr


def test_contained_run_allows_explicit_secret_but_redacts_diagnostics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    secret = "contained-secret-value"
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
            "environment": [
                {
                    "name": "API_TOKEN",
                    "value": secret,
                    "allow_sensitive": True,
                },
                {"name": "VISIBLE_VALUE", "value": "display-ok"},
            ],
        },
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )
    captured = {}

    def fake_executor(argv, cwd, timeout_seconds, max_output_bytes):
        captured["argv"] = argv
        assert f"API_TOKEN={secret}" in argv
        return CommandResult(
            "contained-run",
            0,
            f"token={secret}",
            f"Authorization: Bearer {secret}",
            0.01,
        )

    result = _run(config_path, ["true"], tmp_path, docker_executor=fake_executor)
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    serialized = json.dumps(report, sort_keys=True)

    assert result.exit_code == 0
    assert "API_TOKEN=[REDACTED]" in result.docker_argv
    assert "VISIBLE_VALUE=[REDACTED]" in result.docker_argv
    assert secret not in json.dumps(result.docker_argv)
    assert secret not in result.command_result.stdout
    assert secret not in result.command_result.stderr
    assert secret not in serialized
    assert report["environment"]["supplied"] == ["API_TOKEN", "VISIBLE_VALUE"]
    assert report["environment"]["sensitive"] == ["API_TOKEN"]


def test_contained_run_required_missing_env_fails_before_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
            "environment": [
                {"name": "MISSING_VALUE", "source": "host", "required": True}
            ],
        },
    )

    def forbidden_preflight(*args, **kwargs):
        raise AssertionError("missing env must fail before preflight")

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        forbidden_preflight,
    )

    result = _run(config_path, ["true"], tmp_path)

    assert result.failure is not None
    assert result.failure.exit_code == contained_run.EXIT_CONFIG
    assert "MISSING_VALUE" in result.failure.message
    assert result.report_path.is_file()


def test_contained_run_host_env_value_validation_happens_before_preflight(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
            "environment": [
                {"name": "HOST_VALUE", "source": "host", "required": True}
            ],
        },
    )
    monkeypatch.setenv("HOST_VALUE", "bad\nvalue")

    def forbidden_preflight(*args, **kwargs):
        raise AssertionError("invalid env must fail before preflight")

    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        forbidden_preflight,
    )

    result = _run(config_path, ["true"], tmp_path)

    assert result.failure is not None
    assert result.failure.exit_code == contained_run.EXIT_CONFIG
    assert "HOST_VALUE" in result.failure.message


@pytest.mark.parametrize(
    "command_result",
    [
        CommandResult("contained-run", 1, "secret=timeout-secret", "", 0.01),
        CommandResult(
            "contained-run",
            124,
            "",
            "timeout-secret",
            0.01,
            timed_out=True,
        ),
        CommandResult("contained-run", 125, "", "timeout-secret", 0.01),
    ],
)
def test_contained_run_redacts_secret_on_failure_and_timeout(
    tmp_path: Path,
    monkeypatch,
    command_result: CommandResult,
) -> None:
    secret = "timeout-secret"
    config_path = _config(
        tmp_path,
        contained_execution={
            "version": 1,
            "platform": "linux-docker-engine",
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.geteuid(),
            "required_gid": os.getegid(),
            "environment": [
                {
                    "name": "FAILURE_TOKEN",
                    "value": secret,
                    "allow_sensitive": True,
                }
            ],
        },
    )
    monkeypatch.setattr(
        "agentguard.core.contained_run.run_docker_preflight",
        lambda config: _preflight(config),
    )

    result = _run(
        config_path,
        ["true"],
        tmp_path,
        docker_executor=lambda argv, cwd, timeout_seconds, max_output_bytes: command_result,
    )
    serialized = json.dumps(
        json.loads(result.report_path.read_text(encoding="utf-8")),
        sort_keys=True,
    )

    assert secret not in serialized
    assert secret not in repr(result)


def test_contained_run_rejects_malformed_contained_config(tmp_path: Path) -> None:
    config_path = _config(tmp_path)
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["contained_execution"]["allow_privileged"] = True
    config_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match="allow_privileged"):
        _run(config_path, ["true"], tmp_path)
