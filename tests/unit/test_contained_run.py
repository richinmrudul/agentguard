import json
import stat
from pathlib import Path

import pytest
import yaml

from agentguard.config.loader import load_config
from agentguard.core.contained_run import (
    EXIT_DOCKER,
    EXIT_POLICY,
    EXIT_PREFLIGHT,
    EXIT_TIMEOUT,
    ContainedRunFailure,
    run_contained_agent_command,
)
from agentguard.core import contained_run
from agentguard.core.result import CommandResult
from agentguard.sandbox import docker_preflight
from agentguard.sandbox.docker_preflight import DockerPreflightStatus


IMAGE = "example.com/team/agent@sha256:" + "a" * 64


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
        },
    }
    data.update(updates)
    path = tmp_path / "agentguard.yaml"
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
    assert "--env" not in captured["argv"]
    assert "--network" in captured["argv"]
    assert captured["argv"][captured["argv"].index("--network") + 1] == "none"
    assert "--read-only" in captured["argv"]
    assert "--cap-drop" in captured["argv"]
    assert "ALL" in captured["argv"]
    assert "--security-opt" in captured["argv"]
    assert "no-new-privileges" in captured["argv"]
    assert captured["workspace_mode"] & stat.S_IWOTH
    assert "new file.txt" in result.diff_summary.added_files
    assert not (load_config(config_path).repo_template / "new file.txt").exists()
    source_mode = stat.S_IMODE(
        (load_config(config_path).repo_template / "hello.txt").stat().st_mode
    )
    assert not source_mode & stat.S_IWOTH
    report = json.loads(result.report_path.read_text(encoding="utf-8"))
    assert report["command"] == command
    assert "source repo" not in " ".join(report["docker_argv"])
    assert report["source_dir"] == "[REDACTED_PATH]"
    assert report["run_dir"] == "[REDACTED_PATH]"


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


def test_contained_run_rejects_malformed_contained_config(tmp_path: Path) -> None:
    config_path = _config(tmp_path)
    data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    data["contained_execution"]["allow_privileged"] = True
    config_path.write_text(yaml.safe_dump(data), encoding="utf-8")

    with pytest.raises(ValueError, match="allow_privileged"):
        _run(config_path, ["true"], tmp_path)
