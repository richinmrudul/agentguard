import json
import os
import stat
import subprocess
from types import SimpleNamespace
from pathlib import Path

import pytest
import yaml

from agentguard.config.loader import load_config
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
