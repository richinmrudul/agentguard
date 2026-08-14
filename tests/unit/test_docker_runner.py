from dataclasses import replace
import io
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from agentguard.agents.custom_command_agent import CustomCommandAgent
from agentguard.config.loader import load_config
from agentguard.config.schema import CommandPolicyConfig, SandboxConfig
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.processes import ProcessCleanupResult
from agentguard.provenance.manifest import detect_agent_version
from agentguard.sandbox.docker_runner import (
    DockerCommandRunner,
    DockerTestRunner,
    _docker_test_argv,
)
from agentguard.sandbox.docker_identity import DockerImageIdentity
from agentguard.sandbox.docker_identity import (
    parse_docker_image_identity,
    select_registry_digest,
)

_PREPARE_CONTAINER_IDENTITY = DockerCommandRunner._prepare_container_identity


@pytest.fixture(autouse=True)
def _established_docker_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        DockerCommandRunner,
        "_prepare_container_identity",
        lambda self, *_args, **_kwargs: DockerImageIdentity(
            configured_reference=self.sandbox.image or "",
            local_image_id="sha256:" + "1" * 64,
            executed_image_id="sha256:" + "1" * 64,
            registry_digest="python@sha256:" + "2" * 64,
            platform="linux/amd64",
            cache_status="present",
        ),
    )
    monkeypatch.setattr(
        DockerCommandRunner,
        "_remove_container",
        lambda self, _name: ProcessCleanupResult(
            attempted=True,
            complete=True,
            message="docker container removed after timeout",
        ),
    )


class FakeProcess:
    def __init__(
        self,
        *,
        returncode: int = 0,
        stdout: str = "ok",
        stderr: str = "",
        timeout: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = io.BytesIO(stdout.encode())
        self.stderr = io.BytesIO(stderr.encode())
        self.timeout = timeout
        self.pid = 12345
        self._waited = False
        self.last_timeout = None
        self.wait_timeouts = []

    def wait(self, timeout=None):
        self.last_timeout = timeout
        self.wait_timeouts.append(timeout)
        if self.timeout and not self._waited:
            self._waited = True
            raise subprocess.TimeoutExpired(
                cmd=["docker"],
                timeout=timeout,
            )
        self.returncode = -9 if self.timeout else self.returncode
        return self.returncode

    def poll(self):
        return self.returncode


def _docker_version_config(**changes):
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_version_command=["agent", "--version"],
        command_timeout_seconds=30,
    )
    return replace(config, **changes)


def test_docker_version_detection_uses_only_docker_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    calls = []

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return FakeProcess(returncode=0, stdout="agent 4.2\n")

    monkeypatch.setattr(
        "agentguard.provenance.manifest.popen_with_process_group",
        lambda *_args, **_kwargs: pytest.fail("host version command executed"),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()
    config = _docker_version_config(
        sandbox=SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            workdir="/agent-work",
            network="none",
            memory="256m",
            cpus=0.5,
            read_only=True,
            timeout_seconds=23,
        ),
        agent_environment={
            "PATH": "/host-only/bin",
            "PYTHONPATH": "/host-only/python",
            "API_TOKEN": "host-secret",
        },
    )

    detected = detect_agent_version(
        config,
        repo_dir=repo_dir,
        command_tracker=tracker,
    )

    assert detected == ("agent 4.2", "detected", None)
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:3] == ["docker", "start", "-a"]
    assert not any("host-only" in part or "host-secret" in part for part in command)
    assert "env" not in kwargs
    assert tracker.commands == ["docker agent version: agent --version"]


def test_docker_version_detection_fails_closed_without_boundary_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "host-marker"
    config = _docker_version_config(
        agent_version_command=[
            "python",
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).touch()",
        ]
    )
    monkeypatch.setattr(
        "agentguard.provenance.manifest.popen_with_process_group",
        lambda *_args, **_kwargs: pytest.fail("host version command executed"),
    )

    version, status, warning = detect_agent_version(config)

    assert version is None
    assert status == "failed"
    assert "prepared repository" in (warning or "")
    assert not marker.exists()


def test_docker_version_detection_reports_missing_docker_without_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    launched = []

    def missing_docker(command, **_kwargs):
        launched.append(command)
        raise FileNotFoundError

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        missing_docker,
    )

    version, status, warning = detect_agent_version(
        _docker_version_config(),
        repo_dir=repo_dir,
        command_tracker=CommandTracker(),
    )

    assert version is None
    assert status == "failed"
    assert warning == "Docker is unavailable for agent version detection."
    assert len(launched) == 1
    assert launched[0][0:2] == ["docker", "start"]


def test_docker_version_detection_controls_boundary_and_command_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    launches = []

    def fake_popen(command, **_kwargs):
        launches.append(command)
        return FakeProcess(returncode=127, stderr="agent: executable not found\n")

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    version, status, warning = detect_agent_version(
        _docker_version_config(),
        repo_dir=repo_dir,
        command_tracker=CommandTracker(),
    )
    assert version is None
    assert status == "failed"
    assert warning == "Agent version command exited with status 127."
    assert len(launches) == 1

    invalid = _docker_version_config(
        sandbox=SandboxConfig(type="docker", image="--privileged"),
    )
    version, status, warning = detect_agent_version(
        invalid,
        repo_dir=repo_dir,
        command_tracker=CommandTracker(),
    )
    assert version is None
    assert status == "failed"
    assert warning == "Agent version command failed: ValueError."
    assert len(launches) == 1


def test_docker_version_detection_applies_policy_before_launch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _docker_version_config(
        agent_version_command=["blocked-version"],
        unsafe_commands=["blocked-version"],
        command_policy=CommandPolicyConfig(mode="enforce"),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: pytest.fail("blocked command launched"),
    )

    version, status, warning = detect_agent_version(
        config,
        repo_dir=tmp_path,
        command_tracker=CommandTracker(),
    )

    assert version is None
    assert status == "blocked"
    assert warning == "Agent version command was blocked by command policy."


def test_docker_version_detection_bounds_timeout_and_sanitizes_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    process = FakeProcess(
        returncode=0,
        stdout="Authorization: Bearer canary-version-token\n",
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    tracker = CommandTracker()

    version, status, warning = detect_agent_version(
        _docker_version_config(command_timeout_seconds=99),
        repo_dir=repo_dir,
        command_tracker=tracker,
    )

    assert (version, status, warning) == (
        "Authorization: [REDACTED]",
        "detected",
        None,
    )
    assert process.last_timeout == 10
    assert "canary-version-token" not in tracker.events[0].stdout
    assert tracker.events[0].stdout == "Authorization: [REDACTED]\n"


def test_docker_version_detection_returns_controlled_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    process = FakeProcess(returncode=None, timeout=True)
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.terminate_process_tree",
        lambda _process: SimpleNamespace(
            attempted=True,
            complete=True,
            kill_required=True,
            message="process tree terminated",
        ),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    version, status, warning = detect_agent_version(
        _docker_version_config(command_timeout_seconds=2),
        repo_dir=repo_dir,
        command_tracker=CommandTracker(),
    )

    assert version is None
    assert status == "failed"
    assert warning == "Agent version command timed out."
    assert process.wait_timeouts[0] == 2


def test_docker_command_includes_expected_container_options(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerTestRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            workdir="/workspace",
            network="none",
            timeout_seconds=30,
        ),
    )

    command = runner._docker_command(repo_dir, ["pytest"])

    assert command[:3] == ["docker", "run", "--rm"]
    assert "-v" in command
    assert f"{repo_dir.resolve()}:/workspace" in command
    assert command[command.index("-w") + 1] == "/workspace"
    assert command[command.index("-e") + 1] == "PYTHONPATH=/workspace/src"
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" not in command
    assert "python:3.11-slim" in command
    assert command[command.index("python:3.11-slim") - 1] == "--"
    assert command[-1] == "pytest"


@pytest.mark.parametrize(
    "image",
    [
        "--network=host",
        "--privileged",
        "--volume=/controlled/host/path:/host",
        "--mount=type=bind,source=/controlled,target=/host",
        "--device=/dev/example",
    ],
)
def test_docker_command_rejects_option_like_images(
    tmp_path: Path,
    image: str,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerCommandRunner(
        CommandTracker(),
        SandboxConfig(type="docker", image=image, network="none"),
    )

    with pytest.raises(ValueError, match="sandbox.image"):
        runner.build_command(repo_dir, ["alpine:3.20", "true"])


def test_docker_command_places_image_after_option_boundary(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    image = "registry.example.com:5443/team/image:release"
    runner = DockerCommandRunner(
        CommandTracker(),
        SandboxConfig(type="docker", image=image, network="none"),
    )

    command = runner.build_command(repo_dir, ["true"])

    boundary = command.index("--")
    assert command[command.index("--network") + 1] == "none"
    assert command.index("--network") < boundary
    assert command[boundary + 1 :] == [image, "true"]


def test_docker_command_includes_configured_resource_limits(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerTestRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            memory="512m",
            cpus=1.0,
        ),
    )

    command = runner._docker_command(repo_dir, ["pytest"])

    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--memory") + 1] == "512m"
    assert command[command.index("--cpus") + 1] == "1.0"
    assert "--read-only" not in command


def test_docker_command_includes_read_only_only_when_true(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerTestRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            read_only=True,
        ),
    )

    command = runner._docker_command(repo_dir, ["pytest"])

    assert "--read-only" in command
    assert command[command.index("--tmpfs") + 1] == "/tmp"


def test_docker_command_sets_pythonpath_for_custom_workdir(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerTestRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="python:3.11-slim",
            workdir="/app",
        ),
    )

    command = runner._docker_command(repo_dir, ["python", "-m", "tests"])

    assert f"{repo_dir.resolve()}:/app" in command
    assert command[command.index("-w") + 1] == "/app"
    assert command[command.index("-e") + 1] == "PYTHONPATH=/app/src"


def test_docker_command_runner_records_readable_agent_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    calls = []

    def fake_popen(command, **kwargs):
        calls.append(command)
        return FakeProcess(returncode=0, stdout="agent ok", stderr="")

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()
    runner = DockerCommandRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )

    result = runner.run_argv(
        repo_dir=repo_dir,
        inner_command=["python", "agent_scripts/safe_agent.py"],
        command_text="docker agent: python agent_scripts/safe_agent.py",
    )

    assert result.exit_code == 0
    assert result.docker_image is not None
    assert result.docker_image.configured_reference == "python:3.11-slim"
    assert result.docker_image.local_image_id == result.docker_image.executed_image_id
    assert tracker.commands == ["docker agent: python agent_scripts/safe_agent.py"]
    assert tracker.events[0].docker_image == result.docker_image
    assert tracker.events[0].command == calls[0]
    assert tracker.events[0].command[:3] == ["docker", "start", "-a"]
    assert "run" not in tracker.events[0].command
    assert "--rm" not in tracker.events[0].command
    assert "PYTHONDONTWRITEBYTECODE=1" not in calls[0]
    assert not any(item.startswith("RUFF_CACHE_DIR=") for item in calls[0])
    assert not any(item.startswith("GOCACHE=") for item in calls[0])


def test_docker_identity_is_bound_to_created_container_before_start(
    tmp_path: Path,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    runner = DockerCommandRunner(
        CommandTracker(),
        SandboxConfig(
            type="docker",
            image="example/app:latest",
            memory="256m",
            cpus=0.5,
            read_only=True,
        ),
        timeout_seconds=137,
    )
    image_id = "sha256:" + "a" * 64
    digest = "example/app@sha256:" + "b" * 64
    calls = []

    def control(command, **kwargs):
        calls.append((command, kwargs.get("timeout_seconds", 10)))
        if command[1:3] == ["image", "inspect"] and command[-1] == "example/app:latest":
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if command[1] == "create":
            assert kwargs["timeout_seconds"] == 137
            assert f"{repo_dir.resolve()}:/workspace" in command
            assert command[command.index("-w") + 1] == "/workspace"
            assert command[command.index("--network") + 1] == "none"
            assert command[command.index("--memory") + 1] == "256m"
            assert command[command.index("--cpus") + 1] == "0.5"
            assert "--read-only" in command
            assert command[command.index("--tmpfs") + 1] == "/tmp"
            assert "EXAMPLE=value" in command
            assert command[command.index("--") + 2 :] == ["true"]
            assert command[command.index("--") + 1] == "example/app:latest"
            return SimpleNamespace(returncode=0, stdout="container-id\n", stderr="")
        if command[1:3] == ["container", "inspect"]:
            return SimpleNamespace(
                returncode=0,
                stdout=f'{{"Image":"{image_id}"}}',
                stderr="",
            )
        return SimpleNamespace(
            returncode=0,
            stdout=(
                f'{{"Id":"{image_id}","RepoDigests":["{digest}"],'
                '"Os":"linux","Architecture":"arm64","Variant":"v8"}'
            ),
            stderr="",
        )

    runner._docker_control = control
    identity = _PREPARE_CONTAINER_IDENTITY(
        runner,
        repo_dir,
        ["true"],
        container_name="agentguard-test",
        environment={"EXAMPLE": "value"},
    )

    assert identity.configured_reference == "example/app:latest"
    assert identity.local_image_id == image_id
    assert identity.executed_image_id == image_id
    assert identity.registry_digest == digest
    assert identity.platform == "linux/arm64/v8"
    assert identity.pull_policy == "docker-default"
    assert identity.cache_status == "present"
    assert [command[0][1] for command in calls] == [
        "image",
        "create",
        "container",
        "image",
    ]
    assert [timeout for _, timeout in calls] == [10, 137, 10, 10]


def test_registry_digest_selection_is_repository_precise() -> None:
    digest_a = "a" * 64
    digest_b = "b" * 64
    values = [
        f"other/app@sha256:{digest_a}",
        f"example/app@sha256:{digest_b}",
    ]

    assert select_registry_digest("example/app:latest", values) == (
        f"example/app@sha256:{digest_b}"
    )
    assert select_registry_digest(
        f"example/app@sha256:{digest_b}", values
    ) == f"example/app@sha256:{digest_b}"
    assert select_registry_digest(
        f"example/app:release@sha256:{digest_b}", values
    ) == f"example/app@sha256:{digest_b}"
    assert select_registry_digest(
        f"example/app@sha256:{digest_a}", values
    ) is None
    assert select_registry_digest(
        "example/app:latest",
        [
            f"example/app@sha256:{digest_a}",
            f"example/app@sha256:{digest_b}",
        ],
    ) is None
    assert select_registry_digest(
        "example/app:latest", ["example/app@sha256:not-a-digest"]
    ) is None


@pytest.mark.parametrize(
    "change",
    [
        {"extra": "field"},
        {"local_image_id": "sha256:short"},
        {"executed_image_id": "sha256:" + "2" * 64},
        {"registry_digest": "other/app@sha256:short"},
        {"registry_digest": "other/app@sha256:" + "3" * 64},
        {"pull_policy": "always"},
        {"cache_status": "maybe"},
        {"platform": "linux"},
    ],
)
def test_docker_identity_parser_rejects_malformed_evidence(change) -> None:
    data = {
        "configured_reference": "example/app:latest",
        "local_image_id": "sha256:" + "1" * 64,
        "executed_image_id": "sha256:" + "1" * 64,
        "registry_digest": None,
        "platform": "linux/amd64",
        "pull_policy": "docker-default",
        "cache_status": "present",
    }
    data.update(change)

    with pytest.raises(ValueError, match="Docker"):
        parse_docker_image_identity(data)


def test_post_start_cleanup_failure_is_preserved_without_replacing_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = DockerCommandRunner(
        CommandTracker(), SandboxConfig(type="docker", image="example/app:latest")
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda _name: ProcessCleanupResult(
            attempted=True,
            complete=False,
            message="docker cleanup incomplete: container removal failed",
        ),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: FakeProcess(returncode=7, stderr="primary failure"),
    )

    result = runner.run_argv(tmp_path, ["false"], "docker: false")

    assert result.exit_code == 7
    assert result.process_cleanup_attempted is True
    assert result.process_cleanup_complete is False
    assert result.process_cleanup_message == (
        "docker cleanup incomplete: container removal failed"
    )
    assert "primary failure" in result.stderr
    assert "docker cleanup incomplete" in result.stderr
    assert runner.command_tracker.events[0].process_cleanup_complete is False


def test_docker_identity_change_produces_distinct_provenance(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def resolve(hex_character: str) -> DockerImageIdentity:
        runner = DockerCommandRunner(
            CommandTracker(),
            SandboxConfig(type="docker", image="example/app:latest"),
        )
        image_id = "sha256:" + hex_character * 64

        def control(command, **_kwargs):
            if command[1:3] == ["image", "inspect"] and command[-1].endswith(":latest"):
                return SimpleNamespace(returncode=1, stdout="", stderr="offline")
            if command[1] == "create":
                return SimpleNamespace(returncode=0, stdout="container\n", stderr="")
            if command[1:3] == ["container", "inspect"]:
                return SimpleNamespace(returncode=0, stdout=f'{{"Image":"{image_id}"}}', stderr="")
            return SimpleNamespace(returncode=0, stdout=f'{{"Id":"{image_id}","RepoDigests":[],"Os":"linux","Architecture":"amd64","Variant":""}}', stderr="")

        runner._docker_control = control
        return _PREPARE_CONTAINER_IDENTITY(
            runner, repo_dir, ["true"], container_name="agentguard-test", environment=None
        )

    assert resolve("a") != resolve("b")


def test_docker_identity_failure_prevents_container_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = DockerCommandRunner(
        CommandTracker(), SandboxConfig(type="docker", image="example/app:latest")
    )
    controls = []

    def control(command, **_kwargs):
        controls.append(command)
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="[]", stderr="")
        if command[1] == "create":
            return SimpleNamespace(returncode=0, stdout="container\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="inspect failed")

    runner._docker_control = control
    monkeypatch.setattr(
        runner,
        "_prepare_container_identity",
        lambda *args, **kwargs: _PREPARE_CONTAINER_IDENTITY(
            runner, *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: pytest.fail("container execution started"),
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda _name: ProcessCleanupResult(attempted=True, complete=True),
    )

    result = runner.run_argv(tmp_path, ["true"], "docker: true")

    assert result.exit_code == 125
    assert result.docker_image is None
    assert result.process_cleanup_attempted is True
    assert result.process_cleanup_complete is True
    assert result.stderr == "Docker could not establish the immutable image identity before execution."
    assert [command[1] for command in controls] == ["image", "create", "container"]
    assert runner.command_tracker.events[0].command == controls[1]
    assert runner.command_tracker.events[0].command[:2] == ["docker", "create"]
    assert "run" not in runner.command_tracker.events[0].command
    assert "--rm" not in runner.command_tracker.events[0].command


def test_inspect_failure_records_incomplete_cleanup_without_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = DockerCommandRunner(
        CommandTracker(), SandboxConfig(type="docker", image="example/app:latest")
    )

    def control(command, **_kwargs):
        if command[1:3] == ["image", "inspect"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="not present")
        if command[1] == "create":
            return SimpleNamespace(returncode=0, stdout="container\n", stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="inspect failed")

    runner._docker_control = control
    monkeypatch.setattr(
        runner,
        "_prepare_container_identity",
        lambda *args, **kwargs: _PREPARE_CONTAINER_IDENTITY(
            runner, *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda _name: ProcessCleanupResult(
            attempted=True,
            complete=False,
            message="docker cleanup incomplete: container removal failed",
        ),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: pytest.fail("container execution started"),
    )

    result = runner.run_argv(tmp_path, ["true"], "docker: true")

    assert result.exit_code == 125
    assert result.process_cleanup_attempted is True
    assert result.process_cleanup_complete is False
    assert result.stderr.startswith(
        "Docker could not establish the immutable image identity before execution."
    )
    assert "docker cleanup incomplete" in result.stderr
    assert runner.command_tracker.events[0].process_cleanup_complete is False
    assert runner.command_tracker.events[0].command[:2] == ["docker", "create"]
    assert "run" not in runner.command_tracker.events[0].command
    assert "--rm" not in runner.command_tracker.events[0].command


def test_create_failure_does_not_claim_cleanup_or_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = DockerCommandRunner(
        CommandTracker(), SandboxConfig(type="docker", image="example/app:latest")
    )

    def control(command, **_kwargs):
        return SimpleNamespace(
            returncode=125 if command[1] == "create" else 1,
            stdout="",
            stderr="create failed",
        )

    runner._docker_control = control
    monkeypatch.setattr(
        runner,
        "_prepare_container_identity",
        lambda *args, **kwargs: _PREPARE_CONTAINER_IDENTITY(
            runner, *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda _name: pytest.fail("cleanup claimed for failed create"),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: pytest.fail("container execution started"),
    )

    result = runner.run_argv(tmp_path, ["true"], "docker: true")

    assert result.exit_code == 125
    assert result.process_cleanup_attempted is False
    assert result.process_cleanup_complete is True
    assert runner.command_tracker.events[0].command[:2] == ["docker", "create"]
    assert "run" not in runner.command_tracker.events[0].command
    assert "--rm" not in runner.command_tracker.events[0].command


def test_docker_runner_records_install_and_test_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    calls = []

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return FakeProcess(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()
    runner = DockerTestRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )

    result = runner.run(repo_dir, "pytest")

    assert result.exit_code == 0
    assert len(calls) == 2
    assert all(command[:3] == ["docker", "start", "-a"] for command, _ in calls)
    assert tracker.commands == [
        "docker: python -m pip install --no-build-isolation -e .",
        "docker: pytest",
    ]


def test_docker_command_runner_uses_configured_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    calls = []

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return FakeProcess(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    runner = DockerCommandRunner(
        CommandTracker(),
        SandboxConfig(type="docker", image="python:3.11-slim"),
        timeout_seconds=7,
    )

    result = runner.run_argv(repo_dir, ["python", "-m", "tests"], "docker: tests")

    assert result.exit_code == 0
    assert calls[0][0][:3] == ["docker", "start", "-a"]
    assert calls[0][0][3].startswith("agentguard-")


def test_docker_command_runner_records_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    remove_calls = []

    def fake_popen(command, **kwargs):
        return FakeProcess(
            returncode=None,
            stdout="partial stdout",
            stderr="partial stderr",
            timeout=True,
        )

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.terminate_process_tree",
        lambda process: SimpleNamespace(
            attempted=True,
            complete=True,
            kill_required=True,
            message="process tree terminated",
        ),
    )
    tracker = CommandTracker()
    runner = DockerCommandRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
        timeout_seconds=3,
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda name: (
            remove_calls.append(["docker", "rm", "-f", name])
            or ProcessCleanupResult(attempted=True, complete=True)
        ),
    )

    result = runner.run_argv(repo_dir, ["python", "-m", "tests"], "docker: tests")

    assert result.exit_code == 124
    assert result.timed_out is True
    assert "Docker command timed out after 3 seconds" in result.stderr
    assert result.process_cleanup_attempted is True
    assert result.process_cleanup_complete is True
    assert remove_calls[0][:3] == ["docker", "rm", "-f"]
    assert tracker.events[0].timed_out is True
    assert tracker.events[0].process_cleanup_complete is True


def test_docker_interrupt_removes_container_and_preserves_interrupt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    process = FakeProcess(returncode=None)
    removed = []

    class InterruptingCapture:
        def __init__(self, *_args):
            pass

        def wait(self, timeout=None):
            raise KeyboardInterrupt("docker interrupted")

        def finish(self, timeout=None):
            return None

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.BoundedProcessOutput",
        InterruptingCapture,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.terminate_process_tree",
        lambda _process: None,
    )
    runner = DockerCommandRunner(
        CommandTracker(),
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda name: removed.append(name),
    )

    with pytest.raises(KeyboardInterrupt, match="docker interrupted"):
        runner.run_argv(repo_dir, ["true"], "docker: true")

    assert len(removed) == 1


def test_docker_timeout_cleanup_failures_remain_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    class TimeoutCapture:
        def __init__(self, *_args):
            pass

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("docker", timeout)

        def finish(self, timeout=None):
            raise RuntimeError("finish failed")

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: object(),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.BoundedProcessOutput",
        TimeoutCapture,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.terminate_process_tree",
        lambda _process: (_ for _ in ()).throw(RuntimeError("cleanup failed")),
    )
    runner = DockerCommandRunner(
        CommandTracker(),
        SandboxConfig(type="docker", image="python:3.11-slim"),
        timeout_seconds=1,
    )
    monkeypatch.setattr(
        runner,
        "_remove_container",
        lambda _name: (_ for _ in ()).throw(RuntimeError("remove failed")),
    )

    result = runner.run_argv(repo_dir, ["true"], "docker: true")

    assert result.exit_code == 124
    assert result.timed_out is True
    assert result.process_cleanup_complete is False


def test_docker_command_runner_truncates_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_popen(command, **kwargs):
        return FakeProcess(
            returncode=0,
            stdout="start" + ("x" * 2000000) + "stdout-end",
            stderr="start" + ("e" * 2000000) + "stderr-end",
        )

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()
    runner = DockerCommandRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
        max_output_bytes=80,
    )

    result = runner.run_argv(repo_dir, ["python", "-m", "tests"], "docker: tests")

    assert result.stdout_truncated is True
    assert len(result.stdout.encode("utf-8")) <= 80
    assert result.stdout.startswith("[agentguard] Output truncated")
    assert result.stdout.endswith("stdout-end")
    assert result.stderr.endswith("stderr-end")
    assert result.stderr_truncated is True
    assert tracker.events[0].stdout_truncated is True


def test_docker_test_argv_normalizes_pytest_command() -> None:
    assert _docker_test_argv("pytest") == ["python", "-m", "pytest"]


def test_docker_test_argv_preserves_pytest_args() -> None:
    assert _docker_test_argv("pytest -q") == ["python", "-m", "pytest", "-q"]


def test_docker_test_argv_preserves_non_pytest_command() -> None:
    assert _docker_test_argv("python -m auth_example.mini_pytest") == [
        "python",
        "-m",
        "auth_example.mini_pytest",
    ]


def test_docker_runner_surfaces_missing_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_popen(command, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()
    runner = DockerTestRunner(
        tracker,
        SandboxConfig(type="docker", image="python:3.11-slim"),
    )

    result = runner.run(repo_dir, "pytest")

    assert result.exit_code == 127
    assert "Docker is not installed" in result.stderr
    assert (
        tracker.events[0].command_text
        == "docker: python -m pip install --no-build-isolation -e ."
    )


def test_custom_command_agent_requires_agent_command(tmp_path: Path) -> None:
    config = load_config(Path("examples/configs/fix_auth_bug_docker.yaml"))
    agent = CustomCommandAgent(config)

    with pytest.raises(ValueError, match="requires config field 'agent_command'"):
        agent.run(tmp_path, CommandTracker())


def test_custom_command_agent_runs_in_docker_with_readable_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_command="python agent_scripts/safe_agent.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    calls = []

    def fake_popen(command, **kwargs):
        calls.append(command)
        return FakeProcess(returncode=0, stdout="agent ok", stderr="")

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()

    CustomCommandAgent(config).run(repo_dir, tracker)

    assert calls[0][:3] == ["docker", "start", "-a"]
    assert tracker.commands == ["docker agent: python agent_scripts/safe_agent.py"]


def test_custom_command_agent_retains_sanitized_nonzero_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "custom-agent-secret"
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_command=f"python agent.py --token {secret}",
        agent_environment={},
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    def fake_popen(command, **kwargs):
        return FakeProcess(
            returncode=7,
            stdout=(
                f"Authorization: Bearer {secret}\n"
                f"echoed={secret}\n{repo_dir}\x1b[31m"
            ),
            stderr=f"https://user:{secret}@example.invalid/error",
        )

    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        fake_popen,
    )
    tracker = CommandTracker()

    CustomCommandAgent(config).run(repo_dir, tracker)

    event = tracker.events[0]
    serialized = repr(event)
    assert event.exit_code == 7
    assert event.executed is True
    assert event.cwd == "[REPOSITORY]"
    assert "[REDACTED]" in serialized
    assert secret not in serialized
    assert str(repo_dir) not in serialized
    assert "\x1b" not in event.stdout
    assert "\\x1b" in event.stdout


@pytest.mark.parametrize(
    ("returncode", "expected"),
    [
        (125, "Docker could not start the custom agent container."),
    ],
)
def test_custom_command_agent_reports_stable_container_setup_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    expected: str,
) -> None:
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_command="python agent.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    canary = "raw-docker-daemon-error\x1b[31m"
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: FakeProcess(
            returncode=returncode,
            stderr=canary,
        ),
    )

    with pytest.raises(ValueError) as caught:
        CustomCommandAgent(config).run(repo_dir, CommandTracker())

    assert str(caught.value) == expected
    assert canary not in str(caught.value)


def test_custom_command_agent_reports_stable_missing_docker_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_command="python agent.py",
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()),
    )

    with pytest.raises(ValueError) as caught:
        CustomCommandAgent(config).run(repo_dir, CommandTracker())

    assert str(caught.value) == (
        "Docker is unavailable; the custom agent container did not start."
    )


def test_custom_command_agent_retains_bounded_timeout_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        agent_command="python agent.py",
        command_timeout_seconds=2,
        max_output_bytes=96,
    )
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    process = FakeProcess(
        returncode=None,
        stdout="output\x1b[31m" * 30,
        stderr="failure\x1b[31m" * 30,
        timeout=True,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.popen_with_process_group",
        lambda *_args, **_kwargs: process,
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.terminate_process_tree",
        lambda *_args, **_kwargs: ProcessCleanupResult(
            attempted=True,
            complete=False,
            kill_required=True,
            message="process cleanup incomplete",
        ),
    )
    monkeypatch.setattr(
        "agentguard.sandbox.docker_runner.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="",
        ),
    )
    tracker = CommandTracker()

    CustomCommandAgent(config).run(repo_dir, tracker)

    event = tracker.events[0]
    assert event.exit_code == 124
    assert event.timed_out is True
    assert event.process_cleanup_attempted is True
    assert event.process_cleanup_complete is False
    assert len(event.stdout.encode("utf-8")) <= 96
    assert len(event.stderr.encode("utf-8")) <= 96
    assert "\x1b" not in event.stdout


def test_sandbox_defaults_to_local(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
""",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config.sandbox.type == "local"
    assert config.sandbox.workdir == "/workspace"
    assert config.sandbox.network == "none"
    assert config.sandbox.timeout_seconds == 60


def test_docker_sandbox_requires_image(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
sandbox:
  type: docker
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.image"):
        load_config(config_path)


def test_invalid_sandbox_type_raises_clear_error(tmp_path: Path) -> None:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(
        """
task_id: task
description: Task.
repo_template: examples/repos/auth_bug
test_command: pytest
expected_modified_files:
  min: 1
  max: 2
sandbox:
  type: vm
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="sandbox.type"):
        load_config(config_path)
