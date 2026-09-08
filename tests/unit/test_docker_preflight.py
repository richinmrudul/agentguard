import ast
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.config.schema import ContainedExecutionConfig, SandboxConfig
from agentguard.sandbox import docker_preflight
from agentguard.sandbox.docker_preflight import (
    DockerPreflightCommandResult,
    DockerPreflightStatus,
    run_docker_preflight,
)


IMAGE_DIGEST = "example.com/agentguard/nonroot@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "1" * 64


def _config(**changes):
    config = replace(
        load_config(Path("examples/configs/fix_auth_bug_docker.yaml")),
        sandbox=SandboxConfig(
            type="docker",
            image=IMAGE_DIGEST,
            network="none",
            memory="256m",
            cpus=1.0,
            read_only=True,
        ),
        contained_execution=ContainedExecutionConfig(
            version=1,
            platform="linux-docker-engine",
            network="none",
            image_provenance="digest-required",
        ),
        agent_command=["python", "-c", "print('agent command must not run')"],
    )
    return replace(config, **changes)


def _version(*, desktop=False, os_name="linux", api_version="1.45"):
    return {
        "Client": {"Version": "27.0.0"},
        "Server": {
            "Version": "27.0.0",
            "ApiVersion": api_version,
            "Os": os_name,
            "Arch": "amd64",
            "Platform": {"Name": "Docker Desktop" if desktop else "Docker Engine"},
        },
    }


def _info(*, desktop=False, memory_limit=True, ncpu=4):
    return {
        "OperatingSystem": (
            "Docker Desktop" if desktop else "Ubuntu 24.04 LTS"
        ),
        "MemoryLimit": memory_limit,
        "NCPU": ncpu,
        "CgroupDriver": "systemd",
        "CgroupVersion": "2",
    }


def _image(*, user="1000:1000", os_name="linux", repo_digests=None):
    return {
        "Id": IMAGE_ID,
        "RepoDigests": [IMAGE_DIGEST] if repo_digests is None else repo_digests,
        "Os": os_name,
        "Architecture": "amd64",
        "Config": {"User": user},
    }


class FakeDocker:
    def __init__(
        self,
        *,
        version=None,
        info=None,
        image=None,
        network=None,
        fail=None,
    ) -> None:
        self.version = _version() if version is None else version
        self.info = _info() if info is None else info
        self.image = _image() if image is None else image
        self.network = {"Name": "none"} if network is None else network
        self.fail = fail or {}
        self.commands = []

    def __call__(self, argv, timeout_seconds, max_output_bytes):
        self.commands.append(argv)
        key = self._key(argv)
        failure = self.fail.get(key)
        if failure == "missing":
            raise FileNotFoundError
        if failure == "timeout":
            return DockerPreflightCommandResult(argv, 124, timed_out=True)
        if failure == "malformed":
            return DockerPreflightCommandResult(argv, 0, stdout="{not json")
        if failure == "oversized":
            return DockerPreflightCommandResult(
                argv,
                0,
                stdout="{}",
                stdout_truncated=True,
            )
        if failure == "daemon":
            return DockerPreflightCommandResult(
                argv,
                1,
                stderr=(
                    "Cannot connect to unix:///Users/alice/.docker/run/docker.sock "
                    "TOKEN=super-secret"
                ),
            )
        payload = {
            "version": self.version,
            "info": self.info,
            "network": self.network,
            "image": self.image,
        }[key]
        return DockerPreflightCommandResult(
            argv,
            0,
            stdout=docker_preflight.json.dumps(payload),
        )

    @staticmethod
    def _key(argv):
        if argv[:2] == ["docker", "version"]:
            return "version"
        if argv[:2] == ["docker", "info"]:
            return "info"
        if argv[:3] == ["docker", "network", "inspect"]:
            return "network"
        if argv[:3] == ["docker", "image", "inspect"]:
            return "image"
        raise AssertionError(f"unexpected docker command: {argv!r}")


def test_authoritative_linux_preflight_success() -> None:
    fake = FakeDocker()

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.SUPPORTED
    assert result.supported is True
    assert result.claim_level == "linux-docker-engine"
    assert result.docker_image is not None
    assert result.docker_image.registry_digest == IMAGE_DIGEST
    assert [command[:2] for command in fake.commands] == [
        ["docker", "version"],
        ["docker", "info"],
        ["docker", "network"],
        ["docker", "image"],
    ]


def test_docker_desktop_is_reduced_claim_when_configured() -> None:
    contained = ContainedExecutionConfig(
        version=1,
        platform="docker-desktop-experimental",
        network="none",
        image_provenance="digest-required",
    )
    fake = FakeDocker(version=_version(desktop=True), info=_info(desktop=True))

    result = run_docker_preflight(
        _config(contained_execution=contained),
        command_runner=fake,
    )

    assert result.status == DockerPreflightStatus.EXPERIMENTAL
    assert result.supported is False
    assert result.claim_level == "docker-desktop-reduced"


def test_docker_cli_missing_is_unavailable() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(fail={"version": "missing"}),
    )

    assert result.status == DockerPreflightStatus.UNAVAILABLE
    assert result.checks[-1].name == "docker_cli_available"


def test_daemon_unavailable_is_sanitized() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(fail={"version": "daemon"}),
    )

    evidence = result.checks[-1].evidence
    assert result.status == DockerPreflightStatus.UNAVAILABLE
    assert "<docker-endpoint>" in evidence["stderr"]
    assert "<path>" not in evidence["stderr"]
    assert "super-secret" not in evidence["stderr"]
    assert "/Users/alice" not in evidence["stderr"]


@pytest.mark.parametrize("failure", ["timeout", "malformed", "oversized"])
def test_bounded_docker_response_failures(failure: str) -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(fail={"version": failure}),
    )

    assert result.status == DockerPreflightStatus.UNAVAILABLE
    assert result.checks[-1].passed is False


def test_unsupported_engine_platform_fails_closed() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(version=_version(os_name="windows")),
    )

    assert result.status == DockerPreflightStatus.UNAVAILABLE
    assert result.checks[-1].name == "engine_platform"


def test_linux_claim_rejects_docker_desktop_contradiction() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(version=_version(desktop=True), info=_info(desktop=True)),
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "platform_claim"


def test_root_user_ambiguity_is_unsafe() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(image=_image(user="")),
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "non_root_user"


def test_unsupported_image_platform_is_unsafe() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(image=_image(os_name="windows")),
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "image_identity"


def test_missing_required_capability_is_unsafe() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(info=_info(memory_limit=False)),
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_limits"


def test_unsafe_config_options_are_rejected_before_docker_calls() -> None:
    contained = replace(_config().contained_execution, allow_privileged=True)
    fake = FakeDocker()

    result = run_docker_preflight(
        _config(contained_execution=contained),
        command_runner=fake,
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "contained_execution_contract"
    assert fake.commands == []


def test_unsafe_sandbox_boundary_is_rejected_before_docker_calls() -> None:
    fake = FakeDocker()

    result = run_docker_preflight(
        _config(sandbox=replace(_config().sandbox, network="bridge")),
        command_runner=fake,
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "sandbox_boundary_inputs"
    assert fake.commands == []


def test_no_agent_execution_on_failure() -> None:
    fake = FakeDocker(fail={"version": "daemon"})

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNAVAILABLE
    assert all(command[0] == "docker" for command in fake.commands)
    assert not any("agent command must not run" in part for command in fake.commands for part in command)


def test_python_39_compatible_syntax() -> None:
    source = Path("agentguard/sandbox/docker_preflight.py").read_text(encoding="utf-8")

    ast.parse(source, feature_version=(3, 9))
