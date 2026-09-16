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
    PROBE_WRITABLE_PATH,
    run_docker_preflight,
)


IMAGE_DIGEST = "example.com/agentguard/nonroot@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "1" * 64
CONTAINER_ID = "2" * 64
PROBE_NAME = "agentguard-preflight-owned"


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
        inspect=None,
        probe=None,
        fail=None,
        present_after_rm=False,
    ) -> None:
        self.version = _version() if version is None else version
        self.info = _info() if info is None else info
        self.image = _image() if image is None else image
        self.network = {"Name": "none"} if network is None else network
        self.inspect = self._inspect_payload() if inspect is None else inspect
        self.probe = (
            {
                "uid": 1000,
                "gid": 1000,
                "writable_path": PROBE_WRITABLE_PATH,
                "root_write_blocked": True,
            }
            if probe is None
            else probe
        )
        self.fail = fail or {}
        self.commands = []
        self.removed = []
        self.container_present = True
        self.present_after_rm = present_after_rm

    def _inspect_payload(self, **overrides):
        payload = {
            "Id": CONTAINER_ID,
            "Name": f"/{PROBE_NAME}",
            "Image": IMAGE_ID,
            "Config": {
                "User": "1000:1000",
                "Labels": {
                    "agentguard.owner": "preflight",
                    "agentguard.preflight": "resource-controls",
                    "agentguard.preflight.name": PROBE_NAME,
                },
            },
            "HostConfig": {
                "PidsLimit": 256,
                "Memory": 512 * 1024 * 1024,
                "NanoCpus": 1_000_000_000,
                "CpuQuota": 0,
                "CpuPeriod": 0,
                "ReadonlyRootfs": True,
                "SecurityOpt": ["no-new-privileges"],
                "CapDrop": ["ALL"],
                "NetworkMode": "none",
                "Privileged": False,
                "PidMode": "",
                "IpcMode": "",
                "UsernsMode": "",
                "UTSMode": "",
                "CgroupnsMode": "private",
                "Devices": [],
                "DeviceRequests": [],
                "Binds": None,
                "Tmpfs": {
                    "/tmp": "rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=700",
                    "/agentguard-workspace": "rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=700",
                },
            },
            "Mounts": [],
        }
        payload.update(overrides)
        return payload

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
        if key == "create":
            name_index = argv.index("--name") + 1
            if isinstance(self.inspect.get("Config"), dict):
                labels = self.inspect["Config"].get("Labels")
                if isinstance(labels, dict):
                    labels["agentguard.preflight.name"] = argv[name_index]
            self.inspect["Name"] = f"/{argv[name_index]}"
            return DockerPreflightCommandResult(argv, 0, stdout=f"{CONTAINER_ID}\n")
        if key == "start":
            return DockerPreflightCommandResult(argv, 0, stdout="")
        if key == "rm":
            self.removed.append(argv[-1])
            self.container_present = self.present_after_rm
            return DockerPreflightCommandResult(argv, 0, stdout=argv[-1])
        if key == "inspect" and not self.container_present:
            return DockerPreflightCommandResult(
                argv,
                1,
                stderr=f"Error: No such container: {argv[-1]}",
            )
        payload = {
            "version": self.version,
            "info": self.info,
            "network": self.network,
            "image": self.image,
            "inspect": self.inspect,
            "probe": self.probe,
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
        if argv[:2] == ["docker", "create"]:
            return "create"
        if argv[:3] == ["docker", "container", "inspect"]:
            return "inspect"
        if argv[:2] == ["docker", "start"]:
            return "start"
        if argv[:2] == ["docker", "rm"]:
            return "rm"
        if argv[:2] == ["docker", "run"]:
            return "probe"
        raise AssertionError(f"unexpected docker command: {argv!r}")


def test_authoritative_linux_preflight_success() -> None:
    fake = FakeDocker()

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.SUPPORTED
    assert result.supported is True
    assert result.claim_level == "linux-docker-engine"
    assert result.docker_image is not None
    assert result.docker_image.registry_digest == IMAGE_DIGEST
    resource = next(check for check in result.checks if check.name == "resource_control_probe")
    assert resource.evidence["requested"]["pids_limit"] == 256
    assert resource.evidence["requested"]["memory_limit"] == "512m"
    assert resource.evidence["requested"]["cpu_limit"] == 1.0
    assert resource.evidence["inspected"]["pids_limit"] == 256
    assert resource.evidence["inspected"]["memory_bytes"] == 512 * 1024 * 1024
    assert resource.evidence["inspected"]["cpu"]["representation"] == "NanoCpus"
    assert resource.evidence["inspected"]["read_only_rootfs"] is True
    assert resource.evidence["inspected"]["no_new_privileges"] is True
    assert resource.evidence["inspected"]["cap_drop_all"] is True
    assert resource.evidence["inspected"]["docker_socket_mount"] is False
    assert resource.evidence["docker_accepted"]["container_created"] is True
    assert resource.evidence["cleanup"]["status"] == "removed"
    probe = result.checks[-1]
    assert probe.name == "uid_gid_writable_path_probe"
    assert probe.evidence["uid"] == 1000
    assert probe.evidence["gid"] == 1000
    assert [command[:2] for command in fake.commands] == [
        ["docker", "version"],
        ["docker", "info"],
        ["docker", "network"],
        ["docker", "image"],
        ["docker", "create"],
        ["docker", "container"],
        ["docker", "start"],
        ["docker", "rm"],
        ["docker", "container"],
        ["docker", "run"],
    ]
    create_command = fake.commands[4]
    assert create_command[:2] == ["docker", "create"]
    assert "--label" in create_command
    assert "--rm" not in create_command
    assert "--pids-limit" in create_command
    assert "256" in create_command
    assert "--memory" in create_command
    assert "512m" in create_command
    assert "--cpus" in create_command
    assert "1" in create_command
    assert fake.commands[5][-1] == CONTAINER_ID
    assert fake.commands[6][-1] == CONTAINER_ID
    assert fake.commands[7][-1] == CONTAINER_ID
    assert fake.commands[8][-1] == CONTAINER_ID
    run_command = fake.commands[-1]
    assert "--user" in run_command
    assert "1000:1000" in run_command
    assert "--security-opt" in run_command
    assert "no-new-privileges" in run_command
    assert "--cap-drop" in run_command
    assert "ALL" in run_command
    assert "--pids-limit" in run_command
    assert "64" in run_command
    assert "--memory" in run_command
    assert "64m" in run_command
    assert "--cpus" in run_command
    assert "1" in run_command
    assert "--tmpfs" in run_command
    assert "--entrypoint" in run_command
    assert "/bin/sh" in run_command
    assert IMAGE_DIGEST in run_command
    forbidden_parts = {
        "--privileged",
        "--device",
        "--pid",
        "--ipc",
        "--userns",
        "--uts",
        "--cgroupns",
        "/var/run/docker.sock",
    }
    assert not forbidden_parts.intersection(run_command)
    assert "host" not in run_command


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


def test_root_uid_gid_probe_result_is_unsafe() -> None:
    result = run_docker_preflight(
        _config(),
        command_runner=FakeDocker(
            image=_image(user=""),
            probe={
                "uid": 0,
                "gid": 0,
                "writable_path": PROBE_WRITABLE_PATH,
                "root_write_blocked": True,
            },
        ),
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "uid_gid_writable_path_probe"


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


@pytest.mark.parametrize(
    ("info", "signal"),
    [
        (_info(memory_limit=False), "memory_limit"),
        ({key: value for key, value in _info().items() if key != "NCPU"}, "cpu_count_present"),
    ],
)
def test_contained_resource_capabilities_required_when_legacy_sandbox_limits_unset(
    info: dict[str, object],
    signal: str,
) -> None:
    sandbox = replace(_config().sandbox, memory=None, cpus=None)

    result = run_docker_preflight(
        _config(sandbox=sandbox),
        command_runner=FakeDocker(info=info),
    )

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_limits"
    assert result.checks[-1].evidence["requested"] == {
        "pids_limit": 256,
        "memory_limit": "512m",
        "cpu_limit": 1.0,
    }
    assert result.checks[-1].evidence["daemon_signals"][signal] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("PidsLimit", 0),
        ("PidsLimit", 128),
        ("PidsLimit", None),
        ("Memory", 0),
        ("Memory", 128 * 1024 * 1024),
        ("Memory", "536870912"),
        ("NanoCpus", 0),
        ("NanoCpus", 500_000_000),
        ("NanoCpus", "1000000000"),
    ],
)
def test_resource_control_probe_rejects_missing_zero_mismatch_and_malformed_values(
    field: str,
    value: object,
) -> None:
    fake = FakeDocker()
    fake.inspect["HostConfig"][field] = value

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe"
    assert ["docker", "rm", "-f", CONTAINER_ID] in fake.commands
    assert not any(command[:2] == ["docker", "run"] for command in fake.commands)


def test_resource_control_probe_accepts_equivalent_cpu_quota_period() -> None:
    fake = FakeDocker()
    fake.inspect["HostConfig"]["NanoCpus"] = 0
    fake.inspect["HostConfig"]["CpuQuota"] = 150_000
    fake.inspect["HostConfig"]["CpuPeriod"] = 100_000
    contained = replace(_config().contained_execution, cpu_limit=1.5)

    result = run_docker_preflight(
        _config(contained_execution=contained),
        command_runner=fake,
    )

    assert result.status == DockerPreflightStatus.SUPPORTED
    resource = next(check for check in result.checks if check.name == "resource_control_probe")
    assert resource.evidence["inspected"]["cpu"]["representation"] == "CpuQuota/CpuPeriod"


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("root", "Id", "3" * 64),
        ("root", "Image", "sha256:" + "4" * 64),
        ("config", "User", "0:0"),
        ("labels", "agentguard.owner", "other"),
        ("host", "ReadonlyRootfs", False),
        ("host", "SecurityOpt", []),
        ("host", "CapDrop", []),
        ("host", "NetworkMode", "host"),
        ("host", "Privileged", True),
        ("host", "PidMode", "host"),
        ("host", "Devices", [{"PathOnHost": "/dev/kvm"}]),
        ("host", "Binds", ["/var/run/docker.sock:/var/run/docker.sock"]),
        ("host", "Tmpfs", {}),
    ],
)
def test_resource_control_probe_rejects_identity_and_adjacent_control_mismatches(
    section: str,
    field: str,
    value: object,
) -> None:
    fake = FakeDocker()
    if section == "root":
        fake.inspect[field] = value
    elif section == "config":
        fake.inspect["Config"][field] = value
    elif section == "labels":
        fake.inspect["Config"]["Labels"][field] = value
    else:
        fake.inspect["HostConfig"][field] = value

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe"
    assert not any(command[:2] == ["docker", "run"] for command in fake.commands)


@pytest.mark.parametrize("failure", ["timeout", "malformed", "oversized", "daemon"])
def test_resource_control_probe_inspect_failures_are_unsafe(failure: str) -> None:
    fake = FakeDocker(fail={"inspect": failure})

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe_inspect"
    assert ["docker", "rm", "-f", CONTAINER_ID] in fake.commands
    assert not any(command[:2] == ["docker", "run"] for command in fake.commands)


@pytest.mark.parametrize("failure", ["timeout", "daemon"])
def test_resource_control_probe_create_and_start_failures_are_unsafe(
    failure: str,
) -> None:
    fake = FakeDocker(fail={"create": failure})

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe_create"
    assert not any(command[:2] == ["docker", "run"] for command in fake.commands)

    fake = FakeDocker(fail={"start": failure})
    result = run_docker_preflight(_config(), command_runner=fake)
    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe_start"
    assert ["docker", "rm", "-f", CONTAINER_ID] in fake.commands
    assert not any(command[:2] == ["docker", "run"] for command in fake.commands)


def test_resource_control_probe_cleanup_failure_is_reported() -> None:
    fake = FakeDocker(fail={"rm": "daemon"})

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe_cleanup"
    assert result.checks[-1].evidence["cleanup_status"] == "cleanup_failed"


def test_resource_control_probe_cleanup_success_requires_verified_absence() -> None:
    fake = FakeDocker()

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.SUPPORTED
    resource = next(check for check in result.checks if check.name == "resource_control_probe")
    assert resource.evidence["cleanup"]["status"] == "removed"
    rm_index = fake.commands.index(["docker", "rm", "-f", CONTAINER_ID])
    assert fake.commands[rm_index + 1] == [
        "docker",
        "container",
        "inspect",
        "--format",
        "{{json .}}",
        CONTAINER_ID,
    ]


def test_resource_control_probe_cleanup_fails_when_container_still_present() -> None:
    fake = FakeDocker(present_after_rm=True)

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe_cleanup"
    assert result.checks[-1].evidence["cleanup_status"] == "cleanup_still_present"
    assert ["docker", "rm", "-f", CONTAINER_ID] in fake.commands


def test_failed_create_does_not_remove_unrelated_similarly_named_container() -> None:
    unrelated = FakeDocker(fail={"create": "daemon"})
    unrelated.inspect["Config"]["Labels"]["agentguard.owner"] = "someone-else"

    result = run_docker_preflight(_config(), command_runner=unrelated)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "resource_control_probe_create"
    assert not any(command[:2] == ["docker", "rm"] for command in unrelated.commands)


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


@pytest.mark.parametrize(
    "change",
    [
        {"required_uid": 0},
        {"required_gid": 0},
        {"required_uid": 2147483648},
        {"required_gid": 2147483648},
    ],
)
def test_unsafe_uid_gid_contract_values_are_rejected_before_docker_calls(
    change: dict[str, int],
) -> None:
    contained = replace(_config().contained_execution, **change)
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


@pytest.mark.parametrize("failure", ["timeout", "malformed", "oversized", "daemon"])
def test_uid_gid_writable_path_probe_failures_are_unsafe(failure: str) -> None:
    fake = FakeDocker(fail={"probe": failure})

    result = run_docker_preflight(_config(), command_runner=fake)

    assert result.status == DockerPreflightStatus.UNSAFE
    assert result.checks[-1].name == "uid_gid_writable_path_probe"
    run_command = fake.commands[-1]
    assert run_command[:2] == ["docker", "run"]
    assert "--user" in run_command
    assert "1000:1000" in run_command
    assert not any("agent command must not run" in part for part in run_command)
    if failure == "daemon":
        assert "super-secret" not in result.checks[-1].evidence["stderr"]
        assert "/Users/alice" not in result.checks[-1].evidence["stderr"]


def test_python_39_compatible_syntax() -> None:
    source = Path("agentguard/sandbox/docker_preflight.py").read_text(encoding="utf-8")

    ast.parse(source, feature_version=(3, 9))
