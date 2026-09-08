import ast
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.schema import ContainedExecutionConfig
from agentguard.sandbox.docker_exec_spec import (
    DockerExecSpec,
    apply_contained_execution_config,
    build_contained_docker_run_argv,
    validate_docker_exec_spec,
    validate_workspace_mount_containment,
)


IMAGE = "example.com/team/agent@sha256:" + "a" * 64


def _spec(tmp_path: Path, **changes: object) -> DockerExecSpec:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    spec = DockerExecSpec(
        image=IMAGE,
        workspace_host_path=workspace,
        workspace_container_path="/workspace",
        command=["python", "-m", "pytest"],
        uid=1000,
        gid=1000,
        container_name="agentguard-safe-123",
        environment={"PYTHONPATH": "/workspace/src", "TERM": "dumb"},
    )
    return replace(spec, **changes)


def test_exact_safe_docker_argv_construction(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    argv = build_contained_docker_run_argv(
        DockerExecSpec(
            image=IMAGE,
            workspace_host_path=workspace,
            workspace_container_path="/workspace",
            command=["python", "-m", "pytest"],
            uid=1000,
            gid=1000,
            network="none",
            cpu_limit=1.5,
            memory_limit="512m",
            pids_limit=256,
            tmpfs_path="/tmp",
            tmpfs_size="128m",
            container_name="agentguard-task-1",
            environment={"TERM": "dumb", "PYTHONPATH": "/workspace/src"},
        )
    )

    assert argv == [
        "docker",
        "run",
        "--rm",
        "--name",
        "agentguard-task-1",
        "--network",
        "none",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "256",
        "--memory",
        "512m",
        "--cpus",
        "1.5",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=700",
        "--mount",
        f"type=bind,source={workspace.resolve()},target=/workspace,rw",
        "--workdir",
        "/workspace",
        "--user",
        "1000:1000",
        "--env",
        "PYTHONPATH=/workspace/src",
        "--env",
        "TERM=dumb",
        "--",
        IMAGE,
        "python",
        "-m",
        "pytest",
    ]


def test_bounded_tmpfs_workspace_probe_has_no_host_mount(tmp_path: Path) -> None:
    argv = build_contained_docker_run_argv(
        _spec(
            tmp_path,
            workspace_host_path=None,
            workspace_tmpfs_size="64k",
            command=["true"],
        )
    )

    tmpfs_values = [
        argv[index + 1]
        for index, value in enumerate(argv)
        if value == "--tmpfs"
    ]
    assert "/workspace:rw,noexec,nosuid,nodev,size=64k,uid=1000,gid=1000,mode=700" in tmpfs_values
    assert "--mount" not in argv


@pytest.mark.parametrize("value", [0.1, 8.0])
def test_cpu_limit_boundaries_are_valid(tmp_path: Path, value: float) -> None:
    validate_docker_exec_spec(_spec(tmp_path, cpu_limit=value))


@pytest.mark.parametrize("value", [0, -1, 0.099, 8.1, "1", float("nan"), float("inf")])
def test_invalid_cpu_limits_are_rejected(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="CPU limit"):
        validate_docker_exec_spec(_spec(tmp_path, cpu_limit=value))


@pytest.mark.parametrize("value", ["64m", "16g"])
def test_memory_limit_boundaries_are_valid(tmp_path: Path, value: str) -> None:
    validate_docker_exec_spec(_spec(tmp_path, memory_limit=value))


@pytest.mark.parametrize("value", ["0", "-1", "63m", "17g", "1t", "abc", 123])
def test_malformed_or_excessive_memory_limits_are_rejected(
    tmp_path: Path,
    value: object,
) -> None:
    with pytest.raises(ValueError, match="memory"):
        validate_docker_exec_spec(_spec(tmp_path, memory_limit=value))


@pytest.mark.parametrize("value", [16, 4096])
def test_pid_limit_boundaries_are_valid(tmp_path: Path, value: int) -> None:
    validate_docker_exec_spec(_spec(tmp_path, pids_limit=value))


@pytest.mark.parametrize("value", [0, -1, 15, 4097, "64"])
def test_invalid_pid_limits_are_rejected(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="PID limit"):
        validate_docker_exec_spec(_spec(tmp_path, pids_limit=value))


@pytest.mark.parametrize("value", ["64k", "4g"])
def test_tmpfs_limit_boundaries_are_valid(tmp_path: Path, value: str) -> None:
    validate_docker_exec_spec(_spec(tmp_path, tmpfs_size=value))


@pytest.mark.parametrize("value", ["0", "-1", "63k", "5g", "1t", "bad"])
def test_invalid_tmpfs_limits_are_rejected(tmp_path: Path, value: str) -> None:
    with pytest.raises(ValueError, match="tmpfs"):
        validate_docker_exec_spec(_spec(tmp_path, tmpfs_size=value))


def test_bridge_network_requires_explicit_valid_spec(tmp_path: Path) -> None:
    argv = build_contained_docker_run_argv(_spec(tmp_path, network="bridge"))

    assert argv[argv.index("--network") + 1] == "bridge"


@pytest.mark.parametrize("network", ["host", "container:abc", "service:db"])
def test_host_and_namespace_networks_are_rejected(
    tmp_path: Path,
    network: str,
) -> None:
    with pytest.raises(ValueError, match="network"):
        validate_docker_exec_spec(_spec(tmp_path, network=network))


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("container_name", "--privileged", "container name"),
        ("container_name", "agentguard-bad name", "container name"),
        ("image", "--device=/dev/kvm", "sandbox.image"),
        ("workspace_container_path", "/var/run", "workspace"),
        ("workspace_container_path", "/workspace/../host", "workspace"),
        ("tmpfs_path", "/dev", "tmpfs"),
        ("entrypoint", "sh -c", "entrypoint"),
    ],
)
def test_option_injection_and_dangerous_paths_are_rejected(
    tmp_path: Path,
    field: str,
    value: object,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        validate_docker_exec_spec(_spec(tmp_path, **{field: value}))


@pytest.mark.parametrize("segment", ["repo,target=/proc", "repo,readonly", "repo\nbad", "repo\x1fbad"])
def test_workspace_mount_field_injection_paths_are_rejected_before_rendering(
    tmp_path: Path,
    segment: str,
) -> None:
    workspace = tmp_path / segment
    workspace.mkdir(parents=True)

    with pytest.raises(ValueError, match="mount-field"):
        build_contained_docker_run_argv(
            _spec(tmp_path, workspace_host_path=workspace)
        )


def test_workspace_mount_containment_allows_paths_renderer_later_rejects(
    tmp_path: Path,
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    workspace = root / "repo,readonly"
    workspace.mkdir()

    assert validate_workspace_mount_containment(workspace, root) == workspace.resolve()
    with pytest.raises(ValueError, match="mount-field"):
        validate_docker_exec_spec(_spec(tmp_path, workspace_host_path=workspace))


def test_relative_workspace_host_path_is_rejected_before_normalization(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="host path must be absolute"):
        validate_docker_exec_spec(_spec(tmp_path, workspace_host_path=Path("repo")))


@pytest.mark.parametrize(
    ("field", "path"),
    [
        ("workspace_container_path", "/proc/workspace"),
        ("workspace_container_path", "/sys/foo"),
        ("workspace_container_path", "/dev/shm"),
        ("workspace_container_path", "/var/run/docker.sock"),
        ("tmpfs_path", "/proc/workspace"),
        ("tmpfs_path", "/sys/foo"),
        ("tmpfs_path", "/dev/shm"),
        ("tmpfs_path", "/var/run/docker.sock"),
        ("entrypoint", "/proc/self/exe"),
        ("entrypoint", "/sys/kernel/foo"),
        ("entrypoint", "/dev/fd/0"),
        ("entrypoint", "/var/run/docker.sock"),
    ],
)
def test_reserved_container_path_prefixes_are_rejected(
    tmp_path: Path,
    field: str,
    path: str,
) -> None:
    with pytest.raises(ValueError, match=field):
        validate_docker_exec_spec(_spec(tmp_path, **{field: path}))


@pytest.mark.parametrize(("uid", "gid"), [(0, 1000), (1000, 0), (-1, 1000)])
def test_non_root_execution_is_enforced(tmp_path: Path, uid: int, gid: int) -> None:
    with pytest.raises(ValueError, match="non-root"):
        validate_docker_exec_spec(_spec(tmp_path, uid=uid, gid=gid))


def test_deterministic_ordering_is_stable(tmp_path: Path) -> None:
    first = build_contained_docker_run_argv(
        _spec(tmp_path, environment={"ZED": "last", "ALPHA": "first"})
    )
    second = build_contained_docker_run_argv(
        _spec(tmp_path, environment={"ALPHA": "first", "ZED": "last"})
    )

    assert first == second
    assert first.index("ALPHA=first") < first.index("ZED=last")


def test_apply_contained_config_rejects_prohibited_switches(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    for field in [
        "allow_privileged",
        "allow_host_network",
        "allow_docker_socket_mount",
        "allow_device_exposure",
        "allow_host_namespace_sharing",
    ]:
        contained = replace(ContainedExecutionConfig(version=1, platform="linux-docker-engine"), **{field: True})
        with pytest.raises(ValueError):
            apply_contained_execution_config(contained, spec)


def test_workspace_mount_must_stay_under_allowed_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    workspace = root / "repo"
    workspace.mkdir()

    assert validate_workspace_mount_containment(workspace, root) == workspace.resolve()
    with pytest.raises(ValueError, match="allowed root"):
        validate_workspace_mount_containment(tmp_path / "outside", root)


def test_python_39_compatible_syntax() -> None:
    source = Path("agentguard/sandbox/docker_exec_spec.py").read_text(encoding="utf-8")

    ast.parse(source, feature_version=(3, 9))
