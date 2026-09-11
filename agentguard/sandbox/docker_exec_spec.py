import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Sequence

from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.config.schema import (
    ContainedExecutionConfig,
    MAX_CONTAINED_EXECUTION_UID_GID,
)


MIN_CONTAINED_CPUS = 0.1
MAX_CONTAINED_CPUS = 8.0
MIN_CONTAINED_MEMORY_BYTES = 64 * 1024 * 1024
MAX_CONTAINED_MEMORY_BYTES = 16 * 1024 * 1024 * 1024
MIN_CONTAINED_PIDS = 16
MAX_CONTAINED_PIDS = 4096
MIN_CONTAINED_TMPFS_BYTES = 64 * 1024
MAX_CONTAINED_TMPFS_BYTES = 4 * 1024 * 1024 * 1024
CONTAINED_CONTAINER_PATH = re.compile(r"^/[A-Za-z0-9._/-]+$")
SAFE_CONTAINER_NAME = re.compile(r"^agentguard-[a-z0-9][a-z0-9_.-]{0,62}$")
_MEMORY_LIMIT = re.compile(r"^([1-9][0-9]*)([kKmMgG]?)$")
_DOCKER_MOUNT_FIELD_UNSAFE = re.compile(r"[,=\x00-\x1f\x7f]")
_RESERVED_CONTAINER_PATH_PREFIXES = ("/proc", "/sys", "/dev", "/var/run")


@dataclass(frozen=True)
class DockerExecSpec:
    image: str
    workspace_host_path: Optional[Path]
    workspace_container_path: str
    command: list[str]
    uid: int = 1000
    gid: int = 1000
    network: str = "none"
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    pids_limit: int = 256
    tmpfs_path: str = "/tmp"
    tmpfs_size: str = "256m"
    workspace_tmpfs_size: Optional[str] = None
    container_name: Optional[str] = None
    environment: Mapping[str, str] = field(default_factory=dict)
    entrypoint: Optional[str] = None


def build_contained_docker_run_argv(spec: DockerExecSpec) -> list[str]:
    validated = validate_docker_exec_spec(spec)
    argv = [
        "docker",
        "run",
        "--rm",
    ]
    if validated.container_name is not None:
        argv.extend(["--name", validated.container_name])
    argv.extend(
        [
            "--network",
            validated.network,
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            str(validated.pids_limit),
            "--memory",
            validated.memory_limit,
            "--cpus",
            _format_cpu_limit(validated.cpu_limit),
            "--read-only",
            "--tmpfs",
            (
                f"{validated.tmpfs_path}:rw,noexec,nosuid,nodev,"
                f"size={validated.tmpfs_size},uid={validated.uid},"
                f"gid={validated.gid},mode=700"
            ),
        ]
    )
    if validated.workspace_host_path is None:
        argv.extend(
            [
                "--tmpfs",
                (
                    f"{validated.workspace_container_path}:rw,noexec,nosuid,nodev,"
                    f"size={validated.workspace_tmpfs_size},uid={validated.uid},"
                    f"gid={validated.gid},mode=700"
                ),
            ]
        )
    else:
        argv.extend(
            [
                "--mount",
                (
                    "type=bind,"
                    f"source={str(validated.workspace_host_path)},"
                    f"target={validated.workspace_container_path}"
                ),
            ]
        )
    argv.extend(
        [
            "--workdir",
            validated.workspace_container_path,
            "--user",
            f"{validated.uid}:{validated.gid}",
        ]
    )
    for name, value in sorted(validated.environment.items()):
        argv.extend(["--env", f"{name}={value}"])
    if validated.entrypoint is not None:
        argv.extend(["--entrypoint", validated.entrypoint])
    argv.extend(["--", validated.image, *validated.command])
    return argv


def contained_exec_spec_from_config(
    contained: ContainedExecutionConfig,
    *,
    image: str,
    workspace_host_path: Path,
    workspace_container_path: str,
    command: Sequence[str],
    container_name: Optional[str] = None,
    environment: Optional[Mapping[str, str]] = None,
    entrypoint: Optional[str] = None,
) -> DockerExecSpec:
    return DockerExecSpec(
        image=image,
        workspace_host_path=workspace_host_path,
        workspace_container_path=workspace_container_path,
        command=list(command),
        uid=contained.required_uid,
        gid=contained.required_gid,
        network=contained.network,
        cpu_limit=contained.cpu_limit,
        memory_limit=contained.memory_limit,
        pids_limit=contained.pids_limit,
        tmpfs_size=contained.tmpfs_size,
        container_name=container_name,
        environment={} if environment is None else dict(environment),
        entrypoint=entrypoint,
    )


def validate_docker_exec_spec(spec: DockerExecSpec) -> DockerExecSpec:
    validate_docker_image_reference(spec.image)
    if "@sha256:" not in spec.image:
        raise ValueError("Docker execution image must be pinned by sha256 digest.")
    _validate_non_root_id(spec.uid, "uid")
    _validate_non_root_id(spec.gid, "gid")
    if spec.network not in {"none", "bridge"}:
        raise ValueError("Docker execution network must be 'none' or 'bridge'.")
    if spec.network == "host":
        raise ValueError("Docker host networking is not allowed.")
    _validate_cpu_limit(spec.cpu_limit)
    _validate_memory_limit(spec.memory_limit, "memory_limit")
    _validate_pids_limit(spec.pids_limit)
    _validate_memory_limit(spec.tmpfs_size, "tmpfs_size")
    tmpfs_bytes = _memory_limit_bytes(spec.tmpfs_size, "tmpfs_size")
    if tmpfs_bytes < MIN_CONTAINED_TMPFS_BYTES or tmpfs_bytes > MAX_CONTAINED_TMPFS_BYTES:
        raise ValueError("Docker tmpfs size is outside the contained-execution bounds.")
    workspace = None
    if spec.workspace_host_path is None:
        workspace_tmpfs_size = spec.workspace_tmpfs_size or spec.tmpfs_size
        workspace_tmpfs_bytes = _memory_limit_bytes(
            workspace_tmpfs_size,
            "workspace_tmpfs_size",
        )
        if (
            workspace_tmpfs_bytes < MIN_CONTAINED_TMPFS_BYTES
            or workspace_tmpfs_bytes > MAX_CONTAINED_TMPFS_BYTES
        ):
            raise ValueError(
                "Docker workspace tmpfs size is outside the contained-execution bounds."
            )
    else:
        expanded_workspace = spec.workspace_host_path.expanduser()
        if not expanded_workspace.is_absolute():
            raise ValueError("Docker workspace host path must be absolute.")
        workspace = expanded_workspace.resolve()
        _validate_mount_field_path(workspace)
        workspace_tmpfs_size = None
    _validate_container_path(spec.workspace_container_path, "workspace_container_path")
    _validate_container_path(spec.tmpfs_path, "tmpfs_path")
    workspace_container_path = spec.workspace_container_path.rstrip("/") or "/"
    tmpfs_path = spec.tmpfs_path.rstrip("/") or "/"
    if tmpfs_path == workspace_container_path:
        raise ValueError("Docker tmpfs path must not replace the workspace.")
    if spec.container_name is not None and SAFE_CONTAINER_NAME.fullmatch(spec.container_name) is None:
        raise ValueError("Docker container name must be an AgentGuard safe name.")
    if not spec.command or not all(isinstance(item, str) and item for item in spec.command):
        raise ValueError("Docker execution command must be a non-empty argv list.")
    _validate_environment(spec.environment)
    if spec.entrypoint is not None:
        _validate_container_path(spec.entrypoint, "entrypoint")
    return DockerExecSpec(
        image=spec.image,
        workspace_host_path=workspace,
        workspace_container_path=workspace_container_path,
        command=list(spec.command),
        uid=spec.uid,
        gid=spec.gid,
        network=spec.network,
        cpu_limit=spec.cpu_limit,
        memory_limit=spec.memory_limit,
        pids_limit=spec.pids_limit,
        tmpfs_path=tmpfs_path,
        tmpfs_size=spec.tmpfs_size,
        workspace_tmpfs_size=workspace_tmpfs_size,
        container_name=spec.container_name,
        environment=dict(spec.environment),
        entrypoint=spec.entrypoint,
    )


def validate_workspace_mount_containment(
    workspace_host_path: Path,
    allowed_root: Path,
) -> Path:
    workspace = workspace_host_path.expanduser().resolve()
    root = allowed_root.expanduser().resolve()
    try:
        workspace.relative_to(root)
    except ValueError as error:
        raise ValueError("Docker workspace mount must stay within the allowed root.") from error
    return workspace


def apply_contained_execution_config(
    contained: ContainedExecutionConfig,
    spec: DockerExecSpec,
) -> DockerExecSpec:
    if contained.version != 1:
        raise ValueError("Contained-execution version must be 1.")
    if contained.network != spec.network:
        raise ValueError("Contained-execution network does not match the Docker spec.")
    if contained.image_provenance != "digest-required":
        raise ValueError("Contained-execution requires digest image provenance.")
    if contained.allow_privileged:
        raise ValueError("Privileged Docker execution is not allowed.")
    if contained.allow_host_network:
        raise ValueError("Docker host networking is not allowed.")
    if contained.allow_docker_socket_mount:
        raise ValueError("Docker socket mounts are not allowed.")
    if contained.allow_device_exposure:
        raise ValueError("Docker device exposure is not allowed.")
    if contained.allow_host_namespace_sharing:
        raise ValueError("Docker host namespace sharing is not allowed.")
    return validate_docker_exec_spec(
        DockerExecSpec(
            image=spec.image,
            workspace_host_path=spec.workspace_host_path,
            workspace_container_path=spec.workspace_container_path,
            command=spec.command,
            uid=contained.required_uid,
            gid=contained.required_gid,
            network=contained.network,
            cpu_limit=contained.cpu_limit,
            memory_limit=contained.memory_limit,
            pids_limit=contained.pids_limit,
            tmpfs_path=spec.tmpfs_path,
            tmpfs_size=contained.tmpfs_size,
            workspace_tmpfs_size=spec.workspace_tmpfs_size,
            container_name=spec.container_name,
            environment=spec.environment,
            entrypoint=spec.entrypoint,
        )
    )


def _validate_non_root_id(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Docker execution {name} must be a positive non-root integer.")
    if value > MAX_CONTAINED_EXECUTION_UID_GID:
        raise ValueError(
            f"Docker execution {name} must not exceed "
            f"{MAX_CONTAINED_EXECUTION_UID_GID}."
        )


def _validate_cpu_limit(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Docker CPU limit must be a finite number.")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Docker CPU limit must be finite.")
    if number < MIN_CONTAINED_CPUS or number > MAX_CONTAINED_CPUS:
        raise ValueError("Docker CPU limit is outside the contained-execution bounds.")


def _validate_memory_limit(value: object, name: str) -> None:
    size = _memory_limit_bytes(value, name)
    if name == "memory_limit":
        if size < MIN_CONTAINED_MEMORY_BYTES or size > MAX_CONTAINED_MEMORY_BYTES:
            raise ValueError("Docker memory limit is outside the contained-execution bounds.")


def _memory_limit_bytes(value: object, name: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"Docker {name} must be a bounded Docker size string.")
    match = _MEMORY_LIMIT.fullmatch(value)
    if match is None:
        raise ValueError(f"Docker {name} must be a bounded Docker size string.")
    amount = int(match.group(1))
    suffix = match.group(2).lower()
    multiplier = {"": 1, "k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}[suffix]
    return amount * multiplier


def _validate_pids_limit(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Docker PID limit must be an integer.")
    if value < MIN_CONTAINED_PIDS or value > MAX_CONTAINED_PIDS:
        raise ValueError("Docker PID limit is outside the contained-execution bounds.")


def _validate_container_path(value: object, name: str) -> None:
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise ValueError(f"Docker {name} must be an absolute container path.")
    if "//" in value or "/../" in value or value.endswith("/..") or "/./" in value:
        raise ValueError(f"Docker {name} must be normalized.")
    if value == "/" or any(
        value == prefix or value.startswith(f"{prefix}/")
        for prefix in _RESERVED_CONTAINER_PATH_PREFIXES
    ):
        raise ValueError(f"Docker {name} is not allowed.")
    if CONTAINED_CONTAINER_PATH.fullmatch(value) is None:
        raise ValueError(f"Docker {name} contains unsupported characters.")


def _validate_mount_field_path(path: Path) -> None:
    text = str(path)
    if _DOCKER_MOUNT_FIELD_UNSAFE.search(text) is not None:
        raise ValueError(
            "Docker workspace host path contains unsafe mount-field characters."
        )


def _validate_environment(environment: Mapping[str, str]) -> None:
    for name, value in environment.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("Docker environment names must be valid identifiers.")
        if not isinstance(value, str) or "\0" in value:
            raise ValueError("Docker environment values must be strings without NUL.")


def _format_cpu_limit(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.6f}".rstrip("0").rstrip(".")
