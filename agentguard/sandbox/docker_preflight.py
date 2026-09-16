import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.config.schema import (
    MAX_CONTAINED_EXECUTION_UID_GID,
    AgentGuardConfig,
    ContainedExecutionConfig,
)
from agentguard.instrumentation.output_limits import BoundedProcessOutput, limit_output
from agentguard.instrumentation.processes import cleanup_process_after_exception
from agentguard.sandbox.docker_identity import (
    IMAGE_ID_PATTERN,
    DockerImageIdentity,
    parse_docker_image_identity,
    select_registry_digest,
)
from agentguard.sandbox.docker_exec_spec import (
    DockerExecSpec,
    build_contained_docker_run_argv,
)


PREFLIGHT_TIMEOUT_SECONDS = 5
PREFLIGHT_MAX_OUTPUT_BYTES = 65536
DIAGNOSTIC_MAX_BYTES = 512
PREFLIGHT_JSON_MAX_NESTING = 32
PREFLIGHT_JSON_MAX_ITEMS = 512
PREFLIGHT_JSON_MAX_STRING_BYTES = 65536
MIN_DOCKER_API_FOR_READ_ONLY_TMPFS = (1, 25)
PROBE_WRITABLE_PATH = "/agentguard-preflight"
PROBE_WRITABLE_FILE = f"{PROBE_WRITABLE_PATH}/write-check"
PROBE_WORKSPACE_PATH = "/agentguard-workspace"
PROBE_CONTAINER_PREFIX = "agentguard-preflight-"
PROBE_OWNER_LABEL = "agentguard.owner=preflight"
PROBE_KIND_LABEL = "agentguard.preflight=resource-controls"
CONTAINER_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL)[A-Z0-9_]*)"
    r"\s*=\s*[^\s,;]+"
)
DAEMON_ENDPOINT_PATTERN = re.compile(
    r"(?i)\b(?:unix|tcp|npipe|ssh)://[^\s,;]+"
)
PRIVATE_PATH_PATTERN = re.compile(
    r"(?:/Users/[^/\s,;]+|/home/[^/\s,;]+|/private/tmp|/private/var|/tmp)"
    r"(?:/[^\s,;]*)?"
)
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class DockerPreflightStatus(str, Enum):
    SUPPORTED = "supported"
    EXPERIMENTAL = "experimental"
    UNAVAILABLE = "unavailable"
    UNSAFE = "unsafe"


@dataclass(frozen=True)
class DockerPreflightCommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass(frozen=True)
class DockerPreflightCheck:
    name: str
    passed: bool
    status: str
    diagnostic: str
    evidence: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class DockerPreflightResult:
    status: DockerPreflightStatus
    claim_level: str
    supported: bool
    checks: list[DockerPreflightCheck]
    docker_image: Optional[DockerImageIdentity] = None
    evidence: dict[str, object] = field(default_factory=dict)

    def to_evidence(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "status": self.status.value,
            "claim_level": self.claim_level,
            "supported": self.supported,
            "checks": [
                {
                    "name": check.name,
                    "passed": check.passed,
                    "status": check.status,
                    "diagnostic": check.diagnostic,
                    "evidence": check.evidence,
                }
                for check in self.checks
            ],
            "evidence": self.evidence,
        }
        if self.docker_image is not None:
            payload["docker_image"] = {
                "configured_reference": self.docker_image.configured_reference,
                "local_image_id": self.docker_image.local_image_id,
                "executed_image_id": self.docker_image.executed_image_id,
                "registry_digest": self.docker_image.registry_digest,
                "platform": self.docker_image.platform,
                "pull_policy": self.docker_image.pull_policy,
                "cache_status": self.docker_image.cache_status,
            }
        return payload


CommandRunner = Callable[
    [list[str], int, int],
    DockerPreflightCommandResult,
]


class DockerPreflightError(RuntimeError):
    def __init__(self, status: DockerPreflightStatus, check: DockerPreflightCheck):
        super().__init__(check.diagnostic)
        self.status = status
        self.check = check


def run_docker_preflight(
    config: AgentGuardConfig,
    *,
    command_runner: Optional[CommandRunner] = None,
    timeout_seconds: int = PREFLIGHT_TIMEOUT_SECONDS,
    max_output_bytes: int = PREFLIGHT_MAX_OUTPUT_BYTES,
) -> DockerPreflightResult:
    if config.contained_execution is None:
        check = _check(
            "contained_execution_config",
            False,
            DockerPreflightStatus.UNAVAILABLE,
            "contained_execution is not configured.",
        )
        return _result(DockerPreflightStatus.UNAVAILABLE, "none", [check])

    runner = command_runner or _run_docker_command
    checks: list[DockerPreflightCheck] = []
    evidence: dict[str, object] = {"preflight_version": 1}
    docker_image = None

    try:
        _validate_contract(config.contained_execution, checks)
        _validate_sandbox_boundary_inputs(config, checks)
        image = _configured_image(config, checks)
        version = _docker_json(
            runner,
            ["docker", "version", "--format", "{{json .}}"],
            "docker_version",
            timeout_seconds,
            max_output_bytes,
        )
        checks.append(
            _check(
                "docker_cli_and_daemon",
                True,
                DockerPreflightStatus.SUPPORTED,
                "Docker CLI and daemon responded with JSON.",
            )
        )
        server = _object_field(version, "Server", "docker_version")
        client = _object_field(version, "Client", "docker_version")
        platform = _platform_from_version(server, client, checks)
        info = _docker_json(
            runner,
            ["docker", "info", "--format", "{{json .}}"],
            "docker_info",
            timeout_seconds,
            max_output_bytes,
        )
        _validate_platform_claim(
            config.contained_execution,
            server,
            info,
            platform,
            checks,
        )
        _validate_required_capabilities(
            config,
            info,
            server,
            runner,
            timeout_seconds,
            max_output_bytes,
            checks,
        )
        image_metadata = _inspect_image(
            image,
            runner,
            timeout_seconds,
            max_output_bytes,
        )
        docker_image = _validate_image_identity(
            image,
            image_metadata,
            checks,
        )
        _record_image_user_declaration(
            image_metadata,
            checks,
        )
        _probe_resource_controls(
            config.contained_execution,
            image,
            docker_image,
            runner,
            timeout_seconds,
            max_output_bytes,
            checks,
        )
        _probe_uid_gid_writable_path(
            config.contained_execution,
            image,
            runner,
            timeout_seconds,
            max_output_bytes,
            checks,
        )
    except FileNotFoundError:
        checks.append(
            _check(
                "docker_cli_available",
                False,
                DockerPreflightStatus.UNAVAILABLE,
                "Docker CLI is not available on PATH.",
            )
        )
        return _result(DockerPreflightStatus.UNAVAILABLE, "none", checks, evidence=evidence)
    except DockerPreflightError as error:
        checks.append(error.check)
        return _result(error.status, "none", checks, evidence=evidence)

    claim_level = (
        "docker-desktop-reduced"
        if config.contained_execution.platform == "docker-desktop-experimental"
        else "linux-docker-engine"
    )
    status = (
        DockerPreflightStatus.EXPERIMENTAL
        if claim_level == "docker-desktop-reduced"
        else DockerPreflightStatus.SUPPORTED
    )
    evidence["approved_boundary_constructible"] = True
    return _result(
        status,
        claim_level,
        checks,
        docker_image=docker_image,
        evidence=evidence,
    )


def _run_docker_command(
    argv: list[str],
    timeout_seconds: int,
    max_output_bytes: int,
) -> DockerPreflightCommandResult:
    process = None
    capture = None
    try:
        env = {"PATH": os.environ.get("PATH", "")}
        if os.environ.get("HOME"):
            env["HOME"] = os.environ["HOME"]
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        capture = BoundedProcessOutput(process, max_output_bytes, retain_tail=False)
        returncode = capture.wait(timeout=timeout_seconds)
        output = capture.finish(timeout=1)
        return DockerPreflightCommandResult(
            argv=argv,
            returncode=returncode,
            stdout=output.stdout.text,
            stderr=output.stderr.text,
            stdout_truncated=output.stdout.truncated,
            stderr_truncated=output.stderr.truncated,
        )
    except FileNotFoundError:
        raise
    except subprocess.TimeoutExpired:
        cleanup_process_after_exception(process, capture)
        return DockerPreflightCommandResult(
            argv=argv,
            returncode=124,
            timed_out=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return DockerPreflightCommandResult(
            argv=argv,
            returncode=125,
            stderr=error.__class__.__name__,
        )


def _docker_json(
    runner: CommandRunner,
    argv: list[str],
    check_name: str,
    timeout_seconds: int,
    max_output_bytes: int,
    failure_status: DockerPreflightStatus = DockerPreflightStatus.UNAVAILABLE,
) -> dict[str, object]:
    started = time.monotonic()
    completed = runner(argv, timeout_seconds, max_output_bytes)
    duration = round(time.monotonic() - started, 6)
    if completed.timed_out:
        raise DockerPreflightError(
            failure_status,
            _check(
                check_name,
                False,
                failure_status,
                "Docker command timed out.",
                {"duration_seconds": duration},
            ),
        )
    if completed.stdout_truncated or completed.stderr_truncated:
        raise DockerPreflightError(
            failure_status,
            _check(
                check_name,
                False,
                failure_status,
                "Docker command output exceeded the preflight bound.",
                {"duration_seconds": duration},
            ),
        )
    if completed.returncode != 0:
        raise DockerPreflightError(
            failure_status,
            _check(
                check_name,
                False,
                failure_status,
                "Docker command did not complete successfully.",
                {
                    "returncode": completed.returncode,
                    "stderr": _sanitize_diagnostic(completed.stderr),
                    "duration_seconds": duration,
                },
            ),
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise DockerPreflightError(
            failure_status,
            _check(
                check_name,
                False,
                failure_status,
                "Docker command returned malformed JSON.",
                {"duration_seconds": duration},
            ),
        ) from None
    try:
        _validate_json_bounds(value, depth=0)
    except ValueError as error:
        raise DockerPreflightError(
            failure_status,
            _check(
                check_name,
                False,
                failure_status,
                str(error),
                {"duration_seconds": duration},
            ),
        ) from None
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    if not isinstance(value, dict):
        raise DockerPreflightError(
            failure_status,
            _check(
                check_name,
                False,
                failure_status,
                "Docker command returned an unsupported JSON shape.",
            ),
        )
    return value


def _docker_text(
    runner: CommandRunner,
    argv: list[str],
    check_name: str,
    timeout_seconds: int,
    max_output_bytes: int,
    *,
    unsafe: bool = True,
) -> str:
    started = time.monotonic()
    completed = runner(argv, timeout_seconds, max_output_bytes)
    duration = round(time.monotonic() - started, 6)
    status = DockerPreflightStatus.UNSAFE if unsafe else DockerPreflightStatus.UNAVAILABLE
    if completed.timed_out:
        raise DockerPreflightError(
            status,
            _check(
                check_name,
                False,
                status,
                "Docker probe command timed out.",
                {"duration_seconds": duration},
            ),
        )
    if completed.stdout_truncated or completed.stderr_truncated:
        raise DockerPreflightError(
            status,
            _check(
                check_name,
                False,
                status,
                "Docker probe command output exceeded the preflight bound.",
                {"duration_seconds": duration},
            ),
        )
    if completed.returncode != 0:
        raise DockerPreflightError(
            status,
            _check(
                check_name,
                False,
                status,
                "Docker probe command did not complete successfully.",
                {
                    "returncode": completed.returncode,
                    "stderr": _sanitize_diagnostic(completed.stderr),
                    "duration_seconds": duration,
                },
            ),
        )
    return completed.stdout


def _probe_json(
    runner: CommandRunner,
    argv: list[str],
    check_name: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, object]:
    started = time.monotonic()
    completed = runner(argv, timeout_seconds, max_output_bytes)
    duration = round(time.monotonic() - started, 6)
    if completed.timed_out:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                check_name,
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID writable-path probe timed out.",
                {"duration_seconds": duration},
            ),
        )
    if completed.stdout_truncated or completed.stderr_truncated:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                check_name,
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID writable-path probe exceeded the output bound.",
                {"duration_seconds": duration},
            ),
        )
    if completed.returncode != 0:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                check_name,
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID writable-path probe failed.",
                {
                    "returncode": completed.returncode,
                    "stderr": _sanitize_diagnostic(completed.stderr),
                    "duration_seconds": duration,
                },
            ),
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                check_name,
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID writable-path probe returned malformed JSON.",
                {"duration_seconds": duration},
            ),
        ) from None
    if not isinstance(value, dict):
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                check_name,
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID writable-path probe returned an unsupported shape.",
            ),
        )
    return value


def _validate_contract(
    contained: ContainedExecutionConfig,
    checks: list[DockerPreflightCheck],
) -> None:
    unsafe = []
    if contained.version != 1:
        unsafe.append("unsupported contract version")
    if contained.platform not in {"linux-docker-engine", "docker-desktop-experimental"}:
        unsafe.append("unsupported platform")
    if contained.network not in {"none", "bridge"}:
        unsafe.append("unsupported network")
    if contained.image_provenance != "digest-required":
        unsafe.append("unsupported image provenance")
    if (
        isinstance(contained.required_uid, bool)
        or not isinstance(contained.required_uid, int)
        or contained.required_uid <= 0
        or contained.required_uid > MAX_CONTAINED_EXECUTION_UID_GID
    ):
        unsafe.append("unsupported required UID")
    if (
        isinstance(contained.required_gid, bool)
        or not isinstance(contained.required_gid, int)
        or contained.required_gid <= 0
        or contained.required_gid > MAX_CONTAINED_EXECUTION_UID_GID
    ):
        unsafe.append("unsupported required GID")
    flags = {
        "allow_privileged": contained.allow_privileged,
        "allow_host_network": contained.allow_host_network,
        "allow_docker_socket_mount": contained.allow_docker_socket_mount,
        "allow_device_exposure": contained.allow_device_exposure,
        "allow_host_namespace_sharing": contained.allow_host_namespace_sharing,
    }
    unsafe.extend(name for name, enabled in flags.items() if enabled)
    if not contained.require_evidence_outside_agent_repo:
        unsafe.append("in-repository evidence")
    if unsafe:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "contained_execution_contract",
                False,
                DockerPreflightStatus.UNSAFE,
                "Contained-execution config requests unsupported or unsafe options.",
                {"rejected": sorted(unsafe)},
            ),
        )
    checks.append(
        _check(
            "contained_execution_contract",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Contained-execution config uses the v1 approved boundary inputs.",
        )
    )


def _validate_sandbox_boundary_inputs(
    config: AgentGuardConfig,
    checks: list[DockerPreflightCheck],
) -> None:
    rejected = []
    if config.sandbox.type != "docker":
        rejected.append("sandbox.type")
    if config.sandbox.network != config.contained_execution.network:
        rejected.append("sandbox.network")
    if rejected:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "sandbox_boundary_inputs",
                False,
                DockerPreflightStatus.UNSAFE,
                "Sandbox config cannot construct the approved Docker boundary.",
                {"rejected": rejected},
            ),
        )
    checks.append(
        _check(
            "sandbox_boundary_inputs",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Sandbox config matches the contained Docker network mode.",
        )
    )


def _configured_image(config: AgentGuardConfig, checks: list[DockerPreflightCheck]) -> str:
    image = config.sandbox.image
    if not image:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "image_reference",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker image is required for contained preflight.",
            ),
        )
    try:
        validate_docker_image_reference(image)
    except ValueError:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "image_reference",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker image reference is invalid.",
            ),
        ) from None
    if "@sha256:" not in image:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "image_reference",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker image must be pinned by sha256 digest.",
            ),
        )
    checks.append(
        _check(
            "image_reference",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker image reference is digest pinned.",
        )
    )
    return image


def _platform_from_version(
    server: dict[str, object],
    client: dict[str, object],
    checks: list[DockerPreflightCheck],
) -> str:
    server_os = _string_field(server, "Os", "docker_version.Server")
    server_arch = _string_field(server, "Arch", "docker_version.Server")
    _string_field(server, "Version", "docker_version.Server")
    _string_field(client, "Version", "docker_version.Client")
    if server_os != "linux" or not server_arch:
        raise DockerPreflightError(
            DockerPreflightStatus.UNAVAILABLE,
            _check(
                "engine_platform",
                False,
                DockerPreflightStatus.UNAVAILABLE,
                "Docker server is not a supported Linux container platform.",
                {"server_os": _sanitize_diagnostic(server_os)},
            ),
        )
    platform = f"{server_os}/{server_arch}"
    checks.append(
        _check(
            "engine_platform",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker client and Linux server identity are present.",
            {"platform": platform},
        )
    )
    return platform


def _validate_platform_claim(
    contained: ContainedExecutionConfig,
    server: dict[str, object],
    info: dict[str, object],
    platform: str,
    checks: list[DockerPreflightCheck],
) -> None:
    operating_system = str(info.get("OperatingSystem", ""))
    platform_name = str(_object_field(server, "Platform", "docker_version.Server").get("Name", ""))
    desktop = "docker desktop" in f"{operating_system} {platform_name}".lower()
    if contained.platform == "linux-docker-engine" and desktop:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "platform_claim",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker Desktop cannot satisfy the Linux Docker Engine claim.",
            ),
        )
    if contained.platform == "docker-desktop-experimental" and not desktop:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "platform_claim",
                False,
                DockerPreflightStatus.UNSAFE,
                "Configured Docker Desktop claim does not match the Docker server.",
            ),
        )
    checks.append(
        _check(
            "platform_claim",
            True,
            (
                DockerPreflightStatus.EXPERIMENTAL
                if desktop
                else DockerPreflightStatus.SUPPORTED
            ),
            (
                "Docker Desktop is available only with reduced claims."
                if desktop
                else "Linux Docker Engine is the authoritative platform."
            ),
            {"platform": platform, "docker_desktop": desktop},
        )
    )


def _validate_required_capabilities(
    config: AgentGuardConfig,
    info: dict[str, object],
    server: dict[str, object],
    runner: CommandRunner,
    timeout_seconds: int,
    max_output_bytes: int,
    checks: list[DockerPreflightCheck],
) -> None:
    _require_network(
        config.contained_execution.network,
        runner,
        timeout_seconds,
        max_output_bytes,
        checks,
    )
    if config.sandbox.memory is not None and info.get("MemoryLimit") is not True:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "resource_limits",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker daemon did not report memory limit support.",
            ),
        )
    if config.sandbox.cpus is not None and _positive_int(info.get("NCPU")) is None:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "resource_limits",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker daemon did not report CPU limit support.",
            ),
        )
    checks.append(
        _check(
            "resource_limits",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Requested Docker resource-limit inputs are in range; exact container configuration is verified by the controlled inspect probe.",
            {
                "requested": {
                    "pids_limit": config.contained_execution.pids_limit,
                    "memory_limit": config.contained_execution.memory_limit,
                    "cpu_limit": config.contained_execution.cpu_limit,
                },
                "daemon_signals": {
                    "memory_limit": info.get("MemoryLimit") is True,
                    "cpu_count_present": _positive_int(info.get("NCPU")) is not None,
                },
            },
        )
    )
    if config.sandbox.read_only:
        api_version = _api_version(server)
        if api_version is None or api_version < MIN_DOCKER_API_FOR_READ_ONLY_TMPFS:
            raise DockerPreflightError(
                DockerPreflightStatus.UNSAFE,
                _check(
                    "read_only_root_tmpfs",
                    False,
                    DockerPreflightStatus.UNSAFE,
                    "Docker API version is insufficient for read-only root and tmpfs.",
                ),
            )
    checks.append(
        _check(
            "read_only_root_tmpfs",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Read-only root and tmpfs preconditions are satisfied.",
            {"required": config.sandbox.read_only},
        )
    )


def _require_network(
    network_name: str,
    runner: CommandRunner,
    timeout_seconds: int,
    max_output_bytes: int,
    checks: list[DockerPreflightCheck],
) -> None:
    if network_name == "host":
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "network_mode",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker host networking is not allowed.",
            ),
        )
    network = _docker_json(
        runner,
        ["docker", "network", "inspect", network_name, "--format", "{{json .}}"],
        "network_mode",
        timeout_seconds,
        max_output_bytes,
    )
    if network.get("Name") != network_name:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "network_mode",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker network mode is unavailable or ambiguous.",
            ),
        )
    checks.append(
        _check(
            "network_mode",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker network mode is available.",
            {"network": network_name},
        )
    )


def _inspect_image(
    image: str,
    runner: CommandRunner,
    timeout_seconds: int,
    max_output_bytes: int,
) -> dict[str, object]:
    return _docker_json(
        runner,
        ["docker", "image", "inspect", "--format", "{{json .}}", image],
        "image_identity",
        timeout_seconds,
        max_output_bytes,
    )


def _validate_image_identity(
    image: str,
    raw: dict[str, object],
    checks: list[DockerPreflightCheck],
) -> DockerImageIdentity:
    if raw.get("Os") != "linux":
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "image_identity",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker image platform is unsupported for contained execution.",
            ),
        )
    local_id = _normalized_image_id(raw.get("Id"))
    registry_digest = select_registry_digest(image, raw.get("RepoDigests"))
    os_name = raw.get("Os")
    architecture = raw.get("Architecture")
    variant = raw.get("Variant")
    platform = None
    if isinstance(os_name, str) and isinstance(architecture, str):
        platform = f"{os_name}/{architecture}"
        if isinstance(variant, str) and variant:
            platform += f"/{variant}"
    try:
        identity = parse_docker_image_identity(
            {
                "configured_reference": image,
                "local_image_id": local_id,
                "executed_image_id": local_id,
                "registry_digest": registry_digest,
                "platform": platform,
                "pull_policy": "docker-default",
                "cache_status": "present",
            }
        )
    except ValueError:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "image_identity",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker image identity is missing, mutable, or contradictory.",
            ),
        ) from None
    if identity.registry_digest != image:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "image_identity",
                False,
                DockerPreflightStatus.UNSAFE,
                "Configured image digest was not found in local image identity.",
            ),
        )
    checks.append(
        _check(
            "image_identity",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker image identity is locally available and digest matched.",
            {"platform": identity.platform},
        )
    )
    return identity


def _record_image_user_declaration(
    raw: dict[str, object],
    checks: list[DockerPreflightCheck],
) -> None:
    config = raw.get("Config")
    user = config.get("User") if isinstance(config, dict) else None
    checks.append(
        _check(
            "image_user_declaration",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker image user declaration recorded; UID/GID behavior is verified by the controlled probe.",
            {"user_declared": isinstance(user, str) and bool(user.strip())},
        )
    )


def _probe_resource_controls(
    contained: ContainedExecutionConfig,
    image: str,
    docker_image: DockerImageIdentity,
    runner: CommandRunner,
    timeout_seconds: int,
    max_output_bytes: int,
    checks: list[DockerPreflightCheck],
) -> None:
    container_name = f"{PROBE_CONTAINER_PREFIX}{uuid.uuid4().hex[:16]}"
    name_label = f"agentguard.preflight.name={container_name}"
    owner_labels = [PROBE_OWNER_LABEL, PROBE_KIND_LABEL, name_label]
    argv = build_contained_docker_run_argv(
        DockerExecSpec(
            image=image,
            workspace_host_path=None,
            workspace_container_path=PROBE_WORKSPACE_PATH,
            command=["-c", "true"],
            uid=contained.required_uid,
            gid=contained.required_gid,
            network=contained.network,
            cpu_limit=contained.cpu_limit,
            memory_limit=contained.memory_limit,
            pids_limit=contained.pids_limit,
            tmpfs_path="/tmp",
            tmpfs_size=contained.tmpfs_size,
            workspace_tmpfs_size=contained.tmpfs_size,
            container_name=container_name,
            entrypoint="/bin/sh",
        )
    )
    create_argv = _docker_create_probe_argv(argv, owner_labels)
    cleanup_status = "not_created"
    container_id = ""
    validation_evidence: dict[str, object] = {}
    try:
        container_id = _create_probe_container(
            runner,
            create_argv,
            container_name,
            name_label,
            timeout_seconds,
            max_output_bytes,
        )
        inspect = _docker_json(
            runner,
            ["docker", "container", "inspect", "--format", "{{json .}}", container_id],
            "resource_control_probe_inspect",
            timeout_seconds,
            max_output_bytes,
            DockerPreflightStatus.UNSAFE,
        )
        validation_evidence = _validate_resource_probe_inspect(
            inspect,
            contained=contained,
            docker_image=docker_image,
            container_id=container_id,
            container_name=container_name,
            name_label=name_label,
        )
        _docker_text(
            runner,
            ["docker", "start", "-a", container_id],
            "resource_control_probe_start",
            timeout_seconds,
            max_output_bytes,
        )
        cleanup_status = _cleanup_probe_container(
            runner,
            container_id,
            timeout_seconds,
            max_output_bytes,
        )
    except DockerPreflightError:
        if container_id:
            cleanup_status = _cleanup_probe_container_quiet(
                runner,
                container_id,
                timeout_seconds,
                max_output_bytes,
            )
        raise
    if cleanup_status != "removed":
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "resource_control_probe_cleanup",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker resource-control probe cleanup failed.",
                {"cleanup_status": cleanup_status},
            ),
        )
    checks.append(
        _check(
            "resource_control_probe",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker accepted and exposed the requested container controls on the exact created probe container.",
            {
                **validation_evidence,
                "docker_accepted": {"container_created": True, "container_started": True},
                "cleanup": {"status": cleanup_status},
            },
        )
    )


def _docker_create_probe_argv(
    run_argv: list[str],
    owner_labels: list[str],
) -> list[str]:
    if run_argv[:2] != ["docker", "run"]:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "resource_control_probe_create",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker resource-control probe could not render a create command.",
            ),
        )
    create = ["docker", "create", *[part for part in run_argv[2:] if part != "--rm"]]
    try:
        boundary = create.index("--")
    except ValueError:
        boundary = len(create)
    label_args: list[str] = []
    for label in owner_labels:
        label_args.extend(["--label", label])
    return [*create[:boundary], *label_args, *create[boundary:]]


def _create_probe_container(
    runner: CommandRunner,
    create_argv: list[str],
    container_name: str,
    name_label: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> str:
    try:
        stdout = _docker_text(
            runner,
            create_argv,
            "resource_control_probe_create",
            timeout_seconds,
            max_output_bytes,
        )
    except DockerPreflightError as error:
        cleanup_status = _cleanup_named_probe_if_owned(
            runner,
            container_name,
            name_label,
            timeout_seconds,
            max_output_bytes,
        )
        if cleanup_status != "not_found":
            error.check.evidence["cleanup_status"] = cleanup_status
        raise
    container_id = stdout.strip().lower()
    if CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
        _cleanup_probe_container_quiet(
            runner,
            container_name,
            timeout_seconds,
            max_output_bytes,
        )
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "resource_control_probe_create",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker create returned a missing or ambiguous probe container identity.",
            ),
        )
    return container_id


def _validate_resource_probe_inspect(
    inspect: dict[str, object],
    *,
    contained: ContainedExecutionConfig,
    docker_image: DockerImageIdentity,
    container_id: str,
    container_name: str,
    name_label: str,
) -> dict[str, object]:
    try:
        host = _inspect_object(inspect, "HostConfig")
        config = _inspect_object(inspect, "Config")
        labels = config.get("Labels")
        if not isinstance(labels, dict):
            labels = {}
        _expect(inspect.get("Id") == container_id, "container identity mismatch")
        _expect(inspect.get("Name") == f"/{container_name}", "container name mismatch")
        _expect(labels.get("agentguard.owner") == "preflight", "owner label mismatch")
        _expect(
            labels.get("agentguard.preflight") == "resource-controls",
            "probe label mismatch",
        )
        _expect(
            labels.get("agentguard.preflight.name") == container_name
            and name_label.endswith(container_name),
            "probe name label mismatch",
        )
        _expect(
            _normalized_image_id(inspect.get("Image")) == docker_image.local_image_id,
            "container image identity mismatch",
        )
        _expect(
            config.get("User") == f"{contained.required_uid}:{contained.required_gid}",
            "container user identity mismatch",
        )
        requested_memory = _docker_size_bytes(contained.memory_limit)
        inspected_memory = _required_int(host.get("Memory"), "memory limit")
        _expect(
            inspected_memory == requested_memory,
            "container memory limit is missing, zero, or mismatched",
        )
        inspected_pids = _required_int(host.get("PidsLimit"), "PID limit")
        _expect(
            inspected_pids == contained.pids_limit,
            "container PID limit is missing, zero, or mismatched",
        )
        cpu_evidence = _validate_cpu_controls(host, contained.cpu_limit)
        _expect(host.get("ReadonlyRootfs") is True, "read-only rootfs is not set")
        security_opt = _string_list(host.get("SecurityOpt"))
        _expect(
            "no-new-privileges" in security_opt,
            "no-new-privileges is not inspectable",
        )
        cap_drop = [value.upper() for value in _string_list(host.get("CapDrop"))]
        _expect("ALL" in cap_drop, "capability drop-all is not inspectable")
        _expect(host.get("NetworkMode") == contained.network, "network mode mismatch")
        _expect(host.get("Privileged") is False, "privileged mode is enabled")
        _validate_no_host_namespace_config(host)
        _validate_no_devices_or_socket(inspect, host)
        tmpfs_paths = _validate_tmpfs_controls(
            host,
            contained=contained,
            paths=["/tmp", PROBE_WORKSPACE_PATH],
        )
    except ValueError as error:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "resource_control_probe",
                False,
                DockerPreflightStatus.UNSAFE,
                f"Docker inspect could not establish required container controls: {error}.",
            ),
        ) from None
    return {
        "requested": {
            "pids_limit": contained.pids_limit,
            "memory_limit": contained.memory_limit,
            "memory_bytes": requested_memory,
            "cpu_limit": contained.cpu_limit,
            "uid": contained.required_uid,
            "gid": contained.required_gid,
            "network": contained.network,
            "tmpfs_size": contained.tmpfs_size,
        },
        "inspected": {
            "container_identity": "matched",
            "image_identity": "matched",
            "pids_limit": inspected_pids,
            "memory_bytes": inspected_memory,
            "cpu": cpu_evidence,
            "uid_gid": config.get("User"),
            "network": host.get("NetworkMode"),
            "read_only_rootfs": host.get("ReadonlyRootfs"),
            "no_new_privileges": True,
            "cap_drop_all": True,
            "tmpfs_paths": tmpfs_paths,
            "privileged": host.get("Privileged"),
            "host_namespace_sharing": False,
            "device_exposure": False,
            "docker_socket_mount": False,
        },
        "unavailable_or_ambiguous": [],
    }


def _probe_uid_gid_writable_path(
    contained: ContainedExecutionConfig,
    image: str,
    runner: CommandRunner,
    timeout_seconds: int,
    max_output_bytes: int,
    checks: list[DockerPreflightCheck],
) -> None:
    if contained.required_uid == 0 or contained.required_gid == 0:
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "uid_gid_writable_path_probe",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID probe requires non-root UID and GID.",
            ),
        )
    script = _uid_gid_probe_script(contained.required_uid, contained.required_gid)
    argv = build_contained_docker_run_argv(
        DockerExecSpec(
            image=image,
            workspace_host_path=None,
            workspace_container_path="/agentguard-workspace",
            command=["-c", script],
            uid=contained.required_uid,
            gid=contained.required_gid,
            network=contained.network,
            cpu_limit=1.0,
            memory_limit="64m",
            pids_limit=64,
            tmpfs_path=PROBE_WRITABLE_PATH,
            tmpfs_size="64k",
            workspace_tmpfs_size="64k",
            entrypoint="/bin/sh",
        )
    )
    result = _probe_json(
        runner,
        argv,
        "uid_gid_writable_path_probe",
        timeout_seconds,
        max_output_bytes,
    )
    uid = result.get("uid")
    gid = result.get("gid")
    writable_path = result.get("writable_path")
    root_write_blocked = result.get("root_write_blocked")
    if (
        uid != contained.required_uid
        or gid != contained.required_gid
        or writable_path != PROBE_WRITABLE_PATH
        or root_write_blocked is not True
    ):
        raise DockerPreflightError(
            DockerPreflightStatus.UNSAFE,
            _check(
                "uid_gid_writable_path_probe",
                False,
                DockerPreflightStatus.UNSAFE,
                "Docker UID/GID writable-path probe returned contradictory evidence.",
            ),
        )
    checks.append(
        _check(
            "uid_gid_writable_path_probe",
            True,
            DockerPreflightStatus.SUPPORTED,
            "Docker can run the image as the required non-root UID/GID with a controlled writable tmpfs path.",
            {
                "uid": uid,
                "gid": gid,
                "writable_path": writable_path,
                "root_write_blocked": root_write_blocked,
            },
        )
    )


def _uid_gid_probe_script(uid: int, gid: int) -> str:
    return (
        "set -eu\n"
        'actual_uid="$(id -u)"\n'
        'actual_gid="$(id -g)"\n'
        f'test "$actual_uid" = "{uid}"\n'
        f'test "$actual_gid" = "{gid}"\n'
        f'printf agentguard > "{PROBE_WRITABLE_FILE}"\n'
        f'test "$(cat "{PROBE_WRITABLE_FILE}")" = "agentguard"\n'
        'root_write_blocked=true\n'
        '(printf denied > /agentguard-preflight-denied) 2>/dev/null && root_write_blocked=false || true\n'
        'test "$root_write_blocked" = "true"\n'
        'printf \'{"uid":%s,"gid":%s,"writable_path":"%s","root_write_blocked":true}\\n\' '
        f'"$actual_uid" "$actual_gid" "{PROBE_WRITABLE_PATH}"\n'
    )


def _inspect_object(mapping: dict[str, object], key: str) -> dict[str, object]:
    value = mapping.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"{key} is missing or malformed")
    return value


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _required_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} is missing, zero, or malformed")
    return value


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _validate_cpu_controls(
    host: dict[str, object],
    requested_cpu: float,
) -> dict[str, object]:
    expected_nano = int(round(requested_cpu * 1_000_000_000))
    nano = host.get("NanoCpus")
    quota = host.get("CpuQuota")
    period = host.get("CpuPeriod")
    representations = []
    if isinstance(nano, int) and not isinstance(nano, bool) and nano > 0:
        representations.append("NanoCpus")
        if nano != expected_nano:
            raise ValueError("container CPU limit NanoCpus is mismatched")
    elif nano not in {None, 0}:
        raise ValueError("container CPU limit NanoCpus is malformed")
    quota_period_present = (
        isinstance(quota, int)
        and not isinstance(quota, bool)
        and quota > 0
        and isinstance(period, int)
        and not isinstance(period, bool)
        and period > 0
    )
    if quota_period_present:
        representations.append("CpuQuota/CpuPeriod")
        observed = quota / period
        if abs(observed - requested_cpu) > 0.000001:
            raise ValueError("container CPU quota/period is mismatched")
    elif quota not in {None, 0} or period not in {None, 0}:
        raise ValueError("container CPU quota/period is malformed or ambiguous")
    if not representations:
        raise ValueError("container CPU limit is missing or zero")
    return {
        "requested_cpus": requested_cpu,
        "nano_cpus": nano if isinstance(nano, int) else None,
        "cpu_quota": quota if isinstance(quota, int) else None,
        "cpu_period": period if isinstance(period, int) else None,
        "representation": "+".join(representations),
    }


def _validate_no_host_namespace_config(host: dict[str, object]) -> None:
    namespace_fields = {
        "PidMode": {"", "private"},
        "IpcMode": {"", "private"},
        "UsernsMode": {"", "private"},
        "UTSMode": {"", "private"},
        "CgroupnsMode": {"", "private"},
    }
    for field_name, safe_values in namespace_fields.items():
        value = host.get(field_name, "")
        if value is None:
            value = ""
        if not isinstance(value, str) or value not in safe_values:
            raise ValueError(f"{field_name} indicates host namespace sharing")


def _validate_no_devices_or_socket(
    inspect: dict[str, object],
    host: dict[str, object],
) -> None:
    for field_name in ("Devices", "DeviceRequests"):
        value = host.get(field_name)
        if value not in (None, []):
            raise ValueError(f"{field_name} exposes host devices")
    for bind in _string_list(host.get("Binds")):
        if "/var/run/docker.sock" in bind:
            raise ValueError("Docker socket bind mount is configured")
        raise ValueError("unexpected bind mount is configured")
    mounts = inspect.get("Mounts")
    if mounts is None:
        mounts = []
    if not isinstance(mounts, list):
        raise ValueError("Mounts is malformed")
    for mount in mounts:
        if not isinstance(mount, dict):
            raise ValueError("Mounts contains malformed entries")
        if mount.get("Type") == "bind":
            source = str(mount.get("Source", ""))
            destination = str(mount.get("Destination", ""))
            if "/var/run/docker.sock" in f"{source}:{destination}":
                raise ValueError("Docker socket mount is configured")
            raise ValueError("unexpected bind mount is configured")
        if mount.get("Type") not in {None, "tmpfs"}:
            raise ValueError("unsupported mount type is configured")


def _validate_tmpfs_controls(
    host: dict[str, object],
    *,
    contained: ContainedExecutionConfig,
    paths: list[str],
) -> list[str]:
    tmpfs = host.get("Tmpfs")
    if not isinstance(tmpfs, dict):
        raise ValueError("tmpfs configuration is missing or malformed")
    observed = []
    for path in paths:
        options = tmpfs.get(path)
        if not isinstance(options, str):
            raise ValueError(f"tmpfs {path} is missing")
        option_set = set(options.split(","))
        required = {
            "rw",
            "noexec",
            "nosuid",
            "nodev",
            f"size={contained.tmpfs_size}",
            f"uid={contained.required_uid}",
            f"gid={contained.required_gid}",
            "mode=700",
        }
        if not required.issubset(option_set):
            raise ValueError(f"tmpfs {path} is missing required bounded options")
        observed.append(path)
    return observed


def _docker_size_bytes(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([kKmMgG]?)", value)
    if match is None:
        raise ValueError("Docker size string is malformed")
    amount = int(match.group(1))
    suffix = match.group(2).lower()
    multiplier = {"": 1, "k": 1024, "m": 1024 * 1024, "g": 1024 * 1024 * 1024}[suffix]
    return amount * multiplier


def _cleanup_probe_container(
    runner: CommandRunner,
    container_ref: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> str:
    try:
        _docker_text(
            runner,
            ["docker", "rm", "-f", container_ref],
            "resource_control_probe_cleanup",
            timeout_seconds,
            max_output_bytes,
        )
    except DockerPreflightError:
        return "cleanup_failed"
    return "removed"


def _cleanup_probe_container_quiet(
    runner: CommandRunner,
    container_ref: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> str:
    return _cleanup_probe_container(runner, container_ref, timeout_seconds, max_output_bytes)


def _cleanup_named_probe_if_owned(
    runner: CommandRunner,
    container_name: str,
    name_label: str,
    timeout_seconds: int,
    max_output_bytes: int,
) -> str:
    try:
        inspect = _docker_json(
            runner,
            ["docker", "container", "inspect", "--format", "{{json .}}", container_name],
            "resource_control_probe_create_cleanup_inspect",
            timeout_seconds,
            max_output_bytes,
        )
    except DockerPreflightError:
        return "not_found"
    config = inspect.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if (
        inspect.get("Name") != f"/{container_name}"
        or not isinstance(labels, dict)
        or labels.get("agentguard.owner") != "preflight"
        or labels.get("agentguard.preflight") != "resource-controls"
        or labels.get("agentguard.preflight.name") != container_name
        or not name_label.endswith(container_name)
    ):
        return "unowned_not_removed"
    container_id = str(inspect.get("Id", ""))
    if CONTAINER_ID_PATTERN.fullmatch(container_id) is None:
        return "ambiguous_not_removed"
    return _cleanup_probe_container(
        runner,
        container_id,
        timeout_seconds,
        max_output_bytes,
    )


def _object_field(
    mapping: dict[str, object],
    key: str,
    context: str,
) -> dict[str, object]:
    value = mapping.get(key)
    if not isinstance(value, dict):
        raise DockerPreflightError(
            DockerPreflightStatus.UNAVAILABLE,
            _check(
                context,
                False,
                DockerPreflightStatus.UNAVAILABLE,
                "Docker response is missing required object fields.",
            ),
        )
    return value


def _string_field(mapping: dict[str, object], key: str, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise DockerPreflightError(
            DockerPreflightStatus.UNAVAILABLE,
            _check(
                context,
                False,
                DockerPreflightStatus.UNAVAILABLE,
                "Docker response is missing required string fields.",
            ),
        )
    return value


def _api_version(server: dict[str, object]) -> Optional[tuple[int, int]]:
    value = server.get("ApiVersion") or server.get("APIVersion")
    if not isinstance(value, str):
        return None
    pieces = value.split(".")
    if len(pieces) < 2:
        return None
    try:
        return int(pieces[0]), int(pieces[1])
    except ValueError:
        return None


def _positive_int(value: object) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    return None


def _normalized_image_id(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.lower()
    return candidate if IMAGE_ID_PATTERN.fullmatch(candidate) else ""


def _check(
    name: str,
    passed: bool,
    status: DockerPreflightStatus,
    diagnostic: str,
    evidence: Optional[dict[str, object]] = None,
) -> DockerPreflightCheck:
    sanitized_evidence = _sanitize_evidence_mapping(evidence or {})
    return DockerPreflightCheck(
        name=name,
        passed=passed,
        status=status.value,
        diagnostic=_sanitize_diagnostic(diagnostic),
        evidence=sanitized_evidence,
    )


def _validate_json_bounds(value: object, *, depth: int) -> None:
    if depth > PREFLIGHT_JSON_MAX_NESTING:
        raise ValueError("Docker command returned JSON beyond the nesting bound.")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > PREFLIGHT_JSON_MAX_STRING_BYTES:
            raise ValueError("Docker command returned a JSON string beyond the size bound.")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, list):
        if len(value) > PREFLIGHT_JSON_MAX_ITEMS:
            raise ValueError("Docker command returned a JSON array beyond the item bound.")
        for item in value:
            _validate_json_bounds(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > PREFLIGHT_JSON_MAX_ITEMS:
            raise ValueError("Docker command returned a JSON object beyond the item bound.")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Docker command returned JSON with non-string keys.")
            _validate_json_bounds(key, depth=depth + 1)
            _validate_json_bounds(item, depth=depth + 1)
        return
    raise ValueError("Docker command returned unsupported JSON values.")


def _sanitize_evidence_mapping(value: dict[str, object]) -> dict[str, object]:
    sanitized = _sanitize_evidence_value(value, depth=0)
    if not isinstance(sanitized, dict):
        return {}
    return sanitized


def _sanitize_evidence_value(value: object, *, depth: int) -> object:
    if depth > 8:
        return "<truncated>"
    if isinstance(value, str):
        return _sanitize_diagnostic(value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) <= 10**15 else 0
    if isinstance(value, float):
        return round(value, 6) if -10**12 <= value <= 10**12 else 0.0
    if isinstance(value, list):
        return [
            _sanitize_evidence_value(item, depth=depth + 1)
            for item in value[:64]
        ]
    if isinstance(value, tuple):
        return [
            _sanitize_evidence_value(item, depth=depth + 1)
            for item in value[:64]
        ]
    if isinstance(value, dict):
        sanitized = {}
        for key, item in list(value.items())[:64]:
            safe_key = _sanitize_diagnostic(key)
            sanitized[safe_key] = _sanitize_evidence_value(item, depth=depth + 1)
        return sanitized
    return _sanitize_diagnostic(value)


def _result(
    status: DockerPreflightStatus,
    claim_level: str,
    checks: list[DockerPreflightCheck],
    *,
    docker_image: Optional[DockerImageIdentity] = None,
    evidence: Optional[dict[str, object]] = None,
) -> DockerPreflightResult:
    return DockerPreflightResult(
        status=status,
        claim_level=claim_level,
        supported=status == DockerPreflightStatus.SUPPORTED,
        checks=checks,
        docker_image=docker_image,
        evidence=evidence or {},
    )


def _sanitize_diagnostic(text: object) -> str:
    value = CONTROL_CHARACTER_PATTERN.sub(" ", str(text))
    value = SECRET_VALUE_PATTERN.sub(r"\1=<redacted>", value)
    value = DAEMON_ENDPOINT_PATTERN.sub("<docker-endpoint>", value)
    value = PRIVATE_PATH_PATTERN.sub("<path>", value)
    value = " ".join(value.split())
    return limit_output(value, DIAGNOSTIC_MAX_BYTES).text
