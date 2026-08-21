import hashlib
import json
import os
import platform
import re
import shlex
import subprocess
import warnings
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional, Union

from agentguard import __version__
from agentguard.config.schema import AgentGuardConfig, ScalarMetadata
from agentguard.io import atomic_write_text
from agentguard.instrumentation.output_limits import BoundedProcessOutput, limit_output
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.processes import (
    PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS,
    cleanup_process_after_exception,
    popen_with_process_group,
    terminate_process_tree,
)
from agentguard.policy.command_policy import evaluate_command_policy
from agentguard.sandbox.docker_runner import DockerCommandRunner
from agentguard.terminal import sanitize_terminal_text
from agentguard.provenance.portable_paths import portable_reference


MANIFEST_SCHEMA = "agentguard.execution-manifest"
MANIFEST_SCHEMA_VERSION = 1
SECRET_KEY_PATTERN = re.compile(
    r"(TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL|AUTH|COOKIE)",
    re.IGNORECASE,
)
URL_CREDENTIALS_PATTERN = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@",
    re.IGNORECASE,
)
AUTHORIZATION_PATTERN = re.compile(
    r"(?i)(authorization\s*:\s*)(basic|bearer)\s+\S+"
)
VERSION_OUTPUT_LIMIT = 4096
VERSION_TIMEOUT_SECONDS = 10


@dataclass(frozen=True)
class GitIdentity:
    git_commit: Optional[str] = None
    dirty_worktree: Optional[bool] = None


@dataclass(frozen=True)
class AgentGuardIdentity:
    version: str
    git_commit: Optional[str] = None
    dirty_worktree: Optional[bool] = None


@dataclass(frozen=True)
class HostIdentity:
    operating_system: str
    architecture: str
    python_version: str
    docker_version: Optional[str] = None


@dataclass(frozen=True)
class SourceIdentity:
    repository: str
    git_commit: Optional[str] = None
    dirty_worktree: Optional[bool] = None


@dataclass(frozen=True)
class ConfigurationIdentity:
    path: str
    sha256: str
    resolved_options: dict[str, object]


@dataclass(frozen=True)
class AgentIdentity:
    adapter: str
    configured_name: Optional[str]
    executable: Optional[str]
    version: Optional[str]
    model: Optional[str]
    arguments: list[str]
    environment_names: list[str]
    metadata: dict[str, ScalarMetadata]
    version_status: str
    version_warning: Optional[str] = None


@dataclass(frozen=True)
class BenchmarkIdentity:
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    config_path: str
    config_sha256: str


@dataclass(frozen=True)
class PolicyIdentity:
    command_policy_mode: str
    sandbox_type: str
    network: Optional[str]
    read_only: Optional[bool]
    cpus: Optional[float]
    memory: Optional[str]
    timeout_seconds: int
    max_output_bytes: int


@dataclass(frozen=True)
class ArtifactIdentity:
    json_report: Optional[str]
    markdown_report: Optional[str]
    command_log: Optional[str] = None
    trace: Optional[str] = None
    json_report_sha256: Optional[str] = None
    markdown_report_sha256: Optional[str] = None
    command_log_sha256: Optional[str] = None


@dataclass(frozen=True)
class ChildExecution:
    execution_id: str
    execution_type: str
    manifest_path: Optional[str]
    task_id: Optional[str] = None
    agent: Optional[str] = None
    trial_index: Optional[int] = None


@dataclass(frozen=True)
class ExecutionManifest:
    execution_id: str
    execution_type: str
    created_at: str
    completed_at: str
    duration_seconds: float
    agentguard: AgentGuardIdentity
    host: HostIdentity
    source: SourceIdentity
    configuration: ConfigurationIdentity
    agent: Optional[AgentIdentity]
    benchmarks: list[BenchmarkIdentity]
    policies: list[PolicyIdentity]
    artifacts: ArtifactIdentity
    docker_images: list[dict[str, object]] = field(default_factory=list)
    parent_execution_id: Optional[str] = None
    parent_execution_type: Optional[str] = None
    child_executions: list[ChildExecution] = field(default_factory=list)
    matrix: Optional[dict[str, object]] = None
    guard: Optional[dict[str, object]] = None
    command_guard: Optional[dict[str, object]] = None
    guard_metrics: Optional[dict[str, object]] = None
    guard_incident: Optional[dict[str, object]] = None
    schema: str = MANIFEST_SCHEMA
    schema_version: int = MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class VerificationResult:
    status: str
    messages: list[str]

    @property
    def exit_code(self) -> int:
        if self.status == "valid":
            return 0
        if self.status == "changed":
            return 1
        return 2


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def portable_path(path: Optional[Path], root: Optional[Path] = None) -> Optional[str]:
    if path is None:
        return None
    return portable_reference(path, root)


def git_identity(path: Path) -> GitIdentity:
    resolved = path.expanduser().resolve()
    cwd = resolved if resolved.is_dir() else resolved.parent
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (FileNotFoundError, subprocess.SubprocessError):
        return GitIdentity()
    return GitIdentity(git_commit=commit or None, dirty_worktree=bool(status.strip()))


def _docker_version() -> Optional[str]:
    try:
        completed = subprocess.run(
            ["docker", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


def host_identity(*, docker_relevant: bool) -> HostIdentity:
    return HostIdentity(
        operating_system=f"{platform.system()} {platform.release()}".strip(),
        architecture=platform.machine(),
        python_version=platform.python_version(),
        docker_version=_docker_version() if docker_relevant else None,
    )


def agentguard_identity() -> AgentGuardIdentity:
    package_root = Path(__file__).resolve().parents[2]
    identity = git_identity(package_root)
    return AgentGuardIdentity(
        version=__version__,
        git_commit=identity.git_commit,
        dirty_worktree=identity.dirty_worktree,
    )


def _argv(command: Optional[Union[str, list[str]]]) -> list[str]:
    if isinstance(command, str):
        return shlex.split(command)
    return list(command or [])


def sensitive_values_for_config(
    config: AgentGuardConfig,
    additional_values: Optional[list[str]] = None,
) -> list[str]:
    values = [value for value in config.agent_environment.values() if value]
    if config.agent_environment_isolated and os.environ.get("PATH"):
        values.append(os.environ["PATH"])
    values.extend(
        str(value)
        for key, value in config.agent_metadata.items()
        if SECRET_KEY_PATTERN.search(key) and str(value)
    )
    values.extend(
        pattern.contains
        for pattern in config.secret_content_patterns
        if pattern.contains
    )
    secret_options = {
        "--token",
        "--api-key",
        "--apikey",
        "--password",
        "--passwd",
        "--client-secret",
        "--access-token",
        "--auth-token",
    }
    for command in (config.agent_command, config.agent_version_command):
        argv = _argv(command)
        for index, argument in enumerate(argv):
            lowered = argument.lower()
            if lowered in secret_options and index + 1 < len(argv):
                values.append(argv[index + 1])
                continue
            if any(
                lowered.startswith(f"{option}=") for option in secret_options
            ):
                values.append(argument.split("=", 1)[1])
    values.extend(value for value in additional_values or [] if value)
    return sorted(set(values), key=len, reverse=True)


def sanitize_text(value: str, sensitive_values: Optional[list[str]] = None) -> str:
    sanitized = URL_CREDENTIALS_PATTERN.sub(r"\g<scheme>[REDACTED]@", value)
    sanitized = AUTHORIZATION_PATTERN.sub(r"\1[REDACTED]", sanitized)
    for secret in sensitive_values or []:
        sanitized = sanitized.replace(secret, "[REDACTED]")
    return sanitized


def sanitize_arguments(
    command: Optional[Union[str, list[str]]],
    sensitive_values: Optional[list[str]] = None,
) -> list[str]:
    argv = _argv(command)
    sanitized: list[str] = []
    redact_next = False
    header_next = False
    for argument in argv:
        lowered = argument.lower()
        if redact_next:
            sanitized.append("[REDACTED]")
            redact_next = False
            continue
        if header_next:
            sanitized.append(sanitize_text(argument, sensitive_values))
            header_next = False
            continue
        secret_options = {
            "--token",
            "--api-key",
            "--apikey",
            "--password",
            "--passwd",
            "--client-secret",
            "--access-token",
            "--auth-token",
        }
        if lowered in secret_options:
            sanitized.append(argument)
            redact_next = True
            continue
        if any(
            lowered.startswith(f"{option}=")
            for option in secret_options
        ):
            sanitized.append(f"{argument.split('=', 1)[0]}=[REDACTED]")
            continue
        if lowered in {"-h", "--header"}:
            sanitized.append(argument)
            header_next = True
            continue
        sanitized.append(sanitize_text(argument, sensitive_values))
    return sanitized


def sanitize_metadata(
    metadata: dict[str, ScalarMetadata],
) -> dict[str, ScalarMetadata]:
    return {
        key: "[REDACTED]" if SECRET_KEY_PATTERN.search(key) else value
        for key, value in sorted(metadata.items())
    }


def detect_agent_version(
    config: AgentGuardConfig,
    *,
    repo_dir: Optional[Path] = None,
    command_tracker: Optional[CommandTracker] = None,
) -> tuple[Optional[str], str, Optional[str]]:
    if config.agent_version_command is None:
        return None, "not_configured", None
    argv = _argv(config.agent_version_command)
    command_text = shlex.join(argv)
    decision = evaluate_command_policy(
        command_text=command_text,
        unsafe_patterns=config.unsafe_commands,
        mode=config.command_policy.mode,
    )
    if not decision.allowed:
        return None, "blocked", "Agent version command was blocked by command policy."

    if config.sandbox.type == "docker":
        if repo_dir is None or command_tracker is None:
            return (
                None,
                "failed",
                "Docker agent version detection requires a prepared repository "
                "and command tracker.",
            )
        version_tracker = CommandTracker()
        try:
            result = DockerCommandRunner(
                version_tracker,
                config.sandbox,
                timeout_seconds=min(
                    config.command_timeout_seconds,
                    VERSION_TIMEOUT_SECONDS,
                ),
                max_output_bytes=VERSION_OUTPUT_LIMIT,
            ).run_argv(
                repo_dir=repo_dir,
                inner_command=argv,
                command_text=(
                    "docker agent version: "
                    + shlex.join(
                        sanitize_arguments(argv, sensitive_values_for_config(config))
                    )
                ),
                preflight_matched_patterns=decision.matched_patterns,
                policy_mode=decision.mode if decision.matched_patterns else None,
            )
        except (OSError, TypeError, ValueError) as error:
            return (
                None,
                "failed",
                f"Agent version command failed: {type(error).__name__}.",
            )
        sensitive_values = [
            *sensitive_values_for_config(
                config,
                [str(repo_dir), str(repo_dir.resolve())],
            ),
        ]
        for event in version_tracker.events:
            event.command = sanitize_arguments(event.command, sensitive_values)
            event.cwd = "[REPOSITORY]"
            event.command_text = sanitize_terminal_text(
                sanitize_text(event.command_text, sensitive_values),
                preserve_newlines=False,
            )
            stdout = limit_output(
                sanitize_terminal_text(
                    sanitize_text(event.stdout, sensitive_values)
                ),
                VERSION_OUTPUT_LIMIT,
            )
            stderr = limit_output(
                sanitize_terminal_text(
                    sanitize_text(event.stderr, sensitive_values)
                ),
                VERSION_OUTPUT_LIMIT,
            )
            event.stdout = stdout.text
            event.stderr = stderr.text
            event.stdout_truncated = event.stdout_truncated or stdout.truncated
            event.stderr_truncated = event.stderr_truncated or stderr.truncated
            if event.reason is not None:
                event.reason = sanitize_terminal_text(
                    sanitize_text(event.reason, sensitive_values)
                )
        command_tracker.extend(version_tracker.events)
        output = limit_output(
            sanitize_terminal_text(
                sanitize_text(
                    result.stdout if result.stdout.strip() else result.stderr,
                    sensitive_values,
                )
            ),
            VERSION_OUTPUT_LIMIT,
        )
        version = next(
            (line.strip() for line in output.text.splitlines() if line.strip()),
            None,
        )
        if result.timed_out:
            return None, "failed", "Agent version command timed out."
        if result.exit_code == 127 and result.stderr.startswith(
            "Docker is not installed"
        ):
            return None, "failed", "Docker is unavailable for agent version detection."
        if result.exit_code != 0:
            return (
                None,
                "failed",
                f"Agent version command exited with status {result.exit_code}.",
            )
        if not version:
            return None, "failed", "Agent version command produced no version output."
        return version, "detected", None

    process = None
    capture = None
    cleanup_started = False
    try:
        environment = (
            {
                "PATH": os.environ.get("PATH", os.defpath),
                **config.agent_environment,
            }
            if config.agent_environment_isolated
            else {**os.environ, **config.agent_environment}
        )
        process = popen_with_process_group(
            argv,
            cwd=config.agent_workdir_path or config.config_path.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        capture = BoundedProcessOutput(
            process,
            VERSION_OUTPUT_LIMIT,
            retain_tail=False,
        )
        returncode = capture.wait(
            timeout=min(config.command_timeout_seconds, VERSION_TIMEOUT_SECONDS)
        )
    except FileNotFoundError:
        if process is not None:
            cleanup_process_after_exception(process, capture)
            raise
        return None, "failed", "Agent version executable was not found."
    except subprocess.TimeoutExpired:
        cleanup_started = True
        try:
            terminate_process_tree(process)
        except BaseException:
            pass
        try:
            capture.wait(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
        except BaseException:
            pass
        try:
            capture.finish(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
        except BaseException:
            pass
        return None, "failed", "Agent version command timed out."
    except (OSError, TypeError, ValueError) as error:
        cleanup_process_after_exception(
            process,
            capture,
            cleanup_started=cleanup_started,
        )
        return None, "failed", f"Agent version command failed: {type(error).__name__}."
    except BaseException:
        cleanup_process_after_exception(
            process,
            capture,
            cleanup_started=cleanup_started,
        )
        raise

    try:
        captured = capture.finish()
    except (OSError, TypeError, ValueError) as error:
        cleanup_process_after_exception(process, capture)
        return None, "failed", f"Agent version command failed: {type(error).__name__}."
    except BaseException:
        cleanup_process_after_exception(process, capture)
        raise
    output = captured.stdout.text or captured.stderr.text
    output = sanitize_text(output, sensitive_values_for_config(config))
    version = next((line.strip() for line in output.splitlines() if line.strip()), None)
    if returncode != 0:
        return (
            None,
            "failed",
            f"Agent version command exited with status {returncode}.",
        )
    if not version:
        return None, "failed", "Agent version command produced no version output."
    return version, "detected", None


def agent_identity(
    config: AgentGuardConfig,
    adapter: str,
    detected_version: Optional[str],
    version_status: str,
    version_warning: Optional[str],
) -> AgentIdentity:
    command = config.agent_display_command or config.agent_command
    arguments = sanitize_arguments(command, sensitive_values_for_config(config))
    return AgentIdentity(
        adapter=adapter,
        configured_name=config.agent_name,
        executable=arguments[0] if arguments else None,
        version=detected_version,
        model=config.agent_model,
        arguments=arguments[1:] if arguments else [],
        environment_names=sorted(config.agent_environment),
        metadata=sanitize_metadata(config.agent_metadata),
        version_status=version_status,
        version_warning=version_warning,
    )


def source_identity(path: Optional[Path]) -> SourceIdentity:
    if path is None:
        return SourceIdentity(repository="unavailable")
    identity = git_identity(path)
    return SourceIdentity(
        repository=portable_path(path) or "unavailable",
        git_commit=identity.git_commit,
        dirty_worktree=identity.dirty_worktree,
    )


def configuration_identity(
    path: Path,
    resolved_options: dict[str, object],
) -> ConfigurationIdentity:
    return ConfigurationIdentity(
        path=portable_path(path) or path.as_posix(),
        sha256=sha256_file(path),
        resolved_options=resolved_options,
    )


def benchmark_identity(config: AgentGuardConfig) -> BenchmarkIdentity:
    return BenchmarkIdentity(
        benchmark_id=config.benchmark.id,
        benchmark_version=config.benchmark.version,
        config_path=portable_path(config.config_path) or config.config_path.as_posix(),
        config_sha256=sha256_file(config.config_path),
    )


def policy_identity(config: AgentGuardConfig) -> PolicyIdentity:
    return PolicyIdentity(
        command_policy_mode=config.command_policy.mode,
        sandbox_type=config.sandbox.type,
        network=config.sandbox.network if config.sandbox.type == "docker" else None,
        read_only=(
            config.sandbox.read_only if config.sandbox.type == "docker" else None
        ),
        cpus=config.sandbox.cpus if config.sandbox.type == "docker" else None,
        memory=config.sandbox.memory if config.sandbox.type == "docker" else None,
        timeout_seconds=config.command_timeout_seconds,
        max_output_bytes=config.max_output_bytes,
    )


def artifact_identity(
    json_report: Optional[Path],
    markdown_report: Optional[Path],
    command_log: Optional[Path] = None,
    trace: Optional[Path] = None,
) -> ArtifactIdentity:
    return ArtifactIdentity(
        json_report=portable_path(json_report),
        markdown_report=portable_path(markdown_report),
        command_log=portable_path(command_log),
        trace=portable_path(trace),
        json_report_sha256=(
            sha256_file(json_report)
            if json_report is not None and json_report.is_file()
            else None
        ),
        markdown_report_sha256=(
            sha256_file(markdown_report)
            if markdown_report is not None and markdown_report.is_file()
            else None
        ),
        command_log_sha256=(
            sha256_file(command_log)
            if command_log is not None and command_log.is_file()
            else None
        ),
    )


def manifest_dict(manifest: ExecutionManifest) -> dict[str, Any]:
    return _drop_none(asdict(manifest))


def serialize_manifest(manifest: ExecutionManifest) -> str:
    return json.dumps(manifest_dict(manifest), indent=2, sort_keys=True) + "\n"


def write_manifest(manifest: ExecutionManifest, path: Path) -> Optional[Path]:
    try:
        atomic_write_text(path, serialize_manifest(manifest))
    except (OSError, TypeError, ValueError) as error:
        warnings.warn(
            f"AgentGuard manifest write failed: {error}",
            RuntimeWarning,
            stacklevel=2,
        )
        return None
    return path


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid manifest JSON: {error}") from error
    if not isinstance(data, dict):
        raise ValueError("Invalid manifest schema: root must be an object.")
    return data


def verify_manifest(
    path: Path,
    trusted_references: Optional[Mapping[str, Path]] = None,
) -> VerificationResult:
    try:
        data = load_manifest(path)
        _validate_manifest_structure(data)
    except ValueError as error:
        return VerificationResult("invalid", [str(error)])

    messages = []
    changed = False
    references = [
        (
            data["configuration"]["path"],
            data["configuration"]["sha256"],
            "configuration",
        )
    ]
    references.extend(
        (
            benchmark["config_path"],
            benchmark["config_sha256"],
            f"benchmark {benchmark.get('benchmark_id') or index + 1}",
        )
        for index, benchmark in enumerate(data["benchmarks"])
    )
    seen: set[tuple[str, str]] = set()
    for reference, expected_hash, label in references:
        key = (reference, expected_hash)
        if key in seen:
            continue
        seen.add(key)
        input_path = None
        if trusted_references is not None and reference in trusted_references:
            trusted = trusted_references[reference].expanduser()
            if trusted.is_file():
                input_path = trusted.resolve()
        if input_path is None:
            input_path = _resolve_reference(path, reference)
        if input_path is None:
            changed = True
            messages.append(f"MISSING {label}: {reference}")
            continue
        try:
            actual_hash = sha256_file(input_path)
        except OSError:
            changed = True
            messages.append(f"MISSING {label}: {reference}")
            continue
        if actual_hash != expected_hash:
            changed = True
            messages.append(f"CHANGED {label}: {reference}")
        else:
            messages.append(f"MATCH {label}: {reference}")
    return VerificationResult("changed" if changed else "valid", messages)


def provenance_summary(data: dict[str, Any]) -> str:
    parent = data.get("parent_execution_id")
    lines = [
        f"Execution: {data['execution_id']} ({data['execution_type']})",
        f"AgentGuard: {data['agentguard']['version']}",
        f"Source commit: {data['source'].get('git_commit') or 'unavailable'}",
        f"Benchmarks: {len(data['benchmarks'])}",
    ]
    if parent:
        lines.append(f"Parent: {parent}")
    lines.append(f"Children: {len(data.get('child_executions', []))}")
    return "\n".join(lines)


def _drop_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _drop_none(item)
            for key, item in value.items()
            if item is not None
        }
    if isinstance(value, list):
        return [_drop_none(item) for item in value]
    return value


def _validate_manifest_structure(data: dict[str, Any]) -> None:
    if data.get("schema") != MANIFEST_SCHEMA:
        raise ValueError("Invalid manifest schema identifier.")
    if data.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError("Unsupported manifest schema version.")
    required = [
        "execution_id",
        "execution_type",
        "created_at",
        "completed_at",
        "duration_seconds",
        "agentguard",
        "host",
        "source",
        "configuration",
        "benchmarks",
        "policies",
        "artifacts",
    ]
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError(
            f"Invalid manifest schema: missing required field(s): {', '.join(missing)}"
        )
    if data["execution_type"] not in {"run", "suite", "matrix"}:
        raise ValueError("Invalid manifest execution_type.")
    if not isinstance(data["execution_id"], str) or not data["execution_id"]:
        raise ValueError("Invalid manifest execution_id.")
    if not isinstance(data["created_at"], str) or not isinstance(
        data["completed_at"], str
    ):
        raise ValueError("Invalid manifest timestamps.")
    if not isinstance(data["duration_seconds"], (int, float)):
        raise ValueError("Invalid manifest duration_seconds.")
    _require_mapping_fields(data, "agentguard", ("version",))
    _require_mapping_fields(
        data,
        "host",
        ("operating_system", "architecture", "python_version"),
    )
    _require_mapping_fields(data, "source", ("repository",))
    _require_mapping_fields(
        data,
        "artifacts",
        ("json_report", "markdown_report"),
    )
    configuration = data["configuration"]
    if not isinstance(configuration, dict) or not all(
        key in configuration for key in ("path", "sha256", "resolved_options")
    ):
        raise ValueError("Invalid manifest configuration identity.")
    if not isinstance(data["benchmarks"], list):
        raise ValueError("Invalid manifest benchmarks field.")
    if not isinstance(data["policies"], list):
        raise ValueError("Invalid manifest policies field.")
    for benchmark in data["benchmarks"]:
        if not isinstance(benchmark, dict) or not all(
            key in benchmark for key in ("config_path", "config_sha256")
        ):
            raise ValueError("Invalid manifest benchmark identity.")


def _require_mapping_fields(
    data: dict[str, Any],
    key: str,
    fields: tuple[str, ...],
) -> None:
    value = data.get(key)
    if not isinstance(value, dict) or not all(field in value for field in fields):
        raise ValueError(f"Invalid manifest {key} identity.")


def _resolve_reference(manifest_path: Path, reference: str) -> Optional[Path]:
    candidate = Path(reference).expanduser()
    candidates = [candidate] if candidate.is_absolute() else [Path.cwd() / candidate]
    if not candidate.is_absolute():
        candidates.extend(parent / candidate for parent in manifest_path.resolve().parents)
    for path in candidates:
        if path.is_file():
            return path.resolve()
    return None
