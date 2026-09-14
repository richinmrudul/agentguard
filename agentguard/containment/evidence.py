from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field, is_dataclass, replace
from pathlib import Path
from typing import Optional, Union

from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import BenchmarkResult, CommandResult
from agentguard.instrumentation.output_limits import limit_output
from agentguard.provenance.artifact_paths import artifact_roots
from agentguard.provenance.portable_paths import portable_value
from agentguard.redaction import redact_credential_arguments, redact_credentials
from agentguard.sandbox.contained_workspace import PreparedContainedWorkspace
from agentguard.sandbox.docker_identity import (
    IMAGE_ID_PATTERN,
    REGISTRY_DIGEST_PATTERN,
    DockerImageIdentity,
    parse_docker_image_identity,
)


CONTAINMENT_EVIDENCE_SCHEMA = "agentguard.containment-evidence"
CONTAINMENT_EVIDENCE_SCHEMA_VERSION = 1

STATE_VALUES = {"unknown", "unavailable", "not_applicable", "recorded"}
EXECUTION_MODES = {"contained-run", "docker-sandbox", "local", "unknown"}
PREFLIGHT_STATUSES = {
    "supported",
    "experimental",
    "unavailable",
    "unsafe",
    "unknown",
    "not_applicable",
}
EXECUTION_STATUSES = {
    "executed",
    "policy_blocked",
    "preflight_blocked",
    "skipped",
    "unknown",
}
CLEANUP_STATUSES = {
    "not_created",
    "removed",
    "already_absent",
    "verification_unavailable",
    "cleanup_incomplete",
    "force_killed",
    "cleanly_terminated",
    "retained",
    "incomplete",
    "unknown",
    "not_applicable",
}
SECURITY_CLAIM_LEVELS = {
    "linux-docker-engine",
    "docker-desktop-reduced",
    "none",
    "unknown",
    "not_applicable",
}
MAX_STRING_CHARS = 512
MAX_LIST_ITEMS = 64
MAX_DICT_ITEMS = 64
MAX_NESTING = 8
MAX_SERIALIZED_BYTES = 32 * 1024
MAX_CONTAINER_REF_LENGTH = 256
CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
PRIVATE_PATH_PATTERN = re.compile(
    r"(?:/Users/[^/\s,;]+|/home/[^/\s,;]+|/private/tmp|/private/var|/tmp)"
    r"(?:/[^\s,;]*)?"
)
CONTAINER_ID_HASH_PATTERN = re.compile(r"^[0-9a-f]{16}$")


@dataclass(frozen=True)
class ContainmentImageEvidence:
    state: str
    configured_reference: Optional[str] = None
    registry_digest: Optional[str] = None
    local_image_id: Optional[str] = None
    container_bound_image_id: Optional[str] = None
    platform: Optional[str] = None
    pull_policy: Optional[str] = None
    cache_status: Optional[str] = None


@dataclass(frozen=True)
class ContainmentPreflightEvidence:
    state: str
    status: str
    claim_level: str
    reduced_claim: Optional[bool] = None
    checks_total: Optional[int] = None
    checks_passed: Optional[int] = None
    approved_boundary_constructible: Optional[bool] = None


@dataclass(frozen=True)
class ContainmentControlsEvidence:
    state: str
    network: Optional[str] = None
    no_new_privileges: Optional[bool] = None
    cap_drop_all: Optional[bool] = None
    read_only_root: Optional[bool] = None
    tmpfs_paths: list[str] = field(default_factory=list)
    pids_limit: Optional[int] = None
    memory_limit: Optional[str] = None
    cpu_limit: Optional[float] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    docker_socket_mount: Optional[bool] = None
    host_network: Optional[bool] = None
    privileged: Optional[bool] = None
    device_exposure: Optional[bool] = None
    host_namespace_sharing: Optional[bool] = None


@dataclass(frozen=True)
class ContainmentEnvironmentEvidence:
    state: str
    supplied_names: list[str] = field(default_factory=list)
    sensitive_names: list[str] = field(default_factory=list)
    missing_names: list[str] = field(default_factory=list)
    default_names: list[str] = field(default_factory=list)
    values_recorded: bool = False


@dataclass(frozen=True)
class ContainmentWorkspaceEvidence:
    state: str
    source_kind: Optional[str] = None
    agent_mount: Optional[str] = None
    evidence_mount: Optional[str] = None
    writable_paths: list[str] = field(default_factory=list)
    baseline_digest: Optional[str] = None
    current_digest: Optional[str] = None
    changed_files_count: Optional[int] = None
    lifecycle_schema_version: Optional[int] = None
    cleanup_complete: Optional[bool] = None
    cleanup_status: Optional[str] = None


@dataclass(frozen=True)
class ContainmentExecutionEvidence:
    state: str
    status: str
    command: list[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    timed_out: Optional[bool] = None
    duration_seconds: Optional[float] = None
    stdout_truncated: Optional[bool] = None
    stderr_truncated: Optional[bool] = None


@dataclass(frozen=True)
class ContainmentCleanupEvidence:
    state: str
    container_attempted: Optional[bool] = None
    container_complete: Optional[bool] = None
    container_status: Optional[str] = None
    container_identity: Optional[dict[str, str]] = None
    liveness_verified: Optional[bool] = None
    workspace_complete: Optional[bool] = None
    workspace_status: Optional[str] = None
    overall_complete: Optional[bool] = None


@dataclass(frozen=True)
class ContainmentEvidence:
    execution_mode: str
    state: str
    security_claim_level: str
    requested: dict[str, object]
    preflight: ContainmentPreflightEvidence
    image: ContainmentImageEvidence
    controls: ContainmentControlsEvidence
    environment: ContainmentEnvironmentEvidence
    workspace: ContainmentWorkspaceEvidence
    execution: ContainmentExecutionEvidence
    cleanup: ContainmentCleanupEvidence
    notes: list[str] = field(default_factory=list)
    schema: str = CONTAINMENT_EVIDENCE_SCHEMA
    schema_version: int = CONTAINMENT_EVIDENCE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, object]:
        return sanitize_containment_evidence(asdict(self))


def canonical_containment_json(
    evidence: Union[ContainmentEvidence, dict[str, object]],
) -> str:
    payload = evidence.to_dict() if isinstance(evidence, ContainmentEvidence) else evidence
    validated = parse_containment_evidence(payload)
    return json.dumps(validated, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def parse_containment_evidence(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("Containment evidence must be an object.")
    bounded = sanitize_containment_evidence(value)
    _validate_root(bounded)
    serialized = json.dumps(
        bounded,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) > MAX_SERIALIZED_BYTES:
        raise ValueError("Containment evidence exceeds the serialized size limit.")
    return bounded


def sanitize_containment_evidence(value: object) -> dict[str, object]:
    sanitized = _sanitize_value(value, depth=0)
    if not isinstance(sanitized, dict):
        raise ValueError("Containment evidence must be an object.")
    return sanitized


def missing_containment_evidence(*, mode: str = "unknown") -> ContainmentEvidence:
    execution_mode = mode if mode in EXECUTION_MODES else "unknown"
    state = "not_applicable" if execution_mode == "local" else "unavailable"
    return ContainmentEvidence(
        execution_mode=execution_mode,
        state=state,
        security_claim_level="not_applicable" if state == "not_applicable" else "unknown",
        requested={"state": state},
        preflight=ContainmentPreflightEvidence(
            state=state,
            status="not_applicable" if state == "not_applicable" else "unknown",
            claim_level="not_applicable" if state == "not_applicable" else "unknown",
        ),
        image=ContainmentImageEvidence(state=state),
        controls=ContainmentControlsEvidence(state=state),
        environment=ContainmentEnvironmentEvidence(state=state),
        workspace=ContainmentWorkspaceEvidence(state=state),
        execution=ContainmentExecutionEvidence(
            state=state,
            status="skipped" if state == "not_applicable" else "unknown",
        ),
        cleanup=ContainmentCleanupEvidence(state=state),
        notes=[
            "Containment evidence was not recorded for this artifact."
            if state == "unavailable"
            else "Containment evidence is not applicable to this execution mode."
        ],
    )


def evidence_from_benchmark_result(result: BenchmarkResult) -> ContainmentEvidence:
    mode = "local"
    if result.sandbox is not None and result.sandbox.type == "docker":
        mode = "docker-sandbox"
    if mode == "local":
        return missing_containment_evidence(mode=mode)
    image = _first_docker_image(result)
    return ContainmentEvidence(
        execution_mode=mode,
        state="recorded" if image is not None else "unavailable",
        security_claim_level="unknown",
        requested={
            "state": "recorded" if result.sandbox is not None else "unavailable",
            "sandbox_type": result.sandbox.type if result.sandbox is not None else None,
            "network": result.sandbox.network if result.sandbox is not None else None,
            "configured_image": result.sandbox.configured_image if result.sandbox is not None else None,
        },
        preflight=ContainmentPreflightEvidence(
            state="not_applicable",
            status="not_applicable",
            claim_level="not_applicable",
        ),
        image=_image_evidence(
            image,
            state="recorded" if image is not None else "unavailable",
        ),
        controls=ContainmentControlsEvidence(
            state="recorded" if result.sandbox is not None else "unavailable",
            network=result.sandbox.network if result.sandbox is not None else None,
            read_only_root=result.sandbox.read_only if result.sandbox is not None else None,
            memory_limit=result.sandbox.memory if result.sandbox is not None else None,
            cpu_limit=result.sandbox.cpus if result.sandbox is not None else None,
        ),
        environment=ContainmentEnvironmentEvidence(state="unavailable"),
        workspace=ContainmentWorkspaceEvidence(state="not_applicable"),
        execution=_execution_evidence(result.test_result, state="recorded"),
        cleanup=ContainmentCleanupEvidence(
            state="recorded",
            container_attempted=result.test_result.process_cleanup_attempted,
            container_complete=result.test_result.process_cleanup_complete,
            container_status="unknown",
            overall_complete=result.test_result.process_cleanup_complete,
        ),
        notes=[
            "This evidence describes the standard Docker sandbox, not contained-run."
            if mode == "docker-sandbox"
            else "No application-level containment was requested for this run."
        ],
    )


def evidence_from_contained_run(
    *,
    config: AgentGuardConfig,
    source: Path,
    run_dir: Path,
    command: list[str],
    preflight: object,
    prepared: Optional[PreparedContainedWorkspace],
    environment: object,
    command_result: Optional[CommandResult],
    cleanup: object,
    cleanup_complete: bool,
    mutations: dict[str, object],
    failure: object,
    sensitive_values: Optional[list[str]] = None,
) -> ContainmentEvidence:
    contained = config.contained_execution
    preflight_evidence, image_evidence, claim_level = _preflight_evidence(preflight)
    cleanup_container = getattr(cleanup, "container", None)
    observed_image_id = (
        cleanup_container.get("image_id")
        if isinstance(cleanup_container, dict)
        else None
    )
    if isinstance(observed_image_id, str):
        image_evidence = replace(
            image_evidence,
            container_bound_image_id=observed_image_id,
        )
    controls = ContainmentControlsEvidence(
        state="recorded" if contained is not None else "unavailable",
        network=contained.network if contained is not None else None,
        no_new_privileges=True if contained is not None else None,
        cap_drop_all=True if contained is not None else None,
        read_only_root=True if contained is not None else None,
        tmpfs_paths=["/tmp"] if contained is not None else [],
        pids_limit=contained.pids_limit if contained is not None else None,
        memory_limit=contained.memory_limit if contained is not None else None,
        cpu_limit=contained.cpu_limit if contained is not None else None,
        uid=contained.required_uid if contained is not None else None,
        gid=contained.required_gid if contained is not None else None,
        docker_socket_mount=False if contained is not None else None,
        host_network=contained.allow_host_network if contained is not None else None,
        privileged=contained.allow_privileged if contained is not None else None,
        device_exposure=contained.allow_device_exposure if contained is not None else None,
        host_namespace_sharing=(
            contained.allow_host_namespace_sharing if contained is not None else None
        ),
    )
    workspace = _workspace_evidence(prepared, mutations, cleanup)
    failure_stage = getattr(failure, "stage", None)
    execution_status = (
        "preflight_blocked"
        if failure_stage == "preflight"
        else "policy_blocked"
        if failure_stage == "policy"
        else "executed"
        if command_result is not None
        else "skipped"
    )
    notes = [
        "Docker argv, raw Docker stdout/stderr, secret values, and private host roots are omitted.",
        "Docker is application-level containment, not a VM or syscall boundary.",
    ]
    if preflight_evidence.claim_level == "docker-desktop-reduced":
        notes.append("Docker Desktop evidence has a reduced security claim level.")
    payload = ContainmentEvidence(
        execution_mode="contained-run",
        state="recorded",
        security_claim_level=claim_level,
        requested={
            "state": "recorded",
            "platform": contained.platform if contained is not None else None,
            "network": contained.network if contained is not None else None,
            "image_provenance": (
                contained.image_provenance if contained is not None else None
            ),
            "configured_image": config.sandbox.image,
            "command": _safe_string_list(command, sensitive_values),
            "source_dir": _portable_or_redacted(source, source, run_dir, config.config_path),
            "run_dir": _portable_or_redacted(run_dir, source, run_dir, config.config_path),
        },
        preflight=preflight_evidence,
        image=image_evidence,
        controls=controls,
        environment=_environment_evidence(environment),
        workspace=workspace,
        execution=_execution_evidence(
            command_result,
            state="recorded" if command_result is not None else "unavailable",
            status=execution_status,
            command=command,
            sensitive_values=sensitive_values,
        ),
        cleanup=_cleanup_evidence(cleanup, cleanup_complete),
        notes=notes,
    )
    parse_containment_evidence(payload.to_dict())
    return payload


def _sanitize_value(value: object, *, depth: int) -> object:
    if depth > MAX_NESTING:
        raise ValueError("Containment evidence exceeds the nesting limit.")
    if is_dataclass(value) and not isinstance(value, type):
        return _sanitize_value(asdict(value), depth=depth)
    if isinstance(value, Path):
        return _sanitize_text(str(value))
    if isinstance(value, str):
        return _sanitize_text(value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > 10**12:
            raise ValueError("Containment evidence integer is outside bounds.")
        return value
    if isinstance(value, float):
        if not (-10**12 <= value <= 10**12):
            raise ValueError("Containment evidence number is outside bounds.")
        return round(value, 6)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_ITEMS:
            raise ValueError("Containment evidence list exceeds the item limit.")
        return [_sanitize_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_DICT_ITEMS:
            raise ValueError("Containment evidence object exceeds the item limit.")
        sanitized = {}
        for key, item in sorted(value.items(), key=lambda entry: str(entry[0])):
            if not isinstance(key, str) or not key:
                raise ValueError("Containment evidence object keys must be strings.")
            safe_key = _sanitize_text(key)
            sanitized[safe_key] = _sanitize_value(item, depth=depth + 1)
        return sanitized
    return _sanitize_text(str(value))


def _sanitize_text(value: str) -> str:
    text = redact_credentials(value)
    text = CONTROL_CHARACTER_PATTERN.sub("", text)
    if text != "/tmp":
        text = PRIVATE_PATH_PATTERN.sub("[REDACTED_PATH]", text)
    return limit_output(text, MAX_STRING_CHARS).text


def _safe_string_list(
    values: list[str],
    sensitive_values: Optional[list[str]] = None,
) -> list[str]:
    redacted = redact_credential_arguments(values, sensitive_values)
    return [
        limit_output(redact_credentials(value, sensitive_values), MAX_STRING_CHARS).text
        for value in redacted[:MAX_LIST_ITEMS]
    ]


def _portable_or_redacted(
    path: Path,
    source: Path,
    run_dir: Path,
    config_path: Path,
) -> str:
    roots = artifact_roots(
        repository_root=source,
        run_root=run_dir,
        config_path=config_path,
    )
    portable = portable_value(path, roots)
    return _sanitize_text(str(portable))


def _preflight_evidence(
    preflight: object,
) -> tuple[ContainmentPreflightEvidence, ContainmentImageEvidence, str]:
    if preflight is None:
        return (
            ContainmentPreflightEvidence(
                state="unavailable",
                status="unknown",
                claim_level="unknown",
            ),
            ContainmentImageEvidence(state="unavailable"),
            "unknown",
        )
    status = getattr(getattr(preflight, "status", None), "value", None) or str(
        getattr(preflight, "status", "unknown")
    )
    claim_level = str(getattr(preflight, "claim_level", "unknown") or "unknown")
    checks = list(getattr(preflight, "checks", []) or [])
    evidence = getattr(preflight, "evidence", {}) or {}
    preflight_evidence = ContainmentPreflightEvidence(
        state="recorded",
        status=status if status in PREFLIGHT_STATUSES else "unknown",
        claim_level=claim_level if claim_level in SECURITY_CLAIM_LEVELS else "unknown",
        reduced_claim=claim_level == "docker-desktop-reduced",
        checks_total=len(checks),
        checks_passed=sum(1 for check in checks if bool(getattr(check, "passed", False))),
        approved_boundary_constructible=(
            evidence.get("approved_boundary_constructible")
            if isinstance(evidence.get("approved_boundary_constructible"), bool)
            else None
        ),
    )
    image = _image_evidence(
        getattr(preflight, "docker_image", None),
        state="recorded",
        include_executed=False,
    )
    return preflight_evidence, image, preflight_evidence.claim_level


def _image_evidence(
    image: Optional[DockerImageIdentity],
    *,
    state: str,
    include_executed: bool = True,
) -> ContainmentImageEvidence:
    if image is None:
        return ContainmentImageEvidence(state=state)
    return ContainmentImageEvidence(
        state="recorded",
        configured_reference=image.configured_reference,
        registry_digest=image.registry_digest,
        local_image_id=image.local_image_id,
        container_bound_image_id=image.executed_image_id if include_executed else None,
        platform=image.platform,
        pull_policy=image.pull_policy,
        cache_status=image.cache_status,
    )


def _environment_evidence(environment: object) -> ContainmentEnvironmentEvidence:
    return ContainmentEnvironmentEvidence(
        state="recorded",
        supplied_names=_safe_name_list(getattr(environment, "supplied", []) or []),
        sensitive_names=_safe_name_list(getattr(environment, "sensitive", []) or []),
        missing_names=_safe_name_list(getattr(environment, "missing", []) or []),
        default_names=_safe_name_list(getattr(environment, "defaults", []) or []),
        values_recorded=False,
    )


def _safe_name_list(values: object) -> list[str]:
    if not isinstance(values, list):
        values = list(values) if isinstance(values, tuple) else []
    names = []
    for value in values[:MAX_LIST_ITEMS]:
        if isinstance(value, str):
            names.append(_sanitize_text(value))
    return sorted(names)


def _workspace_evidence(
    prepared: Optional[PreparedContainedWorkspace],
    mutations: dict[str, object],
    cleanup: object,
) -> ContainmentWorkspaceEvidence:
    if prepared is None:
        return ContainmentWorkspaceEvidence(state="unavailable")
    metadata = prepared.metadata
    changed = mutations.get("changed_files")
    return ContainmentWorkspaceEvidence(
        state="recorded",
        source_kind=metadata.source_kind,
        agent_mount=metadata.agent_mount,
        evidence_mount=metadata.evidence_mount,
        writable_paths=list(metadata.agent_visible_writable_paths),
        baseline_digest=metadata.baseline.digest,
        current_digest=(
            str(mutations["current_digest"])
            if isinstance(mutations.get("current_digest"), str)
            else None
        ),
        changed_files_count=len(changed) if isinstance(changed, list) else None,
        lifecycle_schema_version=metadata.schema_version,
        cleanup_complete=getattr(cleanup, "workspace_complete", None),
        cleanup_status=getattr(cleanup, "workspace_status", None),
    )


def _execution_evidence(
    result: Optional[CommandResult],
    *,
    state: str,
    status: str = "executed",
    command: Optional[list[str]] = None,
    sensitive_values: Optional[list[str]] = None,
) -> ContainmentExecutionEvidence:
    return ContainmentExecutionEvidence(
        state=state,
        status=status,
        command=_safe_string_list(command or [], sensitive_values),
        exit_code=result.exit_code if result is not None else None,
        timed_out=result.timed_out if result is not None else None,
        duration_seconds=result.duration_seconds if result is not None else None,
        stdout_truncated=result.stdout_truncated if result is not None else None,
        stderr_truncated=result.stderr_truncated if result is not None else None,
    )


def _cleanup_evidence(cleanup: object, cleanup_complete: bool) -> ContainmentCleanupEvidence:
    status = str(getattr(cleanup, "status", "unknown") or "unknown")
    liveness_verified = None
    if status in {"removed", "already_absent", "force_killed", "cleanly_terminated"}:
        liveness_verified = True
    elif status in {"verification_unavailable", "cleanup_incomplete"}:
        liveness_verified = False
    container = getattr(cleanup, "container", None)
    return ContainmentCleanupEvidence(
        state="recorded",
        container_attempted=getattr(cleanup, "attempted", None),
        container_complete=getattr(cleanup, "complete", None),
        container_status=status,
        container_identity=container if isinstance(container, dict) else None,
        liveness_verified=liveness_verified,
        workspace_complete=getattr(cleanup, "workspace_complete", None),
        workspace_status=getattr(cleanup, "workspace_status", None),
        overall_complete=cleanup_complete,
    )


def _first_docker_image(result: BenchmarkResult) -> Optional[DockerImageIdentity]:
    if result.test_result.docker_image is not None:
        return result.test_result.docker_image
    for event in result.command_events:
        if event.docker_image is not None:
            return event.docker_image
    return None


def _validate_root(data: dict[str, object]) -> None:
    expected = {
        "schema",
        "schema_version",
        "execution_mode",
        "state",
        "security_claim_level",
        "requested",
        "preflight",
        "image",
        "controls",
        "environment",
        "workspace",
        "execution",
        "cleanup",
        "notes",
    }
    if set(data) != expected:
        raise ValueError("Containment evidence fields are invalid.")
    if data["schema"] != CONTAINMENT_EVIDENCE_SCHEMA:
        raise ValueError("Containment evidence schema is invalid.")
    if data["schema_version"] != CONTAINMENT_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("Containment evidence schema version is unsupported.")
    _require_enum(data["execution_mode"], EXECUTION_MODES, "execution mode")
    _require_enum(data["state"], STATE_VALUES, "state")
    _require_enum(
        data["security_claim_level"],
        SECURITY_CLAIM_LEVELS,
        "security claim level",
    )
    for name in ("requested", "preflight", "image", "controls", "environment", "workspace", "execution", "cleanup"):
        if not isinstance(data[name], dict):
            raise ValueError("Containment evidence section must be an object.")
    if not isinstance(data["notes"], list) or not all(
        isinstance(item, str) for item in data["notes"]
    ):
        raise ValueError("Containment evidence notes must be strings.")
    _validate_preflight(data["preflight"])
    _validate_image(data["image"])
    _validate_controls(data["controls"])
    _validate_environment(data["environment"])
    _validate_workspace(data["workspace"])
    _validate_execution(data["execution"])
    _validate_cleanup(data["cleanup"])


def _require_enum(value: object, choices: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"Containment evidence {label} is invalid.")
    return value


def _validate_preflight(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "preflight state")
    _require_enum(data.get("status"), PREFLIGHT_STATUSES, "preflight status")
    _require_enum(
        data.get("claim_level"),
        SECURITY_CLAIM_LEVELS,
        "preflight claim level",
    )
    _optional_bool(data.get("reduced_claim"), "preflight reduced claim")
    _optional_nonnegative_int(data.get("checks_total"), "preflight checks total")
    _optional_nonnegative_int(data.get("checks_passed"), "preflight checks passed")
    _optional_bool(
        data.get("approved_boundary_constructible"),
        "preflight boundary flag",
    )


def _validate_image(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "image state")
    configured = data.get("configured_reference")
    local_id = data.get("local_image_id")
    bound_id = data.get("container_bound_image_id")
    registry = data.get("registry_digest")
    platform = data.get("platform")
    identity_payload = {
        "configured_reference": configured,
        "local_image_id": local_id,
        "executed_image_id": bound_id if bound_id is not None else local_id,
        "registry_digest": registry,
        "platform": platform,
        "pull_policy": data.get("pull_policy"),
        "cache_status": data.get("cache_status"),
    }
    if any(value is not None for value in identity_payload.values()):
        parse_docker_image_identity(identity_payload)
    if configured is not None and (
        not isinstance(configured, str)
        or len(configured) > MAX_CONTAINER_REF_LENGTH
    ):
        raise ValueError("Containment image configured reference is invalid.")
    if registry is not None and (
        not isinstance(registry, str) or REGISTRY_DIGEST_PATTERN.fullmatch(registry) is None
    ):
        raise ValueError("Containment image registry digest is invalid.")
    for value, label in (
        (local_id, "local image ID"),
        (bound_id, "container-bound image ID"),
    ):
        if value is not None and (
            not isinstance(value, str) or IMAGE_ID_PATTERN.fullmatch(value) is None
        ):
            raise ValueError(f"Containment image {label} is invalid.")


def _validate_controls(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "controls state")
    for key in (
        "no_new_privileges",
        "cap_drop_all",
        "read_only_root",
        "docker_socket_mount",
        "host_network",
        "privileged",
        "device_exposure",
        "host_namespace_sharing",
    ):
        _optional_bool(data.get(key), f"controls {key}")
    for key in ("pids_limit", "uid", "gid"):
        _optional_nonnegative_int(data.get(key), f"controls {key}")
    cpu = data.get("cpu_limit")
    if cpu is not None and not isinstance(cpu, (int, float)):
        raise ValueError("Containment controls CPU limit is invalid.")
    tmpfs = data.get("tmpfs_paths")
    if not isinstance(tmpfs, list) or not all(isinstance(item, str) for item in tmpfs):
        raise ValueError("Containment tmpfs paths must be strings.")


def _validate_environment(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "environment state")
    for key in ("supplied_names", "sensitive_names", "missing_names", "default_names"):
        names = data.get(key)
        if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
            raise ValueError("Containment environment names must be strings.")
    if data.get("values_recorded") is not False:
        raise ValueError("Containment evidence must not record environment values.")


def _validate_workspace(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "workspace state")
    _optional_bool(data.get("cleanup_complete"), "workspace cleanup complete")
    for key in ("baseline_digest", "current_digest"):
        value = data.get(key)
        if value is not None and (
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        ):
            raise ValueError("Containment workspace digest is invalid.")
    _optional_nonnegative_int(data.get("changed_files_count"), "workspace changed files")
    _optional_nonnegative_int(
        data.get("lifecycle_schema_version"),
        "workspace schema version",
    )


def _validate_execution(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "execution state")
    _require_enum(data.get("status"), EXECUTION_STATUSES, "execution status")
    command = data.get("command")
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise ValueError("Containment execution command must be a string list.")
    _optional_bool(data.get("timed_out"), "execution timed out")
    _optional_bool(data.get("stdout_truncated"), "execution stdout truncation")
    _optional_bool(data.get("stderr_truncated"), "execution stderr truncation")
    exit_code = data.get("exit_code")
    if exit_code is not None and not isinstance(exit_code, int):
        raise ValueError("Containment execution exit code is invalid.")


def _validate_cleanup(data: dict[str, object]) -> None:
    _require_enum(data.get("state"), STATE_VALUES, "cleanup state")
    _require_enum(
        data.get("container_status") or "unknown",
        CLEANUP_STATUSES,
        "cleanup container status",
    )
    _require_enum(
        data.get("workspace_status") or "unknown",
        CLEANUP_STATUSES,
        "cleanup workspace status",
    )
    for key in (
        "container_attempted",
        "container_complete",
        "liveness_verified",
        "workspace_complete",
        "overall_complete",
    ):
        _optional_bool(data.get(key), f"cleanup {key}")
    identity = data.get("container_identity")
    if identity is not None:
        required = {
            "id_sha256",
            "name_sha256",
            "owner_label_sha256",
        }
        if not isinstance(identity, dict) or frozenset(identity) not in {
            frozenset(required),
            frozenset({*required, "image_id"}),
        }:
            raise ValueError("Containment cleanup container identity is invalid.")
        if any(
            not isinstance(value, str) or CONTAINER_ID_HASH_PATTERN.fullmatch(value) is None
            for key, value in identity.items()
            if key != "image_id"
        ):
            raise ValueError("Containment cleanup identity hashes are invalid.")
        image_id = identity.get("image_id")
        if image_id is not None and (
            not isinstance(image_id, str) or IMAGE_ID_PATTERN.fullmatch(image_id) is None
        ):
            raise ValueError("Containment cleanup image identity is invalid.")


def _optional_bool(value: object, label: str) -> None:
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"Containment evidence {label} must be boolean or null.")


def _optional_nonnegative_int(value: object, label: str) -> None:
    if value is not None and (
        not isinstance(value, int) or isinstance(value, bool) or value < 0
    ):
        raise ValueError(f"Containment evidence {label} must be nonnegative or null.")
