from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.instrumentation.output_limits import limit_output
from agentguard.redaction import redact_credentials
from agentguard.sandbox.docker_identity import (
    IMAGE_ID_PATTERN,
    DockerImageIdentity,
    parse_docker_image_identity,
)


LIVE_STUDY_EGRESS_POLICY_SCHEMA = "agentguard.live-study-egress-policy"
LIVE_STUDY_EGRESS_POLICY_SCHEMA_VERSION = 1
LIVE_STUDY_EGRESS_MANIFEST_SCHEMA = "agentguard.live-study-egress-manifest"
LIVE_STUDY_EGRESS_MANIFEST_SCHEMA_VERSION = 1
LIVE_STUDY_EGRESS_EXECUTION_MODE = "study-egress"
LIVE_STUDY_EGRESS_EXECUTION_BOUNDARY = "study-egress-gateway"
LIVE_STUDY_GATEWAY_ALIAS = "agentguard-study-egress-gateway"
LIVE_STUDY_GATEWAY_PROXY_PORT = 8080

MAX_EGRESS_HOST_LENGTH = 253
MAX_EGRESS_RULES = 64
MAX_EGRESS_EVENTS = 256
MAX_EGRESS_STRING = 512
MAX_EGRESS_SERIALIZED_BYTES = 64 * 1024
MAX_EGRESS_ADDRESSES = 8
MAX_EGRESS_HEADER_VALUE = 8192
MAX_EGRESS_BYTES = 10**12
MAX_EGRESS_NESTING = 8
MAX_EGRESS_OBJECT_ITEMS = 96
MAX_EGRESS_LIST_ITEMS = 256
MAX_DOCKER_NAME = 63
GATEWAY_POLICY_CONTAINER_PATH = "/agentguard-egress/policy.json"
GATEWAY_EVIDENCE_CONTAINER_PATH = "/agentguard-egress/gateway-evidence.json"
GATEWAY_EVIDENCE_HOST_NAME = "gateway-evidence.json"
DEFAULT_GATEWAY_COMMAND = (
    "/agentguard-live-egress-gateway",
    "--policy",
    GATEWAY_POLICY_CONTAINER_PATH,
    "--evidence",
    GATEWAY_EVIDENCE_CONTAINER_PATH,
)

_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SAFE_DOCKER_NAME = re.compile(r"^agentguard-[a-z0-9][a-z0-9_.-]{0,62}$")
_SAFE_NETWORK_NAME = re.compile(r"^agentguard-study-[a-z0-9]{12}-[a-z]+$")
_PRIVATE_PATH = re.compile(
    r"(?:/Users/[^/\s,;]+|/home/[^/\s,;]+|/private/tmp|/private/var|/tmp)"
    r"(?:/[^\s,;]*)?"
)
_URL_QUERY = re.compile(r"(?P<prefix>\bhttps?://[^\s?#]+[^\s?#]*)(?:\?[^\s#]*)")
_BARE_QUERY = re.compile(r"\?[A-Za-z0-9_.~%=&:+/-]{1,512}")
_DANGEROUS_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "host.docker.internal",
    "gateway.docker.internal",
    "docker.for.mac.localhost",
    "docker.for.mac.host.internal",
    "kubernetes.docker.internal",
    "metadata",
    "metadata.google.internal",
}
_DANGEROUS_HOST_SUFFIXES = (
    ".docker.internal",
    ".localhost",
)
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "2001:db8::/32",
    )
)
_BLOCKED_ROUTE_KINDS = {
    "alternate-dns",
    "direct-outbound",
    "proxy-bypass",
    "udp",
    "quic",
    "unix-socket",
}
_ALLOWED_PROTOCOLS = {"connect", "http", "https", "tcp"}
_BLOCKED_PROTOCOLS = {"udp", "quic", "dns", "unix"}


@dataclass(frozen=True)
class EgressDestinationRule:
    host: str
    port: int
    purpose: str = "approved-destination"
    test_only: bool = False
    test_only_ip_literal: bool = False


@dataclass(frozen=True)
class LiveStudyEgressPolicy:
    destinations: tuple[EgressDestinationRule, ...]
    schema: str = LIVE_STUDY_EGRESS_POLICY_SCHEMA
    schema_version: int = LIVE_STUDY_EGRESS_POLICY_SCHEMA_VERSION


@dataclass(frozen=True)
class LiveStudyGatewayResources:
    uid: int = 65532
    gid: int = 65532
    cpu_limit: float = 0.5
    memory_limit: str = "128m"
    pids_limit: int = 128
    tmpfs_size: str = "64m"


@dataclass(frozen=True)
class LiveStudyEgressDockerPlan:
    trial_id: str
    internal_network: str
    outbound_network: str
    agent_container: str
    gateway_container: str
    commands: dict[str, list[str]]
    labels: dict[str, str]


@dataclass(frozen=True)
class LiveStudyEgressTrialRequest:
    plan_digest: str
    profile_hash: str
    fixture_hash: str
    trial_id: str
    profile_id: str
    fixture_id: str
    workspace: Path
    evidence_dir: Path
    prompt_path: Path
    agent_image: str
    agent_command: list[str]
    policy: LiveStudyEgressPolicy
    gateway_image: str
    platform: str
    gateway_command: tuple[str, ...] = DEFAULT_GATEWAY_COMMAND
    gateway_resources: LiveStudyGatewayResources = LiveStudyGatewayResources()
    agent_uid: int = 1000
    agent_gid: int = 1000
    timeout_seconds: int = 30
    allow_local_image_id: bool = False


@dataclass(frozen=True)
class LiveStudyEgressTrialResult:
    manifest: dict[str, object]
    manifest_path: Path
    status: str
    outcome: str
    stop_condition: Optional[str] = None
    message: Optional[str] = None


@dataclass(frozen=True)
class DockerControlResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


DockerControl = Callable[[list[str], int], DockerControlResult]


class LiveStudyEgressError(ValueError):
    pass


def run_live_study_egress_trial(
    request: LiveStudyEgressTrialRequest,
) -> LiveStudyEgressTrialResult:
    validate_live_study_egress_policy(request.policy)
    _validate_execution_image(
        request.gateway_image,
        allow_local_image_id=request.allow_local_image_id,
        label="Gateway image",
    )
    _validate_execution_image(
        request.agent_image,
        allow_local_image_id=request.allow_local_image_id,
        label="Agent image",
    )
    manifest_path = request.evidence_dir / "live-study-egress-manifest.json"
    request.evidence_dir.mkdir(parents=True, exist_ok=True)
    policy_path = request.evidence_dir / "live-study-egress-policy.json"
    policy_path.write_text(
        json.dumps(
            live_study_egress_policy_to_dict(request.policy),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    gateway_evidence_path = request.evidence_dir / GATEWAY_EVIDENCE_HOST_NAME
    aliases = tuple(
        _normalize_rule_host(rule)
        for rule in request.policy.destinations
        if rule.test_only and not rule.test_only_ip_literal
    )
    try:
        gateway_identity = inspect_docker_image_identity(
            request.gateway_image,
            allow_local_image_id=request.allow_local_image_id,
        )
    except LiveStudyEgressError:
        gateway_identity = None
    plan = build_live_study_egress_docker_plan(
        trial_id=request.trial_id,
        agent_image=request.agent_image,
        gateway_image=request.gateway_image,
        workspace_host_path=request.workspace,
        agent_command=list(request.agent_command),
        gateway_command=list(request.gateway_command),
        uid=request.agent_uid,
        gid=request.agent_gid,
        gateway_mounts=[
            (
                "type=bind,"
                f"source={request.evidence_dir.expanduser().resolve()},"
                "target=/agentguard-egress"
            )
        ],
        gateway_outbound_aliases=aliases,
        resources=request.gateway_resources,
        allow_local_image_id=request.allow_local_image_id,
    )
    docker_result = run_live_study_egress_docker_plan(
        plan,
        timeout_seconds=request.timeout_seconds,
    )
    gateway_evidence = load_gateway_evidence(gateway_evidence_path)
    events = gateway_evidence["events"] if isinstance(gateway_evidence["events"], list) else []
    destination = _single_policy_destination(request.policy)
    gateway_status = _combined_gateway_status(
        docker_result=docker_result,
        gateway_evidence=gateway_evidence,
    )
    manifest = build_live_study_egress_manifest(
        plan_digest=request.plan_digest,
        profile_hash=request.profile_hash,
        fixture_hash=request.fixture_hash,
        trial_id=request.trial_id,
        policy=request.policy,
        gateway_image=gateway_identity,
        approved_host=destination[0],
        approved_port=destination[1],
        events=events,
        gateway_status=gateway_status,
        cleanup_status=_cleanup_status_from_docker_result(docker_result),
        liveness_status=_liveness_status_from_docker_result(docker_result),
    )
    manifest_path.write_text(
        canonical_live_study_egress_manifest(manifest) + "\n",
        encoding="utf-8",
    )
    completion = manifest["completion"]
    status = str(completion.get("status"))
    if status == "complete":
        return LiveStudyEgressTrialResult(
            manifest=manifest,
            manifest_path=manifest_path,
            status="completed",
            outcome="completed",
        )
    if status == "failed":
        return LiveStudyEgressTrialResult(
            manifest=manifest,
            manifest_path=manifest_path,
            status="failed",
            outcome="egress_policy_failed",
            stop_condition=str(completion.get("reason") or "study-egress failure"),
            message=str(completion.get("reason") or "Study-egress trial failed."),
        )
    return LiveStudyEgressTrialResult(
        manifest=manifest,
        manifest_path=manifest_path,
        status="incomplete",
        outcome="egress_gateway_evidence_incomplete",
        stop_condition=str(completion.get("reason") or "gateway evidence incomplete"),
        message=str(completion.get("reason") or "Live study-egress gateway evidence is incomplete."),
    )


def live_study_egress_policy_from_dict(data: object) -> LiveStudyEgressPolicy:
    if not isinstance(data, dict):
        raise LiveStudyEgressError("Live-study egress policy must be an object.")
    if data.get("schema") != LIVE_STUDY_EGRESS_POLICY_SCHEMA:
        raise LiveStudyEgressError("Invalid live-study egress policy schema.")
    if data.get("schema_version") != LIVE_STUDY_EGRESS_POLICY_SCHEMA_VERSION:
        raise LiveStudyEgressError("Unsupported live-study egress policy version.")
    raw_destinations = data.get("destinations")
    if not isinstance(raw_destinations, list) or len(raw_destinations) > MAX_EGRESS_RULES:
        raise LiveStudyEgressError("Live-study egress policy destination bound exceeded.")
    rules = []
    for index, raw in enumerate(raw_destinations):
        if not isinstance(raw, dict):
            raise LiveStudyEgressError(
                f"Live-study egress destination {index} must be an object."
            )
        unknown = set(raw) - {
            "host",
            "port",
            "purpose",
            "test_only",
            "test_only_ip_literal",
        }
        if unknown:
            raise LiveStudyEgressError(
                "Live-study egress destination contains unknown field(s): "
                + ", ".join(sorted(unknown))
            )
        rules.append(
            EgressDestinationRule(
                host=_bounded_string(raw.get("host"), "host"),
                port=_port(raw.get("port"), "port"),
                purpose=_bounded_string(
                    raw.get("purpose", "approved-destination"),
                    "purpose",
                ),
                test_only=_bool(raw.get("test_only", False), "test_only"),
                test_only_ip_literal=_bool(
                    raw.get("test_only_ip_literal", False),
                    "test_only_ip_literal",
                ),
            )
        )
    policy = LiveStudyEgressPolicy(destinations=tuple(rules))
    validate_live_study_egress_policy(policy)
    return policy


def inspect_docker_image_identity(
    image: str,
    *,
    allow_local_image_id: bool = False,
) -> Optional[DockerImageIdentity | dict[str, object]]:
    _validate_execution_image(
        image,
        allow_local_image_id=allow_local_image_id,
        label="Docker image",
    )
    completed = _run_docker_control(
        ["docker", "image", "inspect", "--format", "{{json .}}", image],
        timeout_seconds=10,
    )
    if completed.returncode != 0 or completed.timed_out:
        raise LiveStudyEgressError("Docker image identity inspection failed.")
    try:
        raw = json.loads(limit_output(completed.stdout, MAX_EGRESS_SERIALIZED_BYTES).text)
    except json.JSONDecodeError:
        raise LiveStudyEgressError("Docker image identity inspection returned malformed JSON.") from None
    if isinstance(raw, list) and len(raw) == 1:
        raw = raw[0]
    if not isinstance(raw, dict):
        raise LiveStudyEgressError("Docker image identity inspection returned an unsupported shape.")
    local_id = _image_id(raw.get("Id"))
    if local_id is None:
        raise LiveStudyEgressError("Docker image identity is missing local image ID.")
    os_name = raw.get("Os")
    architecture = raw.get("Architecture")
    variant = raw.get("Variant")
    platform = None
    if isinstance(os_name, str) and isinstance(architecture, str):
        platform = f"{os_name}/{architecture}"
        if isinstance(variant, str) and variant:
            platform += f"/{variant}"
    if _is_local_image_id(image):
        if not allow_local_image_id:
            raise LiveStudyEgressError("Local image IDs are allowed only for local mock tests.")
        if image != local_id:
            raise LiveStudyEgressError("Configured local image ID does not match inspected image.")
        return {
            "configured_reference": "local-image-id",
            "local_image_id": local_id,
            "executed_image_id": local_id,
            "registry_digest": None,
            "platform": platform,
            "pull_policy": "local-test-image-id",
            "cache_status": "present",
        }
    repo_digests = raw.get("RepoDigests")
    registry_digest = None
    if isinstance(repo_digests, list) and image in repo_digests:
        registry_digest = image
    try:
        return parse_docker_image_identity(
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
    except ValueError as error:
        raise LiveStudyEgressError("Docker image identity is not immutable or consistent.") from error


def load_gateway_evidence(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {
            "status": "missing",
            "events": [],
            "gateway_status": {
                "status": "unknown",
                "evidence_complete": False,
                "reason": "gateway evidence file missing",
            },
        }
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {
            "status": "unavailable",
            "events": [],
            "gateway_status": {
                "status": "unknown",
                "evidence_complete": False,
                "reason": "gateway evidence file unavailable",
            },
        }
    bounded = limit_output(text, MAX_EGRESS_SERIALIZED_BYTES)
    if bounded.truncated:
        return {
            "status": "truncated",
            "events": [],
            "gateway_status": {
                "status": "unknown",
                "evidence_complete": False,
                "reason": "gateway evidence file truncated",
            },
        }
    try:
        raw = json.loads(bounded.text)
    except json.JSONDecodeError:
        return {
            "status": "malformed",
            "events": [],
            "gateway_status": {
                "status": "unknown",
                "evidence_complete": False,
                "reason": "gateway evidence file malformed",
            },
        }
    if not isinstance(raw, dict):
        return {
            "status": "malformed",
            "events": [],
            "gateway_status": {
                "status": "unknown",
                "evidence_complete": False,
                "reason": "gateway evidence file has unsupported shape",
            },
        }
    events = raw.get("events")
    if not isinstance(events, list) or len(events) > MAX_EGRESS_EVENTS:
        return {
            "status": "malformed",
            "events": [],
            "gateway_status": {
                "status": "unknown",
                "evidence_complete": False,
                "reason": "gateway evidence events are missing or out of bounds",
            },
        }
    gateway_status = raw.get("gateway_status")
    if not isinstance(gateway_status, dict):
        gateway_status = {
            "status": "running",
            "evidence_complete": True,
        }
    return {
        "status": "recorded",
        "events": _sanitize_value(events, depth=0),
        "gateway_status": _sanitize_value(gateway_status, depth=0),
    }


def live_study_egress_policy_to_dict(
    policy: LiveStudyEgressPolicy,
) -> dict[str, object]:
    validate_live_study_egress_policy(policy)
    return {
        "destinations": [
            {
                "host": _normalize_rule_host(rule),
                "port": rule.port,
                "purpose": _sanitize_text(rule.purpose),
                "test_only": rule.test_only,
                "test_only_ip_literal": rule.test_only_ip_literal,
            }
            for rule in sorted(
                policy.destinations,
                key=lambda item: (_normalize_rule_host(item), item.port, item.purpose),
            )
        ],
        "schema": LIVE_STUDY_EGRESS_POLICY_SCHEMA,
        "schema_version": LIVE_STUDY_EGRESS_POLICY_SCHEMA_VERSION,
    }


def live_study_egress_policy_digest(policy: LiveStudyEgressPolicy) -> str:
    return _stable_sha256(live_study_egress_policy_to_dict(policy))


def validate_live_study_egress_policy(policy: LiveStudyEgressPolicy) -> None:
    if policy.schema != LIVE_STUDY_EGRESS_POLICY_SCHEMA:
        raise LiveStudyEgressError("Invalid live-study egress policy schema.")
    if policy.schema_version != LIVE_STUDY_EGRESS_POLICY_SCHEMA_VERSION:
        raise LiveStudyEgressError("Unsupported live-study egress policy version.")
    if len(policy.destinations) > MAX_EGRESS_RULES:
        raise LiveStudyEgressError("Live-study egress policy destination bound exceeded.")
    seen: set[tuple[str, int]] = set()
    for rule in policy.destinations:
        host = _normalize_rule_host(rule)
        if (host, rule.port) in seen:
            raise LiveStudyEgressError("Duplicate live-study egress destination.")
        seen.add((host, rule.port))
        _validate_rule_host(rule)
        _port(rule.port, "port")
        _bounded_string(rule.purpose, "purpose")


def authorize_connect_authority(
    policy: LiveStudyEgressPolicy,
    authority: str,
    *,
    resolved_addresses: Optional[list[str]] = None,
    resolution_status: str = "stable",
) -> dict[str, object]:
    try:
        host, port = _split_authority(authority)
    except LiveStudyEgressError as error:
        return _deny_event(
            event_type="connect",
            protocol="connect",
            host="",
            port=None,
            reason=str(error),
        )
    return evaluate_live_study_egress_destination(
        policy,
        host=host,
        port=port,
        protocol="connect",
        resolved_addresses=resolved_addresses,
        resolution_status=resolution_status,
        event_type="connect",
    )


def authorize_url_destination(
    policy: LiveStudyEgressPolicy,
    url: str,
    *,
    resolved_addresses: Optional[list[str]] = None,
    resolution_status: str = "stable",
    event_type: str = "request",
) -> dict[str, object]:
    split = urlsplit(_bounded_string(url, "url"))
    if not split.scheme or split.scheme.lower() not in {"http", "https"}:
        return _deny_event(
            event_type=event_type,
            protocol=split.scheme.lower() if split.scheme else "unknown",
            host="",
            port=None,
            reason="unsupported_url_scheme",
        )
    if not split.hostname:
        return _deny_event(
            event_type=event_type,
            protocol=split.scheme.lower(),
            host="",
            port=None,
            reason="missing_url_host",
        )
    port = split.port or (443 if split.scheme.lower() == "https" else 80)
    return evaluate_live_study_egress_destination(
        policy,
        host=split.hostname,
        port=port,
        protocol=split.scheme.lower(),
        resolved_addresses=resolved_addresses,
        resolution_status=resolution_status,
        event_type=event_type,
    )


def evaluate_live_study_egress_destination(
    policy: LiveStudyEgressPolicy,
    *,
    host: str,
    port: int,
    protocol: str = "connect",
    resolved_addresses: Optional[list[str]] = None,
    resolution_status: str = "stable",
    event_type: str = "connect",
    bytes_in: Optional[int] = None,
    bytes_out: Optional[int] = None,
    timestamp_start: Optional[float] = None,
    timestamp_end: Optional[float] = None,
) -> dict[str, object]:
    validate_live_study_egress_policy(policy)
    protocol = _sanitize_text(protocol).lower()
    requested_host = _sanitize_text(host)
    try:
        normalized_host = _normalize_destination_host(host)
        destination_port = _port(port, "port")
    except LiveStudyEgressError as error:
        return _deny_event(
            event_type=event_type,
            protocol=protocol,
            host=requested_host,
            port=port if isinstance(port, int) else None,
            reason=str(error),
        )
    if protocol in _BLOCKED_PROTOCOLS:
        return _decision(
            event_type=event_type,
            protocol=protocol,
            requested_host=requested_host,
            effective_host=normalized_host,
            port=destination_port,
            decision="deny",
            reason=f"{protocol}_blocked",
            resolved_addresses=[],
            resolution_status="blocked",
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )
    if protocol not in _ALLOWED_PROTOCOLS:
        return _decision(
            event_type=event_type,
            protocol=protocol,
            requested_host=requested_host,
            effective_host=normalized_host,
            port=destination_port,
            decision="deny",
            reason="unsupported_protocol",
            resolved_addresses=[],
            resolution_status="blocked",
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )
    rule = _matching_rule(policy, normalized_host, destination_port)
    if rule is None:
        return _decision(
            event_type=event_type,
            protocol=protocol,
            requested_host=requested_host,
            effective_host=normalized_host,
            port=destination_port,
            decision="deny",
            reason="destination_not_approved",
            resolved_addresses=[],
            resolution_status="not_approved",
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )
    resolution = _validate_resolution_evidence(
        host=normalized_host,
        rule=rule,
        resolved_addresses=resolved_addresses,
        resolution_status=resolution_status,
    )
    if resolution["status"] != "stable":
        return _decision(
            event_type=event_type,
            protocol=protocol,
            requested_host=requested_host,
            effective_host=normalized_host,
            port=destination_port,
            decision="deny",
            reason=resolution["status"],
            resolved_addresses=resolution["addresses"],
            resolution_status=resolution["status"],
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
        )
    return _decision(
        event_type=event_type,
        protocol=protocol,
        requested_host=requested_host,
        effective_host=normalized_host,
        port=destination_port,
        decision="allow",
        reason="approved_destination",
        resolved_addresses=resolution["addresses"],
        resolution_status="stable",
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
    )


def record_blocked_route(
    *,
    route_kind: str,
    host: Optional[str] = None,
    port: Optional[int] = None,
    protocol: str = "tcp",
) -> dict[str, object]:
    kind = _sanitize_text(route_kind).lower()
    reason = f"{kind}_blocked" if kind in _BLOCKED_ROUTE_KINDS else "unexpected_route"
    return _decision(
        event_type=kind or "unexpected-route",
        protocol=protocol,
        requested_host="" if host is None else _sanitize_text(host),
        effective_host="" if host is None else _sanitize_text(host),
        port=port if isinstance(port, int) else None,
        decision="deny",
        reason=reason,
        resolved_addresses=[],
        resolution_status="blocked",
    )


def build_live_study_egress_manifest(
    *,
    plan_digest: str,
    profile_hash: str,
    fixture_hash: str,
    trial_id: str,
    policy: LiveStudyEgressPolicy,
    gateway_image: Optional[DockerImageIdentity | dict[str, object]],
    approved_host: Optional[str],
    approved_port: Optional[int],
    events: list[dict[str, object]],
    gateway_status: dict[str, object],
    cleanup_status: dict[str, object],
    liveness_status: dict[str, object],
) -> dict[str, object]:
    manifest = {
        "schema": LIVE_STUDY_EGRESS_MANIFEST_SCHEMA,
        "schema_version": LIVE_STUDY_EGRESS_MANIFEST_SCHEMA_VERSION,
        "plan_digest": _sha256_string(plan_digest, "plan_digest"),
        "profile_hash": _sha256_string(profile_hash, "profile_hash"),
        "fixture_hash": _sha256_string(fixture_hash, "fixture_hash"),
        "trial_id": _bounded_string(trial_id, "trial_id"),
        "egress_policy_digest": live_study_egress_policy_digest(policy),
        "approved_destination": {
            "host": _sanitize_text(approved_host or ""),
            "port": approved_port,
        },
        "gateway_image_identity": _gateway_image_identity(gateway_image),
        "events": events,
        "gateway_status": gateway_status,
        "cleanup_status": cleanup_status,
        "liveness_status": liveness_status,
        "completion": {
            "status": "unknown",
            "reason": None,
            "success_eligible": False,
        },
    }
    manifest["completion"] = classify_live_study_egress_manifest(manifest)
    return parse_live_study_egress_manifest(manifest)


def classify_live_study_egress_manifest(
    manifest: dict[str, object],
) -> dict[str, object]:
    events = manifest.get("events", [])
    if not isinstance(events, list):
        return _completion("incomplete", "egress event evidence is missing")
    if not isinstance(manifest.get("gateway_image_identity"), dict):
        return _completion("incomplete", "gateway image identity evidence is missing")
    gateway = manifest.get("gateway_status", {})
    cleanup = manifest.get("cleanup_status", {})
    liveness = manifest.get("liveness_status", {})
    if gateway.get("crashed") is True:
        return _completion("failed", "gateway crashed")
    if not isinstance(gateway, dict) or gateway.get("status") != "running":
        return _completion("incomplete", "gateway liveness was not established")
    if gateway.get("evidence_complete") is not True:
        return _completion("incomplete", "gateway evidence is incomplete")
    if not isinstance(cleanup, dict) or cleanup.get("overall_complete") is not True:
        return _completion("incomplete", "cleanup or liveness verification failed")
    if not isinstance(liveness, dict) or liveness.get("verified") is not True:
        return _completion("incomplete", "post-cleanup liveness was not verified")
    for event in events:
        if not isinstance(event, dict):
            return _completion("incomplete", "egress event evidence is malformed")
        if event.get("evidence_complete") is not True:
            return _completion("incomplete", "egress event evidence is incomplete")
        if event.get("decision") == "deny":
            return _completion("failed", "unexpected destination or bypass was blocked")
        if event.get("decision") != "allow":
            return _completion("incomplete", "egress event decision is missing")
    return _completion("complete", None)


def canonical_live_study_egress_manifest(manifest: dict[str, object]) -> str:
    parsed = parse_live_study_egress_manifest(manifest)
    return json.dumps(parsed, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def parse_live_study_egress_manifest(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LiveStudyEgressError("Live-study egress manifest must be an object.")
    sanitized = _sanitize_value(value, depth=0)
    if not isinstance(sanitized, dict):
        raise LiveStudyEgressError("Live-study egress manifest must be an object.")
    if sanitized.get("schema") != LIVE_STUDY_EGRESS_MANIFEST_SCHEMA:
        raise LiveStudyEgressError("Invalid live-study egress manifest schema.")
    if sanitized.get("schema_version") != LIVE_STUDY_EGRESS_MANIFEST_SCHEMA_VERSION:
        raise LiveStudyEgressError("Unsupported live-study egress manifest version.")
    events = sanitized.get("events")
    if not isinstance(events, list) or len(events) > MAX_EGRESS_EVENTS:
        raise LiveStudyEgressError("Live-study egress manifest event bound exceeded.")
    serialized = json.dumps(
        sanitized,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    if len(serialized.encode("utf-8")) > MAX_EGRESS_SERIALIZED_BYTES:
        raise LiveStudyEgressError("Live-study egress manifest exceeds size bound.")
    return sanitized


def build_live_study_egress_docker_plan(
    *,
    trial_id: str,
    agent_image: str,
    gateway_image: str,
    workspace_host_path: Path,
    agent_command: list[str],
    gateway_command: list[str],
    uid: int,
    gid: int,
    resources: LiveStudyGatewayResources = LiveStudyGatewayResources(),
    run_token: Optional[str] = None,
    gateway_mounts: Optional[list[str]] = None,
    gateway_environment: Optional[dict[str, str]] = None,
    gateway_outbound_aliases: tuple[str, ...] = (),
    allow_local_image_id: bool = False,
) -> LiveStudyEgressDockerPlan:
    _validate_execution_image(
        agent_image,
        allow_local_image_id=allow_local_image_id,
        label="Agent image",
    )
    _validate_execution_image(
        gateway_image,
        allow_local_image_id=allow_local_image_id,
        label="Gateway image",
    )
    if not agent_command or not all(isinstance(item, str) and item for item in agent_command):
        raise LiveStudyEgressError("Agent command must be a non-empty argv.")
    if not gateway_command or not all(
        isinstance(item, str) and item for item in gateway_command
    ):
        raise LiveStudyEgressError("Gateway command must be a non-empty argv.")
    _non_root(uid, "uid")
    _non_root(gid, "gid")
    _non_root(resources.uid, "gateway uid")
    _non_root(resources.gid, "gateway gid")
    token = run_token or hashlib.sha256(trial_id.encode("utf-8")).hexdigest()[:12]
    if not re.fullmatch(r"[a-z0-9]{12}", token):
        raise LiveStudyEgressError("Live-study egress run token is invalid.")
    internal_network = f"agentguard-study-{token}-internal"
    outbound_network = f"agentguard-study-{token}-outbound"
    agent_container = f"agentguard-study-{token}-agent"
    gateway_container = f"agentguard-study-{token}-gateway"
    for name in [internal_network, outbound_network]:
        _validate_network_name(name)
    for name in [agent_container, gateway_container]:
        _validate_container_name(name)
    workspace = workspace_host_path.expanduser().resolve()
    gateway_mounts = list(gateway_mounts or [])
    gateway_environment = dict(gateway_environment or {})
    outbound_aliases = _docker_network_aliases(gateway_outbound_aliases)
    labels = {
        "agentguard.owner": "study-egress",
        "agentguard.study-egress.trial": _sanitize_text(trial_id),
        "agentguard.study-egress.token": token,
    }
    connect_gateway_outbound = ["docker", "network", "connect"]
    for alias in outbound_aliases:
        connect_gateway_outbound.extend(["--alias", alias])
    connect_gateway_outbound.extend([outbound_network, gateway_container])
    commands = {
        "create_internal_network": [
            "docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--internal",
            "--label",
            "agentguard.owner=study-egress",
            "--label",
            f"agentguard.study-egress.token={token}",
            internal_network,
        ],
        "create_outbound_network": [
            "docker",
            "network",
            "create",
            "--driver",
            "bridge",
            "--label",
            "agentguard.owner=study-egress",
            "--label",
            f"agentguard.study-egress.token={token}",
            outbound_network,
        ],
        "create_gateway": _container_create_argv(
            container_name=gateway_container,
            network=internal_network,
            image=gateway_image,
            command=gateway_command,
            uid=resources.uid,
            gid=resources.gid,
            cpu_limit=resources.cpu_limit,
            memory_limit=resources.memory_limit,
            pids_limit=resources.pids_limit,
            tmpfs_size=resources.tmpfs_size,
            labels={
                **labels,
                "agentguard.study-egress.role": "gateway",
            },
            network_alias=LIVE_STUDY_GATEWAY_ALIAS,
            mounts=gateway_mounts,
            environment=gateway_environment,
            workdir="/tmp",
        ),
        "connect_gateway_outbound": connect_gateway_outbound,
        "create_agent": _container_create_argv(
            container_name=agent_container,
            network=internal_network,
            image=agent_image,
            command=agent_command,
            uid=uid,
            gid=gid,
            cpu_limit=resources.cpu_limit,
            memory_limit=resources.memory_limit,
            pids_limit=resources.pids_limit,
            tmpfs_size=resources.tmpfs_size,
            labels={
                **labels,
                "agentguard.study-egress.role": "agent",
            },
            network_alias=None,
            mounts=[f"type=bind,source={workspace},target=/workspace"],
            environment={
                "HTTP_PROXY": (
                    f"http://{LIVE_STUDY_GATEWAY_ALIAS}:"
                    f"{LIVE_STUDY_GATEWAY_PROXY_PORT}"
                ),
                "HTTPS_PROXY": (
                    f"http://{LIVE_STUDY_GATEWAY_ALIAS}:"
                    f"{LIVE_STUDY_GATEWAY_PROXY_PORT}"
                ),
                "ALL_PROXY": (
                    f"http://{LIVE_STUDY_GATEWAY_ALIAS}:"
                    f"{LIVE_STUDY_GATEWAY_PROXY_PORT}"
                ),
                "NO_PROXY": "",
            },
            workdir="/workspace",
        ),
        "start_gateway": ["docker", "start", gateway_container],
        "inspect_gateway": [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            gateway_container,
        ],
        "start_agent": ["docker", "start", "-a", agent_container],
        "cleanup_agent": ["docker", "rm", "-f", agent_container],
        "cleanup_gateway": ["docker", "rm", "-f", gateway_container],
        "cleanup_internal_network": ["docker", "network", "rm", internal_network],
        "cleanup_outbound_network": ["docker", "network", "rm", outbound_network],
    }
    plan = LiveStudyEgressDockerPlan(
        trial_id=trial_id,
        internal_network=internal_network,
        outbound_network=outbound_network,
        agent_container=agent_container,
        gateway_container=gateway_container,
        commands=commands,
        labels=labels,
    )
    validate_live_study_egress_docker_plan(plan)
    return plan


def validate_live_study_egress_docker_plan(
    plan: LiveStudyEgressDockerPlan,
) -> None:
    for network in [plan.internal_network, plan.outbound_network]:
        _validate_network_name(network)
    for container in [plan.agent_container, plan.gateway_container]:
        _validate_container_name(container)
    forbidden = {
        "--privileged",
        "--pid",
        "--ipc",
        "--uts",
        "--cgroupns",
        "--userns",
        "--device",
        "--add-host",
        "--network=host",
        "/var/run/docker.sock",
    }
    for label, argv in plan.commands.items():
        if not argv or argv[0] != "docker":
            raise LiveStudyEgressError(f"Docker plan command {label} is invalid.")
        if "host" in _option_values(argv, "--network"):
            raise LiveStudyEgressError("Docker host networking is not allowed.")
        if forbidden.intersection(argv):
            raise LiveStudyEgressError("Docker plan contains a forbidden option.")
    gateway_create = plan.commands["create_gateway"]
    agent_create = plan.commands["create_agent"]
    if gateway_create[gateway_create.index("--network") + 1] != plan.internal_network:
        raise LiveStudyEgressError("Gateway must initially join the internal study network.")
    if agent_create[agent_create.index("--network") + 1] != plan.internal_network:
        raise LiveStudyEgressError("Agent must join only the internal study network.")
    if plan.outbound_network in agent_create:
        raise LiveStudyEgressError("Agent must not join the outbound network.")
    if "--read-only" not in gateway_create or "--cap-drop" not in gateway_create:
        raise LiveStudyEgressError("Gateway hardening flags are incomplete.")


def run_live_study_egress_docker_plan(
    plan: LiveStudyEgressDockerPlan,
    *,
    command_runner: Optional[DockerControl] = None,
    timeout_seconds: int = 30,
) -> dict[str, object]:
    validate_live_study_egress_docker_plan(plan)
    runner = command_runner or _run_docker_control
    statuses: dict[str, object] = {}
    cleanup: dict[str, object] = {
        "agent_container": "not_created",
        "gateway_container": "not_created",
        "internal_network": "not_created",
        "outbound_network": "not_created",
        "overall_complete": False,
    }
    try:
        for step in [
            "create_internal_network",
            "create_outbound_network",
            "create_gateway",
            "connect_gateway_outbound",
            "create_agent",
            "start_gateway",
            "inspect_gateway",
            "start_agent",
        ]:
            result = runner(plan.commands[step], timeout_seconds)
            statuses[step] = _docker_step_evidence(result)
            if result.returncode != 0 or result.timed_out:
                statuses["failure_step"] = step
                statuses["status"] = "failed"
                break
            if step == "inspect_gateway":
                running = _gateway_inspect_running(result.stdout)
                statuses["gateway_liveness_verified"] = running
                if not running:
                    statuses["failure_step"] = "gateway_liveness"
                    statuses["status"] = "failed"
                    break
        else:
            statuses["status"] = "completed"
    finally:
        cleanup = _cleanup_live_study_egress_plan(
            plan,
            runner=runner,
            timeout_seconds=timeout_seconds,
        )
    statuses["cleanup"] = cleanup
    if cleanup.get("overall_complete") is not True:
        statuses["status"] = "incomplete"
        statuses["failure_step"] = "cleanup"
    return statuses


def _cleanup_live_study_egress_plan(
    plan: LiveStudyEgressDockerPlan,
    *,
    runner: DockerControl,
    timeout_seconds: int,
) -> dict[str, object]:
    cleanup_steps = [
        ("agent_container", "cleanup_agent"),
        ("gateway_container", "cleanup_gateway"),
        ("internal_network", "cleanup_internal_network"),
        ("outbound_network", "cleanup_outbound_network"),
    ]
    evidence: dict[str, object] = {}
    complete = True
    for label, step in cleanup_steps:
        result = runner(plan.commands[step], timeout_seconds)
        status = "removed" if result.returncode == 0 and not result.timed_out else "incomplete"
        evidence[label] = status
        evidence[f"{label}_evidence"] = _docker_step_evidence(result)
        if status != "removed":
            complete = False
    evidence["overall_complete"] = complete
    evidence["liveness_verified"] = complete
    return evidence


def _container_create_argv(
    *,
    container_name: str,
    network: str,
    image: str,
    command: list[str],
    uid: int,
    gid: int,
    cpu_limit: float,
    memory_limit: str,
    pids_limit: int,
    tmpfs_size: str,
    labels: dict[str, str],
    network_alias: Optional[str],
    mounts: list[str],
    environment: dict[str, str],
    workdir: str,
) -> list[str]:
    if not isinstance(workdir, str) or not workdir.startswith("/") or _CONTROL_CHARACTER.search(workdir):
        raise LiveStudyEgressError("Unsafe Docker working directory.")
    argv = [
        "docker",
        "create",
        "--name",
        container_name,
        "--network",
        network,
    ]
    if network_alias is not None:
        argv.extend(["--network-alias", network_alias])
    argv.extend(
        [
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            str(_bounded_positive_int(pids_limit, "pids_limit")),
            "--memory",
            _bounded_size(memory_limit, "memory_limit"),
            "--cpus",
            _format_cpu(cpu_limit),
            "--read-only",
            "--tmpfs",
            (
                "/tmp:rw,noexec,nosuid,nodev,"
                f"size={_bounded_size(tmpfs_size, 'tmpfs_size')},"
                f"uid={uid},gid={gid},mode=700"
            ),
            "--workdir",
            workdir,
            "--user",
            f"{uid}:{gid}",
        ]
    )
    for key, value in sorted(labels.items()):
        argv.extend(["--label", f"{key}={_label_value(value)}"])
    for mount in mounts:
        if "\x00" in mount or "\n" in mount or "\r" in mount or ",target=/var/run" in mount:
            raise LiveStudyEgressError("Unsafe Docker mount field.")
        argv.extend(["--mount", mount])
    for key, value in sorted(environment.items()):
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", key):
            raise LiveStudyEgressError("Unsafe Docker environment name.")
        if _CONTROL_CHARACTER.search(value) is not None or len(value) > 4096:
            raise LiveStudyEgressError("Unsafe Docker environment value.")
        argv.extend(["--env", f"{key}={value}"])
    argv.extend(["--", image, *command])
    return argv


def _validate_resolution_evidence(
    *,
    host: str,
    rule: EgressDestinationRule,
    resolved_addresses: Optional[list[str]],
    resolution_status: str,
) -> dict[str, object]:
    normalized_status = _sanitize_text(resolution_status).lower()
    if normalized_status != "stable":
        return {"status": "resolution_uncertain", "addresses": []}
    if _is_ip_literal(host):
        try:
            ip = ipaddress.ip_address(_strip_ipv6_brackets(host))
        except ValueError:
            return {"status": "invalid_ip_literal", "addresses": []}
        if not rule.test_only_ip_literal:
            return {"status": "ip_literal_not_approved", "addresses": []}
        if _unsafe_ip(ip, test_only=rule.test_only):
            return {"status": "unsafe_ip_literal", "addresses": [str(ip)]}
        return {"status": "stable", "addresses": [str(ip)]}
    if not resolved_addresses:
        return {"status": "resolution_missing", "addresses": []}
    if not isinstance(resolved_addresses, list) or len(resolved_addresses) > MAX_EGRESS_ADDRESSES:
        return {"status": "resolution_ambiguous", "addresses": []}
    addresses = []
    for value in resolved_addresses:
        try:
            ip = ipaddress.ip_address(_bounded_string(value, "resolved_address"))
        except (ValueError, LiveStudyEgressError):
            return {"status": "resolution_invalid", "addresses": []}
        addresses.append(ip)
    unique = sorted({str(ip) for ip in addresses})
    if len(unique) != 1:
        return {"status": "resolution_ambiguous", "addresses": unique}
    if _unsafe_ip(addresses[0], test_only=rule.test_only):
        return {"status": "resolution_unsafe", "addresses": unique}
    return {"status": "stable", "addresses": unique}


def _decision(
    *,
    event_type: str,
    protocol: str,
    requested_host: str,
    effective_host: str,
    port: Optional[int],
    decision: str,
    reason: str,
    resolved_addresses: list[str],
    resolution_status: str,
    bytes_in: Optional[int] = None,
    bytes_out: Optional[int] = None,
    timestamp_start: Optional[float] = None,
    timestamp_end: Optional[float] = None,
) -> dict[str, object]:
    event = {
        "event_type": _sanitize_text(event_type),
        "protocol": _sanitize_text(protocol),
        "requested": {
            "host": _sanitize_text(requested_host),
            "port": port,
        },
        "effective": {
            "host": _sanitize_text(effective_host),
            "port": port,
        },
        "resolved_addresses": [
            _sanitize_text(address) for address in resolved_addresses[:MAX_EGRESS_ADDRESSES]
        ],
        "resolution_status": _sanitize_text(resolution_status),
        "decision": decision if decision in {"allow", "deny"} else "deny",
        "reason": _sanitize_text(reason),
        "bytes": {
            "in": _optional_bounded_nonnegative_int(bytes_in, "bytes_in"),
            "out": _optional_bounded_nonnegative_int(bytes_out, "bytes_out"),
        },
        "timestamps": {
            "start": _optional_timestamp(timestamp_start),
            "end": _optional_timestamp(timestamp_end),
        },
        "evidence_complete": True,
        "evidence_truncated": False,
    }
    return _sanitize_value(event, depth=0)


def _deny_event(
    *,
    event_type: str,
    protocol: str,
    host: str,
    port: Optional[int],
    reason: str,
) -> dict[str, object]:
    return _decision(
        event_type=event_type,
        protocol=protocol,
        requested_host=host,
        effective_host=host,
        port=port,
        decision="deny",
        reason=reason,
        resolved_addresses=[],
        resolution_status="blocked",
    )


def _matching_rule(
    policy: LiveStudyEgressPolicy,
    host: str,
    port: int,
) -> Optional[EgressDestinationRule]:
    for rule in policy.destinations:
        if _normalize_rule_host(rule) == host and rule.port == port:
            return rule
    return None


def _validate_rule_host(rule: EgressDestinationRule) -> None:
    host = _normalize_rule_host(rule)
    if "*" in host:
        raise LiveStudyEgressError("Wildcards are not allowed in egress destinations.")
    ip = _ip_literal_or_none(host)
    if ip is not None:
        if not rule.test_only_ip_literal:
            raise LiveStudyEgressError("IP literals require a test-only reviewed rule.")
        if not rule.test_only:
            raise LiveStudyEgressError("IP literal exceptions must be test-only.")
        if _unsafe_ip(ip, test_only=rule.test_only):
            raise LiveStudyEgressError("Unsafe IP literals are not allowed.")


def _normalize_rule_host(rule: EgressDestinationRule) -> str:
    return _normalize_destination_host(rule.host)


def _normalize_destination_host(host: object) -> str:
    text = _bounded_string(host, "host").strip().lower()
    if text.endswith("."):
        raise LiveStudyEgressError("Destination host must be exact and unqualified.")
    if any(character in text for character in "/*?=&#@[] "):
        if not (text.startswith("[") and text.endswith("]")):
            raise LiveStudyEgressError("Destination host contains unsupported characters.")
    if text in _DANGEROUS_HOSTS or any(
        text.endswith(suffix) for suffix in _DANGEROUS_HOST_SUFFIXES
    ):
        raise LiveStudyEgressError("Docker-internal, metadata, or host-gateway names are blocked.")
    ip = _ip_literal_or_none(text)
    if ip is not None:
        return str(ip)
    labels = text.split(".")
    if len(labels) < 2 or any(_HOST_LABEL.fullmatch(label) is None for label in labels):
        raise LiveStudyEgressError("Destination host must be an exact approved hostname.")
    return text


def _ip_literal_or_none(host: str) -> Optional[ipaddress._BaseAddress]:
    try:
        return ipaddress.ip_address(_strip_ipv6_brackets(host))
    except ValueError:
        return None


def _is_ip_literal(host: str) -> bool:
    return _ip_literal_or_none(host) is not None


def _strip_ipv6_brackets(value: str) -> str:
    if value.startswith("[") and value.endswith("]"):
        return value[1:-1]
    return value


def _unsafe_ip(ip: ipaddress._BaseAddress, *, test_only: bool) -> bool:
    if test_only and any(ip in network for network in _DOCUMENTATION_NETWORKS):
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or not ip.is_global
    )


def _split_authority(authority: str) -> tuple[str, int]:
    value = _bounded_string(authority, "authority")
    if _CONTROL_CHARACTER.search(value) is not None or len(value) > MAX_EGRESS_HEADER_VALUE:
        raise LiveStudyEgressError("CONNECT authority is malformed.")
    if value.startswith("["):
        end = value.find("]")
        if end <= 0 or end + 2 > len(value) or value[end + 1] != ":":
            raise LiveStudyEgressError("CONNECT IPv6 authority is malformed.")
        host = value[: end + 1]
        port_text = value[end + 2 :]
    else:
        if value.count(":") != 1:
            raise LiveStudyEgressError("CONNECT authority must be host:port.")
        host, port_text = value.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        raise LiveStudyEgressError("CONNECT authority port is invalid.") from None
    return host, _port(port, "port")


def _gateway_image_identity(
    image: Optional[DockerImageIdentity | dict[str, object]],
) -> Optional[dict[str, object]]:
    if image is None:
        return None
    if isinstance(image, dict):
        return _sanitize_value(image, depth=0)  # type: ignore[return-value]
    return {
        "configured_reference": image.configured_reference,
        "local_image_id": image.local_image_id,
        "executed_image_id": image.executed_image_id,
        "registry_digest": image.registry_digest,
        "platform": image.platform,
        "pull_policy": image.pull_policy,
        "cache_status": image.cache_status,
    }


def parse_gateway_image_identity(value: object) -> DockerImageIdentity:
    return parse_docker_image_identity(value)


def _validate_execution_image(
    image: str,
    *,
    allow_local_image_id: bool,
    label: str,
) -> None:
    if _is_local_image_id(image):
        if allow_local_image_id:
            return
        raise LiveStudyEgressError(f"{label} must be digest-pinned.")
    try:
        validate_docker_image_reference(image)
    except ValueError as error:
        raise LiveStudyEgressError(str(error)) from None
    if "@sha256:" not in image:
        raise LiveStudyEgressError(f"{label} must be digest-pinned.")


def _is_local_image_id(image: object) -> bool:
    return isinstance(image, str) and IMAGE_ID_PATTERN.fullmatch(image) is not None


def _image_id(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    return text if IMAGE_ID_PATTERN.fullmatch(text) is not None else None


def _docker_network_aliases(aliases: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    seen: set[str] = set()
    for alias in aliases:
        host = _normalize_destination_host(alias)
        if _is_ip_literal(host):
            raise LiveStudyEgressError("Docker outbound aliases must be hostnames.")
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    return tuple(sorted(normalized))


def _single_policy_destination(
    policy: LiveStudyEgressPolicy,
) -> tuple[Optional[str], Optional[int]]:
    if len(policy.destinations) != 1:
        return None, None
    rule = policy.destinations[0]
    return _normalize_rule_host(rule), rule.port


def _combined_gateway_status(
    *,
    docker_result: dict[str, object],
    gateway_evidence: dict[str, object],
) -> dict[str, object]:
    failure_step = docker_result.get("failure_step")
    evidence_status = gateway_evidence.get("status")
    raw_gateway_status = gateway_evidence.get("gateway_status")
    gateway_status = raw_gateway_status if isinstance(raw_gateway_status, dict) else {}
    evidence_complete = (
        evidence_status == "recorded"
        and gateway_status.get("evidence_complete") is True
    )
    liveness_established = docker_result.get("gateway_liveness_verified") is True
    gateway_failure_steps = {
        "start_gateway",
        "inspect_gateway",
        "gateway_liveness",
    }
    if failure_step in gateway_failure_steps:
        return {
            "status": "crashed",
            "crashed": True,
            "evidence_complete": evidence_complete,
            "reason": "gateway crashed or failed liveness",
        }
    status = "running" if liveness_established else str(gateway_status.get("status") or "unknown")
    result = {
        "status": status,
        "crashed": gateway_status.get("crashed") is True,
        "evidence_complete": evidence_complete,
    }
    reason = gateway_status.get("reason")
    if isinstance(reason, str) and reason:
        result["reason"] = _sanitize_text(reason)
    if evidence_status != "recorded":
        result["reason"] = _sanitize_text(
            str(gateway_status.get("reason") or "gateway evidence incomplete")
        )
    return result


def _cleanup_status_from_docker_result(docker_result: dict[str, object]) -> dict[str, object]:
    cleanup = docker_result.get("cleanup")
    if isinstance(cleanup, dict):
        return _sanitize_value(cleanup, depth=0)  # type: ignore[return-value]
    return {
        "overall_complete": False,
        "reason": "cleanup evidence missing",
    }


def _liveness_status_from_docker_result(docker_result: dict[str, object]) -> dict[str, object]:
    cleanup = docker_result.get("cleanup")
    verified = isinstance(cleanup, dict) and cleanup.get("liveness_verified") is True
    return {
        "verified": verified,
        "reason": None if verified else "post-cleanup liveness verification failed",
    }


def _completion(status: str, reason: Optional[str]) -> dict[str, object]:
    return {
        "status": status,
        "reason": reason,
        "success_eligible": status == "complete",
    }


def _docker_step_evidence(result: DockerControlResult) -> dict[str, object]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "stdout": _sanitize_text(result.stdout),
        "stderr": _sanitize_text(result.stderr),
    }


def _gateway_inspect_running(stdout: str) -> bool:
    try:
        payload = json.loads(limit_output(stdout, MAX_EGRESS_SERIALIZED_BYTES).text)
    except (json.JSONDecodeError, TypeError):
        return False
    if isinstance(payload, list) and len(payload) == 1:
        payload = payload[0]
    if not isinstance(payload, dict):
        return False
    state = payload.get("State")
    return isinstance(state, dict) and state.get("Running") is True


def _run_docker_control(argv: list[str], timeout_seconds: int) -> DockerControlResult:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        return DockerControlResult(
            argv=argv,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            timed_out=False,
        )
    except subprocess.TimeoutExpired as error:
        return DockerControlResult(
            argv=argv,
            returncode=124,
            stdout=error.stdout or "",
            stderr=error.stderr or "",
            timed_out=True,
        )
    except OSError as error:
        return DockerControlResult(
            argv=argv,
            returncode=125,
            stderr=error.__class__.__name__,
            timed_out=False,
        )
    finally:
        _ = time.monotonic() - started


def _sanitize_value(value: object, *, depth: int) -> object:
    if depth > MAX_EGRESS_NESTING:
        raise LiveStudyEgressError("Live-study egress evidence nesting limit exceeded.")
    if is_dataclass(value) and not isinstance(value, type):
        return _sanitize_value(asdict(value), depth=depth)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > MAX_EGRESS_BYTES:
            raise LiveStudyEgressError("Live-study egress integer bound exceeded.")
        return value
    if isinstance(value, float):
        if value < 0 or value > MAX_EGRESS_BYTES:
            raise LiveStudyEgressError("Live-study egress number bound exceeded.")
        return round(value, 6)
    if isinstance(value, str):
        return _sanitize_text(value)
    if isinstance(value, Path):
        return _sanitize_text(str(value))
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_EGRESS_LIST_ITEMS:
            raise LiveStudyEgressError("Live-study egress list bound exceeded.")
        return [_sanitize_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_EGRESS_OBJECT_ITEMS:
            raise LiveStudyEgressError("Live-study egress object bound exceeded.")
        sanitized = {}
        for key, item in sorted(value.items(), key=lambda entry: str(entry[0])):
            if not isinstance(key, str) or not key:
                raise LiveStudyEgressError("Live-study egress evidence keys must be strings.")
            sanitized[_sanitize_text(key)] = _sanitize_value(item, depth=depth + 1)
        return sanitized
    return _sanitize_text(str(value))


def _sanitize_text(value: object) -> str:
    text = redact_credentials("" if value is None else str(value))
    text = _CONTROL_CHARACTER.sub("", text)
    text = _URL_QUERY.sub(r"\g<prefix>", text)
    text = _BARE_QUERY.sub("[REDACTED_QUERY]", text)
    text = _PRIVATE_PATH.sub("[REDACTED_PATH]", text)
    return limit_output(text, MAX_EGRESS_STRING).text


def _bounded_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_EGRESS_HOST_LENGTH:
        raise LiveStudyEgressError(f"Live-study egress field {label} is invalid.")
    if _CONTROL_CHARACTER.search(value) is not None:
        raise LiveStudyEgressError(f"Live-study egress field {label} has control characters.")
    return value


def _sha256_string(value: object, label: str) -> str:
    text = _bounded_string(value, label)
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise LiveStudyEgressError(f"Live-study egress field {label} must be sha256.")
    return text


def _port(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > 65535:
        raise LiveStudyEgressError(f"Live-study egress field {label} must be a port.")
    return value


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise LiveStudyEgressError(f"Live-study egress field {label} must be boolean.")
    return value


def _optional_bounded_nonnegative_int(value: Optional[int], label: str) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > MAX_EGRESS_BYTES:
        raise LiveStudyEgressError(f"Live-study egress field {label} is out of bounds.")
    return value


def _optional_timestamp(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise LiveStudyEgressError("Live-study egress timestamp is invalid.")
    return round(float(value), 6)


def _stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _non_root(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 2147483647:
        raise LiveStudyEgressError(f"Docker {label} must be a non-root integer.")


def _bounded_positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > 4096:
        raise LiveStudyEgressError(f"Docker {label} is outside bounds.")
    return value


def _bounded_size(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]*[kKmMgG]?", value) is None:
        raise LiveStudyEgressError(f"Docker {label} must be a Docker size.")
    return value


def _format_cpu(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LiveStudyEgressError("Docker cpu limit is invalid.")
    number = float(value)
    if number < 0.1 or number > 8.0:
        raise LiveStudyEgressError("Docker cpu limit is outside bounds.")
    return ("%f" % number).rstrip("0").rstrip(".")


def _validate_network_name(name: str) -> None:
    if _SAFE_NETWORK_NAME.fullmatch(name) is None or len(name) > MAX_DOCKER_NAME:
        raise LiveStudyEgressError("Unsafe live-study egress Docker network name.")


def _validate_container_name(name: str) -> None:
    if _SAFE_DOCKER_NAME.fullmatch(name) is None or len(name) > MAX_DOCKER_NAME:
        raise LiveStudyEgressError("Unsafe live-study egress Docker container name.")


def _label_value(value: str) -> str:
    text = _sanitize_text(value)
    if not text or any(character in text for character in "\n\r,"):
        raise LiveStudyEgressError("Unsafe Docker label value.")
    return text


def _option_values(argv: list[str], option: str) -> list[str]:
    values = []
    for index, value in enumerate(argv[:-1]):
        if value == option:
            values.append(argv[index + 1])
    return values
