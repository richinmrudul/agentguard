from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from agentguard.artifact_paths import validate_artifact_id
from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.config.loader import (
    CONTAINED_ENVIRONMENT_NAME,
    MAX_CONTAINED_ENVIRONMENT_NAME_LENGTH,
    _contained_cpu_limit,
    _contained_limit_string,
    _contained_pids_limit,
)
from agentguard.config.yaml import load_yaml, reject_unknown_keys
from agentguard.redaction import SECRET_KEY_PATTERN


CONTAINED_PROFILE_SCHEMA = "agentguard.contained-agent-profile"
CONTAINED_PROFILE_SCHEMA_VERSION = 1
MAX_PROFILE_ARGV_ITEMS = 64
MAX_PROFILE_STRING_LENGTH = 2048
MAX_PROFILE_TOTAL_SERIALIZED_BYTES = 32768
MAX_PROFILE_ENVIRONMENT_NAMES = 32
MAX_PROFILE_CAPABILITIES = 32
MAX_PROFILE_METADATA_ITEMS = 32
MAX_PROFILE_TIMEOUT_SECONDS = 86400
MIN_PROFILE_OUTPUT_BYTES = 1024
MAX_PROFILE_OUTPUT_BYTES = 50 * 1024 * 1024
VALID_PROFILE_NETWORKS = {"bridge", "none"}
PROFILE_UNSAFE_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
PROFILE_CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
PROFILE_SECRET_VALUE = re.compile(
    r"(?:"
    r"sk-[A-Za-z0-9_-]{8,}|"
    r"gh[pousr]_[A-Za-z0-9_]{8,}|"
    r"xox[baprs]-[A-Za-z0-9-]{8,}|"
    r"Bearer\s+\S+|"
    r"AKIA[0-9A-Z]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)
PROFILE_ALLOWED_TOP_LEVEL_KEYS = {
    "argv",
    "capabilities",
    "display_label",
    "environment",
    "identity",
    "image",
    "limits",
    "metadata",
    "network",
    "schema",
    "schema_version",
    "id",
}
PROFILE_ENVIRONMENT_KEYS = {"required", "unset"}
PROFILE_LIMIT_KEYS = {
    "cpu_limit",
    "max_output_bytes",
    "memory_limit",
    "pids_limit",
    "timeout_seconds",
}
PROFILE_IDENTITY_KEYS = {"agent_name", "agent_version", "evidence_source"}
PROFILE_METADATA_KEYS = {"max_cost_usd", "max_input_tokens", "max_output_tokens"}


@dataclass(frozen=True)
class ContainedProfileEnvironment:
    required: list[str] = field(default_factory=list)
    unset: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ContainedProfileLimits:
    timeout_seconds: int = 60
    cpu_limit: float = 1.0
    memory_limit: str = "512m"
    pids_limit: int = 256
    max_output_bytes: int = 200000


@dataclass(frozen=True)
class ContainedProfileIdentity:
    agent_name: Optional[str] = None
    agent_version: Optional[str] = None
    evidence_source: str = "profile-declared"


@dataclass(frozen=True)
class ContainedProfileMetadata:
    max_cost_usd: Optional[float] = None
    max_input_tokens: Optional[int] = None
    max_output_tokens: Optional[int] = None


@dataclass(frozen=True)
class ContainedAgentProfile:
    id: str
    display_label: str
    image: str
    argv: list[str]
    profile_path: Path
    environment: ContainedProfileEnvironment = field(
        default_factory=ContainedProfileEnvironment
    )
    network: str = "none"
    limits: ContainedProfileLimits = field(default_factory=ContainedProfileLimits)
    capabilities: list[str] = field(default_factory=list)
    identity: ContainedProfileIdentity = field(default_factory=ContainedProfileIdentity)
    metadata: ContainedProfileMetadata = field(default_factory=ContainedProfileMetadata)
    schema: str = CONTAINED_PROFILE_SCHEMA
    schema_version: int = CONTAINED_PROFILE_SCHEMA_VERSION


def load_contained_agent_profile(path: Path) -> ContainedAgentProfile:
    profile_path = path.expanduser().resolve()
    with profile_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}
    if not isinstance(data, dict):
        raise ValueError("Contained agent profile must be a YAML mapping.")
    reject_unknown_keys(data, PROFILE_ALLOWED_TOP_LEVEL_KEYS)
    if data.get("schema") != CONTAINED_PROFILE_SCHEMA:
        raise ValueError("Invalid contained agent profile schema.")
    if data.get("schema_version") != CONTAINED_PROFILE_SCHEMA_VERSION:
        raise ValueError("Unsupported contained agent profile schema version.")
    profile_id = validate_artifact_id(
        _required_string(data, "id", "Contained agent profile"),
        "Contained agent profile id",
    )
    display_label = _bounded_string(
        data.get("display_label"),
        "display_label",
        allow_empty=False,
    )
    image = _load_image(data)
    environment = _load_environment(data)
    argv = _load_argv(data, environment)
    network = _load_network(data)
    limits = _load_limits(data)
    capabilities = _load_capabilities(data)
    identity = _load_identity(data)
    metadata = _load_metadata(data)
    profile = ContainedAgentProfile(
        id=profile_id,
        display_label=display_label,
        image=image,
        argv=argv,
        environment=environment,
        network=network,
        limits=limits,
        capabilities=capabilities,
        identity=identity,
        metadata=metadata,
        profile_path=profile_path,
    )
    _validate_serialized_size(profile)
    return profile


def contained_agent_profile_to_dict(profile: ContainedAgentProfile) -> dict[str, object]:
    data: dict[str, object] = {
        "argv": list(profile.argv),
        "capabilities": list(profile.capabilities),
        "display_label": profile.display_label,
        "environment": {
            "required": list(profile.environment.required),
            "unset": list(profile.environment.unset),
        },
        "id": profile.id,
        "identity": {
            "agent_name": profile.identity.agent_name,
            "agent_version": profile.identity.agent_version,
            "evidence_source": profile.identity.evidence_source,
        },
        "image": profile.image,
        "limits": {
            "cpu_limit": profile.limits.cpu_limit,
            "max_output_bytes": profile.limits.max_output_bytes,
            "memory_limit": profile.limits.memory_limit,
            "pids_limit": profile.limits.pids_limit,
            "timeout_seconds": profile.limits.timeout_seconds,
        },
        "metadata": {
            "max_cost_usd": profile.metadata.max_cost_usd,
            "max_input_tokens": profile.metadata.max_input_tokens,
            "max_output_tokens": profile.metadata.max_output_tokens,
        },
        "network": profile.network,
        "schema": profile.schema,
        "schema_version": profile.schema_version,
    }
    return data


def serialize_contained_agent_profile(profile: ContainedAgentProfile) -> str:
    return _canonical_json(contained_agent_profile_to_dict(profile))


def contained_agent_profile_diagnostics(profile: ContainedAgentProfile) -> dict[str, object]:
    return {
        "argv_sha256": _stable_sha256(profile.argv),
        "capabilities": list(profile.capabilities),
        "display_label": profile.display_label,
        "environment": {
            "required": list(profile.environment.required),
            "unset": list(profile.environment.unset),
            "values_recorded": False,
        },
        "id": profile.id,
        "image": profile.image,
        "limits": {
            "cpu_limit": profile.limits.cpu_limit,
            "max_output_bytes": profile.limits.max_output_bytes,
            "memory_limit": profile.limits.memory_limit,
            "pids_limit": profile.limits.pids_limit,
            "timeout_seconds": profile.limits.timeout_seconds,
        },
        "network": profile.network,
        "schema": profile.schema,
        "schema_version": profile.schema_version,
    }


def _required_string(data: dict[str, Any], key: str, owner: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{owner} field '{key}' must be a non-empty string.")
    return _bounded_string(value, key, allow_empty=False)


def _bounded_string(value: object, label: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Contained agent profile field '{label}' must be a string.")
    if not allow_empty and not value.strip():
        raise ValueError(
            f"Contained agent profile field '{label}' must be a non-empty string."
        )
    if len(value) > MAX_PROFILE_STRING_LENGTH:
        raise ValueError(f"Contained agent profile field '{label}' is too long.")
    if PROFILE_UNSAFE_CONTROL.search(value) is not None:
        raise ValueError(
            f"Contained agent profile field '{label}' must not contain control "
            "characters."
        )
    if PROFILE_SECRET_VALUE.search(value) is not None:
        raise ValueError(
            f"Contained agent profile field '{label}' appears to contain a secret value."
        )
    return value


def _load_image(data: dict[str, Any]) -> str:
    image = _required_string(data, "image", "Contained agent profile")
    try:
        validate_docker_image_reference(image)
    except ValueError as error:
        raise ValueError(str(error).replace("sandbox.image", "image")) from error
    if "@sha256:" not in image:
        raise ValueError(
            "Contained agent profile image must use an immutable @sha256 digest."
        )
    return image


def _load_environment(data: dict[str, Any]) -> ContainedProfileEnvironment:
    raw_environment = data.get("environment", {})
    if raw_environment is None:
        raw_environment = {}
    if not isinstance(raw_environment, dict):
        raise ValueError("Contained agent profile field 'environment' must be an object.")
    reject_unknown_keys(raw_environment, PROFILE_ENVIRONMENT_KEYS, "environment")
    required = _environment_name_list(raw_environment, "required")
    unset = _environment_name_list(raw_environment, "unset")
    overlap = sorted(set(required) & set(unset))
    if overlap:
        raise ValueError(
            "Contained agent profile environment names cannot be both required "
            "and unset: "
            + ", ".join(overlap)
        )
    return ContainedProfileEnvironment(required=required, unset=unset)


def _environment_name_list(mapping: dict[str, Any], key: str) -> list[str]:
    value = mapping.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"Contained agent profile environment.{key} must be a list.")
    if len(value) > MAX_PROFILE_ENVIRONMENT_NAMES:
        raise ValueError(
            f"Contained agent profile environment.{key} exceeds the maximum "
            f"of {MAX_PROFILE_ENVIRONMENT_NAMES} names."
        )
    names = [
        _environment_name(item, f"environment.{key}[{index}]")
        for index, item in enumerate(value)
    ]
    if len(set(names)) != len(names):
        raise ValueError(
            f"Contained agent profile environment.{key} contains duplicate names."
        )
    return sorted(names)


def _environment_name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Contained agent profile {label} must be a non-empty string.")
    if len(value) > MAX_CONTAINED_ENVIRONMENT_NAME_LENGTH:
        raise ValueError(f"Contained agent profile {label} is too long.")
    if PROFILE_UNSAFE_CONTROL.search(value) is not None:
        raise ValueError(f"Contained agent profile {label} has a control character.")
    if CONTAINED_ENVIRONMENT_NAME.fullmatch(value) is None:
        raise ValueError(
            f"Contained agent profile {label} must use uppercase letters, digits, "
            "and underscores, and must not start with a digit."
        )
    return value


def _load_argv(
    data: dict[str, Any],
    environment: ContainedProfileEnvironment,
) -> list[str]:
    raw_argv = data.get("argv")
    if not isinstance(raw_argv, list) or not raw_argv:
        raise ValueError("Contained agent profile field 'argv' must be a non-empty list.")
    if len(raw_argv) > MAX_PROFILE_ARGV_ITEMS:
        raise ValueError(
            f"Contained agent profile argv exceeds the maximum of {MAX_PROFILE_ARGV_ITEMS}."
        )
    argv = [
        _bounded_string(item, f"argv[{index}]", allow_empty=False)
        for index, item in enumerate(raw_argv)
    ]
    if any(item in {"sh", "bash", "/bin/sh", "/bin/bash", "zsh", "/bin/zsh"} for item in argv):
        raise ValueError("Contained agent profile argv must not invoke a shell.")
    shell_joined = " ".join(argv)
    if any(marker in shell_joined for marker in ("&&", "||", ";", "$(", "`", "|", ">")):
        raise ValueError(
            "Contained agent profile argv must be structured tokens, not a shell command."
        )
    _reject_inline_secrets(argv, environment.required)
    return argv


def _reject_inline_secrets(argv: list[str], required_environment: list[str]) -> None:
    allowed_env_names = set(required_environment)
    for index, item in enumerate(argv):
        lower = item.lower()
        if "://" in item and re.match(r"^[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", item, re.I):
            raise ValueError("Contained agent profile argv must not contain URL credentials.")
        if PROFILE_SECRET_VALUE.search(item) is not None:
            raise ValueError("Contained agent profile argv appears to contain a secret value.")
        if "=" in item:
            key, value = item.split("=", 1)
            if SECRET_KEY_PATTERN.search(key) and value and value not in allowed_env_names:
                raise ValueError(
                    "Contained agent profile argv must not contain inline credential values."
                )
        if SECRET_KEY_PATTERN.search(lower.lstrip("-")) and index + 1 < len(argv):
            next_item = argv[index + 1]
            if next_item not in allowed_env_names and not next_item.startswith("--"):
                raise ValueError(
                    "Contained agent profile argv must pass credential values by "
                    "approved environment name only."
                )


def _load_network(data: dict[str, Any]) -> str:
    network = data.get("network", "none")
    if not isinstance(network, str):
        raise ValueError("Contained agent profile field 'network' must be a string.")
    if network == "host":
        raise ValueError("Contained agent profile network must not be host.")
    if network not in VALID_PROFILE_NETWORKS:
        valid = ", ".join(sorted(VALID_PROFILE_NETWORKS))
        raise ValueError(f"Contained agent profile network must be one of: {valid}.")
    return network


def _load_limits(data: dict[str, Any]) -> ContainedProfileLimits:
    raw_limits = data.get("limits", {})
    if raw_limits is None:
        raw_limits = {}
    if not isinstance(raw_limits, dict):
        raise ValueError("Contained agent profile field 'limits' must be an object.")
    reject_unknown_keys(raw_limits, PROFILE_LIMIT_KEYS, "limits")
    timeout = _positive_int(raw_limits, "timeout_seconds", 60, MAX_PROFILE_TIMEOUT_SECONDS)
    max_output = _positive_int(
        raw_limits,
        "max_output_bytes",
        200000,
        MAX_PROFILE_OUTPUT_BYTES,
        minimum=MIN_PROFILE_OUTPUT_BYTES,
    )
    return ContainedProfileLimits(
        timeout_seconds=timeout,
        cpu_limit=_contained_cpu_limit(raw_limits),
        memory_limit=_contained_limit_string(raw_limits, "memory_limit", "512m"),
        pids_limit=_contained_pids_limit(raw_limits),
        max_output_bytes=max_output,
    )


def _positive_int(
    mapping: dict[str, Any],
    key: str,
    default: int,
    maximum: int,
    *,
    minimum: int = 1,
) -> int:
    value = mapping.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or value > maximum:
        raise ValueError(
            f"Contained agent profile limits.{key} must be an integer from "
            f"{minimum} to {maximum}."
        )
    return value


def _load_capabilities(data: dict[str, Any]) -> list[str]:
    raw_capabilities = data.get("capabilities", [])
    if not isinstance(raw_capabilities, list):
        raise ValueError("Contained agent profile field 'capabilities' must be a list.")
    if len(raw_capabilities) > MAX_PROFILE_CAPABILITIES:
        raise ValueError(
            f"Contained agent profile capabilities exceed {MAX_PROFILE_CAPABILITIES}."
        )
    capabilities: list[str] = []
    for index, raw_capability in enumerate(raw_capabilities):
        capability = _bounded_string(
            raw_capability,
            f"capabilities[{index}]",
            allow_empty=False,
        )
        if PROFILE_CAPABILITY.fullmatch(capability) is None:
            raise ValueError(
                "Contained agent profile capabilities must be lowercase portable identifiers."
            )
        capabilities.append(capability)
    if len(set(capabilities)) != len(capabilities):
        raise ValueError("Contained agent profile capabilities must be unique.")
    return sorted(capabilities)


def _load_identity(data: dict[str, Any]) -> ContainedProfileIdentity:
    raw_identity = data.get("identity", {})
    if raw_identity is None:
        raw_identity = {}
    if not isinstance(raw_identity, dict):
        raise ValueError("Contained agent profile field 'identity' must be an object.")
    reject_unknown_keys(raw_identity, PROFILE_IDENTITY_KEYS, "identity")
    evidence_source = _bounded_string(
        raw_identity.get("evidence_source", "profile-declared"),
        "identity.evidence_source",
        allow_empty=False,
    )
    if evidence_source not in {"profile-declared", "image-digest"}:
        raise ValueError(
            "Contained agent profile identity.evidence_source must be "
            "profile-declared or image-digest."
        )
    return ContainedProfileIdentity(
        agent_name=_optional_bounded_string(raw_identity, "agent_name"),
        agent_version=_optional_bounded_string(raw_identity, "agent_version"),
        evidence_source=evidence_source,
    )


def _optional_bounded_string(mapping: dict[str, Any], key: str) -> Optional[str]:
    value = mapping.get(key)
    if value is None:
        return None
    return _bounded_string(value, f"identity.{key}", allow_empty=False)


def _load_metadata(data: dict[str, Any]) -> ContainedProfileMetadata:
    raw_metadata = data.get("metadata", {})
    if raw_metadata is None:
        raw_metadata = {}
    if not isinstance(raw_metadata, dict):
        raise ValueError("Contained agent profile field 'metadata' must be an object.")
    reject_unknown_keys(raw_metadata, PROFILE_METADATA_KEYS, "metadata")
    if len(raw_metadata) > MAX_PROFILE_METADATA_ITEMS:
        raise ValueError("Contained agent profile metadata has too many entries.")
    return ContainedProfileMetadata(
        max_cost_usd=_optional_float(raw_metadata, "max_cost_usd", maximum=1000.0),
        max_input_tokens=_optional_positive_int(raw_metadata, "max_input_tokens"),
        max_output_tokens=_optional_positive_int(raw_metadata, "max_output_tokens"),
    )


def _optional_float(
    mapping: dict[str, Any],
    key: str,
    *,
    maximum: float,
) -> Optional[float]:
    value = mapping.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Contained agent profile metadata.{key} must be a number.")
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > maximum:
        raise ValueError(
            f"Contained agent profile metadata.{key} must be between 0 and {maximum:g}."
        )
    return number


def _optional_positive_int(mapping: dict[str, Any], key: str) -> Optional[int]:
    value = mapping.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 10_000_000:
        raise ValueError(
            f"Contained agent profile metadata.{key} must be an integer from 0 to 10000000."
        )
    return value


def _validate_serialized_size(profile: ContainedAgentProfile) -> None:
    serialized = serialize_contained_agent_profile(profile)
    if len(serialized.encode("utf-8")) > MAX_PROFILE_TOTAL_SERIALIZED_BYTES:
        raise ValueError("Contained agent profile serialized form is too large.")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _stable_sha256(value: object) -> str:
    import hashlib

    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
