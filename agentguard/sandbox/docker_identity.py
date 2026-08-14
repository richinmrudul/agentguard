from dataclasses import dataclass
import re
from typing import Optional

from agentguard.config.docker_image import validate_docker_image_reference


IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
REGISTRY_DIGEST_PATTERN = re.compile(
    r"^(?P<repository>[^@]+)"
    r"@sha256:[0-9a-f]{64}$"
)
PLATFORM_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9_.-]*/[a-z0-9][a-z0-9_.-]*(?:/[a-z0-9][a-z0-9_.-]*)?$"
)
IDENTITY_FIELDS = {
    "configured_reference",
    "local_image_id",
    "executed_image_id",
    "registry_digest",
    "platform",
    "pull_policy",
    "cache_status",
}


@dataclass(frozen=True)
class DockerImageIdentity:
    configured_reference: str
    local_image_id: str
    executed_image_id: str
    registry_digest: Optional[str] = None
    platform: Optional[str] = None
    pull_policy: str = "docker-default"
    cache_status: str = "unknown"


def parse_docker_image_identity(value: object) -> DockerImageIdentity:
    if not isinstance(value, dict):
        raise ValueError("Docker image identity must be an object.")
    if set(value) != IDENTITY_FIELDS:
        raise ValueError("Docker image identity fields are invalid.")
    configured = value["configured_reference"]
    local_id = value["local_image_id"]
    executed_id = value["executed_image_id"]
    registry_digest = value["registry_digest"]
    platform = value["platform"]
    pull_policy = value["pull_policy"]
    cache_status = value["cache_status"]
    if (
        not isinstance(configured, str)
        or not configured
        or len(configured) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in configured)
    ):
        raise ValueError("Docker configured image reference is invalid.")
    try:
        validate_docker_image_reference(configured)
    except ValueError:
        raise ValueError("Docker configured image reference is invalid.") from None
    if not isinstance(local_id, str) or not IMAGE_ID_PATTERN.fullmatch(local_id):
        raise ValueError("Docker local image ID is invalid.")
    if not isinstance(executed_id, str) or executed_id != local_id:
        raise ValueError("Docker executed image ID does not match the local image ID.")
    if registry_digest is not None and (
        not isinstance(registry_digest, str)
        or len(registry_digest) > 4096
        or not REGISTRY_DIGEST_PATTERN.fullmatch(registry_digest)
    ):
        raise ValueError("Docker registry digest is invalid.")
    if registry_digest is not None:
        try:
            validate_docker_image_reference(registry_digest)
        except ValueError:
            raise ValueError("Docker registry digest is invalid.") from None
        if select_registry_digest(configured, [registry_digest]) != registry_digest:
            raise ValueError(
                "Docker registry digest does not match the configured repository."
            )
    if platform is not None and (
        not isinstance(platform, str)
        or len(platform) > 128
        or not PLATFORM_PATTERN.fullmatch(platform)
    ):
        raise ValueError("Docker platform is invalid.")
    if pull_policy != "docker-default":
        raise ValueError("Docker pull policy evidence is invalid.")
    if cache_status not in {"present", "not-present", "unknown"}:
        raise ValueError("Docker cache status evidence is invalid.")
    return DockerImageIdentity(
        configured_reference=configured,
        local_image_id=local_id,
        executed_image_id=executed_id,
        registry_digest=registry_digest,
        platform=platform,
        pull_policy=pull_policy,
        cache_status=cache_status,
    )


def select_registry_digest(
    configured_reference: str,
    repo_digests: object,
) -> Optional[str]:
    if not isinstance(repo_digests, list):
        return None
    configured_name, separator, configured_digest = configured_reference.partition("@")
    last_slash = configured_name.rfind("/")
    last_colon = configured_name.rfind(":")
    configured_repository = (
        configured_name[:last_colon]
        if last_colon > last_slash
        else configured_name
    )
    matching = set()
    for candidate in repo_digests:
        if not isinstance(candidate, str):
            continue
        match = REGISTRY_DIGEST_PATTERN.fullmatch(candidate)
        if match is None or match.group("repository") != configured_repository:
            continue
        try:
            validate_docker_image_reference(candidate)
        except ValueError:
            continue
        matching.add(candidate)
    if separator:
        expected = f"{configured_repository}@{configured_digest}"
        return expected if expected in matching else None
    return next(iter(matching)) if len(matching) == 1 else None
