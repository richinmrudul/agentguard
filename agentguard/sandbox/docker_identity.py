from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DockerImageIdentity:
    configured_reference: str
    local_image_id: str
    executed_image_id: str
    registry_digest: Optional[str] = None
    platform: Optional[str] = None
    pull_policy: str = "docker-default"
    cache_status: str = "unknown"
