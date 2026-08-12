import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agentguard.policy.path_matcher import matches_path, normalize_posix_path


INTERNAL_ARTIFACT_PATTERNS = [
    ".agentguard_agent_events.jsonl",
    ".agentguard/**",
    ".pytest_cache/**",
    "**/__pycache__/**",
    "**/*.pyc",
    ".ruff_cache/**",
    ".DS_Store",
]


@dataclass
class OwnedArtifact:
    """Identity of an artifact created by AgentGuard for the current run."""

    path: str
    device: int
    inode: int
    descriptor: int

    def close(self) -> None:
        descriptor = self.descriptor
        self.descriptor = -1
        if descriptor < 0:
            return
        try:
            os.close(descriptor)
        except OSError:
            pass

    def __del__(self) -> None:
        self.close()


def adopt_owned_artifact(
    repo_dir: Path,
    relative_path: str,
    descriptor: int,
) -> Optional[OwnedArtifact]:
    """Adopt an already-open validated file as a run-owned artifact."""
    normalized = normalize_posix_path(relative_path)
    path_parts = Path(relative_path).parts
    if (
        normalized != relative_path
        or normalized in {"", "."}
        or "\\" in relative_path
        or Path(relative_path).is_absolute()
        or any(part in {"", ".", ".."} for part in path_parts)
    ):
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise ValueError("Owned artifact path must be a normalized relative path.")

    artifact_path = repo_dir / relative_path
    try:
        opened = os.fstat(descriptor)
        current = artifact_path.lstat()
    except OSError:
        opened = None
        current = None
    if (
        opened is None
        or current is None
        or not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(current.st_mode)
        or opened.st_nlink != 1
        or current.st_nlink != 1
        or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
    ):
        try:
            os.close(descriptor)
        except OSError:
            pass
        return None
    return OwnedArtifact(
        path=relative_path,
        device=opened.st_dev,
        inode=opened.st_ino,
        descriptor=descriptor,
    )


def verified_owned_paths(
    repo_dir: Path,
    owned_artifacts: tuple[OwnedArtifact, ...],
) -> set[str]:
    """Return run-owned paths whose original regular-file identity still exists."""
    verified: set[str] = set()
    for artifact in owned_artifacts:
        path = repo_dir / artifact.path
        try:
            opened = os.fstat(artifact.descriptor)
            current = path.lstat()
        except OSError:
            continue
        opened_identity = (opened.st_dev, opened.st_ino)
        current_identity = (current.st_dev, current.st_ino)
        expected_identity = (artifact.device, artifact.inode)
        if stat.S_ISREG(opened.st_mode) and stat.S_ISREG(current.st_mode):
            if (
                opened.st_nlink == 1
                and current.st_nlink == 1
                and opened_identity == expected_identity
                and current_identity == expected_identity
            ):
                verified.add(artifact.path)
    return verified


def is_internal_artifact(path: str) -> bool:
    normalized = normalize_posix_path(path)
    return any(
        matches_path(normalized, pattern)
        or (
            pattern.startswith("**/")
            and matches_path(normalized, pattern.removeprefix("**/"))
        )
        for pattern in INTERNAL_ARTIFACT_PATTERNS
    )
