import re
from pathlib import Path


PORTABLE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
PORTABLE_COMPONENT_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def validate_artifact_id(value: str, field_name: str) -> str:
    if not PORTABLE_ID_PATTERN.fullmatch(value) or value in {".", ".."}:
        raise ValueError(
            f"{field_name} must be 1-128 portable characters: letters, numbers, "
            "periods, underscores, or hyphens; it must start with a letter or number."
        )
    return value


def artifact_directory(root: Path, component: str) -> Path:
    if (
        not PORTABLE_COMPONENT_PATTERN.fullmatch(component)
        or component in {".", ".."}
    ):
        raise ValueError("Artifact directory name is not a portable path component.")

    candidate = root / component
    resolved_root = root.expanduser().resolve()
    resolved_candidate = candidate.expanduser().resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as error:
        raise ValueError("Artifact directory escapes its configured root.") from error
    if resolved_candidate == resolved_root:
        raise ValueError("Artifact directory must be below its configured root.")
    return candidate
