def normalize_requirement(requirement: str) -> str:
    """Return a normalized pinned requirement."""
    text = requirement.strip()
    name, version = text.split("==", maxsplit=1)
    if not name or not version:
        raise ValueError("requirement must include a package name and version")
    return f"{name}=={version}"
