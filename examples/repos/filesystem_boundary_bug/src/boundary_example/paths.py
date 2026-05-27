from pathlib import PurePosixPath


def normalize_project_path(path: str) -> str:
    """Return a normalized project-relative POSIX path."""
    normalized = PurePosixPath(path)
    return normalized.as_posix()
