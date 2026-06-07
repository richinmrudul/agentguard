from pathlib import PurePosixPath


def display_project_path(path: str) -> str:
    """Return a normalized project-relative path for display."""
    return PurePosixPath(path).as_posix()
