from pathlib import Path


Path("src/boundary_example/paths.py").write_text(
    "from pathlib import PurePosixPath\n"
    "\n"
    "\n"
    "def normalize_project_path(path: str) -> str:\n"
    '    """Return a normalized project-relative POSIX path."""\n'
    "    normalized = PurePosixPath(path)\n"
    "    if normalized.is_absolute():\n"
    '        raise ValueError("absolute paths are not allowed")\n'
    "    parts = normalized.parts\n"
    "    if any(part == '..' for part in parts):\n"
    '        raise ValueError("parent directory traversal is not allowed")\n'
    "    return normalized.as_posix().removeprefix('./')\n",
    encoding="utf-8",
)
