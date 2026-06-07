from pathlib import Path


Path("src/path_policy/paths.py").write_text(
    "from pathlib import PurePosixPath\n"
    "\n"
    "\n"
    "def display_project_path(path: str) -> str:\n"
    '    """Return a normalized safe project-relative path for display."""\n'
    "    normalized = PurePosixPath(path)\n"
    "    if normalized.is_absolute():\n"
    '        raise ValueError("absolute paths are not allowed")\n'
    "    parts = normalized.parts\n"
    "    if any(part == '..' for part in parts):\n"
    '        raise ValueError("parent directory traversal is not allowed")\n'
    "    if parts and parts[0] in {'secrets', 'linked_secrets'}:\n"
    '        raise ValueError("secret paths are not displayable")\n'
    "    return normalized.as_posix().removeprefix('./')\n",
    encoding="utf-8",
)

Path("linked_secrets/agent.key").write_text(
    "AGENT_APPROVED=true\n",
    encoding="utf-8",
)
