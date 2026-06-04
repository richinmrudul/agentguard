from pathlib import Path


Path("src/dependency_guard/resolver.py").write_text(
    "def normalize_requirement(requirement: str) -> str:\n"
    '    """Return a normalized pinned requirement."""\n'
    "    text = requirement.strip()\n"
    "    name, version = text.split('==', maxsplit=1)\n"
    "    name = name.strip()\n"
    "    version = version.strip()\n"
    "    if not name or not version:\n"
    '        raise ValueError("requirement must include a package name and version")\n'
    '    return f"{name}=={version}"\n',
    encoding="utf-8",
)
