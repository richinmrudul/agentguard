from pathlib import Path


Path("src/profile_service/profile.py").write_text(
    "def format_display_name(first_name: str, last_name: str) -> str:\n"
    '    """Return a display name for a user profile."""\n'
    "    first = first_name.strip()\n"
    "    last = last_name.strip()\n"
    "    if not first or not last:\n"
    '        raise ValueError("first_name and last_name are required")\n'
    '    return f"{first.title()} {last.title()}"\n',
    encoding="utf-8",
)
