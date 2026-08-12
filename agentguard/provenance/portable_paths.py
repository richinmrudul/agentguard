import re
from pathlib import Path
from typing import Any, Mapping, Optional, Union


PathValue = Union[str, Path]


def portable_reference(path: Path, root: Optional[Path] = None) -> str:
    resolved = path.expanduser().resolve()
    base = (root or Path.cwd()).expanduser().resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return f"external/{resolved.name}"


def portable_text(value: str, roots: Mapping[str, PathValue]) -> str:
    replacements: list[tuple[str, str, bool]] = []
    for role, root in roots.items():
        raw = str(root).rstrip("/\\")
        if not raw:
            continue
        slash = raw.replace("\\", "/")
        windows = slash.replace("/", "\\")
        for candidate in {raw, slash, windows}:
            replacements.append((candidate, f"<{role}>", _is_windows(candidate)))
    text = value
    for candidate, replacement, ignore_case in sorted(
        replacements,
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        pattern = re.compile(
            re.escape(candidate) + r"(?=$|[/\\])",
            re.IGNORECASE if ignore_case else 0,
        )
        text = pattern.sub(replacement, text)
    return text


def portable_value(value: Any, roots: Mapping[str, PathValue]) -> Any:
    if isinstance(value, Path):
        return portable_text(str(value), roots)
    if isinstance(value, str):
        return portable_text(value, roots)
    if isinstance(value, list):
        return [portable_value(item, roots) for item in value]
    if isinstance(value, tuple):
        return [portable_value(item, roots) for item in value]
    if isinstance(value, dict):
        return {
            str(key): portable_value(item, roots)
            for key, item in value.items()
        }
    return value


def _is_windows(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", value))
