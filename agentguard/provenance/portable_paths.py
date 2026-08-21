import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Mapping, Optional, Union


PathValue = Union[str, Path]

_PORTABLE_REFERENCE = re.compile(
    r"<(?P<role>[A-Za-z][A-Za-z0-9_-]*)>"
    r"(?P<suffix>(?:[/\\][^\s<>\"'`,;]*)?)"
)
_MALFORMED_REFERENCE = re.compile(
    r"<[^<>]*>|<[A-Za-z][A-Za-z0-9_-]*(?=$|[/\\])"
)


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


def resolve_portable(value: Any, roots: Mapping[str, PathValue]) -> Any:
    if isinstance(value, Path):
        return _resolve_portable_text(str(value), roots)
    if isinstance(value, str):
        return _resolve_portable_text(value, roots)
    if isinstance(value, list):
        return [resolve_portable(item, roots) for item in value]
    if isinstance(value, tuple):
        return [resolve_portable(item, roots) for item in value]
    if isinstance(value, dict):
        return {
            str(key): resolve_portable(item, roots)
            for key, item in value.items()
        }
    return value


def _resolve_portable_text(value: str, roots: Mapping[str, PathValue]) -> str:
    def replace_reference(match: re.Match) -> str:
        role = match.group("role")
        if role not in roots:
            raise ValueError(f"Unknown portable path role: {role}")
        root = roots[role]
        suffix = match.group("suffix")
        _validate_within_root(root, suffix, role)
        return str(root).rstrip("/\\") + suffix

    resolved = _PORTABLE_REFERENCE.sub(replace_reference, value)
    malformed = _MALFORMED_REFERENCE.search(resolved)
    if malformed is not None:
        raise ValueError(
            f"Malformed portable path reference: {malformed.group(0)}"
        )
    return resolved


def _validate_within_root(root: PathValue, suffix: str, role: str) -> None:
    if not str(root).rstrip("/\\"):
        raise ValueError(f"Trusted portable path root is empty: {role}")
    relative = suffix.lstrip("/\\")
    if isinstance(root, Path):
        base_path = root.expanduser().resolve()
        parts = [part for part in re.split(r"[/\\]+", relative) if part]
        candidate_path = base_path.joinpath(*parts).resolve(strict=False)
        try:
            candidate_path.relative_to(base_path)
        except ValueError as exc:
            raise ValueError(
                f"Portable path reference escapes trusted root: {role}"
            ) from exc
        return
    if _is_windows(str(root)):
        base = PureWindowsPath(str(root))
        candidate = base / PureWindowsPath(relative.replace("/", "\\"))
    else:
        base = PurePosixPath(str(root))
        candidate = base / PurePosixPath(relative.replace("\\", "/"))
    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValueError(
            f"Portable path reference escapes trusted root: {role}"
        ) from exc
    if ".." in candidate.parts[len(base.parts) :]:
        raise ValueError(
            f"Portable path reference escapes trusted root: {role}"
        )


def _is_windows(value: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:[\\/]", value))
