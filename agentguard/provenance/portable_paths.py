import re
from pathlib import Path, PurePath, PureWindowsPath
from typing import Any, Mapping, Optional, Union


PathLikeValue = Union[str, PurePath]

PORTABLE_ROOT_ROLES = frozenset(
    {
        "AGENTGUARD_ROOT",
        "CONFIG_ROOT",
        "REPOSITORY_ROOT",
        "RUN_ROOT",
    }
)

_ROLE_ALIASES = {
    "agentguard": "AGENTGUARD_ROOT",
    "agentguard_root": "AGENTGUARD_ROOT",
    "config": "CONFIG_ROOT",
    "config_root": "CONFIG_ROOT",
    "configuration": "CONFIG_ROOT",
    "repository": "REPOSITORY_ROOT",
    "repository_root": "REPOSITORY_ROOT",
    "repo": "REPOSITORY_ROOT",
    "repo_root": "REPOSITORY_ROOT",
    "run": "RUN_ROOT",
    "run_root": "RUN_ROOT",
}

_REFERENCE_TOKEN = re.compile(r"\$\{(?P<role>[A-Z][A-Z0-9_]{0,63})\}")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE_REFERENCE = re.compile(r"^[A-Za-z]:[/\\]")
_PATH_COMPONENT_CHARACTER = re.compile(r"[A-Za-z0-9._-]")
_TEXT_REFERENCE_DELIMITERS = frozenset(".,;!?)]}'\"")


class PortablePathError(ValueError):
    """Controlled error for refused portable path references."""


def portable_reference(
    path: PathLikeValue,
    root: Optional[Union[PathLikeValue, Mapping[str, PathLikeValue]]] = None,
) -> str:
    if root is None:
        return _path_text(path)
    if isinstance(root, Mapping):
        roots = _normalize_roots(root)
    else:
        roots = _normalize_roots({"REPOSITORY_ROOT": root})
    match = _portable_match(path, roots)
    if match is None:
        return _path_text(path)
    role, relative = match
    return f"${{{role}}}" if not relative else f"${{{role}}}/{relative}"


def portable_text(value: str, roots: Mapping[str, PathLikeValue]) -> str:
    portable = value
    normalized_roots = _normalize_roots(roots)
    replacements = []
    for role, root in normalized_roots.items():
        for variant in _root_variants(root.original):
            replacements.append((variant, role))
    replacements.sort(key=lambda item: len(item[0]), reverse=True)
    for variant, role in replacements:
        portable = _replace_root_variant(portable, variant, role)
    return portable


def portable_value(value: Any, roots: Mapping[str, PathLikeValue]) -> Any:
    if isinstance(value, PurePath):
        return portable_reference(value, roots)
    if isinstance(value, str):
        return portable_text(value, roots)
    if isinstance(value, list):
        return [portable_value(item, roots) for item in value]
    if isinstance(value, tuple):
        return [portable_value(item, roots) for item in value]
    if isinstance(value, dict):
        return {
            key: portable_value(item, roots)
            for key, item in sorted(value.items(), key=lambda entry: str(entry[0]))
        }
    return value


def resolve_portable_reference(
    reference: str,
    roots: Mapping[str, PathLikeValue],
) -> PurePath:
    role, parts = _parse_reference(reference)
    normalized_roots = _normalize_roots(roots)
    root = normalized_roots.get(role)
    if root is None:
        raise PortablePathError("Portable reference role is missing from trusted roots.")
    return root.path.joinpath(*parts)


def resolve_portable_text(value: str, roots: Mapping[str, PathLikeValue]) -> str:
    pieces = []
    position = 0
    while True:
        start = value.find("${", position)
        if start < 0:
            pieces.append(value[position:])
            return "".join(pieces)
        pieces.append(value[position:start])
        end = _reference_text_end(value, start)
        pieces.append(str(resolve_portable_reference(value[start:end], roots)))
        position = end


def resolve_portable_value(value: Any, roots: Mapping[str, PathLikeValue]) -> Any:
    if isinstance(value, str):
        _reject_raw_path_reference(value)
        if "${" in value:
            if _is_bare_reference(value):
                return resolve_portable_reference(value, roots)
            return resolve_portable_text(value, roots)
        return value
    if isinstance(value, list):
        return [resolve_portable_value(item, roots) for item in value]
    if isinstance(value, dict):
        return {
            key: resolve_portable_value(item, roots)
            for key, item in value.items()
        }
    return value


def resolve_portable(value: Any, roots: Mapping[str, PathLikeValue]) -> Any:
    return resolve_portable_value(value, roots)


class _Root:
    def __init__(self, original: PathLikeValue) -> None:
        self.original = original
        self.path = _coerce_path(original)
        self.normalized = _normalized_path_text(self.path)


def _canonical_role(role: object) -> str:
    if not isinstance(role, str) or not role:
        raise PortablePathError("Portable root role is malformed.")
    normalized = _ROLE_ALIASES.get(role.lower(), role)
    if normalized not in PORTABLE_ROOT_ROLES:
        raise PortablePathError("Portable root role is not recognized.")
    return normalized


def _normalize_roots(roots: Mapping[str, PathLikeValue]) -> dict[str, _Root]:
    normalized: dict[str, _Root] = {}
    for raw_role, raw_root in roots.items():
        role = _canonical_role(raw_role)
        if role in normalized:
            raise PortablePathError("Trusted portable root roles are ambiguous.")
        root = _Root(raw_root)
        if _is_anchor_only(root.path):
            raise PortablePathError("Portable root must not be a filesystem anchor.")
        normalized[role] = root
    return normalized


def _coerce_path(value: PathLikeValue) -> PurePath:
    if isinstance(value, PurePath):
        return value
    if _looks_windows_path(value):
        return PureWindowsPath(value)
    return Path(value)


def _looks_windows_path(value: str) -> bool:
    return bool(_DRIVE_REFERENCE.match(value) or value.startswith("\\\\") or "\\" in value)


def _is_anchor_only(path: PurePath) -> bool:
    return bool(path.anchor) and tuple(path.parts) == (path.anchor,)


def _path_text(path: PathLikeValue) -> str:
    return str(path)


def _normalized_path_text(path: PurePath) -> str:
    text = path.as_posix() if isinstance(path, PureWindowsPath) else str(path)
    return _strip_trailing_separators(text.replace("\\", "/"))


def _strip_trailing_separators(value: str) -> str:
    if value in {"/", "//"} or re.fullmatch(r"[A-Za-z]:/", value):
        return value
    while len(value) > 1 and value.endswith("/"):
        value = value[:-1]
    return value


def _root_variants(root: PathLikeValue) -> set[str]:
    variants = {_path_text(root)}
    coerced = _coerce_path(root)
    variants.add(coerced.as_posix() if isinstance(coerced, PureWindowsPath) else str(coerced))
    if isinstance(root, Path):
        try:
            variants.add(str(root.expanduser().resolve()))
        except OSError:
            pass
    return {variant for variant in variants if variant}


def _portable_match(
    path: PathLikeValue,
    roots: Mapping[str, _Root],
) -> Optional[tuple[str, str]]:
    normalized = _normalized_path_text(_coerce_path(path))
    matches = []
    for role, root in roots.items():
        if normalized == root.normalized:
            matches.append((role, ""))
        elif normalized.startswith(f"{root.normalized}/"):
            matches.append((role, normalized[len(root.normalized) + 1 :]))
    if not matches:
        return None
    matches.sort(key=lambda item: len(roots[item[0]].normalized), reverse=True)
    return matches[0]


def _replace_root_variant(value: str, variant: str, role: str) -> str:
    output = []
    position = 0
    while True:
        start = value.find(variant, position)
        if start < 0:
            output.append(value[position:])
            return "".join(output)
        end = start + len(variant)
        if not _has_path_boundary(value, start, end):
            output.append(value[position:end])
            position = end
            continue
        output.append(value[position:start])
        output.append(f"${{{role}}}")
        position = end


def _has_path_boundary(value: str, start: int, end: int) -> bool:
    before = value[start - 1] if start > 0 else ""
    after = value[end] if end < len(value) else ""
    if before and _PATH_COMPONENT_CHARACTER.fullmatch(before):
        return False
    return not after or after in {"/", "\\"} or not _PATH_COMPONENT_CHARACTER.fullmatch(after)


def _reference_text_end(value: str, start: int) -> int:
    token = _REFERENCE_TOKEN.match(value, start)
    if token is None:
        raise PortablePathError("Malformed portable reference.")
    role = token.group("role")
    if role not in PORTABLE_ROOT_ROLES:
        raise PortablePathError("Portable reference role is not recognized.")
    suffix_start = token.end()
    if suffix_start >= len(value):
        return suffix_start
    next_character = value[suffix_start]
    if next_character.isspace() or next_character in _TEXT_REFERENCE_DELIMITERS:
        return suffix_start
    if next_character not in {"/", "\\"}:
        raise PortablePathError("Malformed portable reference.")

    end = suffix_start + 1
    while end < len(value) and _is_reference_path_character(value[end]):
        end += 1
    while end > suffix_start and value[end - 1] == ".":
        end -= 1
    if value.startswith("${", end):
        raise PortablePathError("Portable reference is ambiguous.")
    if end < len(value) and not _is_text_reference_delimiter(value[end]):
        raise PortablePathError("Malformed portable reference.")
    return end


def _is_bare_reference(value: str) -> bool:
    token = _REFERENCE_TOKEN.match(value)
    if token is None:
        return False
    return _reference_text_end(value, 0) == len(value)


def _is_reference_path_character(character: str) -> bool:
    return character in {"/", "\\"} or bool(
        _PATH_COMPONENT_CHARACTER.fullmatch(character)
    )


def _is_text_reference_delimiter(character: str) -> bool:
    return character.isspace() or character in _TEXT_REFERENCE_DELIMITERS


def _parse_reference(reference: str) -> tuple[str, tuple[str, ...]]:
    token = _REFERENCE_TOKEN.match(reference)
    if token is None:
        raise PortablePathError("Malformed portable reference.")
    role = token.group("role")
    if role not in PORTABLE_ROOT_ROLES:
        raise PortablePathError("Portable reference role is not recognized.")
    suffix = reference[token.end() :]
    if not suffix:
        return role, ()
    if not suffix.startswith(("/", "\\")):
        raise PortablePathError("Malformed portable reference.")
    return role, _relative_parts(suffix[1:])


def _relative_parts(value: str) -> tuple[str, ...]:
    if not value:
        raise PortablePathError("Malformed portable reference.")
    normalized = value.replace("\\", "/")
    if _CONTROL_CHARACTER.search(normalized):
        raise PortablePathError("Malformed portable reference.")
    if any(character.isspace() for character in normalized):
        raise PortablePathError("Malformed portable reference.")
    if normalized.startswith("/") or _DRIVE_REFERENCE.match(normalized):
        raise PortablePathError("Portable reference must be root-relative.")
    parts = tuple(normalized.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        raise PortablePathError("Portable reference must not traverse directories.")
    if any("${" in part or "}" in part for part in parts):
        raise PortablePathError("Portable reference is ambiguous.")
    if any(":" in part for part in parts):
        raise PortablePathError("Portable reference must not contain drive syntax.")
    return parts


def _reject_raw_path_reference(value: str) -> None:
    if _CONTROL_CHARACTER.search(value):
        raise PortablePathError("Malformed portable reference.")
    if value.startswith(("/", "\\\\")) or _DRIVE_REFERENCE.match(value):
        raise PortablePathError("Portable reference must use a recognized role.")
    if "${" in value:
        return
