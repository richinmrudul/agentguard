import posixpath
import re
from typing import Any

from agentguard.policy.path_matcher import matches_path


_DRIVE_PATH = re.compile(r"^[A-Za-z]:[\\/]")
_URI_PATH = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_GLOB_CHARS = frozenset("*?[")
_ROOT_WIDE_PATTERNS = {"*", "**", "**/*", "*/**", "**/**"}
_PROTECTED_ROOT_NAMES = {
    ".agentguard",
    ".bzr",
    ".fossil-settings",
    ".git",
    ".hg",
    ".svn",
    "_darcs",
}
_PROTECTED_FILE_NAMES = {".agentguard_agent_events.jsonl"}


def load_guard_ignore_patterns(
    data: dict[str, Any],
    *,
    test_paths: list[str],
    forbidden_paths: list[str],
    secret_patterns: list[str],
) -> list[str]:
    value = data.get("guard_ignore_paths", [])
    if not isinstance(value, list):
        raise ValueError("Config field 'guard_ignore_paths' must be a list of strings.")

    normalized: list[str] = []
    seen: set[str] = set()
    protected = [
        ("test_paths", pattern) for pattern in test_paths
    ] + [
        ("forbidden_paths", pattern) for pattern in forbidden_paths
    ] + [
        ("secret_patterns", pattern) for pattern in secret_patterns
    ]
    for raw_pattern in value:
        pattern = _normalize_pattern(raw_pattern)
        if pattern in seen:
            raise ValueError(
                f"Invalid guard_ignore_paths pattern {raw_pattern!r}: "
                f"duplicates normalized pattern {pattern!r}."
            )
        _validate_protected_pattern(pattern)
        for field_name, protected_pattern in protected:
            if _patterns_overlap(pattern, protected_pattern):
                raise ValueError(
                    f"Invalid guard_ignore_paths pattern {raw_pattern!r}: "
                    f"overlaps protected {field_name} pattern "
                    f"{protected_pattern!r}."
                )
        seen.add(pattern)
        normalized.append(pattern)
    return normalized


def _normalize_pattern(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: must be a string."
        )
    if "\x00" in value:
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: contains a NUL character."
        )
    stripped = value.strip()
    if not stripped:
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: must be non-empty."
        )
    if stripped.startswith("~"):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: home-relative paths "
            "are not allowed."
        )
    if (
        stripped.startswith(("/", "\\"))
        or stripped.startswith("//")
        or stripped.startswith("\\\\")
        or _DRIVE_PATH.match(stripped)
    ):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: absolute paths "
            "are not allowed."
        )
    if _URI_PATH.match(stripped):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: URI-like paths "
            "are not allowed."
        )

    posix_value = stripped.replace("\\", "/")
    components = posix_value.split("/")
    if any(component in {".", ".."} for component in components):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: traversal and dot "
            "components are not allowed."
        )
    normalized = posixpath.normpath(posix_value)
    if normalized in {".", ".."} or normalized.startswith("../"):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: must stay within "
            "the workspace."
        )
    if normalized in _ROOT_WIDE_PATTERNS:
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {value!r}: root-wide patterns "
            "are not allowed."
        )
    return normalized


def _validate_protected_pattern(pattern: str) -> None:
    components = pattern.split("/")
    literal_components = [
        component
        for component in components
        if not any(char in component for char in _GLOB_CHARS)
    ]
    if any(component in _PROTECTED_ROOT_NAMES for component in literal_components):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {pattern!r}: repository metadata "
            "and AgentGuard evidence paths cannot be ignored."
        )
    if any(component in _PROTECTED_FILE_NAMES for component in literal_components):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {pattern!r}: AgentGuard event "
            "evidence cannot be ignored."
        )
    protected_samples = [
        ".git/config",
        ".hg/store",
        ".svn/entries",
        ".agentguard/runs/evidence.json",
        ".agentguard_agent_events.jsonl",
    ]
    if any(matches_path(sample, pattern) for sample in protected_samples):
        raise ValueError(
            f"Invalid guard_ignore_paths pattern {pattern!r}: repository metadata "
            "and AgentGuard evidence paths cannot be ignored."
        )


def _patterns_overlap(ignore_pattern: str, protected_pattern: str) -> bool:
    if matches_path(ignore_pattern, protected_pattern) or matches_path(
        protected_pattern,
        ignore_pattern,
    ):
        return True

    ignore_prefix = _literal_prefix(ignore_pattern)
    protected_prefix = _literal_prefix(protected_pattern)
    if not ignore_prefix:
        return True
    if not protected_prefix:
        return False
    common = min(len(ignore_prefix), len(protected_prefix))
    return ignore_prefix[:common] == protected_prefix[:common]


def _literal_prefix(pattern: str) -> tuple[str, ...]:
    prefix = []
    for component in pattern.replace("\\", "/").strip("/").split("/"):
        if any(char in component for char in _GLOB_CHARS):
            break
        prefix.append(component)
    return tuple(prefix)
