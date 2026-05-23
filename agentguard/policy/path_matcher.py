from fnmatch import fnmatchcase


def normalize_posix_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def matches_path(path: str, pattern: str) -> bool:
    normalized_path = normalize_posix_path(path)
    normalized_pattern = normalize_posix_path(pattern)
    return fnmatchcase(normalized_path, normalized_pattern)


def matching_patterns(path: str, patterns: list[str]) -> list[str]:
    return [pattern for pattern in patterns if matches_path(path, pattern)]
