from agentguard.policy.path_matcher import matches_path, normalize_posix_path


INTERNAL_ARTIFACT_PATTERNS = [
    ".agentguard_agent_events.jsonl",
    ".agentguard/**",
    ".pytest_cache/**",
    "**/__pycache__/**",
    "**/*.pyc",
    ".ruff_cache/**",
    ".DS_Store",
]


def is_internal_artifact(path: str) -> bool:
    normalized = normalize_posix_path(path)
    return any(
        matches_path(normalized, pattern)
        or (
            pattern.startswith("**/")
            and matches_path(normalized, pattern.removeprefix("**/"))
        )
        for pattern in INTERNAL_ARTIFACT_PATTERNS
    )
