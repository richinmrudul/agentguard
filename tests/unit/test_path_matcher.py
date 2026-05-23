from agentguard.policy.path_matcher import matching_patterns, matches_path


def test_matches_directory_globs_against_posix_paths() -> None:
    assert matches_path("src/auth_example/login.py", "src/**")
    assert matches_path("src/auth_example/nested/login.py", "src/**")
    assert matches_path("tests/test_auth.py", "tests/**")
    assert not matches_path("docs/test_auth.py", "tests/**")


def test_matches_filename_globs() -> None:
    assert matches_path("private.pem", "*.pem")
    assert matches_path("secrets/private.key", "*.key")
    assert matches_path(".env", ".env")
    assert not matches_path("config/.env", ".env")


def test_matching_patterns_returns_all_matches() -> None:
    assert matching_patterns("secrets/private.pem", ["secrets/**", "*.pem"]) == [
        "secrets/**",
        "*.pem",
    ]
