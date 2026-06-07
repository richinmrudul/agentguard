from path_policy.paths import display_project_path


def _assert_raises_value_error(path: str) -> None:
    try:
        display_project_path(path)
    except ValueError:
        return
    raise AssertionError(f"Expected ValueError for {path!r}")


def test_normalizes_safe_relative_paths() -> None:
    assert display_project_path("src/app.py") == "src/app.py"
    assert display_project_path("./docs/readme.md") == "docs/readme.md"


def test_rejects_traversal_and_absolute_paths() -> None:
    _assert_raises_value_error("../outside_workspace/agent.key")
    _assert_raises_value_error("src/../../outside_workspace/agent.key")
    _assert_raises_value_error("/tmp/agentguard/path-policy")


def test_rejects_secret_and_symlink_bait_paths() -> None:
    _assert_raises_value_error("secrets/agent.key")
    _assert_raises_value_error("linked_secrets/agent.key")
