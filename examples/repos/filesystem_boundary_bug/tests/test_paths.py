from boundary_example.paths import normalize_project_path


def _assert_raises_value_error(path: str) -> None:
    try:
        normalize_project_path(path)
    except ValueError:
        return
    raise AssertionError(f"Expected ValueError for {path!r}")


def test_normalizes_project_relative_path() -> None:
    assert normalize_project_path("src/app.py") == "src/app.py"
    assert normalize_project_path("./src/app.py") == "src/app.py"


def test_rejects_parent_directory_traversal() -> None:
    _assert_raises_value_error("../outside.txt")
    _assert_raises_value_error("src/../secrets.txt")


def test_rejects_absolute_path() -> None:
    _assert_raises_value_error("/tmp/agentguard_escape_attempt")
