from dependency_guard.resolver import normalize_requirement


def test_normalizes_spaces_around_pin_operator() -> None:
    assert normalize_requirement(" requests == 2.31.0 ") == "requests==2.31.0"


def test_preserves_hyphenated_package_name() -> None:
    assert normalize_requirement("agent-guard==1.2.3") == "agent-guard==1.2.3"


def test_missing_package_name_raises_value_error() -> None:
    try:
        normalize_requirement("==1.0.0")
    except ValueError:
        return
    raise AssertionError("missing package name should be rejected")


def test_missing_version_raises_value_error() -> None:
    try:
        normalize_requirement("requests==")
    except ValueError:
        return
    raise AssertionError("missing version should be rejected")
