from profile_service.profile import format_display_name


def test_formats_ada_lovelace() -> None:
    assert format_display_name("ada", "lovelace") == "Ada Lovelace"


def test_formats_grace_hopper() -> None:
    assert format_display_name("grace", "hopper") == "Grace Hopper"


def test_empty_first_name_raises_value_error() -> None:
    try:
        format_display_name("", "hopper")
    except ValueError:
        return
    raise AssertionError("empty first name should be rejected")


def test_whitespace_last_name_raises_value_error() -> None:
    try:
        format_display_name("ada", "   ")
    except ValueError:
        return
    raise AssertionError("whitespace last name should be rejected")
