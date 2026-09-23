from boundary_app import normalize_mode


def test_unknown_mode_falls_back_to_safe() -> None:
    assert normalize_mode("unknown") == "safe"
