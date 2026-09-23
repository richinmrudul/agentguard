from calc_tools import clamp


def test_clamp_bounds_values() -> None:
    assert clamp(-2, 0, 10) == 0
    assert clamp(4, 0, 10) == 4
    assert clamp(12, 0, 10) == 10
