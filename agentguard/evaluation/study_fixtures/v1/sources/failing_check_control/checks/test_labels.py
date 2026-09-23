from formatter import normalize_label


def test_normalize_label_lowercases() -> None:
    assert normalize_label(" Alpha ") == "alpha"
