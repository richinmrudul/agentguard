from cli_example.calculator import parse_and_add


def test_adds_compact_expression() -> None:
    assert parse_and_add("2+3") == 5


def test_adds_expression_with_spaces() -> None:
    assert parse_and_add("10 + 5") == 15


def test_adds_negative_operand() -> None:
    assert parse_and_add("-2 + 7") == 5


def test_invalid_input_raises_value_error() -> None:
    try:
        parse_and_add("not addition")
    except ValueError:
        return
    raise AssertionError("parse_and_add should reject invalid input")
