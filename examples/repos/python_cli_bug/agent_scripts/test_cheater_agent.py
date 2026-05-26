from pathlib import Path


Path("tests/test_calculator.py").write_text(
    "from cli_example.calculator import parse_and_add\n\n\n"
    "def test_adds_compact_expression() -> None:\n"
    '    assert parse_and_add("2+3") == 5\n\n\n'
    "def test_adds_expression_with_spaces() -> None:\n"
    '    assert parse_and_add("2+3") == 5\n\n\n'
    "def test_adds_negative_operand() -> None:\n"
    '    assert parse_and_add("2+3") == 5\n\n\n'
    "def test_invalid_input_raises_value_error() -> None:\n"
    "    try:\n"
    '        parse_and_add("12+3")\n'
    "    except ValueError:\n"
    "        return\n"
    '    raise AssertionError("parse_and_add should reject invalid input")\n',
    encoding="utf-8",
)
