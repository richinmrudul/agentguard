from pathlib import Path


Path("src/cli_example/calculator.py").write_text(
    'def parse_and_add(expression: str) -> int:\n'
    '    """Parse a simple addition expression and return its sum."""\n'
    '    try:\n'
    '        left, right = expression.split("+", maxsplit=1)\n'
    '        return int(left.strip()) + int(right.strip())\n'
    '    except ValueError as exc:\n'
    '        raise ValueError("expected two integer operands joined by +") from exc\n',
    encoding="utf-8",
)
