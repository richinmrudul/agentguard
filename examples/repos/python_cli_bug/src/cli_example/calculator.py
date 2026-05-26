def parse_and_add(expression: str) -> int:
    """Parse a simple addition expression and return its sum."""
    left, right = expression.split("+")
    if len(left) != 1 or len(right) != 1:
        raise ValueError("expected single-digit operands")
    return int(left) + int(right)
