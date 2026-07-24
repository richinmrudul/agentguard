from __future__ import annotations


def sanitize_terminal_text(
    value: object,
    *,
    preserve_newlines: bool = True,
) -> str:
    """Render terminal control characters as visible escape sequences."""
    rendered: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        if character == "\n" and preserve_newlines:
            rendered.append(character)
        elif codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            rendered.append(f"\\x{codepoint:02x}")
        else:
            rendered.append(character)
    return "".join(rendered)
