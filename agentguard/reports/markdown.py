import re


_MARKDOWN_CONTROL_CHARACTERS = r"`*[]"


def _literal_text(value: object) -> str:
    text = str(value)
    rendered: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character == "\\":
            rendered.append("\\\\")
        elif character == "\r":
            rendered.append(r"\r")
        elif character == "\n":
            rendered.append(r"\n")
        elif character == "\t":
            rendered.append(r"\t")
        elif codepoint < 32 or codepoint == 127:
            rendered.append(f"\\x{codepoint:02x}")
        else:
            rendered.append(character)
    return "".join(rendered)


def markdown_text(value: object) -> str:
    """Render an untrusted value as literal, single-line Markdown text."""
    escaped = _literal_text(value).replace("&", "&amp;").replace("<", "&lt;")
    for character in _MARKDOWN_CONTROL_CHARACTERS:
        escaped = escaped.replace(character, f"\\{character}")
    escaped = re.sub(
        r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])",
        lambda match: f"\\{match.group(0)}",
        escaped,
    )
    return escaped


def markdown_inline_code(value: object) -> str:
    """Render an untrusted value in a code span, including embedded backticks."""
    text = _literal_text(value)
    runs = re.findall(r"`+", text)
    fence = "`" * (max((len(run) for run in runs), default=0) + 1)
    padding = " " if text.startswith(("`", " ")) or text.endswith(("`", " ")) else ""
    return f"{fence}{padding}{text}{padding}{fence}"


def markdown_table_cell(value: object) -> str:
    """Render an untrusted value without allowing a new Markdown table cell."""
    text = str(value).replace("\r\n", "\n").replace("\r", "\n")
    rendered: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character == "&":
            rendered.append("&amp;")
        elif character == "<":
            rendered.append("&lt;")
        elif character == ">":
            rendered.append("&gt;")
        elif character == "\n":
            rendered.append("&#10;")
        elif character == "\t":
            rendered.append("&#9;")
        elif character == "\\":
            rendered.append("\\\\")
        elif character == "|":
            rendered.append(r"\|")
        elif character in "`*[]":
            rendered.append(f"\\{character}")
        elif codepoint < 32 or codepoint == 127:
            rendered.append(f"&#x{codepoint:02x};")
        else:
            rendered.append(character)
    escaped = "".join(rendered)
    return re.sub(
        r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])",
        lambda match: f"\\{match.group(0)}",
        escaped,
    )
