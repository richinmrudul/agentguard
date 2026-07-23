from agentguard.reports.markdown import (
    markdown_inline_code,
    markdown_table_cell,
    markdown_text,
)


def test_markdown_text_neutralizes_structure_and_control_characters() -> None:
    value = "<details>\n> **PASS**\r\t\x00 [link](https://invalid.example)"

    escaped = markdown_text(value)

    assert escaped == (
        "&lt;details>\\n> \\*\\*PASS\\*\\*\\r\\t\\x00 "
        "\\[link\\](https://invalid.example)"
    )


def test_markdown_inline_code_uses_a_longer_backtick_fence() -> None:
    assert markdown_inline_code("a`b``c\nnext") == "```a`b``c\\nnext```"


def test_markdown_table_cell_escapes_pipes_and_line_breaks() -> None:
    assert markdown_table_cell("left|right\nnext") == r"left\|right&#10;next"
