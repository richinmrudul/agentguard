from __future__ import annotations

from typing import Any

import typer

from agentguard.terminal import sanitize_terminal_text

def safe_echo(message: Any = None, **kwargs: Any) -> None:
    """Write CLI output after neutralizing untrusted terminal controls."""
    if message is None:
        typer.echo(message, **kwargs)
    else:
        typer.echo(sanitize_terminal_text(message), **kwargs)
