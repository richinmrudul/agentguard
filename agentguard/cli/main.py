from pathlib import Path

import typer

from agentguard import __version__

app = typer.Typer(
    help="Local-first safety and reliability evaluation framework for AI coding agents."
)


@app.command()
def version() -> None:
    """Print the AgentGuard version."""
    typer.echo(__version__)


@app.command()
def run(
    config_path: Path = typer.Argument(..., help="Path to the AgentGuard config file."),
    agent: str = typer.Option(..., "--agent", help="Name of the coding agent to run."),
) -> None:
    """Run an AgentGuard evaluation placeholder."""
    typer.echo(
        "AgentGuard run placeholder: "
        f"would evaluate agent '{agent}' using config '{config_path}'."
    )


if __name__ == "__main__":
    app()
