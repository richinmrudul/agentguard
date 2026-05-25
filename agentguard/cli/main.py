from pathlib import Path

import typer

from agentguard import __version__
from agentguard.core.benchmark import parse_agent_list, run_multi_agent_benchmark
from agentguard.core.orchestrator import run_benchmark

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
    """Run an AgentGuard benchmark."""
    result = run_benchmark(config_path, agent)

    typer.echo("AgentGuard Report")
    typer.echo(f"Task: {result.task_id}")
    typer.echo(f"Agent: {result.agent}")
    typer.echo(f"Result: {result.result}")
    typer.echo(f"Score: {result.score}/100")
    typer.echo("Checks:")
    for check in result.check_results:
        status = "PASS" if check.passed else "FAIL"
        typer.echo(f"- {status} [{check.severity}] {check.name}: {check.message}")
        for evidence in check.evidence:
            typer.echo(f"  Evidence: {evidence}")
    typer.echo("Modified files:")
    if result.diff_summary.changed_files:
        for path in result.diff_summary.changed_files:
            typer.echo(f"- {path}")
    else:
        typer.echo("- None")
    if result.report_paths.command_log is not None:
        typer.echo(f"Command log path: {result.report_paths.command_log}")
    typer.echo(f"JSON report path: {result.report_paths.json}")
    typer.echo(f"Markdown report path: {result.report_paths.markdown}")


@app.command("benchmark")
def benchmark_command(
    config_path: Path = typer.Argument(..., help="Path to the AgentGuard config file."),
    agents: str = typer.Option(
        ...,
        "--agents",
        help="Comma-separated list of agent names to benchmark.",
    ),
) -> None:
    """Run multiple agents against one AgentGuard benchmark config."""
    try:
        agent_names = parse_agent_list(agents)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--agents") from error

    summary = run_multi_agent_benchmark(config_path, agent_names)

    typer.echo("AgentGuard Benchmark Summary")
    typer.echo(f"Task: {summary.task_id}")
    typer.echo(f"Agents: {summary.total_agents}")
    typer.echo(f"Passed: {summary.pass_count}")
    typer.echo(f"Failed: {summary.fail_count}")
    typer.echo("")
    typer.echo("Agent | Result | Score | Failed Checks")
    typer.echo("--- | --- | ---: | ---")
    for agent in summary.agents:
        failed_checks = ", ".join(agent.failed_checks) if agent.failed_checks else "-"
        typer.echo(
            f"{agent.agent} | {agent.result} | {agent.score} | {failed_checks}"
        )
    typer.echo(f"Benchmark JSON report path: {summary.report_paths.json}")
    typer.echo(f"Benchmark Markdown report path: {summary.report_paths.markdown}")


if __name__ == "__main__":
    app()
