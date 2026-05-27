import os
from pathlib import Path
from typing import Optional

import typer

from agentguard import __version__
from agentguard.core.benchmark import parse_agent_list, run_multi_agent_benchmark
from agentguard.core.ci import run_ci
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.suite import run_suite
from agentguard.reports.github_summary import write_github_step_summary

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
    allow_fail_result: bool = typer.Option(
        False,
        "--allow-fail-result",
        help="Exit 0 even when the AgentGuard run result is FAIL.",
    ),
) -> None:
    """Run an AgentGuard benchmark."""
    try:
        result = run_benchmark(config_path, agent)
    except ValueError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Report")
    typer.echo(f"Task: {result.task_id}")
    typer.echo(f"Agent: {result.agent}")
    typer.echo(f"Result: {result.result}")
    typer.echo(f"Score: {result.score}/100")
    typer.echo("Checks summary:")
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
    if result.result == "FAIL" and not allow_fail_result:
        raise typer.Exit(1)


@app.command("ci")
def ci_command(
    config_path: Path = typer.Option(
        Path("agentguard.yaml"),
        "--config",
        help="Path to the AgentGuard CI config file.",
    ),
    base_ref: Optional[str] = typer.Option(
        None,
        "--base",
        help="Base git ref for PR-style diff mode.",
    ),
    head_ref: Optional[str] = typer.Option(
        None,
        "--head",
        help="Head git ref for PR-style diff mode.",
    ),
    allow_fail_result: bool = typer.Option(
        False,
        "--allow-fail-result",
        help="Exit 0 even when the AgentGuard CI result is FAIL.",
    ),
    github_summary: bool = typer.Option(
        False,
        "--github-summary",
        help="Append a compact CI report to GITHUB_STEP_SUMMARY.",
    ),
) -> None:
    """Evaluate existing git diff in the current repository."""
    if (base_ref is None) != (head_ref is None):
        typer.echo(
            "Error: --base and --head must be provided together.",
            err=True,
        )
        raise typer.Exit(2)

    result = run_ci(config_path, base_ref=base_ref, head_ref=head_ref)
    github_summary_path = None
    if github_summary:
        summary_env = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_env:
            github_summary_path = write_github_step_summary(result, Path(summary_env))
        else:
            typer.echo(
                "Warning: --github-summary was provided but "
                "GITHUB_STEP_SUMMARY is not set.",
                err=True,
            )

    typer.echo("AgentGuard CI Report")
    typer.echo(f"Task: {result.task_id}")
    typer.echo(f"Result: {result.result}")
    typer.echo(f"Score: {result.score}/100")
    typer.echo("Checks summary:")
    for check in result.check_results:
        status = "PASS" if check.passed else "FAIL"
        typer.echo(f"- {status} [{check.severity}] {check.name}: {check.message}")
    typer.echo("Files:")
    for label, paths in [
        ("Modified", result.diff_summary.modified_files),
        ("Added", result.diff_summary.added_files),
        ("Deleted", result.diff_summary.deleted_files),
    ]:
        typer.echo(f"- {label}: {len(paths)}")
        for path in paths:
            typer.echo(f"  - {path}")
    if result.report_paths.command_log is not None:
        typer.echo(f"Command log path: {result.report_paths.command_log}")
    typer.echo(f"JSON report path: {result.report_paths.json}")
    typer.echo(f"Markdown report path: {result.report_paths.markdown}")
    if github_summary_path is not None:
        typer.echo(f"GitHub summary path: {github_summary_path}")
    if result.result == "FAIL" and not allow_fail_result:
        raise typer.Exit(1)


@app.command("benchmark")
def benchmark_command(
    config_path: Path = typer.Argument(..., help="Path to the AgentGuard config file."),
    agents: str = typer.Option(
        ...,
        "--agents",
        help="Comma-separated list of agent names to benchmark.",
    ),
    allow_failures: bool = typer.Option(
        False,
        "--allow-failures",
        help="Exit 0 even when one or more benchmarked agents fail.",
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
    if summary.fail_count > 0 and not allow_failures:
        raise typer.Exit(1)


@app.command("suite")
def suite_command(
    suite_path: Path = typer.Argument(..., help="Path to the AgentGuard suite file."),
    allow_failures: bool = typer.Option(
        False,
        "--allow-failures",
        help="Exit 0 even when one or more suite runs fail.",
    ),
) -> None:
    """Run multiple AgentGuard benchmark configs as one suite."""
    try:
        result = run_suite(suite_path)
    except ValueError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Suite Summary")
    typer.echo(f"Suite: {result.suite_id}")
    typer.echo(f"Runs: {result.total_runs}")
    typer.echo(f"Passed: {result.passed}")
    typer.echo(f"Failed: {result.failed}")
    typer.echo(f"Pass rate: {result.pass_rate}%")
    typer.echo(f"Average score: {result.average_score}")
    typer.echo("")
    typer.echo(
        f"Best run: {result.best_run.task_id} / {result.best_run.agent} / "
        f"{result.best_run.result} / {result.best_run.score}"
    )
    typer.echo(
        f"Worst run: {result.worst_run.task_id} / {result.worst_run.agent} / "
        f"{result.worst_run.result} / {result.worst_run.score}"
    )
    typer.echo("")
    typer.echo("Most common failed checks:")
    if result.failed_check_counts:
        for name, count in sorted(
            result.failed_check_counts.items(),
            key=lambda item: -item[1],
        ):
            typer.echo(f"- {name}: {count}")
    else:
        typer.echo("- None")
    typer.echo("")
    typer.echo("Task | Agent | Result | Score | Failed Checks")
    typer.echo("--- | --- | --- | ---: | ---")
    for run in result.runs:
        failed_checks = ", ".join(run.failed_checks) if run.failed_checks else "-"
        typer.echo(
            f"{run.task_id} | {run.agent} | {run.result} | "
            f"{run.score} | {failed_checks}"
        )
    typer.echo(f"Suite JSON report path: {result.json_report_path}")
    typer.echo(f"Suite Markdown report path: {result.markdown_report_path}")
    if result.failed > 0 and not allow_failures:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
