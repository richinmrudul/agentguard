import os
from pathlib import Path
from typing import Optional

import typer

from agentguard import __version__
from agentguard.benchmarks.registry import (
    DEFAULT_REGISTRY_PATH,
    BenchmarkRegistryEntry,
    find_benchmark,
    generate_suite_data,
    load_benchmark_registry,
    write_generated_suite,
)
from agentguard.core.baseline import write_suite_baseline
from agentguard.core.benchmark import parse_agent_list, run_multi_agent_benchmark
from agentguard.core.ci import run_ci
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.suite import (
    format_suite_filters,
    run_suite,
    suite_filters_from_values,
)
from agentguard.reports.browser import (
    discover_reports,
    format_report_summary,
    format_reports_table,
    latest_report,
    load_report,
    validate_report_type,
)
from agentguard.reports.github_summary import write_github_step_summary

app = typer.Typer(
    help="Local-first safety and reliability evaluation framework for AI coding agents."
)
reports_app = typer.Typer(help="List and inspect local AgentGuard reports.")
app.add_typer(reports_app, name="reports")
benchmarks_app = typer.Typer(help="List and inspect registered AgentGuard benchmarks.")
app.add_typer(benchmarks_app, name="benchmarks")


@app.command()
def version() -> None:
    """Print the AgentGuard version."""
    typer.echo(__version__)


def _format_registry_table(benchmarks: list[BenchmarkRegistryEntry]) -> str:
    lines = [
        "Registered AgentGuard Benchmarks",
        "ID | Version | Category | Difficulty | Tags",
        "--- | ---: | --- | --- | ---",
    ]
    for benchmark in benchmarks:
        tags = ", ".join(benchmark.tags) if benchmark.tags else "-"
        lines.append(
            f"{benchmark.id} | {benchmark.version} | {benchmark.category} | "
            f"{benchmark.difficulty} | {tags}"
        )
    return "\n".join(lines)


def _format_registry_entry(benchmark: BenchmarkRegistryEntry) -> str:
    lines = [
        f"ID: {benchmark.id}",
        f"Version: {benchmark.version}",
        f"Name: {benchmark.name}",
        f"Category: {benchmark.category}",
        f"Difficulty: {benchmark.difficulty}",
        f"Description: {benchmark.description}",
        f"Tags: {', '.join(benchmark.tags) if benchmark.tags else '-'}",
        "Configs:",
    ]
    for label, config_path in benchmark.configs.items():
        lines.append(f"- {label}: {config_path}")
    return "\n".join(lines)


@benchmarks_app.command("list")
def benchmarks_list(
    registry: Path = typer.Option(
        DEFAULT_REGISTRY_PATH,
        "--registry",
        help="Path to the benchmark registry YAML file.",
    ),
) -> None:
    """List registered AgentGuard benchmarks."""
    try:
        benchmark_registry = load_benchmark_registry(registry)
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo(_format_registry_table(benchmark_registry.benchmarks))


@benchmarks_app.command("show")
def benchmarks_show(
    benchmark_id: str = typer.Argument(..., help="Benchmark ID to show."),
    registry: Path = typer.Option(
        DEFAULT_REGISTRY_PATH,
        "--registry",
        help="Path to the benchmark registry YAML file.",
    ),
) -> None:
    """Show a registered AgentGuard benchmark."""
    try:
        benchmark_registry = load_benchmark_registry(registry)
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    benchmark = find_benchmark(benchmark_registry, benchmark_id)
    if benchmark is None:
        typer.echo(f"Error: benchmark not found: {benchmark_id}", err=True)
        raise typer.Exit(2)

    typer.echo(_format_registry_entry(benchmark))


@benchmarks_app.command("generate-suite")
def benchmarks_generate_suite(
    registry: Path = typer.Option(
        DEFAULT_REGISTRY_PATH,
        "--registry",
        help="Path to the benchmark registry YAML file.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        help="Path for the generated suite YAML file.",
    ),
    suite_id: Optional[str] = typer.Option(
        None,
        "--suite-id",
        help="Suite ID to write. Defaults to the output file stem.",
    ),
    description: str = typer.Option(
        "Generated from AgentGuard benchmark registry.",
        "--description",
        help="Suite description to write.",
    ),
    include: Optional[list[str]] = typer.Option(
        None,
        "--include",
        help="Config keys to include. Repeat or use commas.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="Include only benchmarks with this category.",
    ),
    difficulty: Optional[str] = typer.Option(
        None,
        "--difficulty",
        help="Include only benchmarks with this difficulty.",
    ),
    tags: Optional[list[str]] = typer.Option(
        None,
        "--tag",
        help="Include only benchmarks containing all requested tags. Repeat or use commas.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output file if it already exists.",
    ),
) -> None:
    """Generate an AgentGuard suite YAML from the benchmark registry."""
    resolved_suite_id = suite_id or output.stem or "registry_suite"
    try:
        benchmark_registry = load_benchmark_registry(registry)
        suite_data = generate_suite_data(
            benchmark_registry,
            suite_id=resolved_suite_id,
            description=description,
            include=include,
            category=category,
            difficulty=difficulty,
            tags=tags,
        )
        written_path = write_generated_suite(suite_data, output, force=force)
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo(f"Generated suite: {written_path}")
    typer.echo(f"Runs: {len(suite_data['runs'])}")


@reports_app.command("list")
def reports_list(
    report_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="Report type to list: run, suite, or ci.",
    ),
    limit: int = typer.Option(
        10,
        "--limit",
        help="Maximum number of reports to show.",
    ),
) -> None:
    """List recent local AgentGuard reports."""
    if limit <= 0:
        raise typer.BadParameter("limit must be positive.", param_hint="--limit")
    try:
        validated_type = validate_report_type(report_type)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--type") from error

    reports = discover_reports(report_type=validated_type)[:limit]
    typer.echo(format_reports_table(reports))


@reports_app.command("show")
def reports_show(
    path: Optional[Path] = typer.Argument(
        None,
        help="Path to a report JSON file.",
    ),
    latest: bool = typer.Option(
        False,
        "--latest",
        help="Show the latest report.",
    ),
    report_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="Report type for --latest: run, suite, or ci.",
    ),
) -> None:
    """Show a concise local AgentGuard report summary."""
    try:
        validated_type = validate_report_type(report_type)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--type") from error

    if path is not None and latest:
        typer.echo("Error: provide a report path or --latest, not both.", err=True)
        raise typer.Exit(2)
    if path is None and not latest:
        typer.echo("Error: provide a report path or use --latest.", err=True)
        raise typer.Exit(2)

    try:
        report = (
            latest_report(report_type=validated_type)
            if latest
            else load_report(path if path is not None else Path())
        )
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    if report is None:
        typer.echo("No reports found.", err=True)
        raise typer.Exit(1)

    typer.echo(format_report_summary(report))


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
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="Run only suite entries with this benchmark category.",
    ),
    difficulty: Optional[str] = typer.Option(
        None,
        "--difficulty",
        help="Run only suite entries with this benchmark difficulty.",
    ),
    tags: Optional[list[str]] = typer.Option(
        None,
        "--tag",
        help="Run only entries containing all requested tags. Repeat or use commas.",
    ),
    allow_failures: bool = typer.Option(
        False,
        "--allow-failures",
        help="Exit 0 even when one or more suite runs fail.",
    ),
    save_baseline: Optional[Path] = typer.Option(
        None,
        "--save-baseline",
        help="Write a stable suite baseline JSON file after the run.",
    ),
    compare_baseline: Optional[Path] = typer.Option(
        None,
        "--compare-baseline",
        help="Compare this suite run against an existing baseline JSON file.",
    ),
    allow_regressions: bool = typer.Option(
        False,
        "--allow-regressions",
        help="Exit 0 even when baseline comparison finds regressions.",
    ),
) -> None:
    """Run multiple AgentGuard benchmark configs as one suite."""
    try:
        filters = suite_filters_from_values(
            category=category,
            difficulty=difficulty,
            tags=tags,
        )
        result = run_suite(
            suite_path,
            compare_baseline_path=compare_baseline,
            filters=filters,
        )
    except ValueError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Suite Summary")
    typer.echo(f"Suite: {result.suite_id}")
    if result.filters.has_filters():
        typer.echo(f"Filters: {format_suite_filters(result.filters)}")
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
    typer.echo("Task | Category | Agent | Result | Score | Failed Checks")
    typer.echo("--- | --- | --- | --- | ---: | ---")
    for run in result.runs:
        failed_checks = ", ".join(run.failed_checks) if run.failed_checks else "-"
        typer.echo(
            f"{run.task_id} | {run.category or '-'} | {run.agent} | {run.result} | "
            f"{run.score} | {failed_checks}"
        )
    if result.baseline_comparison is not None:
        comparison = result.baseline_comparison
        typer.echo("")
        typer.echo("Baseline comparison")
        typer.echo(f"Baseline: {comparison.baseline_path}")
        typer.echo(f"Regressions: {'yes' if comparison.has_regressions else 'no'}")
        if comparison.regressions:
            typer.echo("Regression details:")
            for message in comparison.regressions:
                typer.echo(f"- {message}")
        else:
            typer.echo("Regression details: none")
        if comparison.improvements:
            typer.echo("Improvements:")
            for message in comparison.improvements:
                typer.echo(f"- {message}")
        else:
            typer.echo("Improvements: none")
        typer.echo(f"Unchanged runs: {comparison.unchanged_count}")
    typer.echo(f"Suite JSON report path: {result.json_report_path}")
    typer.echo(f"Suite Markdown report path: {result.markdown_report_path}")
    if save_baseline is not None:
        baseline_path = write_suite_baseline(result, save_baseline)
        typer.echo(f"Baseline saved: {baseline_path}")
    if (
        result.baseline_comparison is not None
        and result.baseline_comparison.has_regressions
        and not allow_regressions
    ):
        raise typer.Exit(1)
    if result.failed > 0 and not allow_failures:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
