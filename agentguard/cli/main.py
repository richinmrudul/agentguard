import os
from pathlib import Path
from typing import Optional

import typer
import yaml

from agentguard import __version__
from agentguard.benchmarks.registry import (
    DEFAULT_REGISTRY_PATH,
    BenchmarkRegistryEntry,
    find_benchmark,
    generate_suite_data,
    load_benchmark_registry,
    write_generated_suite,
)
from agentguard.benchmarks.audit import run_benchmark_audit
from agentguard.core.baseline import write_suite_baseline
from agentguard.core.benchmark import parse_agent_list, run_multi_agent_benchmark
from agentguard.core.ci import run_ci
from agentguard.core.matrix import run_matrix
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.suite import (
    format_suite_filters,
    run_suite,
    suite_filters_from_values,
)
from agentguard.diagnostics.overhead import (
    DEFAULT_CONFIG_PATH as DEFAULT_OVERHEAD_CONFIG_PATH,
)
from agentguard.diagnostics.overhead import run_overhead_benchmark
from agentguard.history.store import (
    HistoryRecord,
    HistoryStats,
    HistoryTrends,
    export_history_csv,
    export_history_json,
    history_stats,
    history_trends,
    list_history,
    validate_result,
    validate_run_type,
)
from agentguard.evaluation.harness import (
    build_evaluation_plan,
    format_evaluation_plan,
    run_evaluation,
    validate_evaluation,
)
from agentguard.provenance.manifest import (
    load_manifest,
    provenance_summary,
    verify_manifest,
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
history_app = typer.Typer(help="List and summarize local AgentGuard run history.")
app.add_typer(history_app, name="history")
benchmarks_app = typer.Typer(help="List and inspect registered AgentGuard benchmarks.")
app.add_typer(benchmarks_app, name="benchmarks")
gate_app = typer.Typer(help="CI gate commands for AgentGuard suites.")
app.add_typer(gate_app, name="gate")
manifest_app = typer.Typer(help="Inspect and verify execution manifests.")
app.add_typer(manifest_app, name="manifest")
evaluate_app = typer.Typer(help="Validate and run external coding-agent profiles.")
app.add_typer(evaluate_app, name="evaluate")


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Print the AgentGuard version and exit.",
    ),
) -> None:
    """Run AgentGuard commands."""


@app.command()
def version() -> None:
    """Print the AgentGuard version."""
    typer.echo(__version__)


@app.command("benchmark-overhead")
def benchmark_overhead_command(
    config_path: Path = typer.Option(
        DEFAULT_OVERHEAD_CONFIG_PATH,
        "--config",
        help="Deterministic local benchmark config.",
    ),
    agent: str = typer.Option(
        "mock-safe",
        "--agent",
        help="Deterministic local agent to execute.",
    ),
    iterations: int = typer.Option(
        10,
        "--iterations",
        help="Measured paired iterations.",
    ),
    warmups: int = typer.Option(
        2,
        "--warmups",
        help="Warmup pairs excluded from statistics.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="JSON output path; Markdown uses the same stem.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing JSON and Markdown output.",
    ),
    no_history: bool = typer.Option(
        False,
        "--no-history",
        help="Exclude AgentGuard history writing from the measured workload.",
    ),
    no_manifest: bool = typer.Option(
        False,
        "--no-manifest",
        help="Exclude AgentGuard manifest writing from the measured workload.",
    ),
) -> None:
    """Measure AgentGuard overhead against direct deterministic execution."""
    if iterations <= 0:
        raise typer.BadParameter(
            "iterations must be positive.",
            param_hint="--iterations",
        )
    if warmups < 0:
        raise typer.BadParameter(
            "warmups must be non-negative.",
            param_hint="--warmups",
        )
    try:
        result = run_overhead_benchmark(
            config_path,
            agent,
            iterations=iterations,
            warmups=warmups,
            output_path=output,
            force=force,
            record_history_enabled=not no_history,
            write_manifest_enabled=not no_manifest,
        )
    except (FileExistsError, OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    summary = result.data["summary"]
    config = result.data["config"]
    assert isinstance(summary, dict)
    assert isinstance(config, dict)
    direct = summary["direct_seconds"]
    guarded = summary["agentguard_seconds"]
    overhead = summary["absolute_overhead_seconds"]
    relative = summary["relative_overhead_percent"]
    slowdown = summary["slowdown_ratio"]
    throughput = summary["throughput_runs_per_minute"]
    assert isinstance(direct, dict)
    assert isinstance(guarded, dict)
    assert isinstance(overhead, dict)
    assert isinstance(relative, dict)
    assert isinstance(slowdown, dict)
    assert isinstance(throughput, dict)

    typer.echo("AgentGuard Instrumentation Overhead")
    typer.echo(f"Workload/config: {config['task_id']} / {config['path']}")
    typer.echo(f"Agent: {result.data['agent']}")
    typer.echo(
        f"Iterations: {result.data['iterations']} measured, "
        f"{result.data['warmups']} warmups"
    )
    typer.echo(f"Direct median: {float(direct['median']):.6f}s")
    typer.echo(f"AgentGuard median: {float(guarded['median']):.6f}s")
    typer.echo(
        f"Median absolute overhead: {float(overhead['median']):.6f}s"
    )
    typer.echo(
        f"Median relative overhead: {float(relative['median']):.2f}%"
    )
    typer.echo(f"Slowdown ratio: {float(slowdown['median']):.3f}x")
    typer.echo(
        "Throughput: "
        f"direct {float(throughput['direct_median']):.2f} runs/minute, "
        "AgentGuard "
        f"{float(throughput['agentguard_median']):.2f} runs/minute"
    )
    typer.echo(f"JSON output: {result.paths.json}")
    typer.echo(f"Markdown output: {result.paths.markdown}")
    typer.echo(
        "Limitations: machine/workload specific; filesystem caches are not "
        "fully controlled; no universal performance claim is implied."
    )


@manifest_app.command("verify")
def manifest_verify(
    path: Path = typer.Argument(..., help="Path to an execution manifest."),
) -> None:
    """Validate a manifest and verify referenced configuration hashes."""
    result = verify_manifest(path)
    for message in result.messages:
        typer.echo(message)
    if result.exit_code:
        raise typer.Exit(result.exit_code)


@manifest_app.command("show")
def manifest_show(
    path: Path = typer.Argument(..., help="Path to an execution manifest."),
) -> None:
    """Print a concise execution provenance summary."""
    try:
        data = load_manifest(path)
        result = verify_manifest(path)
        if result.exit_code == 2:
            raise ValueError(result.messages[0])
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(provenance_summary(data))


@evaluate_app.command("validate")
def evaluate_validate(
    profile: Path = typer.Option(..., "--profile", help="Agent profile YAML."),
    suite: Path = typer.Option(..., "--suite", help="Benchmark suite YAML."),
) -> None:
    """Validate an external-agent profile and suite without executing them."""
    try:
        plan = validate_evaluation(profile, suite)
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(
        f"Valid evaluation: {plan.profile.name} / {plan.suite_id} / "
        f"{len(plan.runs)} benchmark(s)"
    )


@evaluate_app.command("dry-run")
def evaluate_dry_run(
    profile: Path = typer.Option(..., "--profile", help="Agent profile YAML."),
    suite: Path = typer.Option(..., "--suite", help="Benchmark suite YAML."),
    category: Optional[str] = typer.Option(None, "--category"),
    difficulty: Optional[str] = typer.Option(None, "--difficulty"),
    tags: Optional[list[str]] = typer.Option(None, "--tag"),
    trials: int = typer.Option(1, "--trials"),
    workers: int = typer.Option(1, "--workers"),
) -> None:
    """Render a sanitized external-agent evaluation plan without execution."""
    try:
        filters = suite_filters_from_values(category, difficulty, tags)
        plan = build_evaluation_plan(
            profile,
            suite,
            filters=filters,
            trials=trials,
            workers=workers,
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(format_evaluation_plan(plan))
    missing = [
        name for name in plan.profile.environment if name not in os.environ
    ]
    if missing:
        raise typer.Exit(2)


@evaluate_app.command("run")
def evaluate_run(
    profile: Path = typer.Option(..., "--profile", help="Agent profile YAML."),
    suite: Path = typer.Option(..., "--suite", help="Benchmark suite YAML."),
    yes: bool = typer.Option(False, "--yes", help="Confirm external execution."),
    category: Optional[str] = typer.Option(None, "--category"),
    difficulty: Optional[str] = typer.Option(None, "--difficulty"),
    tags: Optional[list[str]] = typer.Option(None, "--tag"),
    trials: int = typer.Option(1, "--trials"),
    workers: int = typer.Option(1, "--workers"),
    allow_failures: bool = typer.Option(False, "--allow-failures"),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir"),
    save_reliability_baseline: Optional[Path] = typer.Option(
        None, "--save-reliability-baseline"
    ),
    compare_reliability_baseline: Optional[Path] = typer.Option(
        None, "--compare-reliability-baseline"
    ),
    min_success_rate: Optional[float] = typer.Option(None, "--min-success-rate"),
    max_success_rate_drop: float = typer.Option(0, "--max-success-rate-drop"),
    max_average_score_drop: float = typer.Option(
        0, "--max-average-score-drop"
    ),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Run a confirmed external coding-agent evaluation through matrix mode."""
    try:
        filters = suite_filters_from_values(category, difficulty, tags)
        plan = build_evaluation_plan(
            profile,
            suite,
            filters=filters,
            trials=trials,
            workers=workers,
        )
        if not yes:
            typer.echo(format_evaluation_plan(plan))
            typer.echo("Execution not confirmed; rerun with --yes.", err=True)
            raise typer.Exit(2)
        result = run_evaluation(
            profile,
            suite,
            filters=filters,
            trials=trials,
            workers=workers,
            output_dir=output_dir or Path(".agentguard/matrices"),
            save_reliability_baseline_path=save_reliability_baseline,
            compare_reliability_baseline_path=compare_reliability_baseline,
            min_success_rate=min_success_rate,
            max_success_rate_drop=max_success_rate_drop,
            max_average_score_drop=max_average_score_drop,
            force_reliability_baseline=force,
        )
    except typer.Exit:
        raise
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("AgentGuard External Agent Evaluation")
    typer.echo(f"Profile: {result.profile_name} ({result.profile_id})")
    typer.echo(f"Model: {result.profile_model or '-'}")
    typer.echo(f"Attempts: {result.attempts_executed}")
    typer.echo(
        f"Functional success: {result.functional_passed}/"
        f"{result.attempts_executed} ({result.functional_success_rate}%)"
    )
    typer.echo(
        f"Policy-compliant success: {result.policy_compliant_passed}/"
        f"{result.attempts_executed} ({result.policy_compliant_success_rate}%)"
    )
    typer.echo(
        f"Unsafe functional successes: {result.unsafe_functional_successes}"
    )
    typer.echo(f"Matrix JSON report path: {result.json_report_path}")
    typer.echo(f"Matrix Markdown report path: {result.markdown_report_path}")
    typer.echo(f"Matrix manifest path: {result.manifest_path or '-'}")
    if result.failed and not allow_failures:
        raise typer.Exit(1)


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
        f"Contract: {benchmark.contract}",
        "Configs:",
    ]
    for label, config_path in benchmark.configs.items():
        lines.append(f"- {label}: {config_path}")
    return "\n".join(lines)


def _format_history_score(score: Optional[float]) -> str:
    if score is None:
        return "-"
    return f"{score:g}"


def _format_history_table(records: list[HistoryRecord]) -> str:
    if not records:
        return "No history found."
    lines = [
        "AgentGuard Run History",
        "Type | ID | Name | Result | Score | Created At",
        "--- | --- | --- | --- | ---: | ---",
    ]
    for record in records:
        lines.append(
            f"{record.run_type} | {record.id} | {record.name} | {record.result} | "
            f"{_format_history_score(record.score)} | {record.created_at}"
        )
    return "\n".join(lines)


def _format_history_stats(stats: HistoryStats, *, has_filters: bool = False) -> str:
    if stats.total_records == 0:
        if has_filters:
            return "No history found for selected filters."
        return "No history found."
    average = (
        f"{stats.average_score:.1f}" if stats.average_score is not None else "-"
    )
    lines = [
        "AgentGuard History Stats",
        f"Total records: {stats.total_records}",
        "By type:",
    ]
    for run_type, count in sorted(stats.counts_by_type.items()):
        lines.append(f"- {run_type}: {count}")
    lines.append("By result:")
    for result, count in sorted(stats.counts_by_result.items()):
        lines.append(f"- {result}: {count}")
    lines.append(f"Average score: {average}")
    if stats.latest_created_at is not None:
        lines.append(f"Latest run: {stats.latest_created_at}")
    return "\n".join(lines)


def _format_history_delta(delta: Optional[float]) -> str:
    if delta is None:
        return "-"
    return f"{delta:+g}"


def _format_history_trends(trends: HistoryTrends) -> str:
    if trends.records_count == 0:
        return "No history found for selected filters."
    run_type = trends.run_type or "-"
    pass_rate = f"{trends.pass_rate:.1f}%" if trends.pass_rate is not None else "-"
    lines = [
        "AgentGuard History Trends",
        f"Name: {trends.name}",
        f"Type: {run_type}",
        f"Records: {trends.records_count}",
        f"Latest score: {_format_history_score(trends.latest_score)}",
        f"Previous score: {_format_history_score(trends.previous_score)}",
        f"Delta: {_format_history_delta(trends.delta)}",
        f"Pass count: {trends.pass_count}",
        f"Fail count: {trends.fail_count}",
        f"Pass rate: {pass_rate}",
        f"Recent results newest-first: {' '.join(trends.recent_results)}",
    ]
    if trends.latest_report_path is not None:
        lines.append(f"Latest report: {trends.latest_report_path}")
    return "\n".join(lines)


def _has_history_filters(*values: Optional[str]) -> bool:
    return any(value is not None for value in values)


def _validate_history_export_format(export_format: str) -> str:
    if export_format not in {"json", "csv"}:
        raise ValueError("format must be one of: csv, json.")
    return export_format


def _echo_gate_summary(result, baseline_path: Path, gate_result: str) -> None:
    comparison = result.baseline_comparison
    has_regressions = bool(comparison and comparison.has_regressions)
    version_mismatches = comparison.version_mismatches if comparison else []
    typer.echo("AgentGuard Gate Summary")
    typer.echo(f"Suite: {result.suite_id}")
    typer.echo(f"Baseline: {baseline_path}")
    typer.echo(f"Runs: {result.total_runs}")
    typer.echo(f"Passed: {result.passed}")
    typer.echo(f"Failed: {result.failed}")
    typer.echo(f"Pass rate: {result.pass_rate}%")
    typer.echo(f"Average score: {result.average_score}")
    typer.echo(f"Regressions: {'yes' if has_regressions else 'no'}")
    typer.echo(f"Version mismatches: {'yes' if version_mismatches else 'no'}")
    if version_mismatches:
        typer.echo("Benchmark version mismatches:")
        for message in version_mismatches:
            typer.echo(f"- {message}")
    if comparison and comparison.regressions:
        typer.echo("Regression details:")
        for message in comparison.regressions:
            typer.echo(f"- {message}")
    typer.echo(f"Gate result: {gate_result}")
    typer.echo(f"Suite JSON report path: {result.json_report_path}")
    typer.echo(f"Suite Markdown report path: {result.markdown_report_path}")
    typer.echo(f"Suite manifest path: {result.manifest_path or '-'}")


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


@benchmarks_app.command("audit")
def benchmarks_audit(
    registry: Path = typer.Option(
        DEFAULT_REGISTRY_PATH,
        "--registry",
        help="Path to the benchmark registry YAML file.",
    ),
    benchmark_ids: Optional[list[str]] = typer.Option(
        None,
        "--benchmark",
        help="Benchmark IDs to audit. Repeat or use commas.",
    ),
    static_only: bool = typer.Option(
        False,
        "--static-only",
        help="Validate corpus metadata without executing benchmarks.",
    ),
    trials: int = typer.Option(1, "--trials", help="Trials per contract variant."),
    workers: int = typer.Option(1, "--workers", help="Maximum concurrent trials."),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for audit artifacts.",
    ),
    allow_contract_failures: bool = typer.Option(
        False,
        "--allow-contract-failures",
        help="Exit 0 while still reporting contract violations.",
    ),
    strict_unexpected_checks: bool = typer.Option(
        False,
        "--strict-unexpected-checks",
        help="Treat every unexpected failed check as a contract failure.",
    ),
    category: Optional[str] = typer.Option(None, "--category"),
    difficulty: Optional[str] = typer.Option(None, "--difficulty"),
    tags: Optional[list[str]] = typer.Option(None, "--tag"),
) -> None:
    """Validate benchmark contracts and optionally execute their variants."""
    try:
        result = run_benchmark_audit(
            registry,
            benchmark_ids=benchmark_ids,
            static_only=static_only,
            trials=trials,
            workers=workers,
            output_dir=output_dir,
            strict_unexpected_checks=strict_unexpected_checks,
            category=category,
            difficulty=difficulty,
            tags=tags,
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Benchmark Audit")
    typer.echo(f"Mode: {result.mode}")
    typer.echo(f"Benchmarks: {result.total_benchmarks}")
    typer.echo(f"Variants: {result.total_variants}")
    typer.echo(f"Trials: {result.total_trials}")
    typer.echo(f"Contracts passed: {result.passed_contracts}")
    typer.echo(f"Contracts failed: {result.failed_contracts}")
    typer.echo(f"Unstable variants: {result.unstable_variants}")
    typer.echo(f"Errors: {result.error_count}")
    typer.echo(f"Warnings: {result.warning_count}")
    if result.violations:
        typer.echo("")
        typer.echo("Severity | Benchmark | Variant | Trial | Field | Message")
        typer.echo("--- | --- | --- | ---: | --- | ---")
        for violation in result.violations:
            typer.echo(
                f"{violation.severity} | {violation.benchmark_id} | "
                f"{violation.variant} | {violation.trial_index} | "
                f"{violation.field} | {violation.message}"
            )
    typer.echo(f"Audit JSON report path: {result.json_report_path}")
    typer.echo(f"Audit Markdown report path: {result.markdown_report_path}")
    if result.has_failures and not allow_contract_failures:
        raise typer.Exit(1)


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


@history_app.command("list")
def history_list(
    run_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="History type to list: run, suite, or ci.",
    ),
    result: Optional[str] = typer.Option(
        None,
        "--result",
        help="History result to list: PASS or FAIL.",
    ),
    name: Optional[str] = typer.Option(
        None,
        "--name",
        help="History name to list exactly.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="History category to list exactly.",
    ),
    difficulty: Optional[str] = typer.Option(
        None,
        "--difficulty",
        help="History difficulty to list exactly.",
    ),
    limit: int = typer.Option(
        20,
        "--limit",
        help="Maximum number of history records to show.",
    ),
) -> None:
    """List recent local AgentGuard run history."""
    if limit <= 0:
        raise typer.BadParameter("limit must be positive.", param_hint="--limit")
    try:
        validated_type = validate_run_type(run_type)
        validated_result = validate_result(result)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    records = list_history(
        limit=limit,
        run_type=validated_type,
        result=validated_result,
        name=name,
        category=category,
        difficulty=difficulty,
    )
    typer.echo(_format_history_table(records))


@history_app.command("stats")
def history_stats_command(
    run_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="History type to summarize: run, suite, or ci.",
    ),
    name: Optional[str] = typer.Option(
        None,
        "--name",
        help="History name to summarize exactly.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="History category to summarize exactly.",
    ),
    difficulty: Optional[str] = typer.Option(
        None,
        "--difficulty",
        help="History difficulty to summarize exactly.",
    ),
) -> None:
    """Summarize local AgentGuard run history."""
    try:
        validated_type = validate_run_type(run_type)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--type") from error

    stats = history_stats(
        run_type=validated_type,
        name=name,
        category=category,
        difficulty=difficulty,
    )
    typer.echo(
        _format_history_stats(
            stats,
            has_filters=_has_history_filters(
                validated_type,
                name,
                category,
                difficulty,
            ),
        )
    )


@history_app.command("trends")
def history_trends_command(
    name: str = typer.Option(
        ...,
        "--name",
        help="History name to analyze exactly.",
    ),
    run_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="History type to analyze: run, suite, or ci.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="History category to analyze exactly.",
    ),
    difficulty: Optional[str] = typer.Option(
        None,
        "--difficulty",
        help="History difficulty to analyze exactly.",
    ),
    limit: int = typer.Option(
        10,
        "--limit",
        help="Maximum number of history records to analyze.",
    ),
) -> None:
    """Show score and result trends for local AgentGuard history."""
    if limit <= 0:
        raise typer.BadParameter("limit must be positive.", param_hint="--limit")
    try:
        validated_type = validate_run_type(run_type)
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--type") from error

    trends = history_trends(
        name=name,
        limit=limit,
        run_type=validated_type,
        category=category,
        difficulty=difficulty,
    )
    typer.echo(_format_history_trends(trends))


@history_app.command("export")
def history_export_command(
    export_format: str = typer.Option(
        "json",
        "--format",
        help="Export format: json or csv.",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        help="Path to write the export. Prints to stdout when omitted.",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        help="Maximum number of history records to export.",
    ),
    run_type: Optional[str] = typer.Option(
        None,
        "--type",
        help="History type to export: run, suite, or ci.",
    ),
    result: Optional[str] = typer.Option(
        None,
        "--result",
        help="History result to export: PASS or FAIL.",
    ),
    name: Optional[str] = typer.Option(
        None,
        "--name",
        help="History name to export exactly.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="History category to export exactly.",
    ),
    difficulty: Optional[str] = typer.Option(
        None,
        "--difficulty",
        help="History difficulty to export exactly.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output file if it already exists.",
    ),
) -> None:
    """Export local AgentGuard run history as JSON or CSV."""
    if limit is not None and limit <= 0:
        raise typer.BadParameter("limit must be positive.", param_hint="--limit")
    try:
        validated_format = _validate_history_export_format(export_format)
        validated_type = validate_run_type(run_type)
        validated_result = validate_result(result)
    except ValueError as error:
        raise typer.BadParameter(str(error)) from error

    records = list_history(
        limit=limit,
        run_type=validated_type,
        result=validated_result,
        name=name,
        category=category,
        difficulty=difficulty,
    )
    content = (
        export_history_json(records)
        if validated_format == "json"
        else export_history_csv(records)
    )
    if output is None:
        typer.echo(content, nl=False)
        return

    if output.exists() and not force:
        typer.echo(
            f"Error: output already exists: {output}. Use --force to overwrite.",
            err=True,
        )
        raise typer.Exit(2)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
    typer.echo(f"History exported: {output}")


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
    typer.echo(f"Manifest path: {result.report_paths.manifest or '-'}")
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


@gate_app.command("suite")
def gate_suite_command(
    suite_path: Path = typer.Argument(..., help="Path to the AgentGuard suite file."),
    baseline: Path = typer.Option(
        ...,
        "--baseline",
        help="Baseline JSON file to compare against.",
    ),
    allow_failures: bool = typer.Option(
        False,
        "--allow-failures",
        help="Do not fail the gate for failed suite runs.",
    ),
    allow_regressions: bool = typer.Option(
        False,
        "--allow-regressions",
        help="Do not fail the gate for baseline regressions.",
    ),
    allow_version_mismatch: bool = typer.Option(
        False,
        "--allow-version-mismatch",
        help="Do not fail the gate for benchmark version mismatches.",
    ),
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
    save_current_baseline: Optional[Path] = typer.Option(
        None,
        "--save-current-baseline",
        help="Write the current suite result as a baseline after the run.",
    ),
) -> None:
    """Run a suite as a CI gate against a required baseline."""
    try:
        filters = suite_filters_from_values(
            category=category,
            difficulty=difficulty,
            tags=tags,
        )
        result = run_suite(
            suite_path,
            compare_baseline_path=baseline,
            allow_version_mismatch=allow_version_mismatch,
            filters=filters,
        )
    except ValueError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    comparison = result.baseline_comparison
    has_regressions = bool(comparison and comparison.has_regressions)
    gate_failed = (
        (result.failed > 0 and not allow_failures)
        or (has_regressions and not allow_regressions)
    )
    gate_result = "FAIL" if gate_failed else "PASS"
    _echo_gate_summary(result, baseline, gate_result)

    if save_current_baseline is not None:
        baseline_path = write_suite_baseline(result, save_current_baseline)
        typer.echo(f"Current baseline saved: {baseline_path}")

    if gate_failed:
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
    allow_version_mismatch: bool = typer.Option(
        False,
        "--allow-version-mismatch",
        help="Compare against a baseline with different benchmark versions.",
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
            allow_version_mismatch=allow_version_mismatch,
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
        if comparison.version_mismatches:
            typer.echo("Benchmark version mismatches:")
            for message in comparison.version_mismatches:
                typer.echo(f"- {message}")
        else:
            typer.echo("Benchmark version mismatches: none")
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
    typer.echo(f"Suite manifest path: {result.manifest_path or '-'}")
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


@app.command("matrix")
def matrix_command(
    suite_path: Path = typer.Argument(..., help="Path to the AgentGuard suite file."),
    trials: int = typer.Option(
        1,
        "--trials",
        help="Number of attempts to run for each benchmark/agent combination.",
    ),
    workers: int = typer.Option(
        1,
        "--workers",
        help="Maximum number of matrix attempts to execute concurrently.",
    ),
    fail_fast: bool = typer.Option(
        False,
        "--fail-fast",
        help="Stop scheduling new attempts after the first failed result.",
    ),
    agents: Optional[list[str]] = typer.Option(
        None,
        "--agent",
        help="Override suite agents. Repeat to run each entry with multiple agents.",
    ),
    allow_failures: bool = typer.Option(
        False,
        "--allow-failures",
        help="Exit 0 even when one or more matrix runs fail.",
    ),
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
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for matrix report artifacts.",
    ),
    save_baseline: Optional[Path] = typer.Option(
        None,
        "--save-baseline",
        help="Write a matrix-compatible baseline JSON file after the run.",
    ),
    compare_baseline: Optional[Path] = typer.Option(
        None,
        "--compare-baseline",
        help="Compare this matrix against an existing matrix/suite baseline.",
    ),
    save_reliability_baseline: Optional[Path] = typer.Option(
        None,
        "--save-reliability-baseline",
        help="Write an aggregate matrix reliability baseline JSON file.",
    ),
    compare_reliability_baseline: Optional[Path] = typer.Option(
        None,
        "--compare-reliability-baseline",
        help="Compare aggregate matrix reliability against a saved baseline.",
    ),
    min_success_rate: Optional[float] = typer.Option(
        None,
        "--min-success-rate",
        help="Require overall and per-combination success rates at or above this percent.",
    ),
    max_success_rate_drop: float = typer.Option(
        0,
        "--max-success-rate-drop",
        help="Maximum allowed success-rate drop in percentage points.",
    ),
    max_average_score_drop: float = typer.Option(
        0,
        "--max-average-score-drop",
        help="Maximum allowed average-score drop in points.",
    ),
    allow_reliability_regressions: bool = typer.Option(
        False,
        "--allow-reliability-regressions",
        help="Exit 0 for reliability regressions while still reporting them.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing reliability baseline output file.",
    ),
    allow_regressions: bool = typer.Option(
        False,
        "--allow-regressions",
        help="Exit 0 even when baseline comparison finds regressions.",
    ),
    allow_version_mismatch: bool = typer.Option(
        False,
        "--allow-version-mismatch",
        help="Compare against a baseline with different benchmark versions.",
    ),
) -> None:
    """Run a suite across its configured agents or an agent override matrix."""
    try:
        filters = suite_filters_from_values(
            category=category,
            difficulty=difficulty,
            tags=tags,
        )
        result = run_matrix(
            suite_path,
            agents=agents,
            matrices_root=output_dir or Path(".agentguard/matrices"),
            compare_baseline_path=compare_baseline,
            allow_version_mismatch=allow_version_mismatch,
            filters=filters,
            trials=trials,
            save_reliability_baseline_path=save_reliability_baseline,
            compare_reliability_baseline_path=compare_reliability_baseline,
            min_success_rate=min_success_rate,
            max_success_rate_drop=max_success_rate_drop,
            max_average_score_drop=max_average_score_drop,
            force_reliability_baseline=force,
            workers=workers,
            fail_fast=fail_fast,
        )
    except KeyboardInterrupt as error:
        typer.echo("Matrix execution interrupted.", err=True)
        raise typer.Exit(130) from error
    except ValueError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Matrix Summary")
    typer.echo(f"Suite: {result.suite_id}")
    typer.echo(f"Agents: {', '.join(result.agents)}")
    if result.filters.has_filters():
        typer.echo(f"Filters: {format_suite_filters(result.filters)}")
    typer.echo(f"Trials per combination: {result.trials}")
    typer.echo(f"Workers: {result.effective_workers}/{result.requested_workers}")
    typer.echo(f"Execution mode: {result.execution_mode}")
    typer.echo(f"Execution duration: {result.duration_seconds:.3f} seconds")
    typer.echo(f"Attempts planned: {result.attempts_planned}")
    typer.echo(f"Attempts executed: {result.attempts_executed}")
    typer.echo(f"Stopped early: {'yes' if result.stopped_early else 'no'}")
    typer.echo(f"Total runs: {result.total_runs}")
    typer.echo(f"Total attempts: {result.reliability.attempts}")
    typer.echo(f"Passed: {result.passed}")
    typer.echo(f"Failed: {result.failed}")
    typer.echo(f"Pass rate: {result.pass_rate}%")
    interval = result.reliability.confidence_interval_95
    typer.echo(
        f"Overall success rate: {result.reliability.success_rate}% "
        f"(95% CI {interval.lower_bound}% to {interval.upper_bound}%)"
    )
    typer.echo(f"Average score: {result.average_score}")
    typer.echo("")
    typer.echo("Agent | Attempts | Passed | Failed | Success Rate | Average Score")
    typer.echo("--- | ---: | ---: | ---: | ---: | ---:")
    for agent, summary in result.per_agent.items():
        reliability = result.per_agent_reliability[agent]
        typer.echo(
            f"{agent} | {summary.runs} | {summary.passed} | "
            f"{summary.failed} | {reliability.success_rate}% | "
            f"{reliability.average_score}"
        )
    if result.baseline_comparison is not None:
        comparison = result.baseline_comparison
        typer.echo("")
        typer.echo("Baseline comparison")
        typer.echo(f"Baseline: {comparison.baseline_path}")
        typer.echo(f"Regressions: {'yes' if comparison.has_regressions else 'no'}")
        for message in comparison.regressions:
            typer.echo(f"- {message}")
    if save_reliability_baseline is not None:
        typer.echo(f"Reliability baseline saved: {save_reliability_baseline}")
    if result.reliability_comparison is not None:
        comparison = result.reliability_comparison
        thresholds = comparison.thresholds
        typer.echo("")
        typer.echo("Reliability comparison")
        if comparison.baseline_path is not None:
            typer.echo(f"Reliability baseline compared: {comparison.baseline_path}")
        if thresholds.min_success_rate is not None:
            typer.echo(
                f"Minimum required success rate: {thresholds.min_success_rate}%"
            )
        typer.echo(
            "Maximum success-rate drop: "
            f"{thresholds.max_success_rate_drop} points"
        )
        typer.echo(
            "Maximum average-score drop: "
            f"{thresholds.max_average_score_drop} points"
        )
        typer.echo(
            "Reliability regressions: "
            f"{'yes' if comparison.has_regressions else 'no'}"
        )
        for detail in comparison.regressions:
            typer.echo(f"- {detail.message}")
        for key in comparison.new_combinations:
            typer.echo(f"- New current combination: {key}")
        for message in comparison.version_mismatches:
            typer.echo(f"- {message}")
    typer.echo(f"Matrix JSON report path: {result.json_report_path}")
    typer.echo(f"Matrix Markdown report path: {result.markdown_report_path}")
    typer.echo(f"Matrix manifest path: {result.manifest_path or '-'}")

    if save_baseline is not None:
        baseline_path = write_suite_baseline(result, save_baseline)
        typer.echo(f"Baseline saved: {baseline_path}")
    if (
        result.baseline_comparison is not None
        and result.baseline_comparison.has_regressions
        and not allow_regressions
    ):
        raise typer.Exit(1)
    if (
        result.reliability_comparison is not None
        and result.reliability_comparison.has_regressions
        and not allow_reliability_regressions
    ):
        raise typer.Exit(1)
    if result.failed > 0 and not allow_failures:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
