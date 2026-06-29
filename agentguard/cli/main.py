import json
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
from agentguard.benchmarks.fuzz import (
    DEFAULT_OUTPUT_DIR as DEFAULT_FUZZ_OUTPUT_DIR,
    run_fuzz_study,
)
from agentguard.benchmarks.packs import (
    BenchmarkPackError,
    BenchmarkPackIntegrityError,
    export_benchmark_pack,
    import_benchmark_pack,
    inspect_benchmark_pack,
    verify_benchmark_pack,
)
from agentguard.benchmarks.index import (
    create_pack_index,
    install_index_pack,
    list_pack_index,
    resolve_index_pack,
    verify_pack_index,
)
from agentguard.benchmarks.signing import (
    BenchmarkPackSignatureError,
    add_trusted_key,
    generate_hmac_keypair,
    init_trust_policy,
    sign_benchmark_pack,
    trust_policy_summary,
    verify_benchmark_pack_signature,
    verify_trust_policy,
)
from agentguard.core.baseline import write_suite_baseline
from agentguard.core.benchmark import parse_agent_list, run_multi_agent_benchmark
from agentguard.core.ci import run_ci
from agentguard.core.matrix import MatrixResult, run_matrix
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
from agentguard.diagnostics.mutations import (
    DEFAULT_CATALOG_PATH as DEFAULT_MUTATION_CATALOG_PATH,
)
from agentguard.diagnostics.mutations import run_mutation_audit
from agentguard.diagnostics.ablation import run_policy_ablation
from agentguard.diagnostics.matrix_stress import (
    DEFAULT_ATTEMPTS as DEFAULT_STRESS_ATTEMPTS,
)
from agentguard.diagnostics.matrix_stress import (
    DEFAULT_WORKERS as DEFAULT_STRESS_WORKERS,
)
from agentguard.diagnostics.matrix_stress import (
    normalize_positive_int_values,
    run_matrix_stress,
)
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
from agentguard.guard.filesystem import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    GuardMode,
    validate_guard_configuration,
)
from agentguard.guard.incident import incident_summary
from agentguard.io import atomic_write_text
from agentguard.evaluation.harness import (
    build_evaluation_plan,
    format_evaluation_plan,
    run_evaluation,
    validate_evaluation,
)
from agentguard.evaluation.report import (
    DEFAULT_OUTPUT_PATH as DEFAULT_EVALUATION_REPORT_PATH,
    EvaluationReportError,
    EvaluationReportOptions,
    generate_evaluation_report,
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
from agentguard.reports.exports import (
    UnsupportedExportInput,
    export_junit,
    export_sarif,
)
from agentguard.reports.github_summary import write_github_step_summary
from agentguard.reports.site import (
    DEFAULT_HISTORY_DB_PATH as DEFAULT_SITE_HISTORY_DB_PATH,
    DEFAULT_REPORTS_ROOT as DEFAULT_SITE_REPORTS_ROOT,
    StaticSiteOptions,
    generate_static_report_site,
)
from agentguard.traces.execution import (
    TraceExportOptions,
    export_execution_trace,
    load_execution_trace,
    trace_summary,
    verify_execution_trace,
)
from agentguard.traces.metamorphic import (
    metamorphic_summary,
    parse_transform_selection,
    run_metamorphic_study,
)
from agentguard.traces.replay import (
    inspect_replayability,
    replay_trace,
    replayability_summary,
)

app = typer.Typer(
    help="Local-first safety and reliability evaluation framework for AI coding agents."
)
reports_app = typer.Typer(help="List and inspect local AgentGuard reports.")
app.add_typer(reports_app, name="reports")
history_app = typer.Typer(help="List and summarize local AgentGuard run history.")
app.add_typer(history_app, name="history")
benchmarks_app = typer.Typer(help="List and inspect registered AgentGuard benchmarks.")
app.add_typer(benchmarks_app, name="benchmarks")
benchmark_pack_app = typer.Typer(help="Export, inspect, verify, and import benchmark packs.")
benchmarks_app.add_typer(benchmark_pack_app, name="pack")
benchmark_pack_trust_app = typer.Typer(help="Manage local benchmark pack trust policies.")
benchmark_pack_app.add_typer(benchmark_pack_trust_app, name="trust")
benchmark_pack_index_app = typer.Typer(help="Create, list, verify, and install pack indexes.")
benchmark_pack_app.add_typer(benchmark_pack_index_app, name="index")
gate_app = typer.Typer(help="CI gate commands for AgentGuard suites.")
app.add_typer(gate_app, name="gate")
manifest_app = typer.Typer(help="Inspect and verify execution manifests.")
app.add_typer(manifest_app, name="manifest")
trace_app = typer.Typer(
    help="Export, inspect, verify, and replay execution traces."
)
app.add_typer(trace_app, name="trace")
evaluate_app = typer.Typer(help="Validate and run external coding-agent profiles.")
app.add_typer(evaluate_app, name="evaluate")
app.add_typer(evaluate_app, name="evaluation")
diagnostics_app = typer.Typer(help="Run deterministic AgentGuard diagnostics.")
app.add_typer(diagnostics_app, name="diagnostics")
guard_app = typer.Typer(help="Inspect online guard incident reports.")
app.add_typer(guard_app, name="guard")


def _echo_matrix_guard_summary(result: MatrixResult) -> None:
    summary = result.guard_summary
    typer.echo("Guard incidents:")
    typer.echo(f"- Incident runs: {summary.incident_runs}")
    typer.echo(f"- Blocked runs: {summary.blocked_runs}")
    typer.echo(f"- Audit-only runs: {summary.audit_only_runs}")
    typer.echo(f"- Total violations: {summary.violations_total}")
    typer.echo(f"- Filesystem violations: {summary.filesystem_violations}")
    typer.echo(f"- Command violations: {summary.command_violations}")
    timing = summary.time_to_first_violation
    if timing.samples:
        typer.echo(f"- Time to first violation p95: {timing.p95_ms} ms")


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


@diagnostics_app.command("mutations")
def diagnostics_mutations_command(
    catalog: Path = typer.Option(
        DEFAULT_MUTATION_CATALOG_PATH,
        "--catalog",
        help="Versioned mutation catalog YAML.",
    ),
    mutations: Optional[list[str]] = typer.Option(
        None,
        "--mutation",
        help="Mutation IDs to run. Repeat or use commas.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="Run only mutations in this category.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for mutation audit artifacts.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Fail on any additional unexpected failed check.",
    ),
    allow_detection_failures: bool = typer.Option(
        False,
        "--allow-detection-failures",
        help="Exit 0 while preserving detection failures in reports.",
    ),
) -> None:
    """Audit check detection behavior with controlled repository mutations."""
    try:
        result = run_mutation_audit(
            catalog,
            mutation_ids=mutations,
            category=category,
            output_dir=output_dir,
            strict=strict,
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Policy Mutation Audit")
    typer.echo(f"Mutations: {result.total_mutations}")
    typer.echo(f"Safe mutations: {result.safe_mutations}")
    typer.echo(f"Unsafe mutations: {result.unsafe_mutations}")
    typer.echo(
        "Controlled mutation detection rate: "
        f"{result.controlled_mutation_detection_rate:.2f}%"
    )
    typer.echo(f"Safe-fixture pass rate: {result.safe_fixture_pass_rate:.2f}%")
    typer.echo(f"Missed detections: {result.missed_detections}")
    typer.echo(f"Forbidden detections: {result.forbidden_detections}")
    typer.echo(f"Unexpected detections: {result.unexpected_detections}")
    typer.echo("")
    typer.echo("Check | Expected | Observed | Misses | Unexpected")
    typer.echo("--- | ---: | ---: | ---: | ---:")
    for check in result.per_check:
        typer.echo(
            f"{check.check} | {check.expected_detections} | "
            f"{check.observed_detections} | {check.misses} | "
            f"{check.unexpected_detections}"
        )
    typer.echo(f"JSON report path: {result.json_report_path}")
    typer.echo(f"Markdown report path: {result.markdown_report_path}")
    if result.has_failures and not allow_detection_failures:
        raise typer.Exit(1)


@benchmarks_app.command("fuzz")
def benchmarks_fuzz_command(
    dimensions: Optional[list[str]] = typer.Option(
        None,
        "--dimension",
        help="Fuzz dimensions to include. Repeat or use commas.",
    ),
    limit: Optional[int] = typer.Option(
        None,
        "--limit",
        help="Maximum number of variants after deterministic seeded ordering.",
    ),
    seed: str = typer.Option(
        "agentguard",
        "--seed",
        help="Deterministic seed controlling variant order and selection.",
    ),
    output_dir: Path = typer.Option(
        DEFAULT_FUZZ_OUTPUT_DIR,
        "--output-dir",
        help="Root directory for benchmark fuzz artifacts.",
    ),
    trials: int = typer.Option(1, "--trials", help="Trials per variant."),
    workers: int = typer.Option(
        1,
        "--workers",
        help="Deterministic aggregation worker count metadata.",
    ),
    static_only: bool = typer.Option(
        False,
        "--static-only",
        help="Validate variants and expectations without running checks.",
    ),
    minimize_failures: bool = typer.Option(
        False,
        "--minimize-failures",
        help="Minimize failed fuzz variants before writing reports.",
    ),
    promote_failures: Optional[Path] = typer.Option(
        None,
        "--promote-failures",
        help="Write minimized failure promotion packages to this path.",
    ),
    max_minimize_steps: int = typer.Option(
        50,
        "--max-minimize-steps",
        help="Maximum deterministic simplification attempts per failed variant.",
    ),
    promotion_format: str = typer.Option(
        "fixture",
        "--promotion-format",
        help="Promotion package format: fixture or patch.",
    ),
    promotion_prefix: str = typer.Option(
        "fuzz_regression",
        "--promotion-prefix",
        help="Prefix for generated promotion package directories.",
    ),
    allow_fuzz_failures: bool = typer.Option(
        False,
        "--allow-fuzz-failures",
        help="Exit 0 while preserving fuzz findings in reports.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing deterministic study directory.",
    ),
) -> None:
    """Generate and run deterministic policy-focused benchmark variants."""
    try:
        result = run_fuzz_study(
            dimensions=dimensions,
            limit=limit,
            seed=seed,
            output_dir=output_dir,
            trials=trials,
            workers=workers,
            static_only=static_only,
            force=force,
            minimize_failures=minimize_failures,
            promote_failures=promote_failures,
            max_minimize_steps=max_minimize_steps,
            promotion_format=promotion_format,
            promotion_prefix=promotion_prefix,
        )
    except (FileExistsError, OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Benchmark Fuzz Study")
    typer.echo(f"Dimensions: {', '.join(result.dimensions)}")
    typer.echo(f"Variants generated: {result.total_variants}")
    typer.echo(
        f"Variants passed/failed: {result.variants_passed}/"
        f"{result.variants_failed}"
    )
    typer.echo("Detection coverage by dimension:")
    for dimension, summary in result.per_dimension.items():
        typer.echo(
            f"- {dimension}: {float(summary['pass_rate']):.2f}% "
            f"({summary['passed_runs']}/{summary['runs']} runs)"
        )
    typer.echo(
        "Missed/forbidden detections: "
        f"{result.missed_expected_detections}/"
        f"{result.forbidden_unexpected_detections}"
    )
    typer.echo(
        "Controlled detection rate: "
        f"{result.controlled_detection_rate:.2f}%"
    )
    typer.echo(f"Safe-variant pass rate: {result.safe_variant_pass_rate:.2f}%")
    if result.minimized_failures:
        typer.echo(f"Minimized failures: {len(result.minimized_failures)}")
        for item in result.minimized_failures:
            typer.echo(
                f"- {item.variant_id}: reduction "
                f"{item.reduction_percentage:.2f}%, "
                f"steps {item.steps_accepted}/{item.steps_attempted}, "
                f"preserved {'yes' if item.failure_preserved else 'no'}"
            )
    if result.promotion_paths:
        typer.echo("Promotion paths:")
        for path in result.promotion_paths:
            typer.echo(f"- {path}")
    typer.echo(f"JSON report path: {result.json_report_path}")
    typer.echo(f"Markdown report path: {result.markdown_report_path}")
    if result.has_failures and not allow_fuzz_failures:
        raise typer.Exit(1)


@diagnostics_app.command("ablation")
def diagnostics_ablation_command(
    catalog: Path = typer.Option(
        DEFAULT_MUTATION_CATALOG_PATH,
        "--catalog",
        help="Versioned mutation catalog YAML.",
    ),
    checks: Optional[list[str]] = typer.Option(
        None,
        "--check",
        help="Checks to study. Repeat or use commas.",
    ),
    mutations: Optional[list[str]] = typer.Option(
        None,
        "--mutation",
        help="Mutation IDs to run. Repeat or use commas.",
    ),
    category: Optional[str] = typer.Option(
        None,
        "--category",
        help="Run only mutations in this category.",
    ),
    trials: int = typer.Option(1, "--trials", help="Trials per condition."),
    workers: int = typer.Option(1, "--workers", help="Concurrent trial workers."),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for ablation study artifacts.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing study directory if IDs collide.",
    ),
    allow_study_failures: bool = typer.Option(
        False,
        "--allow-study-failures",
        help="Exit 0 while preserving invalid, unstable, or failed findings.",
    ),
) -> None:
    """Measure controlled policy-check contribution by single-check ablation."""
    try:
        result = run_policy_ablation(
            catalog,
            check_values=checks,
            mutation_ids=mutations,
            category=category,
            trials=trials,
            workers=workers,
            output_dir=output_dir,
            force=force,
        )
    except (FileExistsError, OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Policy Ablation Study")
    typer.echo(
        f"Control valid: {'yes' if result.control_validity.valid else 'no'}"
    )
    typer.echo(
        "Controlled mutation detection rate: "
        f"{float(result.control_metrics['controlled_mutation_detection_rate']):.2f}%"
    )
    typer.echo(
        "Safe-fixture pass rate: "
        f"{float(result.control_metrics['safe_fixture_pass_rate']):.2f}%"
    )
    typer.echo("")
    typer.echo(
        "Disabled Check | Escaped Mutations | Detection Delta | "
        "Newly Passing Unsafe | Safe Pass Delta"
    )
    typer.echo("--- | ---: | ---: | ---: | ---:")
    for condition in result.conditions[1:]:
        typer.echo(
            f"{condition.disabled_check} | "
            f"{len(condition.escaped_unsafe_mutations)} | "
            f"{condition.detection_rate_delta_percentage_points:+.2f} pp | "
            f"{len(condition.newly_passing_unsafe_mutations)} | "
            f"{condition.safe_fixture_pass_rate_delta_percentage_points:+.2f} pp"
        )
    typer.echo("")
    typer.echo("Unique contribution:")
    if result.check_contributions is None:
        typer.echo("suppressed because the control is invalid")
    else:
        for contribution in result.check_contributions:
            typer.echo(
                f"{contribution.check}: "
                f"{contribution.detections_uniquely_attributable} unique, "
                f"{contribution.detections_redundantly_covered} redundant"
            )
    typer.echo(f"JSON report path: {result.json_report_path}")
    typer.echo(f"Markdown report path: {result.markdown_report_path}")
    if result.has_study_failures and not allow_study_failures:
        raise typer.Exit(1)


@diagnostics_app.command("matrix-stress")
def diagnostics_matrix_stress_command(
    attempts: Optional[list[str]] = typer.Option(
        None,
        "--attempts",
        help="Attempt counts. Repeat or use commas.",
    ),
    workers: Optional[list[str]] = typer.Option(
        None,
        "--workers",
        help="Worker counts including 1. Repeat or use commas.",
    ),
    task_duration_ms: int = typer.Option(
        25,
        "--task-duration-ms",
        help="Synthetic task sleep duration in milliseconds.",
    ),
    failure_rate: float = typer.Option(
        0.0,
        "--failure-rate",
        help="Deterministic synthetic failure percentage.",
    ),
    fail_fast: bool = typer.Option(
        False,
        "--fail-fast",
        help="Stop replenishing work after a failed submitted wave.",
    ),
    repetitions: int = typer.Option(
        3,
        "--repetitions",
        help="Repetitions per attempts/workers cell.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for matrix stress artifacts.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing study directory if IDs collide.",
    ),
    unsafe_large_run: bool = typer.Option(
        False,
        "--unsafe-large-run",
        help="Allow inputs above documented safety caps.",
    ),
    allow_study_failures: bool = typer.Option(
        False,
        "--allow-study-failures",
        help="Exit 0 while preserving integrity failures in reports.",
    ),
) -> None:
    """Stress bounded matrix scheduling with a synthetic internal workload."""
    try:
        attempt_values = normalize_positive_int_values(
            attempts,
            default=DEFAULT_STRESS_ATTEMPTS,
            option_name="attempts",
        )
        worker_values = normalize_positive_int_values(
            workers,
            default=DEFAULT_STRESS_WORKERS,
            option_name="workers",
        )
        result = run_matrix_stress(
            attempts=attempt_values,
            workers=worker_values,
            task_duration_ms=task_duration_ms,
            failure_rate_percent=failure_rate,
            fail_fast=fail_fast,
            repetitions=repetitions,
            output_dir=output_dir,
            force=force,
            unsafe_large_run=unsafe_large_run,
        )
    except (FileExistsError, OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    summary = result.scaling_summary
    typer.echo("AgentGuard Matrix Stress Study")
    typer.echo(
        "Attempted sizes: " + ", ".join(str(value) for value in result.attempts)
    )
    typer.echo(
        "Workers: " + ", ".join(str(value) for value in result.workers)
    )
    typer.echo(f"Repetitions: {result.repetitions}")
    typer.echo(
        "Maximum validated attempts: "
        f"{summary['maximum_validated_attempts'] or '-'}"
    )
    typer.echo(
        "Best measured speedup: "
        f"{float(summary['best_measured_speedup']):.2f}x "
        f"at {summary['best_speedup_workers']} workers"
    )
    typer.echo(
        "Best throughput worker count: "
        f"{summary['best_throughput_workers']}"
    )
    typer.echo(
        f"Integrity status: {'PASS' if result.integrity_passed else 'FAIL'}"
    )
    typer.echo(
        f"Maximum traced Python memory: "
        f"{summary['maximum_peak_memory_bytes']} bytes"
    )
    typer.echo(f"JSON report path: {result.json_report_path}")
    typer.echo(f"Markdown report path: {result.markdown_report_path}")
    if not result.integrity_passed and not allow_study_failures:
        raise typer.Exit(1)


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


@trace_app.command("export")
def trace_export(
    source: Path = typer.Argument(
        ...,
        help="Run directory, report.json, or manifest.json.",
    ),
    output: Path = typer.Option(..., "--output", help="Trace JSONL output path."),
    include_diff: bool = typer.Option(
        False,
        "--include-diff",
        help="Include bounded, sanitized unified diffs.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing trace output.",
    ),
) -> None:
    """Export a portable execution trace from existing run artifacts."""
    try:
        path = export_execution_trace(
            source,
            output,
            TraceExportOptions(include_diff=include_diff, force=force),
        )
    except (FileExistsError, OSError, TypeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Trace exported: {path}")


@trace_app.command("show")
def trace_show(
    path: Path = typer.Argument(..., help="Path to an execution trace."),
) -> None:
    """Print a concise, content-safe execution trace summary."""
    try:
        trace = load_execution_trace(path)
        verification = verify_execution_trace(path)
        if verification.exit_code == 2:
            raise ValueError(verification.messages[0])
    except (OSError, TypeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(trace_summary(trace))


@guard_app.command("show")
def guard_show(
    incident_path: Path = typer.Argument(..., help="Path to guard incident.json."),
) -> None:
    """Print a compact summary of a guard incident."""
    try:
        data = json.loads(incident_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("incident JSON must be an object")
    except (OSError, json.JSONDecodeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(incident_summary(data))


@guard_app.command("list")
def guard_list(
    limit: int = typer.Option(20, "--limit", help="Maximum incidents to list."),
) -> None:
    """List recent guard incidents recorded in history."""
    if limit <= 0:
        raise typer.BadParameter("limit must be positive.", param_hint="--limit")
    records = [
        record for record in list_history(limit=limit) if record.guard_incident_path
    ]
    if not records:
        typer.echo("No guard incidents found.")
        return
    for record in records:
        blocked = "blocked" if record.guard_blocked else "audit"
        typer.echo(
            f"{record.created_at}  {record.name}  {record.agent or '-'}  "
            f"{blocked}  {record.guard_violations_total} violation(s)  "
            f"{record.guard_incident_path}"
        )


@trace_app.command("verify")
def trace_verify(
    path: Path = typer.Argument(..., help="Path to an execution trace."),
    strict_sources: bool = typer.Option(
        False,
        "--strict-sources",
        help="Fail when any referenced source artifact is unavailable.",
    ),
) -> None:
    """Verify trace structure, hash chain, root hash, and source artifacts."""
    result = verify_execution_trace(path, strict_sources=strict_sources)
    for message in result.messages:
        typer.echo(message)
    if result.exit_code:
        raise typer.Exit(result.exit_code)


@trace_app.command("replayability")
def trace_replayability(
    path: Path = typer.Argument(..., help="Path to an execution trace."),
    strict_sources: bool = typer.Option(
        False,
        "--strict-sources",
        help="Require all referenced source artifacts to be available.",
    ),
) -> None:
    """Report whether a verified trace contains complete replay evidence."""
    try:
        status, _ = inspect_replayability(
            path,
            strict_sources=strict_sources,
        )
        trace = load_execution_trace(path)
    except (OSError, TypeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(replayability_summary(trace, status))
    if not status.replayable:
        raise typer.Exit(1)


@trace_app.command("replay")
def trace_replay(
    path: Path = typer.Argument(..., help="Path to an execution trace."),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for replay reports.",
    ),
    strict_sources: bool = typer.Option(
        False,
        "--strict-sources",
        help="Require all referenced source artifacts to be available.",
    ),
    require_equivalence: bool = typer.Option(
        True,
        "--require-equivalence/--no-require-equivalence",
        help="Exit nonzero unless replay is exactly equivalent.",
    ),
    allow_divergence: bool = typer.Option(
        False,
        "--allow-divergence",
        help="Exit zero while retaining divergence details.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing replay report directory.",
    ),
) -> None:
    """Replay captured evidence through the real policy and scoring pipeline."""
    try:
        result = replay_trace(
            path,
            output_dir=output_dir,
            strict_sources=strict_sources,
            force=force,
        )
    except (FileExistsError, OSError, TypeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("AgentGuard Trace Replay")
    typer.echo(f"Trace: {result.trace_id}")
    typer.echo(f"Equivalence: {result.equivalence}")
    typer.echo(
        f"Recorded: {result.recorded_result} / {result.recorded_score}"
    )
    typer.echo(
        f"Recomputed: {result.recomputed_result} / {result.recomputed_score}"
    )
    typer.echo(f"JSON report: {result.report_paths.json}")
    typer.echo(f"Markdown report: {result.report_paths.markdown}")
    typer.echo("External execution: none")
    if (
        result.equivalence != "exact"
        and require_equivalence
        and not allow_divergence
    ):
        raise typer.Exit(1)


@trace_app.command("metamorphic")
def trace_metamorphic(
    source: Path = typer.Argument(..., help="Trace path or directory."),
    transforms: Optional[list[str]] = typer.Option(
        None,
        "--transform",
        help="Transform name, repeatable or comma-separated. Defaults to all.",
    ),
    output_dir: Optional[Path] = typer.Option(
        None,
        "--output-dir",
        help="Root directory for metamorphic study reports.",
    ),
    trials: int = typer.Option(
        1,
        "--trials",
        help="Deterministic trials per transform.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Replace an existing metamorphic study directory.",
    ),
    strict_sources: bool = typer.Option(
        False,
        "--strict-sources",
        help="Require referenced source artifacts to be available.",
    ),
    allow_robustness_failures: bool = typer.Option(
        False,
        "--allow-robustness-failures",
        help="Exit zero while preserving robustness findings.",
    ),
) -> None:
    """Run deterministic metamorphic trace replay transformations."""
    try:
        selected = parse_transform_selection(transforms)
        result = run_metamorphic_study(
            source,
            transform_names=selected,
            output_dir=output_dir,
            trials=trials,
            force=force,
            strict_sources=strict_sources,
        )
    except (FileExistsError, FileNotFoundError, OSError, TypeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(metamorphic_summary(result))
    failures = [
        case for case in result.cases if not case.robustness_passed
    ]
    if failures and not allow_robustness_failures:
        raise typer.Exit(1)


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


@evaluate_app.command("report")
def evaluation_report(
    output: Path = typer.Option(
        DEFAULT_EVALUATION_REPORT_PATH,
        "--output",
        help="Markdown evaluation report output path.",
    ),
    summary_json: Optional[Path] = typer.Option(
        None,
        "--summary-json",
        help="Machine-readable summary JSON path. Defaults next to --output.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing report outputs.",
    ),
    include_machine_specific: bool = typer.Option(
        False,
        "--include-machine-specific",
        help="Include host-specific timing, speed, and memory metrics.",
    ),
    release_candidate: Optional[Path] = typer.Option(
        None,
        "--release-candidate",
        help="Release-candidate summary JSON input.",
    ),
    mutation: Optional[Path] = typer.Option(
        None,
        "--mutation",
        help="Mutation detection summary JSON input.",
    ),
    ablation: Optional[Path] = typer.Option(
        None,
        "--ablation",
        help="Policy ablation summary JSON input.",
    ),
    overhead: Optional[Path] = typer.Option(
        None,
        "--overhead",
        help="Overhead summary JSON input.",
    ),
    scale: Optional[Path] = typer.Option(
        None,
        "--scale",
        help="Matrix scale/stress summary JSON input.",
    ),
    resume: Optional[Path] = typer.Option(
        None,
        "--resume",
        help="Resume/recovery summary JSON input.",
    ),
    replay: Optional[Path] = typer.Option(
        None,
        "--replay",
        help="Trace replay equivalence summary JSON input.",
    ),
    counterfactual: Optional[Path] = typer.Option(
        None,
        "--counterfactual",
        help="Counterfactual policy comparison summary JSON input.",
    ),
    metamorphic: Optional[Path] = typer.Option(
        None,
        "--metamorphic",
        help="Metamorphic testing summary JSON input.",
    ),
    coverage: Optional[Path] = typer.Option(
        None,
        "--coverage",
        help="Coverage summary JSON input.",
    ),
) -> None:
    """Generate a consolidated evaluation report from existing summaries."""
    overrides = {
        key: value
        for key, value in {
            "release_candidate": release_candidate,
            "mutation": mutation,
            "ablation": ablation,
            "overhead": overhead,
            "scale": scale,
            "resume": resume,
            "replay": replay,
            "counterfactual": counterfactual,
            "metamorphic": metamorphic,
            "coverage": coverage,
        }.items()
        if value is not None
    }
    try:
        result = generate_evaluation_report(
            EvaluationReportOptions(
                output_path=output,
                summary_json_path=summary_json,
                force=force,
                include_machine_specific=include_machine_specific,
                input_overrides=overrides,
            )
        )
    except (FileExistsError, OSError, EvaluationReportError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo(f"Evaluation report: {result.markdown_path}")
    typer.echo(f"Summary JSON: {result.summary_json_path}")
    typer.echo(f"Sources: {len(result.sources)}")
    if result.missing_sections:
        typer.echo("Unavailable: " + ", ".join(result.missing_sections))
    if result.omitted_sections:
        typer.echo("Omitted: " + ", ".join(result.omitted_sections))


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
    checkpoint: Optional[Path] = typer.Option(None, "--checkpoint"),
    resume: Optional[Path] = typer.Option(None, "--resume"),
    checkpoint_every: int = typer.Option(1, "--checkpoint-every"),
    retry_failed: bool = typer.Option(False, "--retry-failed"),
    force_resume: bool = typer.Option(False, "--force-resume"),
    guard_mode: GuardMode = typer.Option(
        GuardMode.OFF,
        "--guard-mode",
        help="Online guard mode for every evaluation attempt: off, audit, or enforce.",
    ),
    guard_poll_interval: float = typer.Option(
        DEFAULT_POLL_INTERVAL_SECONDS,
        "--guard-poll-interval",
        help="Guard polling interval in seconds for every evaluation attempt.",
    ),
) -> None:
    """Run a confirmed external coding-agent evaluation through matrix mode."""
    try:
        _validate_guard_poll_interval(guard_poll_interval)
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
            checkpoint_path=checkpoint,
            resume_path=resume,
            checkpoint_every=checkpoint_every,
            retry_failed=retry_failed,
            force_resume=force_resume,
            guard_mode=guard_mode,
            guard_poll_interval_seconds=guard_poll_interval,
        )
    except typer.Exit:
        raise
    except KeyboardInterrupt as error:
        typer.echo("External agent evaluation interrupted.", err=True)
        active_checkpoint = resume or checkpoint
        if active_checkpoint is not None:
            resolved = active_checkpoint.expanduser().resolve()
            typer.echo(f"Checkpoint marked interrupted: {resolved}", err=True)
        raise typer.Exit(130) from error
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("AgentGuard External Agent Evaluation")
    typer.echo(f"Profile: {result.profile_name} ({result.profile_id})")
    typer.echo(f"Model: {result.profile_model or '-'}")
    typer.echo(f"Guard mode: {result.guard_mode}")
    typer.echo(
        f"Guard poll interval: {result.guard_poll_interval_seconds} seconds"
    )
    _echo_matrix_guard_summary(result)
    typer.echo(f"Attempts: {result.attempts_executed}")
    if result.checkpoint_path is not None:
        typer.echo(f"Checkpoint: {result.checkpoint_path}")
        typer.echo(f"Attempts reused: {result.attempts_reused}")
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


@benchmark_pack_app.command("export")
def benchmarks_pack_export(
    benchmark_ids: Optional[list[str]] = typer.Option(
        None,
        "--benchmark",
        help="Benchmark IDs to export. Repeat or use commas.",
    ),
    registry: Path = typer.Option(
        DEFAULT_REGISTRY_PATH,
        "--registry",
        help="Path to the benchmark registry YAML file.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        help="Path for the deterministic .zip benchmark pack.",
    ),
    include_docs: bool = typer.Option(
        False,
        "--include-docs",
        help="Include benchmark documentation files.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing pack output.",
    ),
) -> None:
    """Export registered benchmarks as a portable deterministic pack."""
    try:
        result = export_benchmark_pack(
            registry_path=registry,
            output_path=output,
            benchmark_values=benchmark_ids,
            include_docs=include_docs,
            force=force,
        )
    except (FileExistsError, OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Pack exported: {result['path']}")
    typer.echo(f"Pack ID: {result['pack_id']}")
    typer.echo(f"Benchmarks: {result['benchmark_count']}")
    typer.echo(f"Files: {result['file_count']}")
    typer.echo(f"Root digest: {result['root_digest']}")


@benchmark_pack_app.command("inspect")
def benchmarks_pack_inspect(
    pack: Path = typer.Argument(..., help="Benchmark pack .zip path."),
) -> None:
    """Inspect a benchmark pack without extracting it."""
    try:
        result = inspect_benchmark_pack(pack)
    except BenchmarkPackIntegrityError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (OSError, BenchmarkPackError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("AgentGuard Benchmark Pack")
    typer.echo(f"Pack ID: {result['pack_id']}")
    typer.echo(f"Pack version: {result['pack_version']}")
    typer.echo(f"Root digest: {result['root_digest']}")
    typer.echo("Benchmarks:")
    for benchmark in result["benchmarks"]:
        typer.echo(f"- {benchmark['id']}@{benchmark['version']}")
    typer.echo("Files:")
    for file in result["files"]:
        typer.echo(f"- {file['path']} {file['sha256']} {file['size']} bytes")
    typer.echo("Docs:")
    docs = result["docs"]
    if docs:
        for doc in docs:
            typer.echo(f"- {doc}")
    else:
        typer.echo("- none")
    typer.echo(f"Contracts: {result['contract_status']}")


@benchmark_pack_app.command("verify")
def benchmarks_pack_verify(
    pack: Path = typer.Argument(..., help="Benchmark pack .zip path."),
) -> None:
    """Verify pack schema, hashes, paths, and registry/contract/config consistency."""
    try:
        result = verify_benchmark_pack(pack)
    except BenchmarkPackIntegrityError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (OSError, BenchmarkPackError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("Benchmark pack verification: PASS")
    typer.echo(f"Pack ID: {result.manifest['pack_id']}")
    typer.echo(f"Benchmarks: {len(result.manifest['benchmarks'])}")
    typer.echo(f"Files: {len(result.files)}")
    typer.echo(f"Root digest: {result.root_digest}")


@benchmark_pack_app.command("keygen")
def benchmarks_pack_keygen(
    output_dir: Path = typer.Option(
        ...,
        "--output-dir",
        help="Directory for generated HMAC signing key files.",
    ),
    name: str = typer.Option(
        ...,
        "--name",
        help="Human-readable signer name.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing key files.",
    ),
) -> None:
    """Generate local HMAC signing and verification key files."""
    try:
        result = generate_hmac_keypair(output_dir, name, force=force)
    except (FileExistsError, OSError, ValueError, BenchmarkPackError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Key ID: {result.key_id}")
    typer.echo(f"Private key: {result.private_key_path}")
    typer.echo(f"Verification key: {result.public_key_path}")
    typer.echo("Warning: HMAC keys are shared secrets. Do not commit private keys.")
    typer.echo(
        "Warning: the verification key also contains HMAC secret material; "
        "commit it only for intentionally shared local CI trust."
    )


@benchmark_pack_app.command("sign")
def benchmarks_pack_sign(
    pack: Path = typer.Argument(..., help="Benchmark pack .zip path."),
    key: Path = typer.Option(..., "--key", help="Private HMAC key JSON path."),
    output: Path = typer.Option(..., "--output", help="Detached signature JSON path."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing signature output.",
    ),
) -> None:
    """Sign a verified benchmark pack root digest."""
    try:
        signature = sign_benchmark_pack(pack, key, output, force=force)
    except (FileExistsError, OSError, BenchmarkPackError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Signature written: {output}")
    typer.echo(f"Pack ID: {signature['pack_id']}")
    typer.echo(f"Root digest: {signature['pack_root_digest']}")
    typer.echo(f"Key ID: {signature['key_id']}")
    typer.echo(f"Algorithm: {signature['algorithm']}")


@benchmark_pack_app.command("verify-signature")
def benchmarks_pack_verify_signature(
    pack: Path = typer.Argument(..., help="Benchmark pack .zip path."),
    signature: Path = typer.Option(..., "--signature", help="Detached signature JSON path."),
    key: Path = typer.Option(..., "--key", help="Verification key JSON path."),
) -> None:
    """Verify a detached benchmark pack signature."""
    try:
        result = verify_benchmark_pack_signature(pack, signature, key)
    except BenchmarkPackIntegrityError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (OSError, BenchmarkPackError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(result.message)
    typer.echo(f"Status: {result.status}")
    if result.key_id is not None:
        typer.echo(f"Key ID: {result.key_id}")
    if not result.valid:
        raise typer.Exit(1)


@benchmark_pack_trust_app.command("init")
def benchmarks_pack_trust_init(
    path: Path = typer.Argument(..., help="Trust policy YAML path."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing policy file.",
    ),
) -> None:
    """Initialize a local benchmark pack trust policy."""
    try:
        init_trust_policy(path, force=force)
    except (FileExistsError, OSError, BenchmarkPackError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Trust policy initialized: {path}")


@benchmark_pack_trust_app.command("add-key")
def benchmarks_pack_trust_add_key(
    policy: Path = typer.Argument(..., help="Trust policy YAML path."),
    public_key: Path = typer.Argument(..., help="Verification key JSON path."),
) -> None:
    """Add a verification key to a local trust policy."""
    try:
        updated = add_trusted_key(policy, public_key)
    except (OSError, ValueError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    key = updated["trusted_keys"][-1]
    typer.echo(f"Trusted key added: {key['key_id']} {key['name']}")


@benchmark_pack_trust_app.command("list")
def benchmarks_pack_trust_list(
    policy: Path = typer.Argument(..., help="Trust policy YAML path."),
) -> None:
    """List trusted keys in a local trust policy."""
    try:
        lines = trust_policy_summary(policy)
    except (OSError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    for line in lines:
        typer.echo(line)


@benchmark_pack_trust_app.command("verify")
def benchmarks_pack_trust_verify(
    pack: Path = typer.Argument(..., help="Benchmark pack .zip path."),
    policy: Path = typer.Option(..., "--policy", help="Trust policy YAML path."),
    signatures: Optional[list[Path]] = typer.Option(
        None,
        "--signature",
        help="Detached signature JSON path. Repeat for multiple signatures.",
    ),
) -> None:
    """Verify a benchmark pack against a local trust policy."""
    try:
        result = verify_trust_policy(pack, policy, signatures or [])
    except BenchmarkPackIntegrityError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (OSError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Trust status: {result.status}")
    typer.echo(
        f"Trusted signatures: {result.trusted_signatures}/"
        f"{result.required_signatures}"
    )
    for message in result.messages:
        typer.echo(f"- {message}")
    if not result.valid:
        raise typer.Exit(1)


@benchmark_pack_app.command("import")
def benchmarks_pack_import(
    pack: Path = typer.Option(..., "--pack", help="Benchmark pack .zip path."),
    dest: Path = typer.Option(
        Path("examples/imported-benchmarks"),
        "--dest",
        help="Destination directory for imported pack files.",
    ),
    registry_out: Optional[Path] = typer.Option(
        None,
        "--registry-out",
        help="Optional path to write a registry fragment copy.",
    ),
    suite_out: Optional[Path] = typer.Option(
        None,
        "--suite-out",
        help="Optional path to write a generated safe/adversarial suite.",
    ),
    trust_policy: Optional[Path] = typer.Option(
        None,
        "--trust-policy",
        help="Local trust policy required before import.",
    ),
    signatures: Optional[list[Path]] = typer.Option(
        None,
        "--signature",
        help="Detached signature JSON path. Repeat for multiple signatures.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print planned writes and collisions without writing files.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite destination collisions.",
    ),
) -> None:
    """Verify and import a benchmark pack without executing benchmark code."""
    try:
        plan = import_benchmark_pack(
            pack_path=pack,
            dest_path=dest,
            registry_out=registry_out,
            suite_out=suite_out,
            trust_policy=trust_policy,
            signatures=signatures or [],
            dry_run=dry_run,
            force=force,
        )
    except BenchmarkPackIntegrityError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except BenchmarkPackSignatureError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (FileExistsError, OSError, ValueError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("Benchmark pack import plan" if dry_run else "Benchmark pack imported")
    typer.echo(f"Destination: {dest}")
    typer.echo(f"Files: {len(plan.files)}")
    if plan.trust_status is not None:
        typer.echo(f"Trust status: {plan.trust_status}")
    if plan.collisions:
        typer.echo("Collisions:")
        for path in plan.collisions:
            typer.echo(f"- {path}")
        if not force:
            raise typer.Exit(2)
    for relative_path, target in plan.files:
        typer.echo(f"- {relative_path} -> {target}")
    if plan.registry_path is not None:
        typer.echo(f"Registry output: {plan.registry_path}")
    if plan.suite_path is not None:
        typer.echo(f"Suite output: {plan.suite_path}")


@benchmark_pack_index_app.command("create")
def benchmarks_pack_index_create(
    packs: list[Path] = typer.Option(
        ...,
        "--pack",
        help="Local benchmark pack .zip path. Repeat for multiple packs.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        help="Output benchmark pack index YAML path.",
    ),
    signatures: Optional[list[Path]] = typer.Option(
        None,
        "--signature",
        help="Detached signature JSON path to reference in the index.",
    ),
    base_dir: Optional[Path] = typer.Option(
        None,
        "--base-dir",
        help="Base directory for relative pack and signature paths.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing index output.",
    ),
) -> None:
    """Create a static local benchmark pack index."""
    try:
        index = create_pack_index(
            pack_paths=packs,
            output_path=output,
            signature_paths=signatures or [],
            base_dir=base_dir,
            force=force,
        )
    except (FileExistsError, OSError, ValueError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo(f"Benchmark pack index written: {output}")
    typer.echo(f"Index ID: {index['index_id']}")
    typer.echo(f"Packs: {len(index['packs'])}")


@benchmark_pack_index_app.command("list")
def benchmarks_pack_index_list(
    index: Path = typer.Argument(..., help="Benchmark pack index YAML/JSON path."),
    trust_policy: Optional[Path] = typer.Option(
        None,
        "--trust-policy",
        help="Optional local trust policy for trust status.",
    ),
) -> None:
    """List packs in a static benchmark pack index."""
    try:
        lines = list_pack_index(index, trust_policy=trust_policy)
    except BenchmarkPackIntegrityError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (OSError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    for line in lines:
        typer.echo(line)


@benchmark_pack_index_app.command("verify")
def benchmarks_pack_index_verify(
    index: Path = typer.Argument(..., help="Benchmark pack index YAML/JSON path."),
    trust_policy: Optional[Path] = typer.Option(
        None,
        "--trust-policy",
        help="Optional local trust policy to enforce indexed signatures.",
    ),
) -> None:
    """Verify an index and all referenced local packs."""
    try:
        result = verify_pack_index(index, trust_policy=trust_policy)
    except (BenchmarkPackIntegrityError, BenchmarkPackSignatureError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (OSError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    typer.echo("Benchmark pack index verification: PASS")
    typer.echo(f"Index ID: {result.index['index_id']}")
    typer.echo(f"Packs: {len(result.entries)}")
    for message in result.messages:
        typer.echo(f"- {message}")


@benchmark_pack_index_app.command("show")
def benchmarks_pack_index_show(
    index: Path = typer.Argument(..., help="Benchmark pack index YAML/JSON path."),
    pack_id: str = typer.Option(..., "--pack", help="Pack ID to show."),
    version: Optional[str] = typer.Option(
        None,
        "--version",
        help="Specific strict-semver pack version.",
    ),
) -> None:
    """Show detailed metadata for a selected indexed pack."""
    try:
        resolution = resolve_index_pack(index, pack_id=pack_id, version=version)
    except (OSError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    entry = resolution.entry
    typer.echo(f"Pack ID: {entry['pack_id']}")
    typer.echo(f"Version: {entry['pack_version']}")
    typer.echo(f"Title: {entry['title']}")
    typer.echo(f"Description: {entry['description']}")
    typer.echo(f"Digest: {entry['pack_digest']}")
    typer.echo(f"Size: {entry['size_bytes']} bytes")
    typer.echo(f"Source: {entry['source']['type']}:{entry['source']['path']}")
    typer.echo("Benchmarks:")
    for benchmark_id in entry["benchmark_ids"]:
        version_value = entry["benchmark_versions"].get(benchmark_id)
        typer.echo(f"- {benchmark_id}@{version_value}")
    typer.echo("Signature:")
    if entry.get("signature"):
        signature = entry["signature"]
        typer.echo(f"- key_id={signature['key_id']} path={signature.get('signature_path', 'inline')}")
    else:
        typer.echo("- none")


@benchmark_pack_index_app.command("install")
def benchmarks_pack_index_install(
    index: Path = typer.Argument(..., help="Benchmark pack index YAML/JSON path."),
    pack_id: str = typer.Option(..., "--pack", help="Pack ID to install."),
    version: Optional[str] = typer.Option(
        None,
        "--version",
        help="Specific strict-semver pack version. Defaults to latest.",
    ),
    dest: Path = typer.Option(
        Path("examples/imported-benchmarks"),
        "--dest",
        help="Destination directory for imported pack files.",
    ),
    registry_out: Optional[Path] = typer.Option(
        None,
        "--registry-out",
        help="Optional path to write a registry fragment copy.",
    ),
    suite_out: Optional[Path] = typer.Option(
        None,
        "--suite-out",
        help="Optional path to write a generated safe/adversarial suite.",
    ),
    trust_policy: Optional[Path] = typer.Option(
        None,
        "--trust-policy",
        help="Optional local trust policy required before import.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print planned writes and collisions without writing files.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite destination collisions.",
    ),
) -> None:
    """Verify and import a selected pack from a local static index."""
    try:
        resolution, plan = install_index_pack(
            index,
            pack_id=pack_id,
            version=version,
            dest_path=dest,
            registry_out=registry_out,
            suite_out=suite_out,
            trust_policy=trust_policy,
            dry_run=dry_run,
            force=force,
        )
    except (BenchmarkPackIntegrityError, BenchmarkPackSignatureError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(1) from error
    except (FileExistsError, OSError, ValueError, BenchmarkPackError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    entry = resolution.entry
    typer.echo(
        "Benchmark pack index install plan"
        if dry_run
        else "Benchmark pack installed from index"
    )
    typer.echo(f"Pack: {entry['pack_id']}@{entry['pack_version']}")
    typer.echo(f"Destination: {dest}")
    typer.echo(f"Files: {len(plan.files)}")
    if plan.trust_status is not None:
        typer.echo(f"Trust status: {plan.trust_status}")
    if plan.collisions:
        typer.echo("Collisions:")
        for path in plan.collisions:
            typer.echo(f"- {path}")
        if not force:
            raise typer.Exit(2)
    for relative_path, target in plan.files:
        typer.echo(f"- {relative_path} -> {target}")
    if plan.registry_path is not None:
        typer.echo(f"Registry output: {plan.registry_path}")
    if plan.suite_path is not None:
        typer.echo(f"Suite output: {plan.suite_path}")


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


@reports_app.command("export-sarif")
def reports_export_sarif(
    input_path: Path = typer.Argument(
        ...,
        help="Report JSON file or directory containing AgentGuard reports.",
    ),
    output: Path = typer.Option(..., "--output", help="SARIF output path."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing output file.",
    ),
    tool_name: str = typer.Option(
        "AgentGuard",
        "--tool-name",
        help="SARIF tool driver name.",
    ),
    base_uri: Optional[str] = typer.Option(
        None,
        "--base-uri",
        help="Optional SARIF originalUriBaseIds repository URI.",
    ),
    include_passed: bool = typer.Option(
        False,
        "--include-passed",
        help="Include passed checks as informational SARIF pass results.",
    ),
) -> None:
    """Export AgentGuard policy findings as SARIF 2.1.0."""
    try:
        result = export_sarif(
            input_path,
            output,
            force=force,
            tool_name=tool_name,
            base_uri=base_uri,
            include_passed=include_passed,
        )
    except (FileExistsError, OSError, UnsupportedExportInput, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo(f"SARIF exported: {result.output_path}")
    typer.echo(
        "Reports: "
        f"{result.reports}; rules: {result.rules}; results: {result.results}; "
        f"failed findings: {result.findings}; passed included: "
        f"{result.included_passed}"
    )
    if result.unsupported_files:
        typer.echo(f"Unsupported files skipped: {result.unsupported_files}")


@reports_app.command("export-junit")
def reports_export_junit(
    input_path: Path = typer.Argument(
        ...,
        help="Report JSON file or directory containing AgentGuard reports.",
    ),
    output: Path = typer.Option(..., "--output", help="JUnit XML output path."),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing output file.",
    ),
    tool_name: str = typer.Option(
        "AgentGuard",
        "--tool-name",
        help="JUnit producer name used in system-out.",
    ),
    suite_name: Optional[str] = typer.Option(
        None,
        "--suite-name",
        help="Optional JUnit testsuite name.",
    ),
) -> None:
    """Export AgentGuard run and aggregate outcomes as JUnit XML."""
    try:
        result = export_junit(
            input_path,
            output,
            force=force,
            tool_name=tool_name,
            suite_name=suite_name,
        )
    except (FileExistsError, OSError, UnsupportedExportInput, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo(f"JUnit exported: {result.output_path}")
    typer.echo(
        f"Reports: {result.reports}; tests: {result.tests}; "
        f"failures: {result.failures}"
    )
    if result.unsupported_files:
        typer.echo(f"Unsupported files skipped: {result.unsupported_files}")


@reports_app.command("site")
def reports_site(
    output: Path = typer.Option(..., "--output", help="Static site output path."),
    history_db: Path = typer.Option(
        DEFAULT_SITE_HISTORY_DB_PATH,
        "--history-db",
        help="SQLite history database path.",
    ),
    reports_root: Path = typer.Option(
        DEFAULT_SITE_REPORTS_ROOT,
        "--reports-root",
        help="AgentGuard artifact root to scan.",
    ),
    include_traces: bool = typer.Option(
        False,
        "--include-traces",
        help="Include bounded execution trace summaries.",
    ),
    include_diagnostics: bool = typer.Option(
        False,
        "--include-diagnostics",
        help="Include diagnostic report summaries.",
    ),
    include_results_docs: bool = typer.Option(
        False,
        "--include-results-docs",
        help="Include committed docs/results summary pages.",
    ),
    title: str = typer.Option(
        "AgentGuard Report Site",
        "--title",
        help="Site title.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing output directory.",
    ),
) -> None:
    """Generate a self-contained static HTML report site."""
    try:
        result = generate_static_report_site(
            StaticSiteOptions(
                output=output,
                history_db=history_db,
                reports_root=reports_root,
                include_traces=include_traces,
                include_diagnostics=include_diagnostics,
                include_results_docs=include_results_docs,
                title=title,
                force=force,
            )
        )
    except (FileExistsError, OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo(f"Static report site: {result.output_path}")
    typer.echo(
        "Pages: "
        f"{result.page_count}; reports: {result.reports}; "
        f"matrices: {result.matrices}; diagnostics: {result.diagnostics}; "
        f"traces: {result.traces}; results docs: {result.results_docs}; "
        f"unavailable: {result.unavailable}"
    )


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
    atomic_write_text(output, content)
    typer.echo(f"History exported: {output}")


def _validate_guard_poll_interval(guard_poll_interval: float) -> None:
    try:
        validate_guard_configuration(GuardMode.OFF, guard_poll_interval)
    except ValueError as error:
        raise typer.BadParameter(
            "guard poll interval must be a finite positive number.",
            param_hint="--guard-poll-interval",
        ) from error


@app.command()
def run(
    config_path: Path = typer.Argument(..., help="Path to the AgentGuard config file."),
    agent: str = typer.Option(..., "--agent", help="Name of the coding agent to run."),
    guard_mode: GuardMode = typer.Option(
        GuardMode.OFF,
        "--guard-mode",
        help="Online filesystem guard mode: off, audit, or enforce.",
    ),
    guard_poll_interval: float = typer.Option(
        DEFAULT_POLL_INTERVAL_SECONDS,
        "--guard-poll-interval",
        help="Filesystem guard polling interval in seconds.",
    ),
    allow_fail_result: bool = typer.Option(
        False,
        "--allow-fail-result",
        help="Exit 0 even when the AgentGuard run result is FAIL.",
    ),
) -> None:
    """Run an AgentGuard benchmark."""
    _validate_guard_poll_interval(guard_poll_interval)
    try:
        result = run_benchmark(
            config_path,
            agent,
            guard_mode=guard_mode,
            guard_poll_interval_seconds=guard_poll_interval,
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Report")
    typer.echo(f"Task: {result.task_id}")
    typer.echo(f"Agent: {result.agent}")
    typer.echo(f"Result: {result.result}")
    typer.echo(f"Score: {result.score}/100")
    if result.guard_summary.mode != GuardMode.OFF.value:
        typer.echo(
            "Guard: "
            f"{result.guard_summary.mode}; triggered: "
            f"{result.guard_summary.triggered}; violations: "
            f"{len(result.guard_summary.violations)}"
        )
    if result.command_guard_summary.mode != GuardMode.OFF.value:
        typer.echo(
            "Command guard: "
            f"{result.command_guard_summary.mode}; triggered: "
            f"{result.command_guard_summary.triggered}; violations: "
            f"{len(result.command_guard_summary.violations)}"
        )
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
    if result.report_paths.guard_incident_json is not None:
        typer.echo(f"Guard incident path: {result.report_paths.guard_incident_json}")
    typer.echo(f"JSON report path: {result.report_paths.json}")
    typer.echo(f"Markdown report path: {result.report_paths.markdown}")
    typer.echo(f"Manifest path: {result.report_paths.manifest or '-'}")
    typer.echo(f"Trace path: {result.report_paths.trace or '-'}")
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

    try:
        result = run_ci(config_path, base_ref=base_ref, head_ref=head_ref)
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
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

    try:
        summary = run_multi_agent_benchmark(config_path, agent_names)
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

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
    except (OSError, ValueError, yaml.YAMLError) as error:
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
    guard_mode: GuardMode = typer.Option(
        GuardMode.OFF,
        "--guard-mode",
        help="Online guard mode for every suite run: off, audit, or enforce.",
    ),
    guard_poll_interval: float = typer.Option(
        DEFAULT_POLL_INTERVAL_SECONDS,
        "--guard-poll-interval",
        help="Guard polling interval in seconds for every suite run.",
    ),
) -> None:
    """Run multiple AgentGuard benchmark configs as one suite."""
    try:
        _validate_guard_poll_interval(guard_poll_interval)
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
            guard_mode=guard_mode,
            guard_poll_interval_seconds=guard_poll_interval,
        )
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Suite Summary")
    typer.echo(f"Suite: {result.suite_id}")
    typer.echo(f"Guard mode: {result.guard_mode}")
    typer.echo(
        f"Guard poll interval: {result.guard_poll_interval_seconds} seconds"
    )
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
    checkpoint: Optional[Path] = typer.Option(
        None,
        "--checkpoint",
        help="Create and atomically update a resumable matrix checkpoint.",
    ),
    resume: Optional[Path] = typer.Option(
        None,
        "--resume",
        help="Resume from an existing verified matrix checkpoint.",
    ),
    checkpoint_every: int = typer.Option(
        1,
        "--checkpoint-every",
        help="Persist the checkpoint after this many completed attempts.",
    ),
    retry_failed: bool = typer.Option(
        False,
        "--retry-failed",
        help="Rerun verified failed attempts instead of reusing them.",
    ),
    force_resume: bool = typer.Option(
        False,
        "--force-resume",
        help="Acknowledge listed non-artifact compatibility warnings.",
    ),
    guard_mode: GuardMode = typer.Option(
        GuardMode.OFF,
        "--guard-mode",
        help="Online guard mode for every matrix attempt: off, audit, or enforce.",
    ),
    guard_poll_interval: float = typer.Option(
        DEFAULT_POLL_INTERVAL_SECONDS,
        "--guard-poll-interval",
        help="Guard polling interval in seconds for every matrix attempt.",
    ),
) -> None:
    """Run a suite across its configured agents or an agent override matrix."""
    try:
        _validate_guard_poll_interval(guard_poll_interval)
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
            checkpoint_path=checkpoint,
            resume_path=resume,
            checkpoint_every=checkpoint_every,
            retry_failed=retry_failed,
            force_resume=force_resume,
            guard_mode=guard_mode,
            guard_poll_interval_seconds=guard_poll_interval,
        )
    except KeyboardInterrupt as error:
        typer.echo("Matrix execution interrupted.", err=True)
        active_checkpoint = resume or checkpoint
        if active_checkpoint is not None:
            resolved = active_checkpoint.expanduser().resolve()
            typer.echo(f"Checkpoint marked interrupted: {resolved}", err=True)
            typer.echo(
                f"Resume with: agentguard matrix {suite_path} --resume {resolved}",
                err=True,
            )
        raise typer.Exit(130) from error
    except (OSError, ValueError, yaml.YAMLError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error

    typer.echo("AgentGuard Matrix Summary")
    typer.echo(f"Suite: {result.suite_id}")
    typer.echo(f"Agents: {', '.join(result.agents)}")
    typer.echo(f"Guard mode: {result.guard_mode}")
    typer.echo(
        f"Guard poll interval: {result.guard_poll_interval_seconds} seconds"
    )
    _echo_matrix_guard_summary(result)
    if result.filters.has_filters():
        typer.echo(f"Filters: {format_suite_filters(result.filters)}")
    typer.echo(f"Trials per combination: {result.trials}")
    typer.echo(f"Workers: {result.effective_workers}/{result.requested_workers}")
    typer.echo(f"Execution mode: {result.execution_mode}")
    typer.echo(f"Execution duration: {result.duration_seconds:.3f} seconds")
    typer.echo(f"Attempts planned: {result.attempts_planned}")
    typer.echo(f"Attempts executed: {result.attempts_executed}")
    if result.checkpoint_path is not None:
        typer.echo(f"Checkpoint: {result.checkpoint_path}")
        typer.echo(f"Checkpoint status: {result.checkpoint_status}")
        typer.echo(f"Attempts reused: {result.attempts_reused}")
        typer.echo(f"Attempts skipped: {result.attempts_skipped}")
        typer.echo(
            "Attempts executed this invocation: "
            f"{result.attempts_executed_this_invocation}"
        )
        typer.echo(f"Failed attempts retried: {result.failed_attempts_retried}")
        typer.echo(f"Invalidated attempts: {result.invalidated_attempts}")
        typer.echo(f"Reuse percentage: {result.reuse_percentage}%")
        typer.echo(
            "Estimated recomputation avoided: "
            f"{result.estimated_recomputation_avoided_seconds:.3f} seconds"
        )
        for warning in result.compatibility_warnings:
            typer.echo(f"Compatibility warning: {warning}")
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
