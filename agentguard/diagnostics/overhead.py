import math
import platform
import shlex
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Union

from agentguard.agents.mock_agent import get_agent
from agentguard.config.loader import load_config
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import BenchmarkResult
from agentguard.core.timing import StageTimingRecorder
from agentguard.instrumentation.test_runner import _build_test_env
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.reports.markdown import markdown_table_cell, markdown_text
from agentguard.provenance.manifest import agentguard_identity, sha256_file
from agentguard.repo.internal_artifacts import is_internal_artifact


SCHEMA = "agentguard.overhead-benchmark"
SCHEMA_VERSION = 1
DEFAULT_CONFIG_PATH = Path("examples/configs/fix_auth_bug.yaml")
STAGE_NAMES = (
    "configuration",
    "workspace_preparation",
    "agent_setup",
    "agent_execution",
    "test_execution",
    "policy_check_evaluation",
    "report_writing",
    "history_writing",
    "manifest_writing",
)


@dataclass(frozen=True)
class FunctionalOutcome:
    test_exit_code: int
    changed_files: list[str]
    changed_file_sha256: dict[str, str]


@dataclass(frozen=True)
class WorkloadTiming:
    total_seconds: float
    stages: dict[str, float]
    outcome: FunctionalOutcome


@dataclass(frozen=True)
class SummaryStatistics:
    iterations: int
    minimum: float
    maximum: float
    mean: float
    median: float
    sample_standard_deviation: float
    p95: float


@dataclass(frozen=True)
class OverheadBenchmarkPaths:
    json: Path
    markdown: Path


@dataclass(frozen=True)
class OverheadBenchmarkResult:
    data: dict[str, object]
    paths: OverheadBenchmarkPaths


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value.")
    if percentile <= 0 or percentile > 100:
        raise ValueError("percentile must be greater than 0 and at most 100.")
    ordered = sorted(values)
    rank = math.ceil((percentile / 100.0) * len(ordered))
    return ordered[rank - 1]


def summarize(values: list[float]) -> SummaryStatistics:
    if not values:
        raise ValueError("statistics require at least one value.")
    return SummaryStatistics(
        iterations=len(values),
        minimum=min(values),
        maximum=max(values),
        mean=statistics.fmean(values),
        median=statistics.median(values),
        sample_standard_deviation=statistics.stdev(values) if len(values) > 1 else 0.0,
        p95=nearest_rank_percentile(values, 95),
    )


def execution_order(iteration_index: int) -> tuple[str, str]:
    if iteration_index % 2 == 0:
        return ("direct", "agentguard")
    return ("agentguard", "direct")


def _command_argv(command: Union[str, list[str]]) -> list[str]:
    argv = shlex.split(command) if isinstance(command, str) else list(command)
    if argv and argv[0] == "pytest":
        return [sys.executable, "-m", "pytest", *argv[1:]]
    return argv


def _run_command(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    if not argv:
        raise ValueError("Configured command cannot be empty.")
    try:
        return subprocess.run(
            argv,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as error:
        raise ValueError(f"Command executable not found: {error.filename}") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError(
            f"Command timed out after {timeout_seconds} seconds: {shlex.join(argv)}"
        ) from error


def _direct_agent(config: AgentGuardConfig, agent_name: str, repo_dir: Path) -> None:
    if agent_name.startswith("mock-"):
        get_agent(agent_name).run(repo_dir)
        return
    if agent_name == "custom-command":
        raise ValueError(
            "Overhead benchmarking requires a non-Docker agent; "
            "'custom-command' is not supported."
        )
    if agent_name not in {"local-command", "agent-command"}:
        raise ValueError(
            "Overhead benchmarking supports deterministic mock agents, "
            "'local-command', and 'agent-command'."
        )
    if config.agent_command is None:
        raise ValueError(f"Agent '{agent_name}' requires config field 'agent_command'.")

    workdir = (
        config.config_path.parent
        if agent_name == "agent-command" and config.agent_workdir == "config_dir"
        else repo_dir
    )
    env = _build_test_env(repo_dir)
    env.update(config.agent_environment)
    completed = _run_command(
        _command_argv(config.agent_command),
        cwd=workdir,
        env=env,
        timeout_seconds=config.command_timeout_seconds,
    )
    if completed.returncode != 0:
        raise ValueError(
            f"Direct agent command failed with exit code {completed.returncode}: "
            f"{completed.stderr.strip()}"
        )


def _snapshot(repo_dir: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(repo_dir).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if is_internal_artifact(relative):
            continue
        snapshot[relative] = sha256_file(path)
    return snapshot


def _outcome(
    before: dict[str, str],
    after: dict[str, str],
    test_exit_code: int,
) -> FunctionalOutcome:
    changed = sorted(
        path
        for path in set(before) | set(after)
        if before.get(path) != after.get(path)
    )
    return FunctionalOutcome(
        test_exit_code=test_exit_code,
        changed_files=changed,
        changed_file_sha256={
            path: after[path] for path in changed if path in after
        },
    )


def _agentguard_outcome(result: BenchmarkResult) -> FunctionalOutcome:
    hashes = {
        path: sha256_file(result.repo_dir / path)
        for path in result.diff_summary.changed_files
        if (result.repo_dir / path).is_file()
    }
    return FunctionalOutcome(
        test_exit_code=result.test_result.exit_code,
        changed_files=sorted(result.diff_summary.changed_files),
        changed_file_sha256=hashes,
    )


def run_direct_workload(
    config_path: Path,
    agent_name: str,
    *,
    clock: Callable[[], float] = time.perf_counter,
) -> WorkloadTiming:
    validation_config = load_config(config_path)
    if validation_config.sandbox.type != "local":
        raise ValueError("Overhead benchmarking requires sandbox.type: local.")
    if validation_config.repo_template is None:
        raise ValueError("Overhead benchmarking requires repo_template.")
    before = _snapshot(validation_config.repo_template)

    total_started = clock()
    stage_started = clock()
    config = load_config(config_path)
    configuration_seconds = clock() - stage_started

    with tempfile.TemporaryDirectory(prefix="agentguard-overhead-direct-") as temp_dir:
        repo_dir = Path(temp_dir) / "repo"
        stage_started = clock()
        shutil.copytree(config.repo_template, repo_dir, symlinks=True)
        workspace_seconds = clock() - stage_started

        stage_started = clock()
        _direct_agent(config, agent_name, repo_dir)
        agent_seconds = clock() - stage_started

        stage_started = clock()
        completed = _run_command(
            _command_argv(config.test_command),
            cwd=repo_dir,
            env=_build_test_env(repo_dir),
            timeout_seconds=config.command_timeout_seconds,
        )
        test_seconds = clock() - stage_started
        total_seconds = clock() - total_started
        after = _snapshot(repo_dir)
        outcome = _outcome(before, after, completed.returncode)

    return WorkloadTiming(
        total_seconds=total_seconds,
        stages={
            "configuration": configuration_seconds,
            "workspace_preparation": workspace_seconds,
            "agent_execution": agent_seconds,
            "test_execution": test_seconds,
        },
        outcome=outcome,
    )


def run_agentguard_workload(
    config_path: Path,
    agent_name: str,
    *,
    record_history_enabled: bool = True,
    write_manifest_enabled: bool = True,
    clock: Callable[[], float] = time.perf_counter,
) -> WorkloadTiming:
    timing = StageTimingRecorder(clock)
    result = run_benchmark(
        config_path,
        agent_name,
        timing_recorder=timing,
        record_history_enabled=record_history_enabled,
        write_manifest_enabled=write_manifest_enabled,
    )
    return WorkloadTiming(
        total_seconds=timing.total_seconds,
        stages=dict(timing.stages),
        outcome=_agentguard_outcome(result),
    )


def _assert_matching_outcomes(
    direct: WorkloadTiming,
    agentguard: WorkloadTiming,
    iteration_label: str,
) -> None:
    if direct.outcome != agentguard.outcome:
        raise ValueError(
            f"Direct and AgentGuard outcomes differ for {iteration_label}: "
            f"direct={asdict(direct.outcome)}, "
            f"agentguard={asdict(agentguard.outcome)}"
        )
    if direct.outcome.test_exit_code != 0:
        raise ValueError(
            f"Workload did not produce the expected successful test result for "
            f"{iteration_label}: exit code {direct.outcome.test_exit_code}"
        )


def _default_output_paths(now: datetime) -> OverheadBenchmarkPaths:
    timestamp = now.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    stem = Path(".agentguard/benchmarks") / f"overhead-{timestamp}"
    return OverheadBenchmarkPaths(
        json=stem.with_suffix(".json"),
        markdown=stem.with_suffix(".md"),
    )


def _output_paths(
    output_path: Optional[Path],
    now: datetime,
) -> OverheadBenchmarkPaths:
    if output_path is None:
        return _default_output_paths(now)
    return OverheadBenchmarkPaths(
        json=output_path,
        markdown=output_path.with_suffix(".md"),
    )


def _write_reports(
    data: dict[str, object],
    paths: OverheadBenchmarkPaths,
    *,
    force: bool,
) -> None:
    existing = [path for path in (paths.json, paths.markdown) if path.exists()]
    if existing and not force:
        joined = ", ".join(str(path) for path in existing)
        raise FileExistsError(
            f"output already exists: {joined}. Use --force to overwrite."
        )
    atomic_write_json(paths.json, data, sort_keys=True)
    atomic_write_text(paths.markdown, _markdown_report(data))


def _format_seconds(value: object) -> str:
    return f"{float(value):.6f}s"


def _markdown_report(data: dict[str, object]) -> str:
    summary = data["summary"]
    assert isinstance(summary, dict)
    direct = summary["direct_seconds"]
    guarded = summary["agentguard_seconds"]
    overhead = summary["absolute_overhead_seconds"]
    relative = summary["relative_overhead_percent"]
    slowdown = summary["slowdown_ratio"]
    throughput = summary["throughput_runs_per_minute"]
    stages = data["agentguard_stage_summary"]
    assert isinstance(direct, dict)
    assert isinstance(guarded, dict)
    assert isinstance(overhead, dict)
    assert isinstance(relative, dict)
    assert isinstance(slowdown, dict)
    assert isinstance(throughput, dict)
    assert isinstance(stages, dict)

    lines = [
        "# AgentGuard Instrumentation Overhead",
        "",
        f"- Created at: {markdown_text(data['created_at'])}",
        f"- Config: {markdown_text(data['config']['path'])}",
        f"- Agent: {markdown_text(data['agent'])}",
        f"- Iterations: {data['iterations']}",
        f"- Warmups: {data['warmups']}",
        "",
        "## Summary",
        "",
        f"- Direct median: {_format_seconds(direct['median'])}",
        f"- AgentGuard median: {_format_seconds(guarded['median'])}",
        f"- Median absolute overhead: {_format_seconds(overhead['median'])}",
        f"- Median relative overhead: {float(relative['median']):.2f}%",
        f"- Median slowdown ratio: {float(slowdown['median']):.3f}x",
        f"- Direct throughput: {float(throughput['direct_median']):.2f} runs/minute",
        f"- AgentGuard throughput: {float(throughput['agentguard_median']):.2f} runs/minute",
        "",
        "## AgentGuard Stage Breakdown",
        "",
        "Stage | Mean Seconds | Percentage of Mean Total",
        "--- | ---: | ---:",
    ]
    for stage, values in stages.items():
        assert isinstance(values, dict)
        lines.append(
            f"{markdown_table_cell(stage)} | "
            f"{float(values['mean_seconds']):.6f} | "
            f"{float(values['percentage_of_mean_total']):.2f}%"
        )
    lines.extend(
        [
            "",
            "## Methodology",
            "",
            "- Warmups run first and are excluded from statistics.",
            "- Measured iterations alternate direct and AgentGuard execution order.",
            "- Runs execute serially in fresh isolated workspaces using time.perf_counter.",
            "- Direct runs copy the fixture, execute the same agent action, and run the same tests.",
            "- AgentGuard runs include normal setup, checks, reports, history, and manifest work unless disabled.",
            "- p95 uses the deterministic nearest-rank method: ceil(0.95 * n).",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {warning}" for warning in data["warnings"])
    lines.append("")
    return "\n".join(lines)


def run_overhead_benchmark(
    config_path: Path = DEFAULT_CONFIG_PATH,
    agent_name: str = "mock-safe",
    *,
    iterations: int = 10,
    warmups: int = 2,
    output_path: Optional[Path] = None,
    force: bool = False,
    record_history_enabled: bool = True,
    write_manifest_enabled: bool = True,
    direct_runner: Callable[..., WorkloadTiming] = run_direct_workload,
    agentguard_runner: Callable[..., WorkloadTiming] = run_agentguard_workload,
    now: Optional[datetime] = None,
) -> OverheadBenchmarkResult:
    if iterations <= 0:
        raise ValueError("iterations must be positive.")
    if warmups < 0:
        raise ValueError("warmups must be non-negative.")

    config_path = config_path.expanduser().resolve()
    config = load_config(config_path)
    if config.sandbox.type != "local":
        raise ValueError("Overhead benchmarking requires sandbox.type: local.")
    created_at = now or datetime.now(timezone.utc)
    paths = _output_paths(output_path, created_at)
    if not force:
        existing = [path for path in (paths.json, paths.markdown) if path.exists()]
        if existing:
            joined = ", ".join(str(path) for path in existing)
            raise FileExistsError(
                f"output already exists: {joined}. Use --force to overwrite."
            )

    warmup_records: list[dict[str, object]] = []
    measured_records: list[dict[str, object]] = []
    for phase, count, destination in (
        ("warmup", warmups, warmup_records),
        ("measurement", iterations, measured_records),
    ):
        for index in range(count):
            pair: dict[str, WorkloadTiming] = {}
            order = execution_order(index)
            for workload in order:
                if workload == "direct":
                    pair[workload] = direct_runner(config_path, agent_name)
                else:
                    pair[workload] = agentguard_runner(
                        config_path,
                        agent_name,
                        record_history_enabled=record_history_enabled,
                        write_manifest_enabled=write_manifest_enabled,
                    )
            _assert_matching_outcomes(
                pair["direct"],
                pair["agentguard"],
                f"{phase} {index + 1}",
            )
            destination.append(
                {
                    "index": index + 1,
                    "order": list(order),
                    "direct": {
                        "total_seconds": pair["direct"].total_seconds,
                        "stages": pair["direct"].stages,
                    },
                    "agentguard": {
                        "total_seconds": pair["agentguard"].total_seconds,
                        "stages": pair["agentguard"].stages,
                    },
                    "functional_outcome": asdict(pair["direct"].outcome),
                }
            )

    direct_values = [
        float(record["direct"]["total_seconds"]) for record in measured_records
    ]
    guarded_values = [
        float(record["agentguard"]["total_seconds"]) for record in measured_records
    ]
    overhead_values = [
        guarded - direct
        for direct, guarded in zip(direct_values, guarded_values)
    ]
    relative_values = [
        (overhead / direct) * 100.0
        for direct, overhead in zip(direct_values, overhead_values)
    ]
    slowdown_values = [
        guarded / direct
        for direct, guarded in zip(direct_values, guarded_values)
    ]
    for record, overhead, relative, slowdown in zip(
        measured_records,
        overhead_values,
        relative_values,
        slowdown_values,
    ):
        record["overhead"] = {
            "absolute_seconds": overhead,
            "relative_percent": relative,
            "slowdown_ratio": slowdown,
        }
    direct_summary = summarize(direct_values)
    guarded_summary = summarize(guarded_values)
    stage_summary: dict[str, dict[str, float]] = {}
    for stage in STAGE_NAMES:
        values = [
            float(record["agentguard"]["stages"].get(stage, 0.0))
            for record in measured_records
        ]
        mean_seconds = statistics.fmean(values)
        stage_summary[stage] = {
            "mean_seconds": mean_seconds,
            "percentage_of_mean_total": (
                (mean_seconds / guarded_summary.mean) * 100.0
                if guarded_summary.mean
                else 0.0
            ),
        }
    measured_stage_mean = sum(
        values["mean_seconds"] for values in stage_summary.values()
    )
    other_mean = max(0.0, guarded_summary.mean - measured_stage_mean)
    stage_summary["other_orchestration"] = {
        "mean_seconds": other_mean,
        "percentage_of_mean_total": (
            (other_mean / guarded_summary.mean) * 100.0
            if guarded_summary.mean
            else 0.0
        ),
    }

    identity = agentguard_identity()
    data: dict[str, object] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "created_at": created_at.astimezone(timezone.utc).isoformat(),
        "agentguard": {
            "version": identity.version,
            "git_commit": identity.git_commit,
            "dirty_worktree": identity.dirty_worktree,
        },
        "host": {
            "python_version": platform.python_version(),
            "operating_system": f"{platform.system()} {platform.release()}".strip(),
            "architecture": platform.machine(),
        },
        "config": {
            "path": str(config_path),
            "sha256": sha256_file(config_path),
            "task_id": config.task_id,
        },
        "agent": agent_name,
        "warmups": warmups,
        "iterations": iterations,
        "raw_timings": measured_records,
        "warmup_timings": warmup_records,
        "summary": {
            "direct_seconds": asdict(direct_summary),
            "agentguard_seconds": asdict(guarded_summary),
            "absolute_overhead_seconds": asdict(summarize(overhead_values)),
            "relative_overhead_percent": asdict(summarize(relative_values)),
            "slowdown_ratio": asdict(summarize(slowdown_values)),
            "throughput_runs_per_minute": {
                "direct_median": 60.0 / direct_summary.median,
                "agentguard_median": 60.0 / guarded_summary.median,
            },
        },
        "agentguard_stage_summary": stage_summary,
        "methodology": {
            "timer": "time.perf_counter",
            "serial_execution": True,
            "fresh_workspace_per_run": True,
            "warmups_excluded_from_statistics": True,
            "alternating_measured_order": True,
            "outcomes_verified_each_pair": True,
            "subprocess_startup_subtracted": False,
            "percentile_method": "nearest-rank ceil(p / 100 * n)",
            "history_included": record_history_enabled,
            "manifest_included": write_manifest_enabled,
            "direct_includes_agentguard_checks": False,
            "direct_includes_reports": False,
            "direct_includes_history": False,
            "direct_includes_manifest": False,
        },
        "warnings": [
            "This is a machine- and workload-specific diagnostic, not a universal performance claim.",
            "Operating-system and filesystem caches cannot be fully controlled.",
            "External agents and Docker can dominate runtime and reduce relative instrumentation overhead.",
            "Subprocess startup time is included and no estimated startup cost is subtracted.",
            "The other_orchestration stage is the measured total minus explicitly timed stages; it is not divided or estimated across stages.",
        ],
    }
    _write_reports(data, paths, force=force)
    return OverheadBenchmarkResult(data=data, paths=paths)
