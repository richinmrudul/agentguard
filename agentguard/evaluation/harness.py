import os
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from agentguard.agents.agent_command_agent import AgentCommandAgent
from agentguard.config.loader import load_config
from agentguard.core.matrix import MatrixResult, run_matrix, validate_matrix_workers
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.suite import (
    SuiteFilters,
    filter_suite_runs,
    load_suite_config,
)
from agentguard.evaluation.profile import (
    AgentProfile,
    RenderedInvocation,
    dry_run_invocation,
    executable_available,
    load_agent_profile,
    missing_environment_names,
    validate_profile_for_config,
    version_executable_available,
)


@dataclass(frozen=True)
class EvaluationPlanRun:
    config_path: Path
    task_id: str
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    prompt_source: str
    prompt_sha256: str
    invocation: RenderedInvocation


@dataclass(frozen=True)
class EvaluationPlan:
    profile: AgentProfile
    suite_path: Path
    suite_id: str
    runs: list[EvaluationPlanRun]
    trials: int
    workers: int
    total_attempts: int


def build_evaluation_plan(
    profile_path: Path,
    suite_path: Path,
    *,
    filters: Optional[SuiteFilters] = None,
    trials: int = 1,
    workers: int = 1,
) -> EvaluationPlan:
    if isinstance(trials, bool) or not isinstance(trials, int) or trials <= 0:
        raise ValueError("Evaluation trials must be a positive integer.")
    validate_matrix_workers(workers)
    profile = load_agent_profile(profile_path)
    suite = load_suite_config(suite_path, resolve_config_paths=True)
    selected = filter_suite_runs(suite.runs, filters or SuiteFilters())
    if not executable_available(profile):
        raise ValueError(
            f"Agent profile executable is not available: {profile.command[0]}"
        )
    if not version_executable_available(profile):
        assert profile.version_command is not None
        raise ValueError(
            "Agent profile version executable is not available: "
            f"{profile.version_command[0]}"
        )
    runs = []
    for suite_run in selected:
        config = load_config(suite_run.config_path)
        prompt = validate_profile_for_config(profile, config)
        runs.append(
            EvaluationPlanRun(
                config_path=config.config_path,
                task_id=config.task_id,
                benchmark_id=config.benchmark.id,
                benchmark_version=config.benchmark.version,
                prompt_source=prompt.source,
                prompt_sha256=prompt.sha256,
                invocation=dry_run_invocation(profile, config),
            )
        )
    return EvaluationPlan(
        profile=profile,
        suite_path=suite.suite_path,
        suite_id=suite.suite_id,
        runs=runs,
        trials=trials,
        workers=workers,
        total_attempts=len(runs) * trials,
    )


def validate_evaluation(
    profile_path: Path,
    suite_path: Path,
    *,
    filters: Optional[SuiteFilters] = None,
    trials: int = 1,
    workers: int = 1,
) -> EvaluationPlan:
    plan = build_evaluation_plan(
        profile_path,
        suite_path,
        filters=filters,
        trials=trials,
        workers=workers,
    )
    missing = missing_environment_names(plan.profile)
    if missing:
        raise ValueError(
            "Missing required environment variable(s): " + ", ".join(missing)
        )
    return plan


def format_evaluation_plan(plan: EvaluationPlan) -> str:
    profile = plan.profile
    lines = [
        "AgentGuard External Agent Evaluation Plan",
        f"Profile: {profile.name} ({profile.id})",
        f"Model: {profile.model or '-'}",
        f"Suite: {plan.suite_id}",
        f"Suite path: {plan.suite_path}",
        f"Selected benchmarks: {len(plan.runs)}",
        f"Trials: {plan.trials}",
        f"Workers: {plan.workers}",
        f"Planned combinations: {len(plan.runs)}",
        f"Total attempts: {plan.total_attempts}",
        "Environment:",
    ]
    if profile.environment:
        lines.extend(
            f"- {name}: {'set' if name in os.environ else 'unset'}"
            for name in profile.environment
        )
    else:
        lines.append("- None required")
    lines.extend(
        [
            "Trust warning: local external agents run with host-user permissions "
            "unless the command provides its own sandbox.",
            "",
            "Runs:",
        ]
    )
    for run in plan.runs:
        benchmark = run.benchmark_id or run.task_id
        version = run.benchmark_version if run.benchmark_version is not None else "-"
        lines.extend(
            [
                f"- {run.task_id} ({benchmark} v{version})",
                f"  Config: {run.config_path}",
                f"  Task prompt: {run.prompt_source}, SHA-256 {run.prompt_sha256}",
                f"  Invocation: {shlex.join(run.invocation.display_argv)}",
                f"  Workdir: {run.invocation.workdir}",
            ]
        )
    return "\n".join(lines)


def run_evaluation(
    profile_path: Path,
    suite_path: Path,
    *,
    filters: Optional[SuiteFilters] = None,
    trials: int = 1,
    workers: int = 1,
    output_dir: Path = Path(".agentguard/matrices"),
    save_reliability_baseline_path: Optional[Path] = None,
    compare_reliability_baseline_path: Optional[Path] = None,
    min_success_rate: Optional[float] = None,
    max_success_rate_drop: float = 0,
    max_average_score_drop: float = 0,
    force_reliability_baseline: bool = False,
) -> MatrixResult:
    plan = validate_evaluation(
        profile_path,
        suite_path,
        filters=filters,
        trials=trials,
        workers=workers,
    )
    profile = plan.profile

    def benchmark_runner(
        config_path: Path,
        _agent: str,
        matrix_id: str,
    ):
        return run_benchmark(
            config_path,
            AgentCommandAgent.name,
            parent_execution_id=matrix_id,
            parent_execution_type="matrix",
            evaluation_profile=profile,
        )

    return run_matrix(
        suite_path,
        agents=[AgentCommandAgent.name],
        matrices_root=output_dir,
        filters=filters,
        trials=trials,
        workers=workers,
        benchmark_runner=benchmark_runner,
        profile_id=profile.id,
        profile_name=profile.name,
        profile_model=profile.model,
        resolve_suite_config_paths=True,
        save_reliability_baseline_path=save_reliability_baseline_path,
        compare_reliability_baseline_path=compare_reliability_baseline_path,
        min_success_rate=min_success_rate,
        max_success_rate_drop=max_success_rate_drop,
        max_average_score_drop=max_average_score_drop,
        force_reliability_baseline=force_reliability_baseline,
    )
