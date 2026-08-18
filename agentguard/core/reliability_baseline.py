import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from agentguard.io import atomic_write_json
from agentguard.core.baseline_validation import (
    load_baseline_json,
    require_bool,
    require_fields,
    require_int,
    require_number,
    require_string,
)

MATRIX_RELIABILITY_SCHEMA = "agentguard.matrix-reliability-baseline"
MATRIX_RELIABILITY_SCHEMA_VERSION = 1
WILSON_Z_95 = 1.959963984540054


@dataclass(frozen=True)
class ConfidenceInterval:
    lower_bound: float
    upper_bound: float


@dataclass(frozen=True)
class ReliabilityBaselineFilters:
    category: Optional[str]
    difficulty: Optional[str]
    tags: list[str]


@dataclass(frozen=True)
class ReliabilityBaselineMetrics:
    attempts: int
    passed: int
    failed: int
    success_rate: float
    average_score: float
    minimum_score: int
    maximum_score: int
    score_standard_deviation: float
    confidence_interval_95: ConfidenceInterval
    combinations_with_any_pass: Optional[int] = None
    combinations_with_all_passes: Optional[int] = None


@dataclass(frozen=True)
class ReliabilityBaselineRow:
    key: str
    identity_key: str
    task_id: str
    config_path: str
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    agent: str
    attempts: int
    passed: int
    failed: int
    success_rate: float
    average_score: float
    minimum_score: int
    maximum_score: int
    score_standard_deviation: float
    confidence_interval_95: ConfidenceInterval
    any_pass: bool
    all_passed: bool


@dataclass(frozen=True)
class MatrixReliabilityBaseline:
    schema: str
    schema_version: int
    suite_id: str
    created_at: str
    trials: int
    filters: ReliabilityBaselineFilters
    agents: list[str]
    overall: ReliabilityBaselineMetrics
    per_agent: dict[str, ReliabilityBaselineMetrics]
    per_combination: dict[str, ReliabilityBaselineRow]


@dataclass(frozen=True)
class ReliabilityComparisonThresholds:
    min_success_rate: Optional[float]
    max_success_rate_drop: float
    max_average_score_drop: float


@dataclass(frozen=True)
class ReliabilityRegressionDetail:
    kind: str
    combination_key: Optional[str]
    message: str
    baseline_value: Optional[float] = None
    current_value: Optional[float] = None
    delta: Optional[float] = None


@dataclass(frozen=True)
class ReliabilityComparison:
    baseline_path: Optional[str]
    thresholds: ReliabilityComparisonThresholds
    has_regressions: bool
    regressions: list[ReliabilityRegressionDetail]
    missing_combinations: list[str]
    new_combinations: list[str]
    version_mismatches: list[str]


def wilson_score_interval(passed: int, attempts: int) -> ConfidenceInterval:
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts <= 0:
        raise ValueError("Wilson confidence interval requires at least one attempt.")
    if (
        isinstance(passed, bool)
        or not isinstance(passed, int)
        or passed < 0
        or passed > attempts
    ):
        raise ValueError("Wilson confidence interval passed count is invalid.")

    proportion = passed / attempts
    z_squared = WILSON_Z_95**2
    denominator = 1 + (z_squared / attempts)
    center = proportion + (z_squared / (2 * attempts))
    margin = WILSON_Z_95 * math.sqrt(
        (proportion * (1 - proportion) / attempts)
        + (z_squared / (4 * attempts**2))
    )
    lower = max(0.0, ((center - margin) / denominator) * 100)
    upper = min(100.0, ((center + margin) / denominator) * 100)
    return ConfidenceInterval(
        lower_bound=round(lower, 2),
        upper_bound=round(upper, 2),
    )


def validate_percentage(value: Optional[float], option_name: str) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{option_name} must be a number between 0 and 100.")
    number = float(value)
    if not math.isfinite(number) or number < 0 or number > 100:
        raise ValueError(f"{option_name} must be between 0 and 100.")
    return number


def reliability_thresholds(
    min_success_rate: Optional[float] = None,
    max_success_rate_drop: float = 0,
    max_average_score_drop: float = 0,
) -> ReliabilityComparisonThresholds:
    return ReliabilityComparisonThresholds(
        min_success_rate=validate_percentage(
            min_success_rate,
            "--min-success-rate",
        ),
        max_success_rate_drop=validate_percentage(
            max_success_rate_drop,
            "--max-success-rate-drop",
        )
        or 0.0,
        max_average_score_drop=validate_percentage(
            max_average_score_drop,
            "--max-average-score-drop",
        )
        or 0.0,
    )


def _portable_path(path: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def reliability_identity_key(
    config_path: str,
    benchmark_id: Optional[str],
    task_id: str,
    agent: str,
) -> str:
    benchmark_identity = benchmark_id or task_id
    return f"{benchmark_identity}/{config_path}/{agent}"


def reliability_combination_key(
    config_path: str,
    benchmark_id: Optional[str],
    benchmark_version: Optional[int],
    task_id: str,
    agent: str,
) -> str:
    identity = reliability_identity_key(
        config_path,
        benchmark_id,
        task_id,
        agent,
    )
    version = str(benchmark_version) if benchmark_version is not None else "unversioned"
    return f"{identity}/version-{version}"


def _metrics_from_summary(summary: Any) -> ReliabilityBaselineMetrics:
    if summary.attempts <= 0:
        raise ValueError("Reliability data must contain at least one attempt.")
    return ReliabilityBaselineMetrics(
        attempts=summary.attempts,
        passed=summary.passed,
        failed=summary.failed,
        success_rate=summary.success_rate,
        average_score=summary.average_score,
        minimum_score=summary.minimum_score,
        maximum_score=summary.maximum_score,
        score_standard_deviation=summary.score_standard_deviation,
        confidence_interval_95=summary.confidence_interval_95,
        combinations_with_any_pass=getattr(
            summary,
            "combinations_with_any_pass",
            None,
        ),
        combinations_with_all_passes=getattr(
            summary,
            "combinations_with_all_passes",
            None,
        ),
    )


def baseline_from_matrix_result(
    result: Any,
    created_at: Optional[str] = None,
) -> MatrixReliabilityBaseline:
    if result.reliability is None or result.reliability.attempts <= 0:
        raise ValueError("Reliability data must contain at least one attempt.")

    rows = {}
    for combination in result.combinations.values():
        config_path = _portable_path(combination.config_path)
        identity_key = reliability_identity_key(
            config_path,
            combination.benchmark_id,
            combination.task_id,
            combination.agent,
        )
        key = reliability_combination_key(
            config_path,
            combination.benchmark_id,
            combination.benchmark_version,
            combination.task_id,
            combination.agent,
        )
        rows[key] = ReliabilityBaselineRow(
            key=key,
            identity_key=identity_key,
            task_id=combination.task_id,
            config_path=config_path,
            benchmark_id=combination.benchmark_id,
            benchmark_version=combination.benchmark_version,
            agent=combination.agent,
            attempts=combination.attempts,
            passed=combination.passed,
            failed=combination.failed,
            success_rate=combination.success_rate,
            average_score=combination.average_score,
            minimum_score=combination.minimum_score,
            maximum_score=combination.maximum_score,
            score_standard_deviation=combination.score_standard_deviation,
            confidence_interval_95=combination.confidence_interval_95,
            any_pass=combination.any_pass,
            all_passed=combination.all_passed,
        )

    filters = result.filters
    return MatrixReliabilityBaseline(
        schema=MATRIX_RELIABILITY_SCHEMA,
        schema_version=MATRIX_RELIABILITY_SCHEMA_VERSION,
        suite_id=result.suite_id,
        created_at=created_at or datetime.now(timezone.utc).isoformat(),
        trials=result.trials,
        filters=ReliabilityBaselineFilters(
            category=filters.category,
            difficulty=filters.difficulty,
            tags=sorted(filters.tags),
        ),
        agents=sorted(result.agents),
        overall=_metrics_from_summary(result.reliability),
        per_agent={
            agent: _metrics_from_summary(summary)
            for agent, summary in sorted(result.per_agent_reliability.items())
        },
        per_combination=dict(sorted(rows.items())),
    )


def write_matrix_reliability_baseline(
    result: Any,
    path: Path,
    force: bool = False,
) -> Path:
    output_path = path.expanduser()
    if output_path.exists() and not force:
        raise ValueError(
            f"Reliability baseline already exists: {output_path}. Use --force to overwrite."
        )
    baseline = baseline_from_matrix_result(result)
    atomic_write_json(output_path, asdict(baseline))
    return output_path


def _required_mapping(data: dict[str, Any], key: str) -> dict[str, Any]:
    value = data.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"Reliability baseline field '{key}' must be an object.")
    return value


def _confidence_interval_from_dict(
    data: dict[str, Any],
    label: str,
) -> ConfidenceInterval:
    require_fields(
        data,
        required={"lower_bound", "upper_bound"},
        label=f"Confidence interval for {label}",
    )
    lower = require_number(
        data["lower_bound"], f"Confidence interval lower bound for {label}"
    )
    upper = require_number(
        data["upper_bound"], f"Confidence interval upper bound for {label}"
    )
    if lower < 0 or upper > 100 or lower > upper:
        raise ValueError(f"Invalid confidence interval for {label}.")
    return ConfidenceInterval(lower_bound=lower, upper_bound=upper)


def _metrics_from_dict(
    data: dict[str, Any],
    label: str,
    *,
    aggregate: bool,
    allowed_extra: Iterable[str] = (),
) -> ReliabilityBaselineMetrics:
    fields = {
        "attempts",
        "passed",
        "failed",
        "success_rate",
        "average_score",
        "minimum_score",
        "maximum_score",
        "score_standard_deviation",
        "confidence_interval_95",
    }
    aggregate_fields = {
        "combinations_with_any_pass",
        "combinations_with_all_passes",
    }
    require_fields(
        data,
        required=fields | aggregate_fields if aggregate else fields,
        optional=(aggregate_fields if not aggregate else set()) | set(allowed_extra),
        label=f"Reliability metrics for {label}",
    )
    attempts = require_int(data["attempts"], f"{label} attempts", minimum=1)
    passed = require_int(data["passed"], f"{label} passed", minimum=0)
    failed = require_int(data["failed"], f"{label} failed", minimum=0)
    if passed + failed != attempts:
        raise ValueError(f"Invalid reliability metrics for {label}.")
    success_rate = require_number(
        data["success_rate"], f"{label} success_rate", minimum=0, maximum=100
    )
    if success_rate != round((passed / attempts) * 100, 1):
        raise ValueError(f"Invalid reliability metrics for {label}.")
    minimum_score = require_int(
        data["minimum_score"], f"{label} minimum_score", minimum=0, maximum=100
    )
    maximum_score = require_int(
        data["maximum_score"], f"{label} maximum_score", minimum=0, maximum=100
    )
    average_score = require_number(
        data["average_score"], f"{label} average_score", minimum=0, maximum=100
    )
    if minimum_score > maximum_score or not minimum_score <= average_score <= maximum_score:
        raise ValueError(f"Invalid reliability metrics for {label}.")
    deviation = require_number(
        data["score_standard_deviation"],
        f"{label} score_standard_deviation",
        minimum=0,
    )
    interval = _confidence_interval_from_dict(
        _required_mapping(data, "confidence_interval_95"), label
    )
    expected_interval = wilson_score_interval(passed, attempts)
    if interval != expected_interval:
        raise ValueError(f"Invalid reliability metrics for {label}.")
    any_count = data.get("combinations_with_any_pass")
    all_count = data.get("combinations_with_all_passes")
    if aggregate:
        if any_count is not None:
            any_count = require_int(
                any_count, f"{label} combinations_with_any_pass", minimum=0
            )
        if all_count is not None:
            all_count = require_int(
                all_count, f"{label} combinations_with_all_passes", minimum=0
            )
        if any_count is not None and all_count is not None and all_count > any_count:
            raise ValueError(f"Invalid reliability metrics for {label}.")
    elif any_count is not None or all_count is not None:
        raise ValueError(f"Invalid reliability metrics for {label}.")
    metrics = ReliabilityBaselineMetrics(
        attempts=attempts,
        passed=passed,
        failed=failed,
        success_rate=success_rate,
        average_score=average_score,
        minimum_score=minimum_score,
        maximum_score=maximum_score,
        score_standard_deviation=deviation,
        confidence_interval_95=interval,
        combinations_with_any_pass=any_count,
        combinations_with_all_passes=all_count,
    )
    return metrics


def _row_from_dict(data: dict[str, Any], key: str) -> ReliabilityBaselineRow:
    row_fields = {
        "key",
        "identity_key",
        "task_id",
        "config_path",
        "benchmark_id",
        "benchmark_version",
        "agent",
        "any_pass",
        "all_passed",
    }
    metric_fields = {
        "attempts",
        "passed",
        "failed",
        "success_rate",
        "average_score",
        "minimum_score",
        "maximum_score",
        "score_standard_deviation",
        "confidence_interval_95",
    }
    require_fields(
        data,
        required=row_fields | metric_fields,
        label="Reliability baseline combination",
    )
    metrics = _metrics_from_dict(
        data, "combination", aggregate=False, allowed_extra=row_fields
    )
    task_id = require_string(data["task_id"], "Reliability combination task_id")
    config_path = require_string(
        data["config_path"], "Reliability combination config_path"
    )
    agent = require_string(data["agent"], "Reliability combination agent")
    benchmark_id = data["benchmark_id"]
    if benchmark_id is not None:
        benchmark_id = require_string(
            benchmark_id, "Reliability combination benchmark_id"
        )
    benchmark_version = data["benchmark_version"]
    if benchmark_version is not None:
        benchmark_version = require_int(
            benchmark_version, "Reliability combination benchmark_version", minimum=1
        )
    identity_key = require_string(
        data["identity_key"], "Reliability combination identity_key"
    )
    expected_identity = reliability_identity_key(
        config_path, benchmark_id, task_id, agent
    )
    expected_key = reliability_combination_key(
        config_path, benchmark_id, benchmark_version, task_id, agent
    )
    if identity_key != expected_identity or data["key"] != key or key != expected_key:
        raise ValueError("Reliability baseline combination has an invalid identity.")
    any_pass = require_bool(data["any_pass"], "Reliability combination any_pass")
    all_passed = require_bool(
        data["all_passed"], "Reliability combination all_passed"
    )
    if any_pass != (metrics.passed > 0) or all_passed != (
        metrics.passed == metrics.attempts
    ):
        raise ValueError("Reliability baseline combination has invalid flags.")
    return ReliabilityBaselineRow(
        key=key,
        identity_key=identity_key,
        task_id=task_id,
        config_path=config_path,
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
        agent=agent,
        attempts=metrics.attempts,
        passed=metrics.passed,
        failed=metrics.failed,
        success_rate=metrics.success_rate,
        average_score=metrics.average_score,
        minimum_score=metrics.minimum_score,
        maximum_score=metrics.maximum_score,
        score_standard_deviation=metrics.score_standard_deviation,
        confidence_interval_95=metrics.confidence_interval_95,
        any_pass=any_pass,
        all_passed=all_passed,
    )


def _metrics_match_rows(
    metrics: ReliabilityBaselineMetrics,
    rows: list[ReliabilityBaselineRow],
) -> bool:
    if not rows:
        return False
    attempts = sum(row.attempts for row in rows)
    unrounded_average = (
        sum(row.average_score * row.attempts for row in rows) / attempts
    )
    weighted_average = round(unrounded_average, 2)
    if attempts == 1:
        pooled_deviation = 0.0
    else:
        pooled_variance = sum(
            ((row.attempts - 1) * row.score_standard_deviation**2)
            + (row.attempts * (row.average_score - unrounded_average) ** 2)
            for row in rows
        ) / (attempts - 1)
        pooled_deviation = round(math.sqrt(max(0.0, pooled_variance)), 2)
    return (
        metrics.attempts == attempts
        and metrics.passed == sum(row.passed for row in rows)
        and metrics.failed == sum(row.failed for row in rows)
        and metrics.minimum_score == min(row.minimum_score for row in rows)
        and metrics.maximum_score == max(row.maximum_score for row in rows)
        and abs(metrics.average_score - weighted_average) <= 0.02
        and abs(metrics.score_standard_deviation - pooled_deviation) <= 0.05
        and metrics.combinations_with_any_pass == sum(row.any_pass for row in rows)
        and metrics.combinations_with_all_passes
        == sum(row.all_passed for row in rows)
    )


def load_matrix_reliability_baseline(path: Path) -> MatrixReliabilityBaseline:
    data = load_baseline_json(path, "reliability baseline")
    if not isinstance(data, dict):
        raise ValueError("Reliability baseline must be a JSON object.")
    if data.get("schema") != MATRIX_RELIABILITY_SCHEMA:
        raise ValueError(
            "Reliability baseline schema must be "
            f"'{MATRIX_RELIABILITY_SCHEMA}'."
        )
    require_fields(
        data,
        required={
            "schema",
            "schema_version",
            "suite_id",
            "created_at",
            "trials",
            "filters",
            "agents",
            "overall",
            "per_agent",
            "per_combination",
        },
        label="Reliability baseline",
    )
    if data["schema_version"] != MATRIX_RELIABILITY_SCHEMA_VERSION or isinstance(
        data["schema_version"], bool
    ):
        raise ValueError("Reliability baseline schema_version must be 1.")

    raw_filters = _required_mapping(data, "filters")
    raw_agents = data.get("agents")
    raw_per_agent = _required_mapping(data, "per_agent")
    raw_combinations = _required_mapping(data, "per_combination")
    if not isinstance(raw_agents, list) or not raw_agents:
        raise ValueError("Reliability baseline field 'agents' must be a non-empty string list.")
    agents = [
        require_string(agent, "Reliability baseline agent") for agent in raw_agents
    ]
    if len(agents) != len(set(agents)):
        raise ValueError("Reliability baseline agents must be unique.")
    if any(not isinstance(metrics, dict) for metrics in raw_per_agent.values()):
        raise ValueError("Reliability baseline per_agent values must be objects.")
    if any(not isinstance(row, dict) for row in raw_combinations.values()):
        raise ValueError("Reliability baseline per_combination values must be objects.")
    require_fields(
        raw_filters,
        required={"category", "difficulty", "tags"},
        label="Reliability baseline filters",
    )
    raw_tags = raw_filters["tags"]
    if not isinstance(raw_tags, list) or not all(
        isinstance(tag, str) and tag for tag in raw_tags
    ):
        raise ValueError(
            "Reliability baseline filter tags must be a non-empty string list."
        )
    if len(raw_tags) != len(set(raw_tags)):
        raise ValueError("Reliability baseline filter tags must be unique.")
    trials = require_int(data["trials"], "Reliability baseline trials", minimum=1)
    category = raw_filters["category"]
    if category is not None:
        category = require_string(category, "Reliability baseline filter category")
    difficulty = raw_filters["difficulty"]
    if difficulty is not None:
        difficulty = require_string(
            difficulty, "Reliability baseline filter difficulty"
        )
    if set(raw_per_agent) != set(agents):
        raise ValueError("Reliability baseline per_agent keys must match agents.")
    overall = _metrics_from_dict(
        _required_mapping(data, "overall"), "overall", aggregate=True
    )
    per_agent = {
        require_string(agent, "Reliability baseline per_agent key"): _metrics_from_dict(
            metrics, "agent", aggregate=True
        )
        for agent, metrics in sorted(raw_per_agent.items())
    }
    per_combination = {
        require_string(key, "Reliability baseline combination key"): _row_from_dict(
            row, key
        )
        for key, row in sorted(raw_combinations.items())
    }
    if not per_combination:
        raise ValueError("Reliability baseline per_combination must not be empty.")
    identities = [row.identity_key for row in per_combination.values()]
    if len(identities) != len(set(identities)):
        raise ValueError("Reliability baseline combination identities must be unique.")
    if any(row.agent not in agents for row in per_combination.values()):
        raise ValueError("Reliability baseline combination agent is not declared.")
    if any(row.attempts != trials for row in per_combination.values()):
        raise ValueError("Reliability baseline combination attempts must match trials.")
    all_rows = list(per_combination.values())
    if not _metrics_match_rows(overall, all_rows):
        raise ValueError("Reliability baseline overall metrics do not match combinations.")
    for agent, metrics in per_agent.items():
        rows = [row for row in per_combination.values() if row.agent == agent]
        if not _metrics_match_rows(metrics, rows):
            raise ValueError("Reliability per-agent metrics do not match combinations.")

    return MatrixReliabilityBaseline(
        schema=MATRIX_RELIABILITY_SCHEMA,
        schema_version=MATRIX_RELIABILITY_SCHEMA_VERSION,
        suite_id=require_string(data["suite_id"], "Reliability baseline suite_id"),
        created_at=require_string(
            data["created_at"], "Reliability baseline created_at"
        ),
        trials=trials,
        filters=ReliabilityBaselineFilters(
            category=category,
            difficulty=difficulty,
            tags=sorted(raw_tags),
        ),
        agents=sorted(agents),
        overall=overall,
        per_agent=per_agent,
        per_combination=per_combination,
    )


def _regression(
    kind: str,
    key: Optional[str],
    message: str,
    baseline_value: Optional[float] = None,
    current_value: Optional[float] = None,
    delta: Optional[float] = None,
) -> ReliabilityRegressionDetail:
    return ReliabilityRegressionDetail(
        kind=kind,
        combination_key=key,
        message=message,
        baseline_value=baseline_value,
        current_value=current_value,
        delta=delta,
    )


def evaluate_minimum_reliability(
    result: Any,
    thresholds: ReliabilityComparisonThresholds,
) -> ReliabilityComparison:
    current = baseline_from_matrix_result(result)
    regressions: list[ReliabilityRegressionDetail] = []
    if thresholds.min_success_rate is not None:
        minimum = thresholds.min_success_rate
        if current.overall.success_rate < minimum:
            regressions.append(
                _regression(
                    "minimum_success_rate",
                    None,
                    "Overall success rate below minimum: "
                    f"{current.overall.success_rate}% < {minimum}%",
                    current_value=current.overall.success_rate,
                    delta=round(minimum - current.overall.success_rate, 2),
                )
            )
        for row in current.per_combination.values():
            if row.success_rate < minimum:
                regressions.append(
                    _regression(
                        "minimum_success_rate",
                        row.key,
                        f"{row.task_id}/{row.agent} success rate below minimum: "
                        f"{row.success_rate}% < {minimum}%",
                        current_value=row.success_rate,
                        delta=round(minimum - row.success_rate, 2),
                    )
                )
    return ReliabilityComparison(
        baseline_path=None,
        thresholds=thresholds,
        has_regressions=bool(regressions),
        regressions=regressions,
        missing_combinations=[],
        new_combinations=[],
        version_mismatches=[],
    )


def compare_matrix_reliability(
    result: Any,
    baseline_path: Path,
    thresholds: ReliabilityComparisonThresholds,
    allow_version_mismatch: bool = False,
    only_compare_current_combinations: bool = False,
) -> ReliabilityComparison:
    baseline = load_matrix_reliability_baseline(baseline_path)
    current = baseline_from_matrix_result(result, created_at=baseline.created_at)
    baseline_by_identity = {
        row.identity_key: row for row in baseline.per_combination.values()
    }
    current_by_identity = {
        row.identity_key: row for row in current.per_combination.values()
    }
    minimum_comparison = evaluate_minimum_reliability(result, thresholds)
    regressions = list(minimum_comparison.regressions)
    missing: list[str] = []
    new: list[str] = []
    version_mismatches: list[str] = []

    baseline_identities = set(baseline_by_identity)
    current_identities = set(current_by_identity)
    if not only_compare_current_combinations:
        for identity in sorted(baseline_identities - current_identities):
            row = baseline_by_identity[identity]
            missing.append(row.key)
            regressions.append(
                _regression(
                    "missing_combination",
                    row.key,
                    f"Baseline combination missing: {row.task_id}/{row.agent}",
                )
            )
    for identity in sorted(current_identities - baseline_identities):
        new.append(current_by_identity[identity].key)

    for identity in sorted(baseline_identities & current_identities):
        baseline_row = baseline_by_identity[identity]
        current_row = current_by_identity[identity]
        if baseline_row.benchmark_version != current_row.benchmark_version:
            message = (
                f"Benchmark version mismatch for "
                f"{current_row.task_id}/{current_row.agent}: baseline "
                f"{baseline_row.benchmark_version} -> current "
                f"{current_row.benchmark_version}"
            )
            version_mismatches.append(message)

        success_drop = round(
            baseline_row.success_rate - current_row.success_rate,
            2,
        )
        if success_drop > thresholds.max_success_rate_drop:
            regressions.append(
                _regression(
                    "success_rate_drop",
                    current_row.key,
                    f"{current_row.task_id}/{current_row.agent} success rate "
                    f"dropped {success_drop} points: "
                    f"{baseline_row.success_rate}% -> {current_row.success_rate}%",
                    baseline_row.success_rate,
                    current_row.success_rate,
                    success_drop,
                )
            )

        score_drop = round(
            baseline_row.average_score - current_row.average_score,
            2,
        )
        if score_drop > thresholds.max_average_score_drop:
            regressions.append(
                _regression(
                    "average_score_drop",
                    current_row.key,
                    f"{current_row.task_id}/{current_row.agent} average score "
                    f"dropped {score_drop} points: "
                    f"{baseline_row.average_score} -> {current_row.average_score}",
                    baseline_row.average_score,
                    current_row.average_score,
                    score_drop,
                )
            )

        if baseline_row.any_pass and not current_row.any_pass:
            regressions.append(
                _regression(
                    "any_pass_degradation",
                    current_row.key,
                    f"{current_row.task_id}/{current_row.agent} changed from "
                    "at least one pass to no passes.",
                )
            )
        if baseline_row.all_passed and not current_row.all_passed:
            regressions.append(
                _regression(
                    "all_passed_degradation",
                    current_row.key,
                    f"{current_row.task_id}/{current_row.agent} changed from "
                    "all attempts passing to at least one failure.",
                )
            )

    if version_mismatches and not allow_version_mismatch:
        details = "\n".join(f"- {message}" for message in version_mismatches)
        raise ValueError(
            "Benchmark version mismatch between matrix and reliability baseline:\n"
            f"{details}\n"
            "Use --allow-version-mismatch to compare anyway."
        )

    return ReliabilityComparison(
        baseline_path=baseline_path.expanduser().as_posix(),
        thresholds=thresholds,
        has_regressions=bool(regressions),
        regressions=regressions,
        missing_combinations=missing,
        new_combinations=new,
        version_mismatches=version_mismatches,
    )
