import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


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
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(asdict(baseline), file, indent=2)
        file.write("\n")
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
    try:
        lower = float(data["lower_bound"])
        upper = float(data["upper_bound"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid confidence interval for {label}.") from error
    if lower < 0 or upper > 100 or lower > upper:
        raise ValueError(f"Invalid confidence interval for {label}.")
    return ConfidenceInterval(lower_bound=lower, upper_bound=upper)


def _metrics_from_dict(
    data: dict[str, Any],
    label: str,
) -> ReliabilityBaselineMetrics:
    try:
        attempts = int(data["attempts"])
        passed = int(data["passed"])
        failed = int(data["failed"])
        metrics = ReliabilityBaselineMetrics(
            attempts=attempts,
            passed=passed,
            failed=failed,
            success_rate=float(data["success_rate"]),
            average_score=float(data["average_score"]),
            minimum_score=int(data["minimum_score"]),
            maximum_score=int(data["maximum_score"]),
            score_standard_deviation=float(data["score_standard_deviation"]),
            confidence_interval_95=_confidence_interval_from_dict(
                _required_mapping(data, "confidence_interval_95"),
                label,
            ),
            combinations_with_any_pass=(
                int(data["combinations_with_any_pass"])
                if data.get("combinations_with_any_pass") is not None
                else None
            ),
            combinations_with_all_passes=(
                int(data["combinations_with_all_passes"])
                if data.get("combinations_with_all_passes") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid reliability metrics for {label}.") from error
    if attempts <= 0 or passed < 0 or failed < 0 or passed + failed != attempts:
        raise ValueError(f"Invalid reliability metrics for {label}.")
    return metrics


def _row_from_dict(data: dict[str, Any], key: str) -> ReliabilityBaselineRow:
    try:
        metrics = _metrics_from_dict(data, key)
        return ReliabilityBaselineRow(
            key=key,
            identity_key=str(data["identity_key"]),
            task_id=str(data["task_id"]),
            config_path=str(data["config_path"]),
            benchmark_id=(
                str(data["benchmark_id"])
                if data.get("benchmark_id") is not None
                else None
            ),
            benchmark_version=(
                int(data["benchmark_version"])
                if data.get("benchmark_version") is not None
                else None
            ),
            agent=str(data["agent"]),
            attempts=metrics.attempts,
            passed=metrics.passed,
            failed=metrics.failed,
            success_rate=metrics.success_rate,
            average_score=metrics.average_score,
            minimum_score=metrics.minimum_score,
            maximum_score=metrics.maximum_score,
            score_standard_deviation=metrics.score_standard_deviation,
            confidence_interval_95=metrics.confidence_interval_95,
            any_pass=bool(data["any_pass"]),
            all_passed=bool(data["all_passed"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid reliability baseline combination '{key}'.") from error


def load_matrix_reliability_baseline(path: Path) -> MatrixReliabilityBaseline:
    baseline_path = path.expanduser()
    try:
        with baseline_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except OSError as error:
        raise ValueError(
            f"Could not read reliability baseline: {baseline_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Reliability baseline is not valid JSON: {baseline_path}"
        ) from error

    if not isinstance(data, dict):
        raise ValueError("Reliability baseline must be a JSON object.")
    if data.get("schema") != MATRIX_RELIABILITY_SCHEMA:
        raise ValueError(
            "Reliability baseline schema must be "
            f"'{MATRIX_RELIABILITY_SCHEMA}'."
        )
    if data.get("schema_version") != MATRIX_RELIABILITY_SCHEMA_VERSION:
        raise ValueError("Reliability baseline schema_version must be 1.")

    raw_filters = _required_mapping(data, "filters")
    raw_agents = data.get("agents")
    raw_per_agent = _required_mapping(data, "per_agent")
    raw_combinations = _required_mapping(data, "per_combination")
    if not isinstance(raw_agents, list) or not all(
        isinstance(agent, str) for agent in raw_agents
    ):
        raise ValueError("Reliability baseline field 'agents' must be a string list.")
    if any(not isinstance(metrics, dict) for metrics in raw_per_agent.values()):
        raise ValueError("Reliability baseline per_agent values must be objects.")
    if any(not isinstance(row, dict) for row in raw_combinations.values()):
        raise ValueError("Reliability baseline per_combination values must be objects.")
    raw_tags = raw_filters.get("tags", [])
    if not isinstance(raw_tags, list) or not all(
        isinstance(tag, str) for tag in raw_tags
    ):
        raise ValueError("Reliability baseline filter tags must be a string list.")
    trials = int(data.get("trials", 0))
    if trials <= 0:
        raise ValueError("Reliability baseline trials must be positive.")

    return MatrixReliabilityBaseline(
        schema=MATRIX_RELIABILITY_SCHEMA,
        schema_version=MATRIX_RELIABILITY_SCHEMA_VERSION,
        suite_id=str(data.get("suite_id", "")),
        created_at=str(data.get("created_at", "")),
        trials=trials,
        filters=ReliabilityBaselineFilters(
            category=(
                str(raw_filters["category"])
                if raw_filters.get("category") is not None
                else None
            ),
            difficulty=(
                str(raw_filters["difficulty"])
                if raw_filters.get("difficulty") is not None
                else None
            ),
            tags=sorted(raw_tags),
        ),
        agents=sorted(raw_agents),
        overall=_metrics_from_dict(_required_mapping(data, "overall"), "overall"),
        per_agent={
            str(agent): _metrics_from_dict(metrics, f"agent {agent}")
            for agent, metrics in sorted(raw_per_agent.items())
        },
        per_combination={
            str(key): _row_from_dict(row, str(key))
            for key, row in sorted(raw_combinations.items())
        },
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
