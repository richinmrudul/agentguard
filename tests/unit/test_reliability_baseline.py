import json
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from agentguard.core.reliability_baseline import (
    MATRIX_RELIABILITY_SCHEMA,
    baseline_from_matrix_result,
    compare_matrix_reliability,
    load_matrix_reliability_baseline,
    reliability_combination_key,
    reliability_thresholds,
    wilson_score_interval,
    write_matrix_reliability_baseline,
)
from agentguard.core.suite import SuiteFilters


def _metrics(
    *,
    attempts: int = 4,
    passed: int = 4,
    average_score: float = 100,
):
    return SimpleNamespace(
        attempts=attempts,
        passed=passed,
        failed=attempts - passed,
        success_rate=round((passed / attempts) * 100, 1),
        average_score=average_score,
        minimum_score=int(average_score),
        maximum_score=int(average_score),
        score_standard_deviation=0.0,
        confidence_interval_95=wilson_score_interval(passed, attempts),
        combinations_with_any_pass=int(passed > 0),
        combinations_with_all_passes=int(passed == attempts),
    )


def _combination(
    tmp_path: Path,
    *,
    task_id: str = "auth",
    benchmark_id: str = "auth",
    benchmark_version: int = 1,
    agent: str = "mock-safe",
    attempts: int = 4,
    passed: int = 4,
    average_score: float = 100,
):
    metrics = _metrics(
        attempts=attempts,
        passed=passed,
        average_score=average_score,
    )
    return SimpleNamespace(
        task_id=task_id,
        config_path=tmp_path / f"{task_id}.yaml",
        benchmark_id=benchmark_id,
        benchmark_version=benchmark_version,
        agent=agent,
        trials=attempts,
        attempts=attempts,
        passed=passed,
        failed=attempts - passed,
        success_rate=metrics.success_rate,
        average_score=average_score,
        minimum_score=metrics.minimum_score,
        maximum_score=metrics.maximum_score,
        score_standard_deviation=0.0,
        confidence_interval_95=metrics.confidence_interval_95,
        any_pass=passed > 0,
        all_passed=passed == attempts,
    )


def _result(tmp_path: Path, combinations=None):
    combinations = combinations or [_combination(tmp_path)]
    combination_map = {}
    for combination in combinations:
        config_path = combination.config_path.resolve().as_posix()
        key = reliability_combination_key(
            config_path,
            combination.benchmark_id,
            combination.benchmark_version,
            combination.task_id,
            combination.agent,
        )
        combination_map[key] = combination
    attempts = sum(row.attempts for row in combinations)
    passed = sum(row.passed for row in combinations)
    average_score = sum(
        row.average_score * row.attempts for row in combinations
    ) / attempts
    overall = _metrics(
        attempts=attempts,
        passed=passed,
        average_score=average_score,
    )
    overall.combinations_with_any_pass = sum(row.any_pass for row in combinations)
    overall.combinations_with_all_passes = sum(
        row.all_passed for row in combinations
    )
    agents = sorted({row.agent for row in combinations})
    per_agent = {}
    for agent in agents:
        agent_rows = [row for row in combinations if row.agent == agent]
        metrics = _metrics(
            attempts=sum(row.attempts for row in combinations if row.agent == agent),
            passed=sum(row.passed for row in combinations if row.agent == agent),
            average_score=average_score,
        )
        metrics.combinations_with_any_pass = sum(row.any_pass for row in agent_rows)
        metrics.combinations_with_all_passes = sum(
            row.all_passed for row in agent_rows
        )
        per_agent[agent] = metrics
    return SimpleNamespace(
        suite_id="core",
        trials=combinations[0].trials,
        filters=SuiteFilters(),
        agents=agents,
        reliability=overall,
        per_agent_reliability=per_agent,
        combinations=combination_map,
    )


@pytest.mark.parametrize(
    ("passed", "attempts", "lower", "upper"),
    [
        (0, 1, 0.0, 79.35),
        (1, 1, 20.65, 100.0),
        (2, 3, 20.77, 93.85),
        (80, 100, 71.12, 86.66),
    ],
)
def test_wilson_score_interval(
    passed: int,
    attempts: int,
    lower: float,
    upper: float,
) -> None:
    interval = wilson_score_interval(passed, attempts)

    assert interval.lower_bound == lower
    assert interval.upper_bound == upper


def test_wilson_score_interval_rejects_zero_attempts() -> None:
    with pytest.raises(ValueError, match="at least one attempt"):
        wilson_score_interval(0, 0)


def test_reliability_baseline_serialization_is_deterministic(tmp_path: Path) -> None:
    result = _result(
        tmp_path,
        [
            _combination(tmp_path, task_id="zeta", benchmark_id="zeta"),
            _combination(tmp_path, task_id="alpha", benchmark_id="alpha"),
        ],
    )

    first = baseline_from_matrix_result(
        result,
        created_at="2026-06-06T00:00:00+00:00",
    )
    second = baseline_from_matrix_result(
        result,
        created_at="2026-06-06T00:00:00+00:00",
    )

    assert asdict(first) == asdict(second)
    assert list(first.per_combination) == sorted(first.per_combination)
    assert first.schema == MATRIX_RELIABILITY_SCHEMA


def test_reliability_baseline_round_trip_and_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    result = _result(tmp_path)

    write_matrix_reliability_baseline(result, path)
    loaded = load_matrix_reliability_baseline(path)

    assert loaded.schema == MATRIX_RELIABILITY_SCHEMA
    assert loaded.overall.attempts == 4
    assert next(iter(loaded.per_combination.values())).benchmark_version == 1
    with pytest.raises(ValueError, match="already exists"):
        write_matrix_reliability_baseline(result, path)
    write_matrix_reliability_baseline(result, path, force=True)


def test_suite_baseline_schema_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "suite.json"
    path.write_text(
        json.dumps({"schema_version": 1, "runs": {}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Reliability baseline schema"):
        load_matrix_reliability_baseline(path)


def test_corrupt_reliability_metrics_are_rejected_with_context(tmp_path: Path) -> None:
    path = write_matrix_reliability_baseline(_result(tmp_path), tmp_path / "base.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["overall"]["failed"] = 99
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid reliability metrics for overall"):
        load_matrix_reliability_baseline(path)


def _valid_reliability_data(tmp_path: Path) -> dict[str, Any]:
    path = write_matrix_reliability_baseline(_result(tmp_path), tmp_path / "valid.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _first_combination(data: dict[str, Any]) -> dict[str, Any]:
    return next(iter(data["per_combination"].values()))


def test_boundary_valid_zero_pass_reliability_baseline_loads(tmp_path: Path) -> None:
    result = _result(
        tmp_path,
        [_combination(tmp_path, attempts=1, passed=0, average_score=0)],
    )
    path = write_matrix_reliability_baseline(result, tmp_path / "zero.json")

    loaded = load_matrix_reliability_baseline(path)

    assert loaded.overall.success_rate == 0.0
    assert loaded.overall.minimum_score == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.update(schema_version=True),
        lambda data: data.update(trials="4"),
        lambda data: data.update(extra="unexpected"),
        lambda data: data["filters"].update(tags=["duplicate", "duplicate"]),
        lambda data: data["filters"].update(tags=[""]),
        lambda data: data.update(agents=["mock-safe", "mock-safe"]),
        lambda data: data["overall"].update(success_rate=float("nan")),
        lambda data: data["overall"].update(score_standard_deviation=99),
        lambda data: data["overall"].update(passed=3),
        lambda data: data["overall"]["confidence_interval_95"].update(
            lower_bound=-1
        ),
        lambda data: _first_combination(data).update(any_pass="false"),
        lambda data: _first_combination(data).update(all_passed=False),
        lambda data: _first_combination(data).update(key="wrong"),
        lambda data: _first_combination(data).update(identity_key="wrong"),
        lambda data: data["per_agent"]["mock-safe"].update(attempts=5),
    ],
)
def test_malformed_reliability_baseline_is_rejected(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    data = deepcopy(_valid_reliability_data(tmp_path))
    mutate(data)
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError) as captured:
        load_matrix_reliability_baseline(path)

    assert str(path) not in str(captured.value)


@pytest.mark.parametrize("content", ["", "[]", "{not json", '{"x": Infinity}'])
def test_invalid_reliability_documents_are_rejected(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "private reliability baseline.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError) as captured:
        load_matrix_reliability_baseline(path)

    assert str(path) not in str(captured.value)


def test_matching_comparison_has_no_regression(tmp_path: Path) -> None:
    result = _result(tmp_path)
    path = write_matrix_reliability_baseline(result, tmp_path / "baseline.json")

    comparison = compare_matrix_reliability(
        result,
        path,
        reliability_thresholds(),
    )

    assert comparison.has_regressions is False
    assert comparison.missing_combinations == []
    assert comparison.new_combinations == []


def test_success_rate_and_score_drop_threshold_boundaries(tmp_path: Path) -> None:
    baseline = _result(
        tmp_path,
        [_combination(tmp_path, attempts=4, passed=3, average_score=100)],
    )
    path = write_matrix_reliability_baseline(baseline, tmp_path / "baseline.json")
    current = _result(
        tmp_path,
        [_combination(tmp_path, attempts=4, passed=2, average_score=90)],
    )

    allowed = compare_matrix_reliability(
        current,
        path,
        reliability_thresholds(
            max_success_rate_drop=25,
            max_average_score_drop=10,
        ),
    )
    failed = compare_matrix_reliability(
        current,
        path,
        reliability_thresholds(
            max_success_rate_drop=24.9,
            max_average_score_drop=9.9,
        ),
    )

    assert allowed.has_regressions is False
    assert {"success_rate_drop", "average_score_drop"}.issubset(
        {detail.kind for detail in failed.regressions}
    )


def test_any_pass_and_all_passed_degradations(tmp_path: Path) -> None:
    baseline = _result(tmp_path)
    path = write_matrix_reliability_baseline(baseline, tmp_path / "baseline.json")
    current = _result(
        tmp_path,
        [_combination(tmp_path, attempts=4, passed=0, average_score=0)],
    )

    comparison = compare_matrix_reliability(
        current,
        path,
        reliability_thresholds(
            max_success_rate_drop=100,
            max_average_score_drop=100,
        ),
    )

    assert {detail.kind for detail in comparison.regressions} == {
        "any_pass_degradation",
        "all_passed_degradation",
    }


def test_version_mismatch_behavior(tmp_path: Path) -> None:
    baseline = _result(tmp_path)
    path = write_matrix_reliability_baseline(baseline, tmp_path / "baseline.json")
    current = _result(
        tmp_path,
        [_combination(tmp_path, benchmark_version=2)],
    )

    with pytest.raises(ValueError, match="Benchmark version mismatch"):
        compare_matrix_reliability(
            current,
            path,
            reliability_thresholds(),
        )
    comparison = compare_matrix_reliability(
        current,
        path,
        reliability_thresholds(),
        allow_version_mismatch=True,
    )

    assert len(comparison.version_mismatches) == 1


def test_missing_and_new_combinations(tmp_path: Path) -> None:
    baseline = _result(
        tmp_path,
        [
            _combination(tmp_path, task_id="auth", benchmark_id="auth"),
            _combination(tmp_path, task_id="prompt", benchmark_id="prompt"),
        ],
    )
    path = write_matrix_reliability_baseline(baseline, tmp_path / "baseline.json")
    current = _result(
        tmp_path,
        [
            _combination(tmp_path, task_id="auth", benchmark_id="auth"),
            _combination(tmp_path, task_id="filesystem", benchmark_id="filesystem"),
        ],
    )

    comparison = compare_matrix_reliability(
        current,
        path,
        reliability_thresholds(),
    )

    assert comparison.has_regressions is True
    assert len(comparison.missing_combinations) == 1
    assert len(comparison.new_combinations) == 1


def test_subset_comparison_can_ignore_missing_baseline_combinations(
    tmp_path: Path,
) -> None:
    baseline = _result(
        tmp_path,
        [
            _combination(tmp_path, task_id="auth", benchmark_id="auth"),
            _combination(tmp_path, task_id="prompt", benchmark_id="prompt"),
        ],
    )
    path = write_matrix_reliability_baseline(baseline, tmp_path / "baseline.json")
    current = _result(
        tmp_path,
        [_combination(tmp_path, task_id="auth", benchmark_id="auth")],
    )

    comparison = compare_matrix_reliability(
        current,
        path,
        reliability_thresholds(),
        only_compare_current_combinations=True,
    )

    assert comparison.has_regressions is False
    assert comparison.missing_combinations == []


def test_minimum_success_rate_applies_overall_and_per_combination(
    tmp_path: Path,
) -> None:
    result = _result(
        tmp_path,
        [
            _combination(
                tmp_path,
                task_id="auth",
                benchmark_id="auth",
                passed=4,
            ),
            _combination(
                tmp_path,
                task_id="prompt",
                benchmark_id="prompt",
                passed=2,
            ),
        ],
    )
    path = write_matrix_reliability_baseline(result, tmp_path / "baseline.json")

    comparison = compare_matrix_reliability(
        result,
        path,
        reliability_thresholds(min_success_rate=80),
    )

    assert comparison.has_regressions is True
    assert [detail.kind for detail in comparison.regressions].count(
        "minimum_success_rate"
    ) == 2
