import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

from agentguard.core.baseline import (
    baseline_from_suite_result,
    compare_suite_to_baseline,
    load_suite_baseline,
    write_suite_baseline,
)
from agentguard.core.baseline_validation import (
    MAX_BASELINE_BYTES,
    MAX_BASELINE_DEPTH,
    MAX_BASELINE_ITEMS,
)
from agentguard.config.loader import load_config
from agentguard.core.suite import (
    SuiteResult,
    SuiteRunHeadline,
    SuiteRunSummary,
    load_suite_config,
)


def _suite_result(
    tmp_path: Path,
    pass_rate: float = 50.0,
    average_score: int = 80,
    first_result: str = "PASS",
    first_score: int = 100,
    first_failed_checks: Optional[list[str]] = None,
    first_benchmark_id: Optional[str] = "auth_bug",
    first_benchmark_version: Optional[int] = 1,
    second_result: str = "FAIL",
    second_score: int = 60,
    second_failed_checks: Optional[list[str]] = None,
    second_benchmark_id: Optional[str] = "cli_parser",
    second_benchmark_version: Optional[int] = 1,
    include_second: bool = True,
) -> SuiteResult:
    runs = [
        SuiteRunSummary(
            task_id="fix_auth_bug",
            config_path=Path("examples/configs/fix_auth_bug.yaml"),
            agent="mock-safe",
            result=first_result,
            score=first_score,
            failed_checks=[] if first_failed_checks is None else first_failed_checks,
            warning_checks=[],
            benchmark_id=first_benchmark_id,
            benchmark_version=first_benchmark_version,
            json_report_path=Path("runs/safe/report.json"),
            markdown_report_path=Path("runs/safe/report.md"),
            run_dir=Path("runs/safe"),
        )
    ]
    if include_second:
        runs.append(
            SuiteRunSummary(
                task_id="fix_cli_parser_bug",
                config_path=Path("examples/configs/fix_cli_parser_bug.yaml"),
                agent="mock-test-cheater",
                result=second_result,
                score=second_score,
                failed_checks=(
                    ["Test tampering"]
                    if second_failed_checks is None
                    else second_failed_checks
                ),
                warning_checks=["Scope adherence"],
                benchmark_id=second_benchmark_id,
                benchmark_version=second_benchmark_version,
                json_report_path=Path("runs/cheater/report.json"),
                markdown_report_path=Path("runs/cheater/report.md"),
                run_dir=Path("runs/cheater"),
            )
        )

    return SuiteResult(
        suite_id="local_core",
        description="Local suite.",
        suite_path=Path("suite.yaml"),
        total_runs=len(runs),
        passed=sum(1 for run in runs if run.result == "PASS"),
        failed=sum(1 for run in runs if run.result == "FAIL"),
        pass_rate=pass_rate,
        average_score=average_score,
        best_run=SuiteRunHeadline(
            task_id=runs[0].task_id,
            agent=runs[0].agent,
            result=runs[0].result,
            score=runs[0].score,
        ),
        worst_run=SuiteRunHeadline(
            task_id=runs[-1].task_id,
            agent=runs[-1].agent,
            result=runs[-1].result,
            score=runs[-1].score,
        ),
        failed_check_counts=dict(
            Counter(check for run in runs for check in run.failed_checks)
        ),
        warning_check_counts={"Scope adherence": 1},
        result_counts=dict(Counter(run.result for run in runs)),
        runs=runs,
        json_report_path=tmp_path / "suite.json",
        markdown_report_path=tmp_path / "suite.md",
    )


def test_baseline_serialization_writes_schema_version(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "core.json")

    data = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert data["schema_version"] == 1
    assert data["suite_id"] == "local_core"
    assert data["pass_rate"] == 50.0
    assert data["average_score"] == 80
    assert all(
        not run["config_path"].startswith("/")
        for run in data["runs"].values()
    )
    first_run = data["runs"]["fix_auth_bug/mock-safe/examples/configs/fix_auth_bug.yaml"]
    assert first_run["benchmark_id"] == "auth_bug"
    assert first_run["benchmark_version"] == 1


def test_real_core_suite_baseline_row_has_benchmark_version_one(
    tmp_path: Path,
) -> None:
    suite = load_suite_config(Path("examples/suites/core.yaml"))
    first_run = suite.runs[0]
    config = load_config(first_run.config_path)
    result = SuiteResult(
        suite_id=suite.suite_id,
        description=suite.description,
        suite_path=suite.suite_path,
        total_runs=1,
        passed=1,
        failed=0,
        pass_rate=100.0,
        average_score=100,
        best_run=SuiteRunHeadline(
            task_id=config.task_id,
            agent=first_run.agent,
            result="PASS",
            score=100,
        ),
        worst_run=SuiteRunHeadline(
            task_id=config.task_id,
            agent=first_run.agent,
            result="PASS",
            score=100,
        ),
        failed_check_counts={},
        warning_check_counts={},
        result_counts={"PASS": 1},
        runs=[
            SuiteRunSummary(
                task_id=config.task_id,
                config_path=first_run.config_path,
                agent=first_run.agent,
                result="PASS",
                score=100,
                failed_checks=[],
                warning_checks=[],
                benchmark_id=config.benchmark.id,
                benchmark_version=config.benchmark.version,
                json_report_path=Path("runs/core/report.json"),
                markdown_report_path=Path("runs/core/report.md"),
                run_dir=Path("runs/core"),
            )
        ],
        json_report_path=tmp_path / "suite.json",
        markdown_report_path=tmp_path / "suite.md",
    )

    baseline = baseline_from_suite_result(result)
    baseline_run = next(iter(baseline.runs.values()))

    assert baseline_run.benchmark_id == "auth_bug_safe"
    assert baseline_run.benchmark_version == 1


def test_matching_benchmark_versions_compare_cleanly(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "core.json")

    comparison = compare_suite_to_baseline(_suite_result(tmp_path), baseline_path)

    assert comparison.version_mismatches == []


def test_mismatched_benchmark_versions_fail_by_default(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "core.json")

    with pytest.raises(ValueError, match="Benchmark version mismatch"):
        compare_suite_to_baseline(
            _suite_result(tmp_path, first_benchmark_version=2),
            baseline_path,
        )


def test_allow_version_mismatch_permits_comparison_and_reports_details(
    tmp_path: Path,
) -> None:
    baseline_path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "core.json")

    comparison = compare_suite_to_baseline(
        _suite_result(tmp_path, first_benchmark_version=2),
        baseline_path,
        allow_version_mismatch=True,
    )

    assert comparison.version_mismatches == [
        "Benchmark version mismatch for fix_auth_bug/mock-safe "
        "(auth_bug): baseline 1 -> current 2"
    ]


def test_absent_benchmark_versions_keep_existing_compare_behavior(
    tmp_path: Path,
) -> None:
    baseline_path = write_suite_baseline(
        _suite_result(
            tmp_path,
            first_benchmark_version=None,
            second_benchmark_version=None,
        ),
        tmp_path / "core.json",
    )

    comparison = compare_suite_to_baseline(
        _suite_result(
            tmp_path,
            first_benchmark_version=None,
            second_benchmark_version=None,
        ),
        baseline_path,
    )

    assert comparison.version_mismatches == []


def test_compare_detects_pass_rate_decrease(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(
        _suite_result(
            tmp_path,
            pass_rate=100.0,
            average_score=100,
            second_result="PASS",
            second_score=100,
            second_failed_checks=[],
        ),
        tmp_path / "core.json",
    )

    comparison = compare_suite_to_baseline(_suite_result(tmp_path), baseline_path)

    assert comparison.has_regressions is True
    assert "Pass rate decreased: 100.0 -> 50.0" in comparison.regressions


def test_compare_detects_pass_to_fail_regression(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(
        _suite_result(
            tmp_path,
            pass_rate=100.0,
            average_score=100,
            second_result="PASS",
            second_score=100,
            second_failed_checks=[],
        ),
        tmp_path / "core.json",
    )

    comparison = compare_suite_to_baseline(
        _suite_result(
            tmp_path,
            first_result="FAIL",
            first_score=70,
            first_failed_checks=["Tests passed"],
        ),
        baseline_path,
    )

    assert "Run fix_auth_bug/mock-safe changed PASS -> FAIL" in comparison.regressions
    assert "New failed check for fix_auth_bug/mock-safe: Tests passed" in comparison.regressions


def test_compare_detects_score_decrease(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "core.json")

    comparison = compare_suite_to_baseline(
        _suite_result(tmp_path, first_score=90),
        baseline_path,
    )

    assert "Run fix_auth_bug/mock-safe score decreased: 100 -> 90" in comparison.regressions


def test_compare_detects_missing_baseline_run(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "core.json")

    comparison = compare_suite_to_baseline(
        _suite_result(tmp_path, include_second=False),
        baseline_path,
    )

    assert "Baseline run missing: fix_cli_parser_bug/mock-test-cheater" in comparison.regressions


def test_compare_detects_improvements(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(
        _suite_result(tmp_path, second_result="FAIL", second_score=60),
        tmp_path / "core.json",
    )

    comparison = compare_suite_to_baseline(
        _suite_result(
            tmp_path,
            pass_rate=100.0,
            average_score=100,
            second_result="PASS",
            second_score=100,
            second_failed_checks=[],
        ),
        baseline_path,
    )

    assert comparison.has_regressions is False
    assert "Pass rate increased: 50.0 -> 100.0" in comparison.improvements
    assert (
        "Run fix_cli_parser_bug/mock-test-cheater changed FAIL -> PASS"
        in comparison.improvements
    )
    assert (
        "Failed check disappeared for fix_cli_parser_bug/mock-test-cheater: Test tampering"
        in comparison.improvements
    )


def test_baseline_from_suite_result_uses_stable_run_keys(tmp_path: Path) -> None:
    baseline = baseline_from_suite_result(
        _suite_result(tmp_path),
        created_at="2026-05-27T00:00:00+00:00",
    )

    assert sorted(baseline.runs) == [
        "fix_auth_bug/mock-safe/examples/configs/fix_auth_bug.yaml",
        "fix_cli_parser_bug/mock-test-cheater/examples/configs/fix_cli_parser_bug.yaml",
    ]


def _valid_baseline_data(tmp_path: Path) -> dict[str, Any]:
    path = write_suite_baseline(_suite_result(tmp_path), tmp_path / "valid.json")
    return json.loads(path.read_text(encoding="utf-8"))


def test_historical_v1_run_without_benchmark_fields_remains_valid(
    tmp_path: Path,
) -> None:
    data = _valid_baseline_data(tmp_path)
    for run in data["runs"].values():
        run.pop("benchmark_id")
        run.pop("benchmark_version")
    path = tmp_path / "historical.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    loaded = load_suite_baseline(path)

    assert all(run.benchmark_id is None for run in loaded.runs.values())
    assert all(run.benchmark_version is None for run in loaded.runs.values())


def test_boundary_valid_zero_score_suite_baseline_loads(tmp_path: Path) -> None:
    path = write_suite_baseline(
        _suite_result(
            tmp_path,
            pass_rate=0.0,
            average_score=0,
            first_result="FAIL",
            first_score=0,
            first_failed_checks=[],
            include_second=False,
        ),
        tmp_path / "zero.json",
    )

    loaded = load_suite_baseline(path)

    assert loaded.pass_rate == 0.0
    assert loaded.average_score == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.update(schema_version=True),
        lambda data: data.update(pass_rate="50"),
        lambda data: data.update(pass_rate=float("nan")),
        lambda data: data.update(average_score=True),
        lambda data: data.update(result_counts={"PASS": 2}),
        lambda data: data.update(failed_check_counts={}),
        lambda data: data.update(extra="unexpected"),
        lambda data: data["runs"].update(
            {next(iter(data["runs"])): "not-an-object"}
        ),
        lambda data: next(iter(data["runs"].values())).update(score="100"),
        lambda data: next(iter(data["runs"].values())).update(result="UNKNOWN"),
        lambda data: next(iter(data["runs"].values())).update(task_id="wrong"),
        lambda data: next(iter(data["runs"].values())).update(
            failed_checks=["duplicate", "duplicate"]
        ),
    ],
)
def test_malformed_suite_baseline_is_rejected(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    data = deepcopy(_valid_baseline_data(tmp_path))
    mutate(data)
    path = tmp_path / "malformed.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError):
        load_suite_baseline(path)


@pytest.mark.parametrize("content", ["", "[]", "{not json", '{"x": NaN}'])
def test_invalid_suite_baseline_documents_are_rejected(
    tmp_path: Path,
    content: str,
) -> None:
    path = tmp_path / "private-baseline-name.json"
    path.write_text(content, encoding="utf-8")

    with pytest.raises(ValueError) as captured:
        load_suite_baseline(path)

    assert str(path) not in str(captured.value)


def test_suite_baseline_rejects_duplicate_json_fields(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version": 1, "schema_version": 1}', encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate object field"):
        load_suite_baseline(path)


def test_suite_baseline_rejects_oversized_input(tmp_path: Path) -> None:
    path = tmp_path / "oversized.json"
    path.write_bytes(b" " * (MAX_BASELINE_BYTES + 1))

    with pytest.raises(ValueError, match="byte limit"):
        load_suite_baseline(path)


def test_suite_baseline_rejects_excessive_nesting(tmp_path: Path) -> None:
    nested = "0"
    for _ in range(MAX_BASELINE_DEPTH + 2):
        nested = f"[{nested}]"
    path = tmp_path / "deep.json"
    path.write_text(nested, encoding="utf-8")

    with pytest.raises(ValueError, match="nesting depth"):
        load_suite_baseline(path)


def test_suite_baseline_rejects_excessive_collection_size(tmp_path: Path) -> None:
    path = tmp_path / "many.json"
    path.write_text(json.dumps(list(range(MAX_BASELINE_ITEMS + 1))), encoding="utf-8")

    with pytest.raises(ValueError, match="item limit"):
        load_suite_baseline(path)
