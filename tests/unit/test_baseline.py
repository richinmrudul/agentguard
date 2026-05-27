import json
from pathlib import Path
from typing import Optional

from agentguard.core.baseline import (
    baseline_from_suite_result,
    compare_suite_to_baseline,
    write_suite_baseline,
)
from agentguard.core.suite import SuiteResult, SuiteRunHeadline, SuiteRunSummary


def _suite_result(
    tmp_path: Path,
    pass_rate: float = 50.0,
    average_score: int = 80,
    first_result: str = "PASS",
    first_score: int = 100,
    first_failed_checks: Optional[list[str]] = None,
    second_result: str = "FAIL",
    second_score: int = 60,
    second_failed_checks: Optional[list[str]] = None,
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
        failed_check_counts={"Test tampering": 1},
        warning_check_counts={"Scope adherence": 1},
        result_counts={"PASS": 1, "FAIL": 1},
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


def test_compare_detects_pass_rate_decrease(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(
        _suite_result(tmp_path, pass_rate=100.0),
        tmp_path / "core.json",
    )

    comparison = compare_suite_to_baseline(_suite_result(tmp_path), baseline_path)

    assert comparison.has_regressions is True
    assert "Pass rate decreased: 100.0 -> 50.0" in comparison.regressions


def test_compare_detects_pass_to_fail_regression(tmp_path: Path) -> None:
    baseline_path = write_suite_baseline(
        _suite_result(tmp_path, pass_rate=100.0),
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
