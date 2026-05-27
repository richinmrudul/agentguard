import json
import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.suite import run_suite
from agentguard.sandbox.docker_runner import docker_available


runner = CliRunner()


def _write_local_suite(tmp_path: Path) -> Path:
    suite_path = tmp_path / "local_suite.yaml"
    suite_path.write_text(
        "suite_id: local_core\n"
        "description: Local suite for tests.\n"
        "runs:\n"
        "  - config: examples/configs/fix_auth_bug.yaml\n"
        "    agent: mock-safe\n"
        "  - config: examples/configs/fix_auth_bug.yaml\n"
        "    agent: mock-test-cheater\n",
        encoding="utf-8",
    )
    return suite_path


def _report_path(output: str, label: str) -> Path:
    match = re.search(rf"{label}: (.+)", output)
    assert match is not None
    return Path(match.group(1).strip())


def _expect_all_pass_baseline(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    data["pass_rate"] = 100.0
    data["average_score"] = 100
    data["result_counts"] = {"PASS": 2}
    data["failed_check_counts"] = {}
    for run in data["runs"].values():
        run["result"] = "PASS"
        run["score"] = 100
        run["failed_checks"] = []
        run["warning_checks"] = []
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def test_run_suite_with_local_mock_agents_writes_reports(tmp_path: Path) -> None:
    result = run_suite(_write_local_suite(tmp_path), suites_root=tmp_path / "suites")

    assert result.total_runs == 2
    assert result.passed == 1
    assert result.failed == 1
    assert result.pass_rate == 50.0
    assert result.best_run.task_id == "fix_auth_bug"
    assert result.best_run.agent == "mock-safe"
    assert result.best_run.result == "PASS"
    assert result.best_run.score == 100
    assert result.worst_run.task_id == "fix_auth_bug"
    assert result.worst_run.agent == "mock-test-cheater"
    assert result.worst_run.result == "FAIL"
    assert result.worst_run.score == 60
    assert result.failed_check_counts["Test tampering"] == 1
    assert result.json_report_path.exists()
    assert result.markdown_report_path.exists()


def test_suite_cli_exits_nonzero_by_default_for_failures(tmp_path: Path) -> None:
    result = runner.invoke(app, ["suite", str(_write_local_suite(tmp_path))])

    assert result.exit_code != 0
    assert "AgentGuard Suite Summary" in result.output
    assert "Failed: 1" in result.output
    assert "Pass rate: 50.0%" in result.output
    assert "Best run: fix_auth_bug / mock-safe / PASS / 100" in result.output
    assert "Most common failed checks:" in result.output
    assert "- Test tampering: 1" in result.output


def test_suite_cli_allows_failures(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["suite", str(_write_local_suite(tmp_path)), "--allow-failures"],
    )

    assert result.exit_code == 0
    assert "AgentGuard Suite Summary" in result.output
    assert "Failed: 1" in result.output
    assert "Pass rate: 50.0%" in result.output
    assert "Best run:" in result.output
    assert "Most common failed checks:" in result.output
    assert "Suite JSON report path:" in result.output
    assert "Suite Markdown report path:" in result.output


def test_suite_cli_saves_baseline(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baselines" / "core.json"
    result = runner.invoke(
        app,
        [
            "suite",
            str(_write_local_suite(tmp_path)),
            "--allow-failures",
            "--save-baseline",
            str(baseline_path),
        ],
    )

    assert result.exit_code == 0
    assert baseline_path.exists()
    assert f"Baseline saved: {baseline_path}" in result.output
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert baseline["schema_version"] == 1
    assert baseline["suite_id"] == "local_core"
    assert baseline["pass_rate"] == 50.0


def test_suite_cli_compares_same_baseline_without_regressions(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "baseline.json"
    save_result = runner.invoke(
        app,
        [
            "suite",
            str(suite_path),
            "--allow-failures",
            "--save-baseline",
            str(baseline_path),
        ],
    )
    assert save_result.exit_code == 0

    result = runner.invoke(
        app,
        [
            "suite",
            str(suite_path),
            "--allow-failures",
            "--compare-baseline",
            str(baseline_path),
        ],
    )

    assert result.exit_code == 0
    assert "Baseline comparison" in result.output
    assert "Regressions: no" in result.output
    assert "Regression details: none" in result.output


def test_suite_cli_compare_detects_regression_and_exits_nonzero(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "baseline.json"
    save_result = runner.invoke(
        app,
        [
            "suite",
            str(suite_path),
            "--allow-failures",
            "--save-baseline",
            str(baseline_path),
        ],
    )
    assert save_result.exit_code == 0
    _expect_all_pass_baseline(baseline_path)

    result = runner.invoke(
        app,
        [
            "suite",
            str(suite_path),
            "--allow-failures",
            "--compare-baseline",
            str(baseline_path),
        ],
    )

    assert result.exit_code != 0
    assert "Regressions: yes" in result.output
    assert "Pass rate decreased: 100.0 -> 50.0" in result.output
    assert "changed PASS -> FAIL" in result.output
    json_report_path = _report_path(result.output, "Suite JSON report path")
    markdown_report_path = _report_path(result.output, "Suite Markdown report path")
    report = json.loads(json_report_path.read_text(encoding="utf-8"))
    markdown = markdown_report_path.read_text(encoding="utf-8")
    assert report["baseline_comparison"]["has_regressions"] is True
    assert "## Baseline Comparison" in markdown
    assert "Pass rate decreased: 100.0 -> 50.0" in markdown


def test_suite_cli_allow_regressions_keeps_exit_zero(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "baseline.json"
    save_result = runner.invoke(
        app,
        [
            "suite",
            str(suite_path),
            "--allow-failures",
            "--save-baseline",
            str(baseline_path),
        ],
    )
    assert save_result.exit_code == 0
    _expect_all_pass_baseline(baseline_path)

    result = runner.invoke(
        app,
        [
            "suite",
            str(suite_path),
            "--allow-failures",
            "--compare-baseline",
            str(baseline_path),
            "--allow-regressions",
        ],
    )

    assert result.exit_code == 0
    assert "Regressions: yes" in result.output
    assert "Pass rate decreased: 100.0 -> 50.0" in result.output


def test_suite_command_exists_in_help() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "suite" in result.output


@pytest.mark.skipif(not docker_available(), reason="Docker is not available")
def test_core_docker_suite_runs_when_docker_is_available() -> None:
    result = run_suite(Path("examples/suites/core.yaml"))

    assert result.total_runs == 8
    assert result.passed == 4
    assert result.failed == 4
