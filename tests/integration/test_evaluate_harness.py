import json
import os
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

import agentguard.evaluation.harness as evaluation_harness
from agentguard.cli.main import app
from agentguard.core.matrix import run_matrix
from agentguard.core.result import (
    BenchmarkResult,
    CheckResult,
    CommandResult,
    DiffSummary,
    ReportPaths,
)
from agentguard.evaluation.harness import run_evaluation
from agentguard.guard.filesystem import GuardMode


runner = CliRunner()
ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_PROFILE = ROOT / "examples/agent-profiles/example-local.yaml"
EXAMPLE_SUITE = ROOT / "examples/suites/real_agent_core.yaml"


def _guard_suite(tmp_path: Path) -> Path:
    config = ROOT / "examples/configs/real_agent_source_fix.yaml"
    suite = tmp_path / "guard-evaluation-suite.yaml"
    suite.write_text(
        "suite_id: guard_evaluation\n"
        "description: Guard evaluation fixture.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: agent-command\n",
        encoding="utf-8",
    )
    return suite


def test_dry_run_executes_nothing_and_hides_prompts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "agentguard.evaluation.harness.run_benchmark",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("dry-run executed benchmark")
        ),
    )

    result = runner.invoke(
        app,
        [
            "evaluate",
            "dry-run",
            "--profile",
            str(EXAMPLE_PROFILE),
            "--suite",
            str(EXAMPLE_SUITE),
            "--trials",
            "3",
            "--workers",
            "2",
        ],
    )

    assert result.exit_code == 0
    assert "Total attempts: 15" in result.output
    assert "SHA-256" in result.output
    assert "Fix the authentication bug" not in result.output


def test_run_without_yes_executes_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "agentguard.cli.main.run_evaluation",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("run executed without confirmation")
        ),
    )

    result = runner.invoke(
        app,
        [
            "evaluate",
            "run",
            "--profile",
            str(EXAMPLE_PROFILE),
            "--suite",
            str(EXAMPLE_SUITE),
        ],
    )

    assert result.exit_code == 2
    assert "Execution not confirmed" in result.output


def test_invalid_profile_exits_two_without_traceback(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "evaluate",
            "validate",
            "--profile",
            str(tmp_path / "missing.yaml"),
            "--suite",
            str(EXAMPLE_SUITE),
        ],
    )

    assert result.exit_code == 2
    assert "Error:" in result.output
    assert "Traceback" not in result.output


def test_example_profile_runs_through_matrix_and_records_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    result = run_evaluation(
        EXAMPLE_PROFILE,
        EXAMPLE_SUITE,
        output_dir=tmp_path / "matrices",
        workers=2,
    )

    assert result.total_runs == 5
    assert result.profile_id == "example-local"
    assert result.functional_passed == 5
    assert result.policy_compliant_passed == 5
    assert result.unsafe_functional_successes == 0
    data = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    assert data["functional_success_rate"] == 100.0
    assert data["per_agent"]["example-local"]["functional_passed"] == 5
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["matrix"]["profile_model"] == "deterministic-fixture-v1"
    child = Path(manifest["child_executions"][0]["manifest_path"])
    child_data = json.loads(child.read_text(encoding="utf-8"))
    assert child_data["agent"]["configured_name"] == "example-local"
    assert child_data["agent"]["version"] == "agentguard-deterministic-profile 1.0"
    assert child_data["configuration"]["resolved_options"]["task_prompt_sha256"]


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_evaluation_api_rejects_invalid_guard_interval(
    tmp_path: Path,
    interval: float,
) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        run_evaluation(
            EXAMPLE_PROFILE,
            _guard_suite(tmp_path),
            output_dir=tmp_path / "matrices",
            guard_poll_interval_seconds=interval,
        )


def test_evaluation_cli_propagates_guard_through_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(
        app,
        [
            "evaluate",
            "run",
            "--profile",
            str(EXAMPLE_PROFILE),
            "--suite",
            str(_guard_suite(tmp_path)),
            "--yes",
            "--output-dir",
            str(tmp_path / "matrices"),
            "--guard-mode",
            "audit",
            "--guard-poll-interval",
            "0.05",
        ],
    )

    assert result.exit_code == 0
    assert "Guard mode: audit" in result.output
    assert "Guard poll interval: 0.05 seconds" in result.output
    assert "Guard incidents:" in result.output
    assert "- Incident runs: 0" in result.output
    report_line = next(
        line
        for line in result.output.splitlines()
        if line.startswith("Matrix JSON report path:")
    )
    report = json.loads(
        Path(report_line.split(": ", 1)[1]).read_text(encoding="utf-8")
    )
    assert report["guard_mode"] == "audit"
    assert report["guard_poll_interval_seconds"] == 0.05
    child = json.loads(
        Path(report["runs"][0]["json_report_path"]).read_text(encoding="utf-8")
    )
    assert child["guard_summary"]["mode"] == "audit"


def test_evaluation_inherits_matrix_guard_aggregation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    original = evaluation_harness.run_benchmark

    def guarded_result(*args, **kwargs):
        child = original(*args, **kwargs)
        guard_dir = child.run_dir / "guard"
        guard_dir.mkdir(exist_ok=True)
        incident_json = guard_dir / "incident.json"
        incident_markdown = guard_dir / "incident.md"
        incident_json.write_text("{}\n", encoding="utf-8")
        incident_markdown.write_text("# Incident\n", encoding="utf-8")
        return replace(
            child,
            guard_metrics={
                "guard_violations_total": 1,
                "guard_blocked": False,
                "filesystem_guard_violations": 1,
                "command_guard_violations": 0,
                "time_to_first_violation_ms": 7,
                "time_to_block_ms": None,
            },
            report_paths=replace(
                child.report_paths,
                guard_incident_json=incident_json,
                guard_incident_markdown=incident_markdown,
            ),
        )

    monkeypatch.setattr(evaluation_harness, "run_benchmark", guarded_result)

    result = run_evaluation(
        EXAMPLE_PROFILE,
        _guard_suite(tmp_path),
        output_dir=tmp_path / "matrices",
        guard_mode=GuardMode.AUDIT,
        guard_poll_interval_seconds=0.05,
    )
    report = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")

    assert result.guard_summary.incident_runs == 1
    assert result.guard_summary.filesystem_violations == 1
    assert report["guard_summary"]["time_to_first_violation"]["p95_ms"] == 7
    assert "## Guard Incidents" in markdown
    assert "Incident runs: 1" in markdown


def test_canary_environment_value_absent_from_outputs_and_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "AGENTGUARD-CANARY-SECRET-9247"
    script = tmp_path / "agent.py"
    script.write_text(
        """
import os
import subprocess
import sys
from pathlib import Path
print(os.environ["CANARY_SECRET"])
if "AGENTGUARD_UNLISTED_SECRET" in os.environ:
    raise SystemExit(9)
if subprocess.run(["agentguard-path-probe"], check=False).returncode != 0:
    raise SystemExit(10)
repo = Path(sys.argv[1])
completed = subprocess.run(
    [sys.executable, str(repo / "agent_scripts/safe_agent.py")],
    cwd=repo,
)
(repo / "src" / "canary.txt").write_text(
    os.environ["CANARY_SECRET"],
    encoding="utf-8",
)
raise SystemExit(completed.returncode)
""",
        encoding="utf-8",
    )
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        f"""
schema: agentguard.agent-profile
schema_version: 1
id: canary-profile
name: Canary Profile
command: ["python3", "{script}", "{{repo_dir}}", "{{task_prompt}}"]
workdir: profile_dir
environment: [CANARY_SECRET]
metadata: {{provider: test}}
""",
        encoding="utf-8",
    )
    config = ROOT / "examples/configs/real_agent_source_fix.yaml"
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        "suite_id: canary_suite\n"
        "description: Canary suite.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: agent-command\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    path_probe = bin_dir / "agentguard-path-probe"
    path_probe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path_probe.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("CANARY_SECRET", canary)
    monkeypatch.setenv("AGENTGUARD_UNLISTED_SECRET", "must-not-reach-agent")

    cli = runner.invoke(
        app,
        [
            "evaluate",
            "run",
            "--profile",
            str(profile),
            "--suite",
            str(suite),
            "--yes",
            "--output-dir",
            str(tmp_path / "matrices"),
        ],
    )

    assert cli.exit_code == 0, (cli.output, cli.exception)
    assert canary not in cli.output
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file() and path.suffix in {".json", ".md", ".yaml", ".db"}
    )
    assert canary not in artifact_text
    command_log = next(tmp_path.glob(".agentguard/runs/*/command_log.json"))
    command_log_text = command_log.read_text(encoding="utf-8")
    assert canary not in command_log_text
    assert "Canary Profile (canary-profile)" in command_log_text
    matrix_report = next((tmp_path / "matrices").glob("*/matrix.json"))
    matrix_data = json.loads(matrix_report.read_text(encoding="utf-8"))
    assert matrix_data["functional_passed"] == 1
    assert matrix_data["runs"][0]["functional_passed"] is True
    child_report = next(tmp_path.glob(".agentguard/runs/*/reports/report.json"))
    child_data = json.loads(child_report.read_text(encoding="utf-8"))
    assert child_data["test_result"]["exit_code"] == 0
    assert child_data["result"] == "PASS"
    with sqlite3.connect(tmp_path / ".agentguard/history.db") as connection:
        history_dump = repr(connection.execute("SELECT * FROM runs").fetchall())
    assert canary not in history_dump


def _fake_result(
    config_path: Path,
    *,
    result: str,
    test_exit_code: int,
    run_number: int,
) -> BenchmarkResult:
    run_dir = config_path.parent / f"run-{run_number}"
    return BenchmarkResult(
        task_id="metric-task",
        agent="metric-profile",
        result=result,
        score=100 if result == "PASS" else 40,
        config_path=config_path.resolve(),
        run_dir=run_dir,
        repo_dir=run_dir / "repo",
        test_result=CommandResult(
            command="test",
            exit_code=test_exit_code,
            stdout="",
            stderr="",
            duration_seconds=0,
        ),
        diff_summary=DiffSummary([], [], [], 0, 0, ""),
        check_results=[
            CheckResult("Tests passed", test_exit_code == 0, "error", "")
        ],
        report_paths=ReportPaths(
            json=run_dir / "report.json",
            markdown=run_dir / "report.md",
        ),
    )


def test_functional_and_policy_metrics_count_unsafe_success(
    tmp_path: Path,
) -> None:
    config = ROOT / "examples/configs/real_agent_source_fix.yaml"
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        "suite_id: metric_suite\n"
        "description: Metric suite.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: metric-profile\n",
        encoding="utf-8",
    )
    outcomes = [("PASS", 0), ("FAIL", 0), ("FAIL", 1)]
    calls = 0

    def runner_callback(path: Path, agent: str, matrix_id: str):
        nonlocal calls
        result, exit_code = outcomes[calls]
        calls += 1
        return _fake_result(
            path,
            result=result,
            test_exit_code=exit_code,
            run_number=calls,
        )

    result = run_matrix(
        suite,
        trials=3,
        matrices_root=tmp_path / "matrices",
        benchmark_runner=runner_callback,
    )

    assert result.functional_passed == 2
    assert result.policy_compliant_passed == 1
    assert result.unsafe_functional_successes == 1
    assert result.functional_success_rate == 66.7
    assert result.policy_compliant_success_rate == 33.3


def test_nonzero_external_agent_exit_becomes_failed_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "fail.py"
    script.write_text("raise SystemExit(7)\n", encoding="utf-8")
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        f"""
schema: agentguard.agent-profile
schema_version: 1
id: failing-profile
name: Failing Profile
command: ["python3", "{script}", "{{task_prompt}}"]
workdir: profile_dir
environment: []
metadata: {{provider: test}}
""",
        encoding="utf-8",
    )
    config = ROOT / "examples/configs/real_agent_source_fix.yaml"
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        "suite_id: failing_suite\n"
        "description: Failing suite.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: agent-command\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = run_evaluation(profile, suite, output_dir=tmp_path / "matrices")

    assert result.total_runs == 1
    assert result.failed == 1
    assert result.functional_passed == 0
