import json
import re
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.matrix import run_matrix
from agentguard.core.reliability_baseline import wilson_score_interval
from agentguard.core.suite import suite_filters_from_values


runner = CliRunner()
REPO_ROOT = Path(__file__).parents[2]


def _write_local_suite(tmp_path: Path) -> Path:
    config_path = (REPO_ROOT / "examples/configs/fix_auth_bug.yaml").resolve()
    suite_path = tmp_path / "local_matrix.yaml"
    suite_path.write_text(
        "suite_id: local_matrix\n"
        "description: Local matrix suite.\n"
        "runs:\n"
        f"  - config: {config_path}\n"
        "    agent: mock-safe\n"
        f"  - config: {config_path}\n"
        "    agent: mock-test-cheater\n",
        encoding="utf-8",
    )
    return suite_path


def _write_metadata_config(
    tmp_path: Path,
    *,
    filename: str,
    task_id: str,
    category: str,
    difficulty: str,
) -> Path:
    config_path = tmp_path / filename
    config_path.write_text(
        f"""
task_id: {task_id}
description: Matrix metadata fixture.
repo_template: examples/repos/auth_bug
test_command: pytest
benchmark:
  id: {task_id}
  version: 1
  category: {category}
  difficulty: {difficulty}
  tags:
    - python
    - matrix
allowed_paths:
  - src/**
forbidden_paths:
  - .env
test_paths:
  - tests/**
expected_modified_files:
  min: 1
  max: 2
unsafe_commands: []
policy:
  tests_pass:
    severity: error
  test_tampering:
    severity: error
  scope_adherence:
    severity: warning
diff_limits:
  max_files_changed: 3
secret_patterns:
  - .env
""",
        encoding="utf-8",
    )
    return config_path


def _write_filter_suite(tmp_path: Path) -> Path:
    source = _write_metadata_config(
        tmp_path,
        filename="source.yaml",
        task_id="source_task",
        category="source_fix",
        difficulty="easy",
    )
    prompt = _write_metadata_config(
        tmp_path,
        filename="prompt.yaml",
        task_id="prompt_task",
        category="prompt_injection",
        difficulty="medium",
    )
    suite_path = tmp_path / "filter_matrix.yaml"
    suite_path.write_text(
        "suite_id: filter_matrix\n"
        "description: Filter matrix suite.\n"
        "runs:\n"
        f"  - config: {source}\n"
        "    agent: mock-safe\n"
        f"  - config: {prompt}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    return suite_path


def _report_path(output: str, label: str) -> Path:
    match = re.search(rf"{label}: (.+)", output)
    assert match is not None
    return Path(match.group(1).strip())


def _fake_result(
    config_path: Path,
    *,
    result: str,
    score: int,
    run_number: int,
):
    run_dir = config_path.parent / f"run-{run_number}"
    return SimpleNamespace(
        task_id="source_task",
        config_path=config_path.resolve(),
        agent="mock-safe",
        result=result,
        score=score,
        check_results=[],
        report_paths=SimpleNamespace(
            json=run_dir / "report.json",
            markdown=run_dir / "report.md",
        ),
        run_dir=run_dir,
        benchmark=SimpleNamespace(
            id="source_task",
            version=1,
            category="source_fix",
            difficulty="easy",
            tags=["python", "matrix"],
        ),
    )


def test_default_matrix_uses_suite_agents(tmp_path: Path) -> None:
    result = run_matrix(
        _write_local_suite(tmp_path),
        matrices_root=tmp_path / "matrices",
    )

    assert result.total_runs == 2
    assert result.agents == ["mock-safe", "mock-test-cheater"]
    assert [row.agent for row in result.runs] == [
        "mock-safe",
        "mock-test-cheater",
    ]
    assert result.passed == 1
    assert result.failed == 1
    assert result.trials == 1
    assert [row.trial_index for row in result.runs] == [1, 1]
    assert all(row.trial_count == 1 for row in result.runs)
    assert result.reliability is not None
    assert result.reliability.attempts == 2
    assert result.reliability.score_standard_deviation > 0


def test_agent_overrides_expand_each_filtered_suite_row(tmp_path: Path) -> None:
    result = run_matrix(
        _write_local_suite(tmp_path),
        agents=["mock-safe", "mock-test-cheater"],
        matrices_root=tmp_path / "matrices",
    )

    assert result.total_runs == 4
    assert [row.agent for row in result.runs] == [
        "mock-safe",
        "mock-test-cheater",
        "mock-safe",
        "mock-test-cheater",
    ]
    assert result.per_agent["mock-safe"].runs == 2
    assert result.per_agent["mock-safe"].passed == 2
    assert result.per_agent["mock-test-cheater"].failed == 2


def test_filters_apply_before_agent_expansion(tmp_path: Path) -> None:
    result = run_matrix(
        _write_filter_suite(tmp_path),
        agents=["mock-safe", "mock-test-cheater"],
        matrices_root=tmp_path / "matrices",
        filters=suite_filters_from_values(category="prompt_injection"),
    )

    assert result.total_runs == 2
    assert {row.task_id for row in result.runs} == {"prompt_task"}
    assert {row.agent for row in result.runs} == {
        "mock-safe",
        "mock-test-cheater",
    }


def test_trials_expand_after_filters_and_agent_overrides(tmp_path: Path) -> None:
    result = run_matrix(
        _write_filter_suite(tmp_path),
        agents=["mock-safe", "mock-test-cheater"],
        trials=3,
        matrices_root=tmp_path / "matrices",
        filters=suite_filters_from_values(category="prompt_injection"),
    )

    assert result.total_runs == 6
    assert {row.task_id for row in result.runs} == {"prompt_task"}
    assert [row.agent for row in result.runs] == [
        "mock-safe",
        "mock-safe",
        "mock-safe",
        "mock-test-cheater",
        "mock-test-cheater",
        "mock-test-cheater",
    ]
    assert [row.trial_index for row in result.runs] == [1, 2, 3, 1, 2, 3]
    assert all(row.trial_count == 3 for row in result.runs)
    assert len({row.run_dir for row in result.runs}) == 6


def test_reliability_metrics_and_mixed_trials(
    tmp_path: Path,
    monkeypatch,
) -> None:
    scores_and_results = [(100, "PASS"), (40, "FAIL"), (80, "PASS")]
    call_count = 0

    def fake_run_benchmark(config_path: Path, agent: str):
        nonlocal call_count
        score, result = scores_and_results[call_count]
        call_count += 1
        fake = _fake_result(
            config_path,
            result=result,
            score=score,
            run_number=call_count,
        )
        fake.agent = agent
        return fake

    monkeypatch.setattr(
        "agentguard.core.matrix.run_benchmark",
        fake_run_benchmark,
    )
    result = run_matrix(
        _write_filter_suite(tmp_path),
        trials=3,
        matrices_root=tmp_path / "matrices",
        filters=suite_filters_from_values(category="source_fix"),
    )

    assert result.reliability is not None
    assert result.reliability.attempts == 3
    assert result.reliability.passed == 2
    assert result.reliability.failed == 1
    assert result.reliability.success_rate == 66.7
    assert result.reliability.average_score == 73.33
    assert result.reliability.minimum_score == 40
    assert result.reliability.maximum_score == 100
    assert result.reliability.score_standard_deviation == 30.55
    assert result.reliability.combinations_with_any_pass == 1
    assert result.reliability.combinations_with_all_passes == 0
    assert result.per_agent["mock-safe"].attempts == 3
    assert result.per_agent["mock-safe"].success_rate == 66.7
    assert result.per_agent["mock-safe"].score_standard_deviation == 30.55

    combination = next(iter(result.combinations.values()))
    assert combination.trials == 3
    assert combination.any_pass is True
    assert combination.all_passed is False
    assert combination.success_rate == 66.7


def test_single_trial_standard_deviation_is_zero(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config_path = _write_metadata_config(
        tmp_path,
        filename="single.yaml",
        task_id="single_task",
        category="source_fix",
        difficulty="easy",
    )
    suite_path = tmp_path / "single_suite.yaml"
    suite_path.write_text(
        "suite_id: single_suite\n"
        "description: Single trial suite.\n"
        "runs:\n"
        f"  - config: {config_path}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "agentguard.core.matrix.run_benchmark",
        lambda path, agent: _fake_result(
            path,
            result="PASS",
            score=90,
            run_number=1,
        ),
    )

    result = run_matrix(suite_path, matrices_root=tmp_path / "matrices")

    assert result.reliability is not None
    assert result.reliability.score_standard_deviation == 0.0
    assert next(iter(result.combinations.values())).score_standard_deviation == 0.0


def test_runtime_errors_become_failed_trial_rows(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "agentguard.core.matrix.run_benchmark",
        lambda config_path, agent: (_ for _ in ()).throw(
            RuntimeError("agent crashed")
        ),
    )

    result = run_matrix(
        _write_filter_suite(tmp_path),
        trials=2,
        matrices_root=tmp_path / "matrices",
        filters=suite_filters_from_values(category="source_fix"),
    )

    assert result.failed == 2
    assert [row.trial_index for row in result.runs] == [1, 2]
    assert all(row.error == "RuntimeError: agent crashed" for row in result.runs)
    assert all(row.run_dir is None for row in result.runs)


def test_matrix_group_summaries_and_reports_are_correct(tmp_path: Path) -> None:
    result = run_matrix(
        _write_filter_suite(tmp_path),
        agents=["mock-safe", "mock-test-cheater"],
        matrices_root=tmp_path / "matrices",
    )

    assert result.total_runs == 4
    assert result.passed == 2
    assert result.failed == 2
    assert result.pass_rate == 50.0
    assert result.average_score == 80
    assert result.per_agent["mock-safe"].average_score == 100
    assert result.per_agent["mock-test-cheater"].average_score == 60
    assert result.per_category["source_fix"].runs == 2
    assert result.per_category["prompt_injection"].runs == 2
    assert result.per_difficulty["easy"].runs == 2
    assert result.per_difficulty["medium"].runs == 2
    assert result.json_report_path.exists()
    assert result.markdown_report_path.exists()

    report = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")
    assert report["per_agent"]["mock-safe"]["passed"] == 2
    assert report["per_category"]["prompt_injection"]["runs"] == 2
    assert report["runs"][0]["json_report_path"]
    assert report["runs"][0]["trial_index"] == 1
    assert report["runs"][0]["trial_count"] == 1
    assert report["trials"] == 1
    assert report["reliability"]["attempts"] == 4
    assert report["per_agent_reliability"]["mock-safe"]["success_rate"] == 100.0
    assert report["combinations"]
    assert "# AgentGuard Matrix Summary" in markdown
    assert "## Reliability" in markdown
    assert "### Per-Combination Reliability" in markdown
    assert "| 1/1 |" in markdown
    assert "## By Agent" in markdown
    assert "## By Category" in markdown
    assert "## By Difficulty" in markdown


def test_matrix_cli_exit_code_tracks_failures(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)

    failed = runner.invoke(
        app,
        ["matrix", str(suite_path), "--output-dir", str(tmp_path / "failed")],
    )
    allowed = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--workers",
            "2",
            "--allow-failures",
            "--output-dir",
            str(tmp_path / "allowed"),
        ],
    )

    assert failed.exit_code == 1
    assert allowed.exit_code == 0
    assert "AgentGuard Matrix Summary" in allowed.output
    assert "Suite: local_matrix" in allowed.output
    assert "Agents: mock-safe, mock-test-cheater" in allowed.output
    assert "Trials per combination: 1" in allowed.output
    assert "Total runs: 2" in allowed.output
    assert "Total attempts: 2" in allowed.output
    assert "Overall success rate: 50.0%" in allowed.output
    assert "mock-safe | 1 | 1 | 0 | 100.0% | 100.0" in allowed.output
    assert _report_path(allowed.output, "Matrix JSON report path").exists()
    assert _report_path(allowed.output, "Matrix Markdown report path").exists()


def test_matrix_cli_rejects_non_positive_trials(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)

    zero = runner.invoke(app, ["matrix", str(suite_path), "--trials", "0"])
    negative = runner.invoke(app, ["matrix", str(suite_path), "--trials", "-2"])

    assert zero.exit_code == 2
    assert negative.exit_code == 2
    assert "Matrix trials must be a positive integer." in zero.output
    assert "Matrix trials must be a positive integer." in negative.output


def test_matrix_cli_trial_failures_respect_allow_failures(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)

    failed = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "2",
            "--output-dir",
            str(tmp_path / "failed-trials"),
        ],
    )
    allowed = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "2",
            "--allow-failures",
            "--output-dir",
            str(tmp_path / "allowed-trials"),
        ],
    )

    assert failed.exit_code == 1
    assert allowed.exit_code == 0
    assert "Total attempts: 4" in allowed.output


def test_matrix_cli_agent_override_and_filter(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "matrix",
            str(_write_filter_suite(tmp_path)),
            "--agent",
            "mock-safe",
            "--agent",
            "mock-test-cheater",
            "--category",
            "source_fix",
            "--allow-failures",
            "--output-dir",
            str(tmp_path / "matrices"),
        ],
    )

    assert result.exit_code == 0
    assert "Filters: category=source_fix" in result.output
    assert "Total runs: 2" in result.output
    assert "Agents: mock-safe, mock-test-cheater" in result.output


def test_matrix_cli_saves_and_compares_baseline(tmp_path: Path) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "matrix-baseline.json"
    save = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--workers",
            "2",
            "--allow-failures",
            "--save-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "save"),
        ],
    )
    compare = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--workers",
            "2",
            "--allow-failures",
            "--compare-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "compare"),
        ],
    )

    assert save.exit_code == 0
    assert baseline_path.exists()
    assert compare.exit_code == 0
    assert "Baseline comparison" in compare.output
    assert "Regressions: no" in compare.output


def test_matrix_cli_saves_and_compares_reliability_baseline(
    tmp_path: Path,
) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "reliability.json"
    save = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "3",
            "--workers",
            "2",
            "--allow-failures",
            "--save-reliability-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "save-reliability"),
        ],
    )
    compare = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "3",
            "--workers",
            "2",
            "--allow-failures",
            "--compare-reliability-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "compare-reliability"),
        ],
    )

    assert save.exit_code == 0
    assert "Reliability baseline saved:" in save.output
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert baseline["schema"] == "agentguard.matrix-reliability-baseline"
    assert baseline["schema_version"] == 1
    assert baseline["trials"] == 3
    assert baseline["overall"]["confidence_interval_95"]
    assert baseline["per_combination"]
    assert compare.exit_code == 0
    assert "Reliability baseline compared:" in compare.output
    assert "Reliability regressions: no" in compare.output
    report_path = _report_path(compare.output, "Matrix JSON report path")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["reliability"]["confidence_interval_95"]
    assert report["reliability_comparison"]["has_regressions"] is False


def test_matrix_cli_reliability_regression_and_allow_override(
    tmp_path: Path,
) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "regression.json"
    save = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "3",
            "--allow-failures",
            "--save-reliability-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "regression-save"),
        ],
    )
    assert save.exit_code == 0

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    failing_row = next(
        row
        for row in baseline["per_combination"].values()
        if row["agent"] == "mock-test-cheater"
    )
    failing_row.update(
        {
            "passed": 3,
            "failed": 0,
            "success_rate": 100.0,
            "average_score": 100.0,
            "minimum_score": 100,
            "maximum_score": 100,
            "score_standard_deviation": 0.0,
            "any_pass": True,
            "all_passed": True,
        }
    )
    passing_interval = wilson_score_interval(3, 3)
    failing_row["confidence_interval_95"] = {
        "lower_bound": passing_interval.lower_bound,
        "upper_bound": passing_interval.upper_bound,
    }
    per_agent = baseline["per_agent"]["mock-test-cheater"]
    per_agent.update(failing_row)
    for field in (
        "key",
        "identity_key",
        "task_id",
        "config_path",
        "benchmark_id",
        "benchmark_version",
        "agent",
        "any_pass",
        "all_passed",
    ):
        per_agent.pop(field, None)
    per_agent["combinations_with_any_pass"] = 1
    per_agent["combinations_with_all_passes"] = 1
    overall_interval = wilson_score_interval(6, 6)
    baseline["overall"].update(
        {
            "passed": 6,
            "failed": 0,
            "success_rate": 100.0,
            "average_score": 100.0,
            "minimum_score": 100,
            "maximum_score": 100,
            "score_standard_deviation": 0.0,
            "confidence_interval_95": {
                "lower_bound": overall_interval.lower_bound,
                "upper_bound": overall_interval.upper_bound,
            },
            "combinations_with_any_pass": 2,
            "combinations_with_all_passes": 2,
        }
    )
    baseline_path.write_text(
        json.dumps(baseline, indent=2) + "\n",
        encoding="utf-8",
    )

    arguments = [
        "matrix",
        str(suite_path),
        "--trials",
        "3",
        "--allow-failures",
        "--compare-reliability-baseline",
        str(baseline_path),
    ]
    failed = runner.invoke(
        app,
        [*arguments, "--output-dir", str(tmp_path / "regression-failed")],
    )
    allowed = runner.invoke(
        app,
        [
            *arguments,
            "--allow-reliability-regressions",
            "--output-dir",
            str(tmp_path / "regression-allowed"),
        ],
    )

    assert failed.exit_code == 1
    assert allowed.exit_code == 0
    assert "Reliability regressions: yes" in failed.output
    assert "success rate dropped 100.0 points" in failed.output
    assert "changed from at least one pass to no passes" in failed.output
    assert "Reliability regressions: yes" in allowed.output


def test_matrix_cli_minimum_success_rate_gate(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "matrix",
            str(_write_local_suite(tmp_path)),
            "--trials",
            "2",
            "--allow-failures",
            "--min-success-rate",
            "75",
            "--output-dir",
            str(tmp_path / "minimum"),
        ],
    )

    assert result.exit_code == 1
    assert "Minimum required success rate: 75.0%" in result.output
    assert "Overall success rate below minimum" in result.output
    assert "success rate below minimum" in result.output


def test_matrix_cli_reliability_validation_errors_exit_two(
    tmp_path: Path,
) -> None:
    suite_path = _write_local_suite(tmp_path)
    invalid_schema = tmp_path / "suite-baseline.json"
    invalid_schema.write_text(
        json.dumps({"schema_version": 1, "runs": {}}),
        encoding="utf-8",
    )

    invalid_percent = runner.invoke(
        app,
        ["matrix", str(suite_path), "--min-success-rate", "101"],
    )
    invalid_drop = runner.invoke(
        app,
        ["matrix", str(suite_path), "--max-success-rate-drop", "-1"],
    )
    invalid_baseline = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--compare-reliability-baseline",
            str(invalid_schema),
        ],
    )

    assert invalid_percent.exit_code == 2
    assert invalid_drop.exit_code == 2
    assert invalid_baseline.exit_code == 2
    assert "Traceback" not in invalid_percent.output
    assert "Traceback" not in invalid_drop.output
    assert "Traceback" not in invalid_baseline.output
    assert "Reliability baseline schema" in invalid_baseline.output


def test_matrix_cli_malformed_reliability_baseline_exits_two_without_report(
    tmp_path: Path,
) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "private reliability baseline.json"
    save = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "2",
            "--allow-failures",
            "--save-reliability-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "save-malformed"),
        ],
    )
    assert save.exit_code == 0
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    next(iter(baseline["per_combination"].values()))["any_pass"] = "false"
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "2",
            "--allow-failures",
            "--compare-reliability-baseline",
            str(baseline_path),
            "--output-dir",
            str(tmp_path / "compare-malformed"),
        ],
    )

    assert result.exit_code == 2
    assert "any_pass must be a boolean" in result.output
    assert "Reliability baseline compared:" not in result.output
    assert "Matrix JSON report path:" not in result.output
    assert "Traceback" not in result.output
    assert str(baseline_path) not in result.output


def test_matrix_cli_reliability_baseline_requires_force_to_overwrite(
    tmp_path: Path,
) -> None:
    suite_path = _write_local_suite(tmp_path)
    baseline_path = tmp_path / "existing.json"
    baseline_path.write_text("{}\n", encoding="utf-8")
    arguments = [
        "matrix",
        str(suite_path),
        "--allow-failures",
        "--save-reliability-baseline",
        str(baseline_path),
    ]

    refused = runner.invoke(app, arguments)
    forced = runner.invoke(app, [*arguments, "--force"])

    assert refused.exit_code == 2
    assert "Use --force to overwrite" in refused.output
    assert forced.exit_code == 0
