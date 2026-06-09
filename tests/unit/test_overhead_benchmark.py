import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.diagnostics.overhead import (
    FunctionalOutcome,
    OverheadBenchmarkPaths,
    OverheadBenchmarkResult,
    WorkloadTiming,
    execution_order,
    nearest_rank_percentile,
    run_overhead_benchmark,
    summarize,
)
from agentguard.core.timing import StageTimingRecorder


runner = CliRunner()
CONFIG = Path("examples/configs/fix_auth_bug.yaml")
OUTCOME = FunctionalOutcome(
    test_exit_code=0,
    changed_files=["src/auth_example/login.py"],
    changed_file_sha256={"src/auth_example/login.py": "abc123"},
)


def _timing(
    total: float,
    *,
    outcome: FunctionalOutcome = OUTCOME,
    stages: Optional[dict[str, float]] = None,
) -> WorkloadTiming:
    return WorkloadTiming(
        total_seconds=total,
        stages=stages or {},
        outcome=outcome,
    )


def _fake_runners(
    direct_values: list[float],
    guarded_values: list[float],
    *,
    guarded_stages: Optional[dict[str, float]] = None,
):
    direct_iter = iter(direct_values)
    guarded_iter = iter(guarded_values)

    def direct(*args, **kwargs) -> WorkloadTiming:
        return _timing(next(direct_iter))

    def guarded(*args, **kwargs) -> WorkloadTiming:
        return _timing(next(guarded_iter), stages=guarded_stages)

    return direct, guarded


def test_iteration_and_warmup_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="iterations must be positive"):
        run_overhead_benchmark(
            CONFIG,
            iterations=0,
            output_path=tmp_path / "result.json",
        )
    with pytest.raises(ValueError, match="warmups must be non-negative"):
        run_overhead_benchmark(
            CONFIG,
            warmups=-1,
            output_path=tmp_path / "result.json",
        )


def test_execution_order_alternates() -> None:
    assert execution_order(0) == ("direct", "agentguard")
    assert execution_order(1) == ("agentguard", "direct")
    assert execution_order(2) == ("direct", "agentguard")


def test_stage_timing_recorder_uses_injected_clock() -> None:
    ticks = iter([1.0, 2.0, 2.5, 5.0])
    recorder = StageTimingRecorder(lambda: next(ticks))

    recorder.start_total()
    with recorder.measure("work"):
        pass
    recorder.finish_total()

    assert recorder.stages == {"work": 0.5}
    assert recorder.total_seconds == 4.0


def test_statistics_and_nearest_rank_percentile() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 100.0]
    stats = summarize(values)

    assert stats.iterations == 5
    assert stats.minimum == 1.0
    assert stats.maximum == 100.0
    assert stats.mean == 22.0
    assert stats.median == 3.0
    assert stats.sample_standard_deviation == pytest.approx(43.617656)
    assert stats.p95 == 100.0
    assert nearest_rank_percentile([4.0, 1.0, 3.0, 2.0], 50) == 2.0


def test_one_sample_standard_deviation_is_zero() -> None:
    stats = summarize([2.5])
    assert stats.sample_standard_deviation == 0.0
    assert stats.p95 == 2.5


def test_warmups_excluded_overhead_calculations_and_stage_aggregation(
    tmp_path: Path,
) -> None:
    direct, guarded = _fake_runners(
        [100.0, 1.0, 2.0],
        [200.0, 2.0, 4.0],
        guarded_stages={
            "workspace_preparation": 0.4,
            "test_execution": 0.6,
        },
    )
    result = run_overhead_benchmark(
        CONFIG,
        iterations=2,
        warmups=1,
        output_path=tmp_path / "result.json",
        direct_runner=direct,
        agentguard_runner=guarded,
        now=datetime(2026, 6, 9, tzinfo=timezone.utc),
    )

    summary = result.data["summary"]
    assert summary["direct_seconds"]["mean"] == 1.5
    assert summary["agentguard_seconds"]["mean"] == 3.0
    assert summary["absolute_overhead_seconds"]["median"] == 1.5
    assert summary["relative_overhead_percent"]["median"] == 100.0
    assert summary["slowdown_ratio"]["median"] == 2.0
    assert summary["throughput_runs_per_minute"]["direct_median"] == 40.0
    assert result.data["raw_timings"][0]["order"] == ["direct", "agentguard"]
    assert result.data["raw_timings"][1]["order"] == ["agentguard", "direct"]
    assert result.data["raw_timings"][0]["overhead"] == {
        "absolute_seconds": 1.0,
        "relative_percent": 100.0,
        "slowdown_ratio": 2.0,
    }
    assert len(result.data["warmup_timings"]) == 1

    stages = result.data["agentguard_stage_summary"]
    assert stages["workspace_preparation"]["mean_seconds"] == 0.4
    assert stages["test_execution"]["mean_seconds"] == 0.6
    assert stages["other_orchestration"]["mean_seconds"] == 2.0
    assert sum(
        stage["percentage_of_mean_total"] for stage in stages.values()
    ) == pytest.approx(100.0)


def test_outcome_mismatch_aborts_without_reports(tmp_path: Path) -> None:
    mismatched = FunctionalOutcome(
        test_exit_code=1,
        changed_files=OUTCOME.changed_files,
        changed_file_sha256=OUTCOME.changed_file_sha256,
    )

    def direct(*args, **kwargs) -> WorkloadTiming:
        return _timing(1.0)

    def guarded(*args, **kwargs) -> WorkloadTiming:
        return _timing(2.0, outcome=mismatched)

    output = tmp_path / "result.json"
    with pytest.raises(ValueError, match="outcomes differ"):
        run_overhead_benchmark(
            CONFIG,
            iterations=1,
            warmups=0,
            output_path=output,
            direct_runner=direct,
            agentguard_runner=guarded,
        )
    assert not output.exists()


def test_matching_failed_workloads_abort(tmp_path: Path) -> None:
    failed = FunctionalOutcome(
        test_exit_code=1,
        changed_files=OUTCOME.changed_files,
        changed_file_sha256=OUTCOME.changed_file_sha256,
    )

    def workload(*args, **kwargs) -> WorkloadTiming:
        return _timing(1.0, outcome=failed)

    with pytest.raises(ValueError, match="expected successful test result"):
        run_overhead_benchmark(
            CONFIG,
            iterations=1,
            warmups=0,
            output_path=tmp_path / "result.json",
            direct_runner=workload,
            agentguard_runner=workload,
        )


def test_json_markdown_schema_content_and_overwrite_protection(
    tmp_path: Path,
) -> None:
    direct, guarded = _fake_runners([1.0], [1.5])
    output = tmp_path / "result.json"
    result = run_overhead_benchmark(
        CONFIG,
        iterations=1,
        warmups=0,
        output_path=output,
        direct_runner=direct,
        agentguard_runner=guarded,
    )

    data = json.loads(result.paths.json.read_text(encoding="utf-8"))
    markdown = result.paths.markdown.read_text(encoding="utf-8")
    assert data["schema"] == "agentguard.overhead-benchmark"
    assert data["schema_version"] == 1
    assert data["config"]["sha256"]
    assert data["methodology"]["timer"] == "time.perf_counter"
    assert data["methodology"]["warmups_excluded_from_statistics"] is True
    assert "AgentGuard Instrumentation Overhead" in markdown
    assert "nearest-rank" in markdown
    assert "not a universal performance claim" in markdown

    direct, guarded = _fake_runners([1.0], [1.5])
    with pytest.raises(FileExistsError, match="output already exists"):
        run_overhead_benchmark(
            CONFIG,
            iterations=1,
            warmups=0,
            output_path=output,
            direct_runner=direct,
            agentguard_runner=guarded,
        )


def test_force_overwrites_reports(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    output.write_text("old", encoding="utf-8")
    output.with_suffix(".md").write_text("old", encoding="utf-8")
    direct, guarded = _fake_runners([1.0], [1.5])

    result = run_overhead_benchmark(
        CONFIG,
        iterations=1,
        warmups=0,
        output_path=output,
        force=True,
        direct_runner=direct,
        agentguard_runner=guarded,
    )

    assert json.loads(result.paths.json.read_text(encoding="utf-8"))["schema"]


def test_cli_validation_and_error_exit_codes(tmp_path: Path) -> None:
    invalid_iterations = runner.invoke(
        app,
        ["benchmark-overhead", "--iterations", "0"],
    )
    invalid_warmups = runner.invoke(
        app,
        ["benchmark-overhead", "--warmups", "-1"],
    )
    existing = tmp_path / "existing.json"
    existing.write_text("old", encoding="utf-8")
    collision = runner.invoke(
        app,
        [
            "benchmark-overhead",
            "--iterations",
            "1",
            "--warmups",
            "0",
            "--output",
            str(existing),
        ],
    )

    assert invalid_iterations.exit_code == 2
    assert invalid_warmups.exit_code == 2
    assert collision.exit_code == 2
    assert "output already exists" in collision.output


def test_cli_success_output(monkeypatch, tmp_path: Path) -> None:
    json_path = tmp_path / "result.json"
    markdown_path = tmp_path / "result.md"
    fake = OverheadBenchmarkResult(
        data={
            "agent": "mock-safe",
            "iterations": 2,
            "warmups": 1,
            "config": {"task_id": "fixture", "path": "/fixture.yaml"},
            "summary": {
                "direct_seconds": {"median": 1.0},
                "agentguard_seconds": {"median": 1.5},
                "absolute_overhead_seconds": {"median": 0.5},
                "relative_overhead_percent": {"median": 50.0},
                "slowdown_ratio": {"median": 1.5},
                "throughput_runs_per_minute": {
                    "direct_median": 60.0,
                    "agentguard_median": 40.0,
                },
            },
        },
        paths=OverheadBenchmarkPaths(json=json_path, markdown=markdown_path),
    )
    monkeypatch.setattr(
        "agentguard.cli.main.run_overhead_benchmark",
        lambda *args, **kwargs: fake,
    )

    result = runner.invoke(app, ["benchmark-overhead"])

    assert result.exit_code == 0
    assert "AgentGuard Instrumentation Overhead" in result.output
    assert "Direct median: 1.000000s" in result.output
    assert "Median relative overhead: 50.00%" in result.output
    assert f"JSON output: {json_path}" in result.output


def test_reusable_script_is_strict_and_uses_deterministic_fixture() -> None:
    script = Path("scripts/benchmark_overhead.sh").read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert 'REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"' in script
    assert "examples/configs/fix_auth_bug.yaml" in script
    assert "--agent mock-safe" in script
    assert "--warmups 2" in script
