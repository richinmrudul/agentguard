import json
from dataclasses import replace
from pathlib import Path

from agentguard.core.matrix import MatrixRowSummary, run_matrix
from agentguard.core.orchestrator import run_benchmark
from agentguard.guard.aggregation import (
    aggregate_matrix_guard,
    timing_distribution,
)


ROOT = Path(__file__).resolve().parents[2]


def _row(**overrides: object) -> MatrixRowSummary:
    values = {
        "task_id": "task",
        "config_path": Path("config.yaml"),
        "agent": "agent",
        "result": "PASS",
        "score": 100,
        "failed_checks": [],
        "warning_checks": [],
        "json_report_path": None,
        "markdown_report_path": None,
        "run_dir": None,
        "benchmark_id": "benchmark",
        "category": "category",
    }
    values.update(overrides)
    return MatrixRowSummary(**values)


def test_empty_guard_aggregation_counts_guard_off_and_error_rows(
    tmp_path: Path,
) -> None:
    summary = aggregate_matrix_guard(
        [_row(), _row(task_id="error", result="FAIL", error="failed")],
        tmp_path / "matrix.md",
    )

    assert summary.runs_evaluated == 2
    assert summary.incident_runs == 0
    assert summary.blocked_runs == 0
    assert summary.audit_only_runs == 0
    assert summary.violations_total == 0
    assert summary.time_to_first_violation.samples == 0
    assert summary.time_to_first_violation.minimum_ms is None
    assert summary.incidents == []


def test_guard_aggregation_counts_runs_violations_groups_and_guard_types(
    tmp_path: Path,
) -> None:
    rows = [
        _row(
            task_id="audit-filesystem",
            agent="agent-b",
            benchmark_id=None,
            category=None,
            guard_violations_total=2,
            filesystem_guard_violations=2,
            time_to_first_violation_ms=20,
        ),
        _row(
            task_id="blocked-filesystem",
            agent="agent-a",
            benchmark_id="benchmark-a",
            category="category-a",
            guard_violations_total=1,
            guard_blocked=True,
            filesystem_guard_violations=1,
            time_to_first_violation_ms=10,
            time_to_block_ms=15,
            blocking_guard="filesystem",
        ),
        _row(
            task_id="blocked-command",
            agent="agent-a",
            benchmark_id="benchmark-b",
            category="category-b",
            guard_violations_total=1,
            guard_blocked=True,
            command_guard_violations=1,
            time_to_first_violation_ms=30,
            time_to_block_ms=35,
            blocking_guard="command",
        ),
        _row(
            task_id="both",
            agent="agent-b",
            benchmark_id="benchmark-b",
            category="category-b",
            guard_violations_total=3,
            guard_blocked=True,
            filesystem_guard_violations=1,
            command_guard_violations=2,
            time_to_first_violation_ms=40,
            time_to_block_ms=45,
            blocking_guard="filesystem",
        ),
    ]

    summary = aggregate_matrix_guard(rows, tmp_path / "matrix.md")

    assert summary.runs_evaluated == 4
    assert summary.incident_runs == 4
    assert summary.blocked_runs == 3
    assert summary.audit_only_runs == 1
    assert summary.violations_total == 7
    assert summary.filesystem_violations == 4
    assert summary.command_violations == 3
    assert list(summary.by_agent) == ["agent-a", "agent-b"]
    assert summary.by_agent["agent-a"].blocked_runs == 2
    assert summary.by_agent["agent-b"].violations_total == 5
    assert list(summary.by_benchmark) == [
        "benchmark-a",
        "benchmark-b",
        "unidentified",
    ]
    assert summary.by_benchmark["benchmark-b"].incident_runs == 2
    assert list(summary.by_category) == [
        "category-a",
        "category-b",
        "uncategorized",
    ]
    assert summary.by_category["category-b"].violations_total == 4
    assert summary.by_guard_type["filesystem"].incident_runs == 3
    assert summary.by_guard_type["filesystem"].blocked_runs == 2
    assert summary.by_guard_type["command"].incident_runs == 2
    assert summary.by_guard_type["command"].blocked_runs == 1


def test_timing_distribution_is_deterministic_and_ignores_invalid_values() -> None:
    assert timing_distribution([]).samples == 0
    one = timing_distribution([12])
    assert (one.minimum_ms, one.median_ms, one.p95_ms, one.maximum_ms) == (
        12,
        12,
        12,
        12,
    )
    odd = timing_distribution([30, 10, 20])
    assert odd.median_ms == 20
    even = timing_distribution([40, 10, 30, 20])
    assert even.median_ms == 25.0
    nearest_rank = timing_distribution(list(range(1, 21)))
    assert nearest_rank.p95_ms == 19
    malformed = timing_distribution([None, -1, 0, True, 5])
    assert malformed.samples == 2
    assert malformed.minimum_ms == 0
    assert malformed.maximum_ms == 5


def test_incident_references_are_relative_optional_and_artifact_independent(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "runs" / "run-1"
    guard_dir = run_dir / "guard"
    guard_dir.mkdir(parents=True)
    incident_json = guard_dir / "incident.json"
    incident_markdown = guard_dir / "incident.md"
    incident_json.write_text("not valid json", encoding="utf-8")
    incident_markdown.write_text("# Incident\n", encoding="utf-8")
    report_path = tmp_path / "matrices" / "matrix-1" / "matrix.md"
    report_path.parent.mkdir(parents=True)

    summary = aggregate_matrix_guard(
        [
            _row(
                run_dir=run_dir,
                guard_violations_total=1,
                filesystem_guard_violations=1,
                guard_incident_json_path=incident_json,
                guard_incident_markdown_path=incident_markdown,
            )
        ],
        report_path,
    )

    reference = summary.incidents[0]
    assert reference.incident_json == "../../runs/run-1/guard/incident.json"
    assert reference.incident_markdown == "../../runs/run-1/guard/incident.md"
    assert not Path(reference.incident_json).is_absolute()
    incident_markdown.unlink()
    missing = aggregate_matrix_guard(
        [
            _row(
                run_dir=run_dir,
                guard_violations_total=1,
                filesystem_guard_violations=1,
                guard_incident_json_path=incident_json,
                guard_incident_markdown_path=incident_markdown,
            )
        ],
        report_path,
    )
    assert missing.violations_total == 1
    assert missing.incidents[0].incident_markdown is None


def test_incident_reference_rejects_symlink_escape(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    link = run_dir / "incident.json"
    link.symlink_to(outside)

    summary = aggregate_matrix_guard(
        [
            _row(
                run_dir=run_dir,
                guard_violations_total=1,
                filesystem_guard_violations=1,
                guard_incident_json_path=link,
            )
        ],
        tmp_path / "matrix.md",
    )

    assert summary.incidents[0].incident_json is None


def test_matrix_reports_manifest_and_scoring_use_one_guard_summary(
    tmp_path: Path,
) -> None:
    config = ROOT / "examples/configs/fix_auth_bug.yaml"
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        "suite_id: guard_aggregation\n"
        "description: Guard aggregation fixture.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )

    def benchmark_runner(path: Path, agent: str, _matrix_id: str):
        child = run_benchmark(path, agent)
        guard_dir = child.run_dir / "guard"
        guard_dir.mkdir(exist_ok=True)
        incident_json = guard_dir / "incident.json"
        incident_markdown = guard_dir / "incident.md"
        incident_json.write_text("{corrupt", encoding="utf-8")
        incident_markdown.write_text("# Incident\n", encoding="utf-8")
        return replace(
            child,
            task_id="task|<unsafe>\nnext",
            benchmark=replace(
                child.benchmark,
                id="benchmark|<unsafe>",
                category="category|<unsafe>",
            ),
            guard_metrics={
                "guard_violations_total": 2,
                "guard_blocked": False,
                "filesystem_guard_violations": 1,
                "command_guard_violations": 1,
                "time_to_first_violation_ms": 9,
                "time_to_block_ms": None,
            },
            report_paths=replace(
                child.report_paths,
                guard_incident_json=incident_json,
                guard_incident_markdown=incident_markdown,
            ),
        )

    result = run_matrix(
        suite,
        matrices_root=tmp_path / "matrices",
        benchmark_runner=benchmark_runner,
    )
    report = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")

    assert result.passed == 1
    assert result.failed == 0
    assert result.guard_summary.violations_total == 2
    manifest_summary = manifest["matrix"]["guard_summary"]
    assert manifest_summary["incident_runs"] == report["guard_summary"][
        "incident_runs"
    ]
    assert manifest_summary["violations_total"] == report["guard_summary"][
        "violations_total"
    ]
    assert manifest_summary["time_to_first_violation"] == report[
        "guard_summary"
    ]["time_to_first_violation"]
    assert manifest_summary["time_to_block"]["samples"] == 0
    assert report["guard_summary"]["incident_runs"] == 1
    assert report["guard_summary"]["incidents"][0]["incident_json"].startswith(
        "../../"
    )
    assert "## Guard Incidents" in markdown
    assert "task\\|&lt;unsafe&gt;&#10;next" in markdown
    assert "benchmark\\|&lt;unsafe&gt;" in markdown
    assert "[JSON](../../" in markdown


def test_parallel_row_order_does_not_change_serialized_incidents(
    tmp_path: Path,
) -> None:
    first = _row(task_id="z", agent="b", guard_violations_total=1)
    second = _row(task_id="a", agent="a", guard_violations_total=1)

    forward = aggregate_matrix_guard([first, second], tmp_path / "matrix.md")
    reverse = aggregate_matrix_guard([second, first], tmp_path / "matrix.md")

    assert forward == reverse
