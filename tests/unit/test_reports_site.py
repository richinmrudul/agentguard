import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.history.store import HistoryRecord, record_history
from agentguard.reports.site import StaticSiteOptions, generate_static_report_site


runner = CliRunner()


def test_empty_site_generation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    assert result.page_count == 7
    assert (tmp_path / "site/index.html").exists()
    assert (tmp_path / "site/incidents.html").exists()
    assert (tmp_path / "site/trends.html").exists()
    assert "No records found" in (tmp_path / "site/runs.html").read_text()
    assert "No trend data found" in (tmp_path / "site/trends.html").read_text()


def test_site_from_history_with_runs_suites_and_matrices(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / ".agentguard/history.db"
    _record(db_path, "run-1", "run", "fix_auth_bug", "PASS", 100)
    _record(db_path, "suite-1", "suite", "core", "FAIL", 50)
    _record(db_path, "matrix-1", "matrix", "core-matrix", "PASS", 75)
    _write_json(
        tmp_path / ".agentguard/matrices/matrix-1/matrix.json",
        {
            "matrix_id": "core-matrix",
            "failed": 0,
            "average_score": 75,
            "reliability_summary": {"success_rate": 100},
        },
    )

    result = generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", history_db=db_path, force=True)
    )

    assert result.history_records == 3
    assert "core-matrix" in (tmp_path / "site/matrices.html").read_text()
    assert "Average score" in (tmp_path / "site/index.html").read_text()


def test_includes_results_docs_when_requested(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    results_doc = tmp_path / "docs/results/evaluation-report.md"
    results_doc.parent.mkdir(parents=True)
    results_doc.write_text("# Evaluation\n\nhttps://example.invalid\n", encoding="utf-8")

    result = generate_static_report_site(
        StaticSiteOptions(
            output=tmp_path / "site",
            include_results_docs=True,
            force=True,
        )
    )

    assert result.results_docs == 1
    assert "evaluation-report.md" in (tmp_path / "site/results.html").read_text()
    assert "href=\"https://" not in _all_html(tmp_path / "site")


def test_html_escaping_for_malicious_names(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / ".agentguard/history.db"
    _record(
        db_path,
        "run-1",
        "run",
        "<script>alert('x')</script>",
        "PASS",
        100,
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", history_db=db_path, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


def test_no_external_assets_or_absolute_temp_paths(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / ".agentguard/history.db"
    report_path = tmp_path / ".agentguard/runs/run-1/reports/report.json"
    _write_json(
        report_path,
        {
            "task_id": "uses paths",
            "result": "PASS",
            "score": 100,
            "report_paths": {"json": str(report_path)},
        },
    )
    _record(db_path, "run-1", "run", "uses paths", "PASS", 100, report_path)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", history_db=db_path, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "http://" not in html
    assert "https://" not in html
    assert str(tmp_path) not in html


def test_missing_and_corrupt_reports_are_listed_as_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    corrupt = tmp_path / ".agentguard/runs/bad/reports/report.json"
    corrupt.parent.mkdir(parents=True)
    corrupt.write_text("{not json", encoding="utf-8")

    result = generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    assert result.unavailable == 1
    assert "could not read report summary" in _all_html(tmp_path / "site")


def test_force_overwrite_behavior(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    site = tmp_path / "site"
    site.mkdir()
    (site / "old.txt").write_text("old", encoding="utf-8")

    with pytest.raises(FileExistsError):
        generate_static_report_site(StaticSiteOptions(output=site))

    generate_static_report_site(StaticSiteOptions(output=site, force=True))

    assert not (site / "old.txt").exists()
    assert (site / "index.html").exists()


def test_output_path_safety_rejects_reports_root_child(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError, match="output path cannot be inside reports root"):
        generate_static_report_site(
            StaticSiteOptions(output=tmp_path / ".agentguard/site", force=True)
        )


def test_static_assets_generated(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    assert (tmp_path / "site/assets/site.css").read_text()
    assert (tmp_path / "site/assets/site.js").read_text()


def test_cli_exit_codes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    ok = runner.invoke(app, ["reports", "site", "--output", str(tmp_path / "site")])
    exists = runner.invoke(app, ["reports", "site", "--output", str(tmp_path / "site")])
    unsafe = runner.invoke(
        app,
        ["reports", "site", "--output", str(tmp_path / ".agentguard/site")],
    )

    assert ok.exit_code == 0
    assert "Static report site:" in ok.output
    assert "incidents: 0" in ok.output
    assert exists.exit_code == 2
    assert unsafe.exit_code == 2


def test_includes_traces_and_diagnostics_when_requested(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    trace = tmp_path / ".agentguard/runs/run-1/trace.jsonl"
    trace.parent.mkdir(parents=True)
    trace.write_text('{"trace_id":"run-1"}\n{"event":"complete"}\n', encoding="utf-8")
    _write_json(
        tmp_path / ".agentguard/diagnostics/matrix-stress/study/matrix-stress.json",
        {"schema": "agentguard.matrix-stress", "integrity_passed": True},
    )

    result = generate_static_report_site(
        StaticSiteOptions(
            output=tmp_path / "site",
            include_traces=True,
            include_diagnostics=True,
            force=True,
        )
    )

    assert result.traces == 1
    assert result.diagnostics == 1
    assert (tmp_path / "site/traces.html").exists()
    assert "matrix-stress" in (tmp_path / "site/diagnostics.html").read_text()


def test_secret_canary_is_redacted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    db_path = tmp_path / ".agentguard/history.db"
    report_path = tmp_path / ".agentguard/runs/run-1/reports/report.json"
    _write_json(
        report_path,
        {
            "task_id": "secret test",
            "result": "PASS",
            "score": 100,
            "check_results": [
                {
                    "name": "Secret scan",
                    "passed": False,
                    "evidence": ["AGENTGUARD_SECRET_CANARY_TEST"],
                }
            ],
        },
    )
    _record(db_path, "run-1", "run", "secret test", "PASS", 100, report_path)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", history_db=db_path, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "AGENTGUARD_SECRET_CANARY_TEST" not in html
    assert "[REDACTED]" in html


def test_matrix_detail_renders_guard_incident_summary(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_matrix(
        tmp_path,
        {
            "runs_evaluated": 8,
            "incident_runs": 3,
            "blocked_runs": 1,
            "audit_only_runs": 2,
            "violations_total": 7,
            "filesystem_violations": 5,
            "command_violations": 2,
            "time_to_first_violation": {"median_ms": 12.5, "p95_ms": 40},
            "time_to_block": {"median_ms": 18, "p95_ms": 31},
            "by_guard_type": {
                "filesystem": {
                    "incident_runs": 3,
                    "blocked_runs": 1,
                    "violations_total": 5,
                },
                "command": {
                    "incident_runs": 1,
                    "blocked_runs": 0,
                    "violations_total": 2,
                },
            },
        },
    )

    detail = _generate_matrix_detail(tmp_path)

    assert "<h2>Guard Incidents</h2>" in detail
    for label, value in [
        ("Runs evaluated", "8"),
        ("Incident runs", "3"),
        ("Blocked runs", "1"),
        ("Audit-only runs", "2"),
        ("Total violations", "7"),
        ("Filesystem violations", "5"),
        ("Command violations", "2"),
    ]:
        assert f"<span>{label}</span><strong>{value}</strong>" in detail
    assert "12.5 ms" in detail
    assert "40 ms" in detail
    assert "18 ms" in detail
    assert "31 ms" in detail
    assert "<h3>By guard type</h3>" in detail
    assert "<td>filesystem</td>" in detail
    assert "<td>command</td>" in detail


def test_matrix_detail_renders_zero_guard_incidents(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_matrix(
        tmp_path,
        {
            "runs_evaluated": 4,
            "incident_runs": 0,
            "blocked_runs": 0,
            "audit_only_runs": 0,
            "violations_total": 0,
            "filesystem_violations": 0,
            "command_violations": 0,
            "time_to_first_violation": {
                "median_ms": None,
                "p95_ms": None,
            },
            "time_to_block": {"median_ms": None, "p95_ms": None},
            "by_guard_type": {},
        },
    )

    detail = _generate_matrix_detail(tmp_path)

    assert "<h2>Guard Incidents</h2>" in detail
    assert "<span>Runs evaluated</span><strong>4</strong>" in detail
    assert detail.count("<strong>0</strong>") == 6
    assert "<h3>By guard type</h3>" not in detail


def test_matrix_without_guard_summary_renders_normally(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_matrix(tmp_path)

    detail = _generate_matrix_detail(tmp_path)

    assert "matrix detail" in detail
    assert "<h2>Summary</h2>" in detail
    assert "<h2>Guard Incidents</h2>" not in detail


def test_partial_and_malformed_guard_summary_is_safe(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_matrix(
        tmp_path,
        {
            "runs_evaluated": "not-a-count",
            "incident_runs": 2,
            "blocked_runs": True,
            "time_to_first_violation": "not-a-distribution",
            "time_to_block": {"median_ms": float("nan"), "p95_ms": -1},
            "by_guard_type": {
                "filesystem": "not-counts",
                "command": {"violations_total": 2},
            },
        },
    )

    detail = _generate_matrix_detail(tmp_path)

    assert "<h2>Guard Incidents</h2>" in detail
    assert "<span>Runs evaluated</span><strong>-</strong>" in detail
    assert "<span>Incident runs</span><strong>2</strong>" in detail
    assert "<span>Blocked runs</span><strong>-</strong>" in detail
    assert "<td>command</td>" in detail
    assert "<td>filesystem</td>" not in detail
    assert "nan" not in detail.lower()


def test_guard_type_keys_are_escaped_and_raw_incident_data_is_omitted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    absolute_path = str(tmp_path / "private/incident.json")
    _write_matrix(
        tmp_path,
        {
            "runs_evaluated": 1,
            "incident_runs": 1,
            "by_guard_type": {
                "<script>alert('guard')</script>": {
                    "incident_runs": 1,
                    "blocked_runs": 0,
                    "violations_total": 1,
                },
                absolute_path: {
                    "incident_runs": 1,
                    "blocked_runs": 0,
                    "violations_total": 1,
                },
            },
            "incidents": [
                {
                    "command": "RAW_COMMAND_SHOULD_NOT_RENDER",
                    "evidence": "RAW_EVIDENCE_SHOULD_NOT_RENDER",
                    "incident_json": absolute_path,
                }
            ],
        },
    )

    detail = _generate_matrix_detail(tmp_path)

    assert "<script>alert" not in detail
    assert "&lt;script&gt;alert" in detail
    assert "RAW_COMMAND_SHOULD_NOT_RENDER" not in detail
    assert "RAW_EVIDENCE_SHOULD_NOT_RENDER" not in detail
    assert str(tmp_path) not in detail
    assert "http://" not in detail
    assert "https://" not in detail


def _record(
    db_path: Path,
    record_id: str,
    run_type: str,
    name: str,
    result: str,
    score: float,
    report_path: Path = Path(".agentguard/runs/run-1/reports/report.json"),
) -> None:
    record_history(
        HistoryRecord(
            id=record_id,
            run_type=run_type,
            name=name,
            result=result,
            score=score,
            created_at="2026-05-31T10:00:00+00:00",
            json_report_path=report_path,
            markdown_report_path=report_path.with_suffix(".md"),
            manifest_path=report_path.parent.parent / "manifest.json",
            trace_path=report_path.parent.parent / "trace.jsonl",
            category="source_fix",
            difficulty="easy",
            benchmark_id="auth_bug_safe",
            benchmark_version=1,
            agent="mock-safe",
            failed_checks=["Tests passed"] if result == "FAIL" else [],
        ),
        db_path,
    )


def _write_json(path: Path, data: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _write_matrix(
    tmp_path: Path,
    guard_summary: object = None,
) -> None:
    data: dict[str, object] = {
        "matrix_id": "guard-matrix",
        "failed": 0,
        "average_score": 100,
        "total_runs": 1,
    }
    if guard_summary is not None:
        data["guard_summary"] = guard_summary
    _write_json(
        tmp_path / ".agentguard/matrices/matrix-guard/matrix.json",
        data,
    )


def _generate_matrix_detail(tmp_path: Path) -> str:
    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )
    return (
        tmp_path / "site/details/matrix-matrix-guard.html"
    ).read_text(encoding="utf-8")


def _all_html(site: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(site.rglob("*.html"))
    )
