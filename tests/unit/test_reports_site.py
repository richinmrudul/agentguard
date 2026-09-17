import json
import re
from pathlib import Path
from typing import Optional

import pytest
from typer.testing import CliRunner

import agentguard.reports.site as site_module
from agentguard.cli.main import app
from agentguard.history.store import HistoryRecord, record_history
from agentguard.reports.site import (
    SITE_OUTPUT_MARKER,
    StaticSiteOptions,
    generate_static_report_site,
)


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
    generate_static_report_site(StaticSiteOptions(output=site))
    (site / "old.txt").write_text("old", encoding="utf-8")

    with pytest.raises(FileExistsError):
        generate_static_report_site(StaticSiteOptions(output=site))

    generate_static_report_site(StaticSiteOptions(output=site, force=True))

    assert not (site / "old.txt").exists()
    assert (site / "index.html").exists()
    assert (site / SITE_OUTPUT_MARKER).is_file()


def test_force_rejects_non_site_directory_without_deleting_contents(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    output = tmp_path / "not-a-site"
    output.mkdir()
    valuable_file = output / "valuable-source.txt"
    valuable_file.write_text("preserve me", encoding="utf-8")

    with pytest.raises(ValueError, match="without an AgentGuard static-site marker"):
        generate_static_report_site(StaticSiteOptions(output=output, force=True))

    assert valuable_file.read_text(encoding="utf-8") == "preserve me"


@pytest.mark.parametrize("target_kind", ["cwd", "reports_parent", "filesystem_root"])
def test_force_rejects_broad_targets_without_deleting_contents(
    tmp_path: Path,
    monkeypatch,
    target_kind: str,
) -> None:
    project = tmp_path / "project"
    reports_root = project / ".agentguard"
    reports_root.mkdir(parents=True)
    valuable_file = project / "valuable-source.txt"
    valuable_file.write_text("preserve me", encoding="utf-8")
    monkeypatch.chdir(project)
    targets = {
        "cwd": project,
        "reports_parent": tmp_path,
        "filesystem_root": Path(project.anchor),
    }

    with pytest.raises(ValueError):
        generate_static_report_site(
            StaticSiteOptions(
                output=targets[target_kind],
                reports_root=reports_root,
                force=True,
            )
        )

    assert valuable_file.read_text(encoding="utf-8") == "preserve me"


def test_force_rejects_repository_root_without_deleting_contents(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".git").mkdir()
    valuable_file = repository / "valuable-source.txt"
    valuable_file.write_text("preserve me", encoding="utf-8")

    with pytest.raises(ValueError, match="repository root"):
        generate_static_report_site(
            StaticSiteOptions(
                output=repository,
                reports_root=tmp_path / "artifacts",
                force=True,
            )
        )

    assert valuable_file.read_text(encoding="utf-8") == "preserve me"


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
    valuable_file = tmp_path / "valuable-source.txt"
    valuable_file.write_text("preserve me", encoding="utf-8")

    ok = runner.invoke(app, ["reports", "site", "--output", str(tmp_path / "site")])
    exists = runner.invoke(app, ["reports", "site", "--output", str(tmp_path / "site")])
    unsafe = runner.invoke(
        app,
        ["reports", "site", "--output", str(tmp_path / ".agentguard/site")],
    )
    broad = runner.invoke(app, ["reports", "site", "--output", ".", "--force"])

    assert ok.exit_code == 0
    assert "Static report site:" in ok.output
    assert "incidents: 0" in ok.output
    assert exists.exit_code == 2
    assert unsafe.exit_code == 2
    assert broad.exit_code == 2
    assert valuable_file.read_text(encoding="utf-8") == "preserve me"


def test_includes_traces_and_diagnostics_when_requested(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    trace = tmp_path / ".agentguard/runs/run-1/trace.jsonl"
    trace.parent.mkdir(parents=True)
    _write_trace(trace, event_count=1)
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
    assert "trace summary complete" in _all_html(tmp_path / "site")


def test_trace_summary_handles_empty_trace(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_trace_bytes(tmp_path, "empty", b"")

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "incomplete" in html
    assert "trace is empty" in html


def test_trace_summary_handles_invalid_utf8(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_trace_bytes(tmp_path, "bad-utf8", b"\xff\xfe\n")

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "unavailable" in html
    assert "trace contains invalid UTF-8" in html


def test_trace_summary_handles_malformed_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_trace_bytes(tmp_path, "bad-json", b'{"trace_id":"bad-json"}\n{not json}\n')

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "unavailable" in html
    assert "trace contains malformed JSON" in html


def test_trace_summary_handles_missing_final_newline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_trace_bytes(
        tmp_path,
        "truncated",
        _trace_bytes("truncated", event_count=1).rstrip(b"\n"),
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "incomplete" in html
    assert "final newline is missing" in html


def test_trace_summary_handles_oversized_first_line(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(site_module, "MAX_TRACE_LINE_BYTES", 32)
    _write_trace_bytes(tmp_path, "oversized-first", b'{"' + b"x" * 80 + b'":1}\n')

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "trace line exceeds the summary line limit" in html


def test_trace_summary_handles_oversized_later_line(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(site_module, "MAX_TRACE_LINE_BYTES", 96)
    _write_trace_bytes(
        tmp_path,
        "oversized-later",
        _trace_header_line("oversized-later", event_count=2)
        + b'{"event_type":"agent_command","payload":"'
        + b"x" * 200
        + b'"}\n',
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "incomplete" in html
    assert "trace line exceeds the summary line limit" in html


def test_trace_summary_handles_total_size_bound(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(site_module, "MAX_TRACE_BYTES", 180)
    _write_trace(tmp_path / ".agentguard/runs/too-large/trace.jsonl", event_count=4)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "trace exceeds the summary byte limit" in html


def test_trace_summary_handles_excessive_event_count(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(site_module, "MAX_TRACE_EVENTS", 1)
    _write_trace(tmp_path / ".agentguard/runs/too-many/trace.jsonl", event_count=2)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "trace exceeds the summary event limit" in html


def test_trace_summary_handles_disappearing_trace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / ".agentguard/runs/gone/trace.jsonl"
    _write_trace(target, event_count=1)
    original_open = Path.open

    def disappearing_open(path: Path, *args: object, **kwargs: object):
        if path == target:
            raise FileNotFoundError("gone")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", disappearing_open)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert "unavailable" in html
    assert "trace file is unavailable" in html


def test_trace_summary_continues_when_one_trace_is_malformed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_trace(tmp_path / ".agentguard/runs/good/trace.jsonl", event_count=1)
    _write_trace_bytes(tmp_path, "bad", b"{not json}\n")

    result = generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert result.traces == 2
    assert result.unavailable == 1
    assert "trace summary complete" in html
    assert "trace contains malformed JSON" in html


def test_trace_summary_output_is_deterministic(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_trace(tmp_path / ".agentguard/runs/b/trace.jsonl", event_count=1)
    _write_trace(tmp_path / ".agentguard/runs/a/trace.jsonl", event_count=1)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site-1", include_traces=True, force=True)
    )
    first = _all_html(tmp_path / "site-1")
    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site-2", include_traces=True, force=True)
    )
    second = _all_html(tmp_path / "site-2")

    assert first == second


def test_trace_summary_sanitizes_diagnostics(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    canary = "AGENTGUARD_SECRET_CANARY_TRACE"
    private_path = tmp_path / "private" / "trace.jsonl"
    _write_trace_bytes(
        tmp_path,
        "hostile",
        json.dumps({canary: str(private_path), "event_count": 1}).encode("utf-8")
        + b"\n"
        + json.dumps({"event_type": "execution_completed", "payload": canary}).encode(
            "utf-8"
        )
        + b"\n",
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    html = _all_html(tmp_path / "site")
    assert canary not in html
    assert str(tmp_path) not in html
    assert "[REDACTED]" in html


def test_trace_summary_rejects_oversized_line_before_decoding_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(site_module, "MAX_TRACE_LINE_BYTES", 48)
    hostile = "AGENTGUARD_SECRET_CANARY_UNREAD"
    _write_trace_bytes(tmp_path, "hostile", (hostile * 20).encode("utf-8") + b"\n")
    loads_calls = []
    original_loads = json.loads

    def tracking_loads(value: str) -> object:
        loads_calls.append(value)
        return original_loads(value)

    monkeypatch.setattr(site_module.json, "loads", tracking_loads)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", include_traces=True, force=True)
    )

    assert loads_calls == []
    assert hostile not in _all_html(tmp_path / "site")


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


def test_containment_evidence_after_generic_detail_limit_still_renders(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    data = {f"extra_{index}": f"value-{index}" for index in range(20)}
    data.update(
        {
            "task_id": "contained late evidence",
            "result": "PASS",
            "score": 100,
            "containment_evidence": _containment_evidence(),
        }
    )
    _write_json(tmp_path / ".agentguard/runs/late/reports/report.json", data)

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    detail = (tmp_path / "site/details/run-late.html").read_text(encoding="utf-8")
    assert "<h2>Containment</h2>" in detail
    assert "Contained execution mode" in detail
    assert "contained-run" in detail
    assert "Configured image reference" in detail
    assert "example.com/team/agent@sha256:" in detail


def test_nested_valid_containment_evidence_renders_requested_vs_verified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence = _containment_evidence(
        controls={
            "requested_resource_controls": {
                "pids_limit": 256,
                "memory_limit": "512m",
                "cpu": {"requested_cpus": 1.0},
            },
            "verified_resource_controls": {
                "pids_limit": 256,
                "cpu": {
                    "requested_cpus": 1.0,
                    "nano_cpus": 1_000_000_000,
                },
            },
        }
    )
    _write_json(
        tmp_path / ".agentguard/runs/nested/reports/report.json",
        {"task_id": "nested evidence", "result": "PASS", "containment_evidence": evidence},
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    detail = (tmp_path / "site/details/run-nested.html").read_text(encoding="utf-8")
    assert "requested_cpus=1.0" in detail
    assert re.search(r"<td>memory_limit</td>\s*<td>512m</td>\s*<td>requested-unverified</td>", detail)
    assert re.search(r"<td>pids_limit</td>\s*<td>256</td>\s*<td>verified</td>", detail)


def test_cleanup_failure_and_unknown_liveness_are_prominent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    evidence = _containment_evidence(
        cleanup={
            "container_complete": False,
            "container_status": "cleanup_incomplete",
            "liveness_verified": None,
            "overall_complete": False,
            "workspace_complete": None,
            "workspace_status": "unknown",
        }
    )
    _write_json(
        tmp_path / ".agentguard/runs/cleanup/reports/report.json",
        {"task_id": "cleanup failed", "result": "FAIL", "containment_evidence": evidence},
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    detail = (tmp_path / "site/details/run-cleanup.html").read_text(encoding="utf-8")
    assert "containment-alert" in detail
    assert "Cleanup or liveness is not fully verified" in detail
    assert "cleanup_incomplete" in detail
    assert "Overall cleanup</th><td>failed" in detail
    assert "Liveness verified</th><td>not-recorded" in detail
    assert "Overall cleanup</th><td>verified" not in detail


def test_historical_and_non_contained_pages_remain_usable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_json(
        tmp_path / ".agentguard/runs/plain/reports/report.json",
        {"task_id": "plain run", "result": "PASS", "score": 100},
    )
    _write_json(
        tmp_path / ".agentguard/runs/local/reports/report.json",
        {
            "task_id": "local run",
            "result": "PASS",
            "containment_evidence": _containment_evidence(
                execution_mode="local",
                state="not_applicable",
                claim_level="not_applicable",
                preflight={"status": "not_applicable", "claim_level": "not_applicable"},
                execution={"status": "skipped"},
            ),
        },
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    plain = (tmp_path / "site/details/run-plain.html").read_text(encoding="utf-8")
    local = (tmp_path / "site/details/run-local.html").read_text(encoding="utf-8")
    assert "<h2>Summary</h2>" in plain
    assert "<h2>Containment</h2>" not in plain
    assert "<h2>Containment</h2>" in local
    assert "not_applicable" in local


def test_containment_env_names_only_and_hostile_values_are_sanitized(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    secret_value = "AGENTGUARD_SECRET_CANARY_SITE"
    private_path = str(tmp_path / "private" / "token.txt")
    evidence = _containment_evidence(
        environment={
            "supplied_names": ["API_TOKEN", "TERM\x1b[31m"],
            "sensitive_names": ["API_TOKEN"],
            "missing_names": [],
            "default_names": ["PATH"],
        },
        controls={
            "requested_resource_controls": {
                "memory_limit": "512m",
                "canary": secret_value,
                "private_path": private_path,
                "html": "<img src=x onerror=alert(1)>",
            },
            "verified_resource_controls": {},
        },
        execution={"command": ["docker", "run", "--env", f"API_TOKEN={secret_value}"]},
    )
    _write_json(
        tmp_path / ".agentguard/runs/hostile/reports/report.json",
        {
            "task_id": "hostile containment",
            "result": "PASS",
            "containment_evidence": evidence,
            "docker_argv": ["docker", "run", "--env", f"API_TOKEN={secret_value}"],
        },
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    detail = (tmp_path / "site/details/run-hostile.html").read_text(encoding="utf-8")
    assert "API_TOKEN" in detail
    assert secret_value not in detail
    assert str(tmp_path) not in detail
    assert "[REDACTED]" in detail
    assert "[REDACTED_PATH]" in detail
    assert "<img" not in detail
    assert "&lt;img" in detail
    assert "\x1b" not in detail
    assert "docker, run" not in detail
    assert "API_TOKEN=" not in detail


def test_malformed_and_oversized_containment_evidence_are_controlled(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_json(
        tmp_path / ".agentguard/runs/malformed/reports/report.json",
        {
            "task_id": "bad containment",
            "result": "FAIL",
            "containment_evidence": {
                "schema": "bad",
                "secret": "AGENTGUARD_SECRET_CANARY_MALFORMED",
                "path": str(tmp_path / "private"),
            },
        },
    )
    oversized = _containment_evidence(
        controls={
            "requested_resource_controls": {
                f"control_{index}": index for index in range(24)
            },
            "verified_resource_controls": {},
        }
    )
    _write_json(
        tmp_path / ".agentguard/runs/oversized/reports/report.json",
        {"task_id": "wide containment", "result": "PASS", "containment_evidence": oversized},
    )

    generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )

    malformed = (tmp_path / "site/details/run-malformed.html").read_text(encoding="utf-8")
    oversized_detail = (tmp_path / "site/details/run-oversized.html").read_text(
        encoding="utf-8"
    )
    assert "Containment evidence is malformed or unsupported." in malformed
    assert "AGENTGUARD_SECRET_CANARY_MALFORMED" not in malformed
    assert str(tmp_path) not in malformed
    assert "12 additional control(s) omitted." in oversized_detail
    assert "control_23" not in oversized_detail


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


def _trace_header_line(run_id: str, *, event_count: int) -> bytes:
    return (
        json.dumps(
            {
                "trace_id": run_id,
                "event_count": event_count,
                "schema": "agentguard.execution-trace",
            },
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _trace_bytes(run_id: str, *, event_count: int) -> bytes:
    events = []
    for index in range(event_count):
        event_type = (
            "execution_completed"
            if index == event_count - 1
            else "agent_command"
        )
        events.append(
            json.dumps(
                {"event_type": event_type, "sequence": index + 1},
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    return _trace_header_line(run_id, event_count=event_count) + b"".join(events)


def _write_trace(path: Path, *, event_count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_trace_bytes(path.parent.name, event_count=event_count))


def _write_trace_bytes(tmp_path: Path, run_id: str, content: bytes) -> None:
    path = tmp_path / ".agentguard/runs" / run_id / "trace.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


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


def _containment_evidence(
    *,
    execution_mode: str = "contained-run",
    state: str = "recorded",
    claim_level: str = "linux-docker-engine",
    preflight: Optional[dict[str, object]] = None,
    controls: Optional[dict[str, object]] = None,
    environment: Optional[dict[str, object]] = None,
    execution: Optional[dict[str, object]] = None,
    cleanup: Optional[dict[str, object]] = None,
) -> dict[str, object]:
    image = "example.com/team/agent@sha256:" + "a" * 64
    base_preflight = {
        "state": state,
        "status": "supported",
        "claim_level": claim_level,
        "reduced_claim": claim_level == "docker-desktop-reduced",
        "checks_total": 3,
        "checks_passed": 3,
        "approved_boundary_constructible": True,
    }
    if preflight is not None:
        base_preflight.update(preflight)
        base_preflight.setdefault("state", state)
    base_controls = {
        "state": state,
        "network": "none",
        "no_new_privileges": True,
        "cap_drop_all": True,
        "read_only_root": True,
        "tmpfs_paths": ["/tmp"],
        "pids_limit": 256,
        "memory_limit": "512m",
        "cpu_limit": 1.0,
        "uid": 1000,
        "gid": 1000,
        "docker_socket_mount": False,
        "host_network": False,
        "privileged": False,
        "device_exposure": False,
        "host_namespace_sharing": False,
        "resource_verification_state": "recorded",
        "requested_resource_controls": {
            "pids_limit": 256,
            "memory_limit": "512m",
            "read_only_root": True,
        },
        "verified_resource_controls": {
            "pids_limit": 256,
            "read_only_root": True,
        },
    }
    if controls is not None:
        base_controls.update(controls)
    base_environment = {
        "state": state,
        "supplied_names": ["API_TOKEN"],
        "sensitive_names": ["API_TOKEN"],
        "missing_names": [],
        "default_names": ["PATH"],
        "values_recorded": False,
    }
    if environment is not None:
        base_environment.update(environment)
    base_execution = {
        "state": state,
        "status": "executed",
        "command": [],
        "exit_code": 0,
        "timed_out": False,
        "duration_seconds": 1.25,
        "stdout_truncated": False,
        "stderr_truncated": False,
    }
    if execution is not None:
        base_execution.update(execution)
    base_cleanup = {
        "state": state,
        "container_attempted": True,
        "container_complete": True,
        "container_status": "removed",
        "container_identity": {
            "id_sha256": "1" * 16,
            "name_sha256": "2" * 16,
            "owner_label_sha256": "3" * 16,
            "image_id": "sha256:" + "b" * 64,
        },
        "liveness_verified": True,
        "workspace_complete": True,
        "workspace_status": "removed",
        "overall_complete": True,
    }
    if cleanup is not None:
        base_cleanup.update(cleanup)
    return {
        "schema": "agentguard.containment-evidence",
        "schema_version": 1,
        "execution_mode": execution_mode,
        "state": state,
        "security_claim_level": claim_level,
        "requested": {
            "state": state,
            "platform": claim_level,
            "network": "none",
            "image_provenance": "digest-required",
            "configured_image": image,
            "command": [],
            "source_dir": "${REPOSITORY_ROOT}",
            "run_dir": "${RUN_ROOT}",
        },
        "preflight": base_preflight,
        "image": {
            "state": state,
            "configured_reference": image,
            "registry_digest": image,
            "local_image_id": "sha256:" + "b" * 64,
            "container_bound_image_id": "sha256:" + "b" * 64,
            "platform": "linux/amd64",
            "pull_policy": "docker-default",
            "cache_status": "present",
        },
        "controls": base_controls,
        "environment": base_environment,
        "workspace": {
            "state": state,
            "source_kind": "copy",
            "agent_mount": "/workspace",
            "evidence_mount": "/evidence",
            "writable_paths": ["/workspace"],
            "baseline_digest": "c" * 64,
            "current_digest": "d" * 64,
            "changed_files_count": 1,
            "lifecycle_schema_version": 1,
            "cleanup_complete": True,
            "cleanup_status": "removed",
        },
        "execution": base_execution,
        "cleanup": base_cleanup,
        "notes": [
            "Docker argv, raw Docker stdout/stderr, secret values, and private host roots are omitted.",
            "Docker is application-level containment, not a VM or syscall boundary.",
        ],
    }


def _all_html(site: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(site.rglob("*.html"))
    )
