import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.reports.site import (
    MAX_INCIDENT_JSON_BYTES,
    MAX_RENDERED_INCIDENT_VIOLATIONS,
    StaticSiteOptions,
    generate_static_report_site,
)


runner = CliRunner()


def test_empty_site_has_incident_navigation_and_empty_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    result = _generate(tmp_path)

    assert result.incidents == 0
    page = (tmp_path / "site/incidents.html").read_text(encoding="utf-8")
    assert "No guard incidents found" in page
    assert 'href="incidents.html">Incidents</a>' in _all_html(tmp_path / "site")


def test_incident_index_metrics_filters_and_deterministic_order(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_incident(
        tmp_path,
        "audit-run",
        blocked=False,
        detected_at="2026-06-29T10:00:00+00:00",
        mode="audit",
        agent="agent-b",
        violations=[
            _violation("filesystem", "test_tampering"),
            _violation("command", "unsafe_commands"),
        ],
    )
    _write_incident(
        tmp_path,
        "blocked-run",
        blocked=True,
        detected_at="2026-06-29T11:00:00+00:00",
        mode="enforce",
        agent="agent-a",
        violations=[_violation("filesystem", "scope_adherence")],
    )

    result = _generate(tmp_path)
    page = (tmp_path / "site/incidents.html").read_text(encoding="utf-8")

    assert result.incidents == 2
    for label, value in [
        ("Total incidents", "2"),
        ("Blocked incidents", "1"),
        ("Audit-only incidents", "1"),
        ("Total violations", "3"),
        ("Filesystem violations", "2"),
        ("Command violations", "1"),
    ]:
        assert f"<span>{label}</span><strong>{value}</strong>" in page
    assert page.index("blocked-run") < page.index("audit-run")
    for dimension in [
        "search",
        "status",
        "mode",
        "guard-type",
        "policy",
        "agent",
        "benchmark",
    ]:
        assert f'data-incident-filter="{dimension}"' in page
    assert "test_tampering" in page
    assert "unsafe_commands" in page
    assert 'data-status="v-' in page
    assert 'data-mode="v-' in page
    assert 'data-guard-type="v-' in page
    assert 'data-policy="v-' in page
    assert 'data-agent="v-' in page
    assert 'data-benchmark="v-' in page


def test_guard_trends_render_counts_deltas_and_links(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_json(
        tmp_path / ".agentguard/runs/audit-run/reports/report.json",
        {
            "task_id": "audit task",
            "result": "FAIL",
            "score": 20,
            "benchmark_id": "benchmark-a",
            "category": "test_tampering",
            "agent": "agent-b",
            "check_results": [
                {"name": "Test tampering", "passed": False},
                {"name": "Unsafe commands", "passed": False},
            ],
        },
    )
    _write_json(
        tmp_path / ".agentguard/runs/blocked-run/reports/report.json",
        {
            "task_id": "blocked task",
            "result": "FAIL",
            "score": 0,
            "benchmark_id": "benchmark-b",
            "category": "filesystem_boundary",
            "agent": "agent-a",
            "check_results": [{"name": "Scope adherence", "passed": False}],
        },
    )
    _write_incident(
        tmp_path,
        "audit-run",
        blocked=False,
        detected_at="2026-06-29T10:00:00+00:00",
        mode="audit",
        agent="agent-b",
        task="benchmark-a",
        violations=[
            _violation("filesystem", "test_tampering"),
            _violation("command", "unsafe_commands"),
        ],
    )
    _write_incident(
        tmp_path,
        "blocked-run",
        blocked=True,
        detected_at="2026-06-29T11:00:00+00:00",
        mode="enforce",
        agent="agent-a",
        task="benchmark-b",
        violations=[_violation("filesystem", "scope_adherence")],
    )

    _generate(tmp_path)
    dashboard = (tmp_path / "site/index.html").read_text(encoding="utf-8")
    trends = (tmp_path / "site/trends.html").read_text(encoding="utf-8")

    assert 'href="trends.html">Trends</a>' in dashboard
    assert "<h2>Guard trends</h2>" in dashboard
    assert "<h1>Guard Trends</h1>" in trends
    for label, value in [
        ("Runs represented", "2"),
        ("Guard incidents", "2"),
        ("Guard violations", "3"),
        ("Failed checks", "3"),
        ("Failed evaluations", "2"),
        ("Safe passes", "0"),
        ("Latest incident violations", "1"),
        ("Previous incident violations", "2"),
        ("Incident delta", "-1"),
    ]:
        assert f"<span>{label}</span><strong>{value}</strong>" in trends
    assert "test_tampering" in trends
    assert "unsafe_commands" in trends
    assert "scope_adherence" in trends
    assert "critical" in trends
    assert "audit" in trends
    assert "enforce" in trends
    assert "agent-a" in trends
    assert "agent-b" in trends
    assert 'href="details/incident-blocked-run.html"' in trends
    assert 'href="details/run-blocked-run.html">Run</a>' in trends


def test_guard_trends_escape_labels_and_omit_sensitive_content(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    absolute_path = str(tmp_path / "secret/path.txt")
    _write_json(
        tmp_path / ".agentguard/runs/tricky/reports/report.json",
        {
            "task_id": "<script>alert('run')</script>",
            "result": "FAIL",
            "score": 0,
            "benchmark_id": absolute_path,
            "agent": "<script>alert('agent')</script>",
            "check_results": [
                {
                    "name": "Secret scan",
                    "passed": False,
                    "evidence": ["AGENTGUARD_SECRET_CANARY_TREND"],
                }
            ],
        },
    )
    _write_incident(
        tmp_path,
        "tricky",
        agent="<script>alert('agent')</script>",
        task="<script>alert('task')</script>",
        evidence=f"AGENTGUARD_SECRET_CANARY_TREND {absolute_path} diff --git",
        violations=[
            {
                **_violation("filesystem", "<script>alert('policy')</script>"),
                "evidence_summary": (
                    f"AGENTGUARD_SECRET_CANARY_TREND {absolute_path} diff --git"
                ),
            }
        ],
    )

    _generate(tmp_path)
    html = _all_html(tmp_path / "site")

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html
    assert "AGENTGUARD_SECRET_CANARY_TREND" not in html
    assert str(tmp_path) not in html
    assert "diff --git" not in html


def test_incident_detail_is_sanitized_and_links_to_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    run_id = "run-safe"
    _write_json(
        tmp_path / f".agentguard/runs/{run_id}/reports/report.json",
        {
            "task_id": "safe task",
            "result": "FAIL",
            "score": 0,
            "benchmark_id": "benchmark-safe",
            "category": "security",
        },
    )
    absolute_path = str(tmp_path / "private/evidence.txt")
    _write_incident(
        tmp_path,
        run_id,
        blocked=True,
        command="rm -rf RAW_COMMAND",
        task="<script>alert('task')</script>",
        agent='" onmouseover="alert(1)',
        evidence=(
            "AGENTGUARD_SECRET_CANARY_INCIDENT "
            f"{absolute_path} https://example.invalid javascript:alert(1)"
        ),
    )

    _generate(tmp_path)
    detail = (
        tmp_path / "site/details/incident-run-safe.html"
    ).read_text(encoding="utf-8")

    assert "benchmark-safe" in detail
    assert "security" in detail
    assert "blocked" in detail
    assert "filesystem" in detail
    assert "test_tampering" in detail
    assert "critical" in detail
    assert "block" in detail
    assert "25 ms" in detail
    assert 'href="run-run-safe.html">Open run detail</a>' in detail
    assert 'href="../assets/site.css"' in detail
    assert 'src="../assets/site.js"' in detail
    assert "RAW_COMMAND" not in detail
    assert "AGENTGUARD_SECRET_CANARY_INCIDENT" not in detail
    assert "[REDACTED]" in detail
    assert str(tmp_path) not in detail
    assert "<script>alert" not in detail
    assert "&lt;script&gt;alert" in detail
    assert ' onmouseover="alert' not in detail
    assert 'href="https://' not in detail
    assert 'href="javascript:' not in detail
    assert 'href="file:' not in detail


def test_command_evidence_does_not_render_command_text(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_incident(
        tmp_path,
        "command-run",
        violations=[
            {
                **_violation("command", "unsafe_commands"),
                "command": "curl https://secret.invalid",
                "evidence_summary": "Unsafe command observed: rm -rf private",
            }
        ],
    )

    _generate(tmp_path)
    detail = (
        tmp_path / "site/details/incident-command-run.html"
    ).read_text(encoding="utf-8")

    assert "Command policy violation detected" in detail
    assert "curl" not in detail
    assert "rm -rf" not in detail
    assert "secret.invalid" not in detail


def test_partial_incident_and_missing_run_link_degrade_safely(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_json(
        _incident_path(tmp_path, "partial"),
        {
            "schema_version": 1,
            "run_id": "partial",
            "violations": [{"guard_type": "filesystem"}],
        },
    )

    _generate(tmp_path)
    detail = (
        tmp_path / "site/details/incident-partial.html"
    ).read_text(encoding="utf-8")

    assert "<h1>-</h1>" in detail
    assert "<td>filesystem</td>" in detail
    assert "Run detail: Unavailable" in detail
    assert 'href="run-' not in detail


def test_invalid_corrupt_oversized_and_future_incidents_are_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_json(_incident_path(tmp_path, "invalid"), ["not", "object"])
    corrupt = _incident_path(tmp_path, "corrupt")
    corrupt.parent.mkdir(parents=True)
    corrupt.write_text("{broken", encoding="utf-8")
    oversized = _incident_path(tmp_path, "oversized")
    oversized.parent.mkdir(parents=True)
    oversized.write_bytes(b"x" * (MAX_INCIDENT_JSON_BYTES + 1))
    _write_json(
        _incident_path(tmp_path, "future"),
        {"schema_version": 999, "run_id": "future"},
    )

    result = _generate(tmp_path)
    page = (tmp_path / "site/incidents.html").read_text(encoding="utf-8")

    assert result.incidents == 0
    assert result.unavailable == 4
    assert "Unavailable incidents" in page
    assert "unsupported incident schema version" in page
    assert "incident artifact exceeds the size limit" in page
    assert "{broken" not in page
    assert not list((tmp_path / "site/details").glob("incident-*.html"))


def test_symlinked_incident_is_skipped(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "outside.json"
    _write_json(target, _incident_data("linked"))
    linked = _incident_path(tmp_path, "linked")
    linked.parent.mkdir(parents=True)
    try:
        linked.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")

    result = _generate(tmp_path)

    assert result.incidents == 0
    assert "linked" not in (tmp_path / "site/incidents.html").read_text()


def test_violation_cap_preserves_aggregate_count(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    count = MAX_RENDERED_INCIDENT_VIOLATIONS + 3
    _write_incident(
        tmp_path,
        "many",
        violations=[
            _violation("filesystem", f"policy-{index}")
            for index in range(count)
        ],
    )

    _generate(tmp_path)
    index = (tmp_path / "site/incidents.html").read_text(encoding="utf-8")
    detail = (
        tmp_path / "site/details/incident-many.html"
    ).read_text(encoding="utf-8")

    assert "<span>Total violations</span><strong>53</strong>" in index
    assert "<td>53</td>" in index
    assert "3 additional violation(s) omitted." in detail
    assert detail.count("<td>filesystem</td>") == MAX_RENDERED_INCIDENT_VIOLATIONS


def test_colliding_ids_get_distinct_pages(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_incident(tmp_path, "run a")
    _write_incident(tmp_path, "run-a")

    result = _generate(tmp_path)
    pages = sorted((tmp_path / "site/details").glob("incident-run-a*.html"))

    assert result.incidents == 2
    assert len(pages) == 2
    assert pages[0].name != pages[1].name


def test_cli_reports_incident_count_and_existing_js_filter_remains(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_incident(tmp_path, "cli")

    result = runner.invoke(
        app,
        ["reports", "site", "--output", str(tmp_path / "site"), "--force"],
    )
    script = (tmp_path / "site/assets/site.js").read_text(encoding="utf-8")

    assert result.exit_code == 0
    assert "incidents: 1" in result.output
    assert "data-filter-row" in script
    assert "incidentFilters.every" in script
    assert "http://" not in _all_html(tmp_path / "site")
    assert "https://" not in _all_html(tmp_path / "site")
    assert str(tmp_path) not in _all_html(tmp_path / "site")


def _generate(tmp_path: Path):
    return generate_static_report_site(
        StaticSiteOptions(output=tmp_path / "site", force=True)
    )


def _write_incident(
    tmp_path: Path,
    run_id: str,
    *,
    blocked: bool = False,
    detected_at: str = "2026-06-29T10:00:00+00:00",
    mode: str = "audit",
    agent: str = "local-command",
    task: str = "fix_auth_bug",
    command: str = "RAW COMMAND",
    evidence: str = "Test path changed",
    violations=None,
) -> None:
    data = _incident_data(
        run_id,
        blocked=blocked,
        detected_at=detected_at,
        mode=mode,
        agent=agent,
        task=task,
        command=command,
        evidence=evidence,
        violations=violations,
    )
    _write_json(_incident_path(tmp_path, run_id), data)


def _incident_data(
    run_id: str,
    *,
    blocked: bool = False,
    detected_at: str = "2026-06-29T10:00:00+00:00",
    mode: str = "audit",
    agent: str = "local-command",
    task: str = "fix_auth_bug",
    command: str = "RAW COMMAND",
    evidence: str = "Test path changed",
    violations=None,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "task_id": task,
        "agent": agent,
        "guard_mode": mode,
        "result": "FAIL" if blocked else "PASS",
        "blocked": blocked,
        "blocking_guard": "filesystem" if blocked else None,
        "started_at": "2026-06-29T09:59:59+00:00",
        "detected_at": detected_at,
        "completed_at": "2026-06-29T10:01:00+00:00",
        "time_to_first_violation_ms": 25,
        "time_to_block_ms": 25 if blocked else None,
        "violations": violations
        if violations is not None
        else [
            {
                **_violation("filesystem", "test_tampering"),
                "command": command,
                "evidence_summary": evidence,
                "path": "/private/raw/path",
            }
        ],
        "artifacts": {"report_json": "/private/raw/report.json"},
        "redaction": {"applied": True, "sensitive_values_count": 1},
    }


def _violation(guard_type: str, policy: str) -> dict[str, object]:
    return {
        "guard_type": guard_type,
        "policy": policy,
        "severity": "critical",
        "action": "block",
        "detected_at": "2026-06-29T10:00:00+00:00",
        "elapsed_ms": 25,
        "evidence_summary": "sanitized evidence",
    }


def _incident_path(tmp_path: Path, run_id: str) -> Path:
    return tmp_path / f".agentguard/runs/{run_id}/guard/incident.json"


def _write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _all_html(site: Path) -> str:
    return "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(site.rglob("*.html"))
    )
