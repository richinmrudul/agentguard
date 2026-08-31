import json
import subprocess
import sys
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.reports import exports as report_exports


runner = CliRunner()
CANARY = "AGENTGUARD_SECRET_CANARY_DO_NOT_LEAK"


def test_sarif_single_run_with_failed_checks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(tmp_path, failed=True)
    output = tmp_path / "out.sarif"

    result = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(output)],
    )

    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "AgentGuard"
    assert len(run["results"]) == 1
    assert run["results"][0]["ruleId"] == "scope-adherence"
    assert run["results"][0]["level"] == "error"
    assert "SARIF exported:" in result.output
    assert "results: 1" in result.output


def test_sarif_suite_and_matrix_aggregation(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    child = _write_run_report(tmp_path, run_id="child", failed=True, include_pass=True)
    suite = _write_suite_report(tmp_path, child)
    matrix = _write_matrix_report(tmp_path, child)

    suite_output = tmp_path / "suite.sarif"
    matrix_output = tmp_path / "matrix.sarif"
    suite_result = runner.invoke(
        app,
        [
            "reports",
            "export-sarif",
            str(suite),
            "--output",
            str(suite_output),
            "--include-passed",
        ],
    )
    matrix_result = runner.invoke(
        app,
        ["reports", "export-sarif", str(matrix), "--output", str(matrix_output)],
    )

    assert suite_result.exit_code == 0
    assert matrix_result.exit_code == 0
    assert len(json.loads(suite_output.read_text())["runs"][0]["results"]) == 2
    assert len(json.loads(matrix_output.read_text())["runs"][0]["results"]) == 1


def test_sarif_rule_metadata_severity_and_include_passed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(tmp_path, failed=True, include_pass=True)
    default_output = tmp_path / "default.sarif"
    passed_output = tmp_path / "passed.sarif"

    runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(default_output)],
    )
    result = runner.invoke(
        app,
        [
            "reports",
            "export-sarif",
            str(report),
            "--output",
            str(passed_output),
            "--include-passed",
        ],
    )

    default = json.loads(default_output.read_text(encoding="utf-8"))
    passed = json.loads(passed_output.read_text(encoding="utf-8"))
    rule = passed["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "Scope adherence"
    assert rule["defaultConfiguration"]["level"] == "error"
    assert len(default["runs"][0]["results"]) == 1
    assert len(passed["runs"][0]["results"]) == 2
    assert any(item.get("kind") == "pass" for item in passed["runs"][0]["results"])
    assert "passed included: 1" in result.output


def test_sarif_path_normalization_no_absolute_paths_and_no_location(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(
        tmp_path,
        failed=True,
        changed_path=str(tmp_path / "src/login.py"),
    )
    no_path_report = _write_run_report(
        tmp_path,
        run_id="no-path",
        failed=True,
        changed_path=None,
        evidence=["policy check failed without a file reference"],
    )
    output = tmp_path / "paths.sarif"
    no_path_output = tmp_path / "no-path.sarif"

    runner.invoke(app, ["reports", "export-sarif", str(report), "--output", str(output)])
    runner.invoke(
        app,
        ["reports", "export-sarif", str(no_path_report), "--output", str(no_path_output)],
    )

    text = output.read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    result = json.loads(text)["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.endswith("src/login.py")
    no_path_result = json.loads(no_path_output.read_text())["runs"][0]["results"][0]
    assert "locations" not in no_path_result
    assert "No file location" in no_path_result["message"]["text"]


def test_sarif_evidence_sanitization_and_secret_bounding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(
        tmp_path,
        failed=True,
        evidence=[
            CANARY,
            f"password={CANARY} " + ("x" * 1000),
            f"temporary path {tmp_path}/secret.txt",
        ],
    )
    output = tmp_path / "safe.sarif"

    result = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(output)],
    )

    assert result.exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert CANARY not in text
    assert str(tmp_path) not in text
    assert "[truncated]" in text


def test_sarif_stable_hash_ignores_run_metadata_and_temporary_roots(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    first_root = tmp_path / "first-workspace"
    second_root = tmp_path / "second-workspace"
    first_report = _write_run_report(
        first_root,
        run_id="run-volatile-a",
        failed=True,
        changed_path=str(first_root / "src/login.py"),
        evidence=[f"modified {first_root}/src/login.py"],
    )
    second_report = _write_run_report(
        second_root,
        run_id="run-volatile-b",
        failed=True,
        changed_path=str(second_root / "src/login.py"),
        evidence=[f"modified {second_root}/src/login.py"],
    )
    _update_report(
        first_report,
        {
            "execution_id": "execution-a",
            "run_id": "runtime-a",
            "started_at": "2026-08-31T10:00:00Z",
            "completed_at": "2026-08-31T10:00:02Z",
        },
    )
    _update_report(
        second_report,
        {
            "execution_id": "execution-b",
            "run_id": "runtime-b",
            "started_at": "2026-08-31T11:00:00Z",
            "completed_at": "2026-08-31T11:00:02Z",
        },
    )
    first_output = tmp_path / "first.sarif"
    second_output = tmp_path / "second.sarif"

    first = runner.invoke(
        app,
        ["reports", "export-sarif", str(first_report), "--output", str(first_output)],
    )
    second = runner.invoke(
        app,
        ["reports", "export-sarif", str(second_report), "--output", str(second_output)],
    )

    assert first.exit_code == 0
    assert second.exit_code == 0
    first_text = first_output.read_text(encoding="utf-8")
    second_text = second_output.read_text(encoding="utf-8")
    assert str(first_root) not in first_text
    assert str(second_root) not in second_text
    material = report_exports._fingerprint_material(  # noqa: SLF001
        report_exports.ExportFinding(
            rule_id="scope-adherence",
            rule_name="Scope adherence",
            passed=False,
            severity="error",
            message="Scope changed outside the allowed boundary.",
            evidence=[f"modified {first_root}/src/login.py"],
            paths=["src/login.py"],
            run_id="execution-a",
            task_id="fix_auth_bug",
            agent="mock-safe",
        )
    )
    assert str(first_root) not in material
    assert _stable_hashes(first_output) == _stable_hashes(second_output)


def test_sarif_stable_hash_distinguishes_rule_location_and_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    checks = [
        _check(
            "Scope adherence",
            evidence=["Outside allowed paths: src/login.py"],
        ),
        _check(
            "Forbidden paths",
            evidence=["Forbidden path src/login.py"],
        ),
        _check(
            "Scope adherence",
            evidence=["Outside allowed paths: src/admin.py"],
        ),
        _check(
            "Scope adherence",
            message="Scope changed outside the allowed boundary in a different way.",
            evidence=["Outside allowed paths: src/login.py after deleting admin role"],
        ),
    ]
    report = _write_run_report(
        tmp_path,
        failed=True,
        changed_path=None,
        checks=checks,
    )
    output = tmp_path / "distinctive.sarif"

    result = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(output)],
    )

    assert result.exit_code == 0
    hashes = _stable_hashes(output)
    assert len(hashes) == 4
    assert len(set(hashes)) == 4


def test_sarif_aggregate_row_order_does_not_change_fingerprints_or_serialization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    matrix = _write_matrix_report_with_rows(
        tmp_path,
        [
            _aggregate_row(
                task_id="fix_auth_bug",
                agent="mock-safe",
                failed_checks=["Scope adherence"],
                error="Outside allowed paths: src/login.py",
            ),
            _aggregate_row(
                task_id="fix_auth_bug",
                agent="mock-safe",
                failed_checks=["Forbidden paths"],
                error="Forbidden path secrets/key.txt",
            ),
        ],
    )
    output = tmp_path / "matrix.sarif"
    reordered_output = tmp_path / "matrix-reordered.sarif"

    result = runner.invoke(
        app,
        ["reports", "export-sarif", str(matrix), "--output", str(output)],
    )
    matrix = _write_matrix_report_with_rows(
        tmp_path,
        [
            _aggregate_row(
                task_id="fix_auth_bug",
                agent="mock-safe",
                failed_checks=["Forbidden paths"],
                error="Forbidden path secrets/key.txt",
            ),
            _aggregate_row(
                task_id="fix_auth_bug",
                agent="mock-safe",
                failed_checks=["Scope adherence"],
                error="Outside allowed paths: src/login.py",
            ),
        ],
    )
    reordered_result = runner.invoke(
        app,
        ["reports", "export-sarif", str(matrix), "--output", str(reordered_output)],
    )

    assert result.exit_code == 0
    assert reordered_result.exit_code == 0
    assert _stable_hashes(output) == _stable_hashes(reordered_output)
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(
        reordered_output.read_text(encoding="utf-8")
    )


def test_sarif_serialization_is_deterministic_for_equivalent_exports(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(tmp_path, failed=True)
    first_output = tmp_path / "first.sarif"
    second_output = tmp_path / "second.sarif"

    first = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(first_output)],
    )
    second = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(second_output)],
    )

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert first_output.read_text(encoding="utf-8") == second_output.read_text(
        encoding="utf-8"
    )


def test_sarif_stable_hash_is_deterministic_across_python_processes() -> None:
    script = (
        "from agentguard.reports.exports import ExportFinding, _fingerprint_material, "
        "_stable_hash; "
        "finding = ExportFinding("
        "rule_id='scope-adherence', rule_name='Scope adherence', passed=False, "
        "severity='error', message='failed', evidence=['modified src/login.py'], "
        "paths=['src/login.py'], task_id='fix_auth_bug', agent='mock-safe'); "
        "print(_stable_hash(_fingerprint_material(finding)))"
    )

    first = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert first.stdout == second.stdout


def test_junit_single_run_and_xml_escaping(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(
        tmp_path,
        failed=True,
        message="unsafe <path> & command",
    )
    output = tmp_path / "junit.xml"

    result = runner.invoke(
        app,
        ["reports", "export-junit", str(report), "--output", str(output)],
    )

    assert result.exit_code == 0
    tree = ElementTree.parse(output)
    suite = tree.getroot().find("testsuite")
    assert suite is not None
    assert suite.attrib["tests"] == "1"
    assert suite.attrib["failures"] == "1"
    failure = suite.find("testcase/failure")
    assert failure is not None
    assert "unsafe <path> & command" in (failure.text or "")


def test_junit_suite_matrix_counts_and_timing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    child = _write_run_report(tmp_path, failed=True)
    suite = _write_suite_report(tmp_path, child)
    matrix = _write_matrix_report(tmp_path, child)
    suite_output = tmp_path / "suite.xml"
    matrix_output = tmp_path / "matrix.xml"

    suite_result = runner.invoke(
        app,
        [
            "reports",
            "export-junit",
            str(suite),
            "--output",
            str(suite_output),
            "--suite-name",
            "AgentGuard Suite",
        ],
    )
    matrix_result = runner.invoke(
        app,
        ["reports", "export-junit", str(matrix), "--output", str(matrix_output)],
    )

    assert suite_result.exit_code == 0
    assert matrix_result.exit_code == 0
    assert "tests: 1; failures: 1" in suite_result.output
    suite_xml = ElementTree.parse(suite_output).getroot().find("testsuite")
    matrix_xml = ElementTree.parse(matrix_output).getroot().find("testsuite")
    assert suite_xml is not None and suite_xml.attrib["name"] == "AgentGuard Suite"
    assert matrix_xml is not None and matrix_xml.attrib["tests"] == "1"
    assert all("time" in case.attrib for case in suite_xml.findall("testcase"))


def test_directory_discovery_mixed_files_and_parse_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, run_id="one", failed=True)
    unsupported = tmp_path / "trace.json"
    unsupported.write_text('{"schema": "agentguard.execution-trace"}', encoding="utf-8")
    sarif = tmp_path / "dir.sarif"
    junit = tmp_path / "dir.xml"

    sarif_result = runner.invoke(
        app,
        ["reports", "export-sarif", str(tmp_path), "--output", str(sarif)],
    )
    junit_result = runner.invoke(
        app,
        ["reports", "export-junit", str(tmp_path), "--output", str(junit)],
    )

    assert sarif_result.exit_code == 0
    assert junit_result.exit_code == 0
    json.loads(sarif.read_text(encoding="utf-8"))
    ElementTree.parse(junit)


def test_unsupported_input_and_overwrite_force(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    unsupported = tmp_path / "trace.json"
    unsupported.write_text('{"schema": "agentguard.execution-trace"}', encoding="utf-8")
    report = _write_run_report(tmp_path, failed=True)
    output = tmp_path / "out.sarif"
    output.write_text("old", encoding="utf-8")

    bad = runner.invoke(
        app,
        ["reports", "export-sarif", str(unsupported), "--output", str(tmp_path / "x")],
    )
    conflict = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(output)],
    )
    forced = runner.invoke(
        app,
        ["reports", "export-sarif", str(report), "--output", str(output), "--force"],
    )

    assert bad.exit_code == 2
    assert "Raw trace" in bad.output or "Trace/replay" in bad.output
    assert conflict.exit_code == 2
    assert "Use --force" in conflict.output
    assert forced.exit_code == 0


def test_junit_secret_sanitization(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    report = _write_run_report(
        tmp_path,
        failed=True,
        evidence=[f"token={CANARY}", f"cwd={tmp_path}/work"],
    )
    output = tmp_path / "junit.xml"

    runner.invoke(app, ["reports", "export-junit", str(report), "--output", str(output)])

    text = output.read_text(encoding="utf-8")
    assert CANARY not in text
    assert str(tmp_path) not in text


@pytest.mark.parametrize("path_kind", ["absolute", "traversal"])
def test_suite_exports_reject_child_reports_outside_report_tree(
    tmp_path: Path,
    monkeypatch,
    path_kind: str,
) -> None:
    monkeypatch.chdir(tmp_path)
    safe_child = _write_run_report(tmp_path, run_id="safe", failed=True)
    external_child = _write_run_report(
        tmp_path / "external",
        run_id="outside",
        failed=True,
        message=CANARY,
        evidence=[CANARY],
    )
    suite = _write_suite_report(tmp_path, safe_child)
    child_value = (
        str(external_child)
        if path_kind == "absolute"
        else "../../../external/.agentguard/runs/outside/reports/report.json"
    )
    _set_child_path(suite, child_value)

    sarif = tmp_path / f"{path_kind}.sarif"
    junit = tmp_path / f"{path_kind}.xml"
    sarif_result = runner.invoke(
        app,
        ["reports", "export-sarif", str(suite), "--output", str(sarif)],
    )
    junit_result = runner.invoke(
        app,
        ["reports", "export-junit", str(suite), "--output", str(junit)],
    )

    assert sarif_result.exit_code == 0
    assert junit_result.exit_code == 0
    assert CANARY not in sarif.read_text(encoding="utf-8")
    assert CANARY not in junit.read_text(encoding="utf-8")
    assert "outside the trusted report tree" in sarif.read_text(encoding="utf-8")
    assert "outside the trusted report tree" in junit.read_text(encoding="utf-8")


def test_suite_exports_reject_child_report_symlink_escape(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    safe_child = _write_run_report(tmp_path, run_id="safe", failed=True)
    external_child = _write_run_report(
        tmp_path / "external",
        run_id="outside",
        failed=True,
        message=CANARY,
        evidence=[CANARY],
    )
    suite = _write_suite_report(tmp_path, safe_child)
    link = tmp_path / ".agentguard/runs/linked-reports"
    try:
        link.symlink_to(external_child.parent, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Symlinks are unavailable: {error}")
    _set_child_path(
        suite,
        ".agentguard/runs/linked-reports/report.json",
    )
    output = tmp_path / "symlink.sarif"

    result = runner.invoke(
        app,
        ["reports", "export-sarif", str(suite), "--output", str(output)],
    )

    assert result.exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert CANARY not in text
    assert "outside the trusted report tree" in text


def test_existing_report_browser_unchanged(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_report(tmp_path, failed=False)

    result = runner.invoke(app, ["reports", "show", "--latest"])

    assert result.exit_code == 0
    assert "AgentGuard Run Report" in result.output
    assert "Result: PASS" in result.output


def _write_run_report(
    tmp_path: Path,
    *,
    run_id: str = "run-1",
    failed: bool,
    include_pass: bool = False,
    changed_path: Optional[str] = "src/login.py",
    evidence: Optional[list[str]] = None,
    message: str = "Scope changed outside the allowed boundary.",
    checks: Optional[list[dict[str, object]]] = None,
) -> Path:
    path = tmp_path / ".agentguard/runs" / run_id / "reports/report.json"
    if checks is None:
        checks = [
            {
                "name": "Scope adherence",
                "passed": not failed,
                "severity": "error",
                "message": message,
                "evidence": evidence or ["modified src/login.py"],
            }
        ]
    if include_pass:
        checks.append(
            {
                "name": "Tests passed",
                "passed": True,
                "severity": "info",
                "message": "Tests passed.",
                "evidence": [],
            }
        )
    modified = [] if changed_path is None else [changed_path]
    data = {
        "task_id": "fix_auth_bug",
        "agent": "mock-safe",
        "result": "FAIL" if failed else "PASS",
        "score": 60 if failed else 100,
        "execution_id": run_id,
        "diff_summary": {
            "modified_files": modified,
            "added_files": [],
            "deleted_files": [],
        },
        "check_results": checks,
        "report_paths": {"json": str(path), "markdown": str(path.with_suffix(".md"))},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _check(
    name: str,
    *,
    passed: bool = False,
    severity: str = "error",
    message: Optional[str] = None,
    evidence: Optional[list[str]] = None,
) -> dict[str, object]:
    return {
        "name": name,
        "passed": passed,
        "severity": severity,
        "message": message or f"{name} failed.",
        "evidence": evidence or [],
    }


def _write_suite_report(tmp_path: Path, child: Path) -> Path:
    path = tmp_path / ".agentguard/suites/core-1/suite.json"
    data = {
        "suite_id": "core",
        "total_runs": 1,
        "passed": 0,
        "failed": 1,
        "pass_rate": 0.0,
        "average_score": 60,
        "runs": [_row(child)],
        "json_report_path": str(path),
        "markdown_report_path": str(path.with_suffix(".md")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_matrix_report(tmp_path: Path, child: Path) -> Path:
    path = tmp_path / ".agentguard/matrices/core-1/matrix.json"
    data = {
        "matrix_id": "core-matrix",
        "suite_id": "core",
        "total_runs": 1,
        "passed": 0,
        "failed": 1,
        "pass_rate": 0.0,
        "average_score": 60,
        "runs": [_row(child)],
        "json_report_path": str(path),
        "markdown_report_path": str(path.with_suffix(".md")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_matrix_report_with_rows(
    tmp_path: Path,
    rows: list[dict[str, object]],
    *,
    matrix_id: str = "core-matrix",
) -> Path:
    path = tmp_path / f".agentguard/matrices/{matrix_id}/matrix.json"
    data = {
        "matrix_id": matrix_id,
        "suite_id": "core",
        "total_runs": len(rows),
        "passed": 0,
        "failed": len(rows),
        "pass_rate": 0.0,
        "average_score": 60,
        "runs": rows,
        "json_report_path": str(path),
        "markdown_report_path": str(path.with_suffix(".md")),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _aggregate_row(
    *,
    task_id: str,
    agent: str,
    failed_checks: list[str],
    error: str,
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "config_path": f"examples/configs/{task_id}.yaml",
        "agent": agent,
        "result": "FAIL",
        "score": 60,
        "failed_checks": failed_checks,
        "warning_checks": [],
        "json_report_path": "",
        "markdown_report_path": "",
        "run_dir": "",
        "execution_id": "volatile-execution",
        "trial_index": 1,
        "trial_count": 1,
        "error": error,
    }


def _row(child: Path) -> dict[str, object]:
    return {
        "task_id": "fix_auth_bug",
        "config_path": "examples/configs/fix_auth_bug.yaml",
        "agent": "mock-safe",
        "result": "FAIL",
        "score": 60,
        "failed_checks": ["Scope adherence"],
        "warning_checks": [],
        "json_report_path": str(child),
        "markdown_report_path": str(child.with_suffix(".md")),
        "run_dir": str(child.parent.parent),
        "execution_id": "child",
        "trial_index": 1,
        "trial_count": 1,
    }


def _set_child_path(report: Path, child_path: str) -> None:
    data = json.loads(report.read_text(encoding="utf-8"))
    data["runs"][0]["json_report_path"] = child_path
    report.write_text(json.dumps(data), encoding="utf-8")


def _update_report(report: Path, updates: dict[str, object]) -> None:
    data = json.loads(report.read_text(encoding="utf-8"))
    data.update(updates)
    report.write_text(json.dumps(data), encoding="utf-8")


def _stable_hashes(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [
        result["partialFingerprints"]["agentguardStableHash"]
        for result in data["runs"][0]["results"]
    ]
