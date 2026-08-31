import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Optional
from urllib.parse import quote
from xml.dom import minidom
from xml.etree import ElementTree

from agentguard import __version__
from agentguard.io import atomic_write_json, atomic_write_text


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://json.schemastore.org/sarif-2.1.0.json"
)
SUPPORTED_DIRECTORY_NAMES = {
    "report.json",
    "suite.json",
    "matrix.json",
    "mutations.json",
    "ablation.json",
    "matrix-stress.json",
}
MAX_EVIDENCE_ITEMS = 6
MAX_EVIDENCE_CHARS = 360
MAX_SYSTEM_OUT_CHARS = 1600
XML_ILLEGAL_REPLACEMENT = "\ufffd"

SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_=-]{8,}\b"),
    re.compile(r"AGENTGUARD_SECRET_CANARY[_A-Z0-9-]*", re.IGNORECASE),
]
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w.-])(?:/[^\s,;:'\")\]}]+|[A-Za-z]:[\\/][^\s,;:'\")\]}]+)"
)
URI_PATH_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s,;:'\")\]}]+")
UNC_PATH_PATTERN = re.compile(r"(?<![\w.-])\\\\[^\s,;:'\")\]}]+")
TRAVERSAL_PATH_PATTERN = re.compile(r"(?<![\w.-])\.\.[\\/][^\s,;:'\")\]}]+")
BACKSLASH_PATH_PATTERN = re.compile(r"(?<![\w.-])[\w.-]+\\[^\s,;:'\")\]}]+")
WINDOWS_DRIVE_PATH_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")
URI_SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


@dataclass(frozen=True)
class ExportFinding:
    rule_id: str
    rule_name: str
    passed: bool
    severity: str
    message: str
    evidence: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    report_path: Optional[str] = None
    run_id: Optional[str] = None
    task_id: Optional[str] = None
    agent: Optional[str] = None
    source_type: str = "run"
    fingerprint_seed: str = ""


@dataclass(frozen=True)
class ExportTestCase:
    classname: str
    name: str
    passed: bool
    time_seconds: Optional[float] = None
    failure_message: Optional[str] = None
    system_out: str = ""
    report_path: Optional[str] = None


@dataclass(frozen=True)
class ExportInputSummary:
    input_path: Path
    input_type: str
    reports: int
    findings: list[ExportFinding]
    test_cases: list[ExportTestCase]
    unsupported_files: list[Path] = field(default_factory=list)
    report_sources: list[Path] = field(default_factory=list)


@dataclass(frozen=True)
class SarifExportResult:
    output_path: Path
    reports: int
    rules: int
    results: int
    findings: int
    included_passed: int
    unsupported_files: int = 0


@dataclass(frozen=True)
class JunitExportResult:
    output_path: Path
    reports: int
    tests: int
    failures: int
    unsupported_files: int = 0


class UnsupportedExportInput(ValueError):
    """Raised when a report cannot be mapped to the requested export."""


def export_sarif(
    input_path: Path,
    output_path: Path,
    *,
    force: bool = False,
    tool_name: str = "AgentGuard",
    base_uri: Optional[str] = None,
    include_passed: bool = False,
) -> SarifExportResult:
    summary = load_export_input(input_path, "sarif", include_passed=include_passed)
    findings = [
        finding
        for finding in summary.findings
        if not finding.passed or include_passed
    ]
    sarif = render_sarif(
        findings,
        tool_name=tool_name,
        base_uri=base_uri,
        input_path=summary.input_path,
    )
    _write_output_json(output_path, sarif, force=force)
    return SarifExportResult(
        output_path=output_path.expanduser(),
        reports=summary.reports,
        rules=len(sarif["runs"][0]["tool"]["driver"].get("rules", [])),
        results=len(sarif["runs"][0]["results"]),
        findings=sum(1 for finding in findings if not finding.passed),
        included_passed=sum(1 for finding in findings if finding.passed),
        unsupported_files=len(summary.unsupported_files),
    )


def export_junit(
    input_path: Path,
    output_path: Path,
    *,
    force: bool = False,
    tool_name: str = "AgentGuard",
    suite_name: Optional[str] = None,
) -> JunitExportResult:
    summary = load_export_input(input_path, "junit")
    xml = render_junit(
        summary.test_cases,
        tool_name=tool_name,
        suite_name=suite_name or _default_suite_name(summary),
    )
    _write_output_text(output_path, xml, force=force)
    return JunitExportResult(
        output_path=output_path.expanduser(),
        reports=summary.reports,
        tests=len(summary.test_cases),
        failures=sum(1 for case in summary.test_cases if not case.passed),
        unsupported_files=len(summary.unsupported_files),
    )


def load_export_input(
    input_path: Path,
    export_kind: str,
    *,
    include_passed: bool = False,
) -> ExportInputSummary:
    path = input_path.expanduser()
    if path.is_dir():
        return _load_directory(path, export_kind, include_passed=include_passed)
    data = _load_json(path)
    return _normalize_report(
        data,
        path,
        export_kind,
        include_passed=include_passed,
        strict=True,
    )


def render_sarif(
    findings: list[ExportFinding],
    *,
    tool_name: str,
    base_uri: Optional[str],
    input_path: Path,
) -> dict[str, Any]:
    rules = [_sarif_rule(rule_id, grouped) for rule_id, grouped in _group_rules(findings)]
    results = [_sarif_result(finding) for finding in sorted(findings, key=_finding_sort_key)]
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": tool_name,
                "version": __version__,
                "informationUri": "https://github.com/richinmrudul/agentguard",
                "rules": rules,
            }
        },
        "results": results,
        "properties": {
            "agentguard": {
                "input": _safe_path(input_path),
                "export": "sarif",
            }
        },
    }
    if base_uri:
        run["originalUriBaseIds"] = {
            "AGENTGUARD_REPOSITORY": {"uri": _base_uri(base_uri)}
        }
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [run],
    }


def render_junit(
    cases: list[ExportTestCase],
    *,
    tool_name: str,
    suite_name: str,
) -> str:
    root = ElementTree.Element(
        "testsuites",
        {
            "name": _junit_xml_text(suite_name),
            "tests": str(len(cases)),
            "failures": str(sum(1 for case in cases if not case.passed)),
            "errors": "0",
            "time": _format_time(sum(case.time_seconds or 0 for case in cases)),
        },
    )
    suite = ElementTree.SubElement(
        root,
        "testsuite",
        {
            "name": _junit_xml_text(suite_name),
            "tests": str(len(cases)),
            "failures": str(sum(1 for case in cases if not case.passed)),
            "errors": "0",
            "skipped": "0",
            "time": _format_time(sum(case.time_seconds or 0 for case in cases)),
        },
    )
    ElementTree.SubElement(suite, "properties")
    for case in sorted(cases, key=lambda item: (item.classname, item.name)):
        testcase = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": _junit_xml_text(case.classname),
                "name": _junit_xml_text(case.name),
                "time": _format_time(case.time_seconds or 0),
            },
        )
        if not case.passed:
            message = _junit_xml_text(_bounded(_sanitize(case.failure_message or "Failed")))
            failure = ElementTree.SubElement(
                testcase,
                "failure",
                {
                    "message": message,
                    "type": "AgentGuardFailure",
                },
            )
            failure.text = message
        system_out = ElementTree.SubElement(testcase, "system-out")
        system_out.text = _junit_xml_text(
            _bounded(_sanitize(case.system_out), MAX_SYSTEM_OUT_CHARS)
        )
    ElementTree.SubElement(suite, "system-out").text = (
        _junit_xml_text(f"Generated by {tool_name} {__version__}")
    )
    rough = ElementTree.tostring(root, encoding="utf-8")
    parsed = minidom.parseString(rough)
    return parsed.toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")


def _load_directory(
    path: Path,
    export_kind: str,
    *,
    include_passed: bool,
) -> ExportInputSummary:
    findings: list[ExportFinding] = []
    cases: list[ExportTestCase] = []
    unsupported: list[Path] = []
    report_sources: list[Path] = []
    reports = 0
    for report_path in sorted(path.rglob("*.json")):
        try:
            data = _load_json(report_path)
            summary = _normalize_report(
                data,
                report_path,
                export_kind,
                include_passed=include_passed,
                strict=False,
            )
        except UnsupportedExportInput:
            if report_path.name in SUPPORTED_DIRECTORY_NAMES:
                unsupported.append(report_path)
            continue
        reports += summary.reports
        findings.extend(summary.findings)
        cases.extend(summary.test_cases)
        unsupported.extend(summary.unsupported_files)
        report_sources.extend(summary.report_sources)
    if export_kind == "sarif":
        findings = _deduplicate_directory_sarif_findings(findings)
        reports = len(_unique_report_sources(report_sources))
    if reports == 0:
        raise UnsupportedExportInput(
            "No supported AgentGuard report JSON files found. Raw trace files are "
            "not supported; replay/export reports first."
        )
    return ExportInputSummary(
        input_path=path,
        input_type="directory",
        reports=reports,
        findings=findings,
        test_cases=cases,
        unsupported_files=unsupported,
        report_sources=report_sources,
    )


def _normalize_report(
    data: Any,
    path: Path,
    export_kind: str,
    *,
    include_passed: bool,
    strict: bool,
) -> ExportInputSummary:
    if not isinstance(data, dict):
        raise UnsupportedExportInput("Report JSON must be an object.")
    report_type = _report_type(data, path)
    if report_type in {"run", "ci"}:
        return _normalize_run(data, path, report_type, include_passed=include_passed)
    if report_type == "suite":
        return _normalize_suite_or_matrix(
            data,
            path,
            "suite",
            export_kind,
            include_passed=include_passed,
        )
    if report_type == "matrix":
        return _normalize_suite_or_matrix(
            data,
            path,
            "matrix",
            export_kind,
            include_passed=include_passed,
        )
    if report_type == "benchmark":
        if export_kind == "sarif":
            raise UnsupportedExportInput(
                "Benchmark summary reports are aggregate outcomes; export child "
                "run, suite, or matrix reports for SARIF policy findings."
            )
        return _normalize_benchmark_summary(data, path)
    if report_type == "mutation":
        if export_kind == "sarif":
            raise UnsupportedExportInput(
                "Mutation audit reports are benchmark diagnostics and do not map "
                "cleanly to SARIF policy findings."
            )
        return _normalize_mutation_audit(data, path)
    if report_type in {"ablation", "stress"}:
        if export_kind == "sarif":
            raise UnsupportedExportInput(
                f"{report_type} reports do not contain clean policy findings for SARIF."
            )
        return _normalize_diagnostic_summary(data, path, report_type)
    if report_type in {"replay", "metamorphic", "trace"}:
        message = (
            "Trace/replay inputs are not exported directly in this phase unless "
            "they contain run-style policy findings; replay/export a run report first."
        )
        raise UnsupportedExportInput(message)
    if strict:
        raise UnsupportedExportInput(
            "Unsupported input. Expected a run, suite, matrix, or supported "
            "diagnostic report JSON. Raw trace files are not supported."
        )
    raise UnsupportedExportInput("Unsupported report JSON.")


def _normalize_run(
    data: dict[str, Any],
    path: Path,
    source_type: str,
    *,
    include_passed: bool,
) -> ExportInputSummary:
    raw_checks = data.get("check_results")
    if not isinstance(raw_checks, list):
        raise UnsupportedExportInput("Run report is missing check_results.")
    repo_root = _repo_root_for_report(path)
    changed_paths = _changed_paths(data.get("diff_summary"), repo_root)
    report_path = _report_path(data, path)
    run_id = _run_id(data, path)
    task_id = _string_or_none(data.get("task_id"))
    agent = _string_or_none(data.get("agent")) or source_type
    findings = []
    cases = []
    for raw_check in raw_checks:
        if not isinstance(raw_check, dict):
            continue
        name = str(raw_check.get("name") or "AgentGuard check")
        passed = bool(raw_check.get("passed"))
        severity = str(raw_check.get("severity") or "error")
        message = str(raw_check.get("message") or name)
        evidence = _string_list(raw_check.get("evidence"))
        check_paths = _finding_paths(evidence, changed_paths, repo_root)
        if not passed or include_passed:
            findings.append(
                ExportFinding(
                    rule_id=_rule_id(name),
                    rule_name=name,
                    passed=passed,
                    severity=severity,
                    message=message,
                    evidence=evidence,
                    paths=check_paths,
                    report_path=report_path,
                    run_id=run_id,
                    task_id=task_id,
                    agent=agent,
                    source_type=source_type,
                    fingerprint_seed=name,
                )
            )
        cases.append(
            ExportTestCase(
                classname=f"agentguard.{source_type}.{agent}",
                name=f"{task_id or run_id or path.stem}::{name}",
                passed=passed,
                time_seconds=None,
                failure_message=None if passed else message,
                system_out=_system_out(
                    evidence=evidence,
                    report_path=report_path,
                    paths=check_paths,
                    metadata={
                        "run_id": run_id,
                        "task": task_id,
                        "agent": agent,
                        "severity": severity,
                    },
                ),
                report_path=report_path,
            )
        )
    return ExportInputSummary(
        input_path=path,
        input_type=source_type,
        reports=1,
        findings=findings,
        test_cases=cases,
        report_sources=[path],
    )


def _normalize_suite_or_matrix(
    data: dict[str, Any],
    path: Path,
    report_type: str,
    export_kind: str,
    *,
    include_passed: bool,
) -> ExportInputSummary:
    rows = data.get("runs")
    if not isinstance(rows, list):
        raise UnsupportedExportInput(f"{report_type} report is missing runs.")
    findings: list[ExportFinding] = []
    cases: list[ExportTestCase] = []
    report_sources = [path]
    reports = 1
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        child_path = _resolve_child_report(row.get("json_report_path"), path)
        if child_path is not None and child_path.is_file():
            try:
                child = _normalize_run(
                    _load_json(child_path),
                    child_path,
                    "run",
                    include_passed=include_passed,
                )
            except UnsupportedExportInput:
                child = None
            if child is not None:
                reports += child.reports
                report_sources.extend(child.report_sources)
                findings.extend(
                    _with_source_type(finding, report_type)
                    for finding in child.findings
                    if not finding.passed or include_passed
                )
                if export_kind == "junit":
                    cases.append(_row_test_case(row, path, report_type, index))
                continue
        if export_kind == "sarif":
            findings.extend(_row_findings(row, path, report_type, index))
        else:
            cases.append(_row_test_case(row, path, report_type, index))
    return ExportInputSummary(
        input_path=path,
        input_type=report_type,
        reports=reports,
        findings=findings,
        test_cases=cases,
        report_sources=report_sources,
    )


def _normalize_mutation_audit(
    data: dict[str, Any],
    path: Path,
) -> ExportInputSummary:
    cases = []
    for raw in data.get("mutations", []):
        if not isinstance(raw, dict):
            continue
        mutation_id = str(raw.get("id") or "mutation")
        passed = bool(raw.get("passed"))
        evidence = []
        for key in (
            "missed_detections",
            "forbidden_detections",
            "unexpected_detections",
            "warnings",
        ):
            evidence.extend(_string_list(raw.get(key)))
        cases.append(
            ExportTestCase(
                classname=f"agentguard.diagnostics.mutations.{raw.get('category', 'unknown')}",
                name=mutation_id,
                passed=passed,
                time_seconds=_float_or_none(raw.get("duration_seconds")),
                failure_message=None if passed else f"Mutation audit failed: {mutation_id}",
                system_out=_system_out(
                    evidence=evidence,
                    report_path=_safe_path(path),
                    paths=_string_list(raw.get("modified_files")),
                    metadata={
                        "class": _string_or_none(raw.get("mutation_class")),
                        "score": raw.get("score"),
                    },
                ),
                report_path=_safe_path(path),
            )
        )
    if not cases:
        raise UnsupportedExportInput("Mutation audit report has no mutation cases.")
    return ExportInputSummary(path, "mutation", 1, [], cases)


def _normalize_benchmark_summary(
    data: dict[str, Any],
    path: Path,
) -> ExportInputSummary:
    cases = []
    raw_agents = data.get("agents")
    if not isinstance(raw_agents, list):
        raise UnsupportedExportInput("Benchmark summary report is missing agents.")
    for index, row in enumerate(raw_agents):
        if not isinstance(row, dict):
            continue
        agent = str(row.get("agent") or f"agent-{index + 1}")
        passed = str(row.get("result") or "").upper() == "PASS"
        child = _resolve_child_report(row.get("json_report_path"), path)
        failed_checks = _string_list(row.get("failed_checks"))
        cases.append(
            ExportTestCase(
                classname=f"agentguard.benchmark.{agent}",
                name=f"{data.get('task_id', path.stem)}::{agent}",
                passed=passed,
                time_seconds=None,
                failure_message=(
                    None
                    if passed
                    else "Failed checks: " + (", ".join(failed_checks) or "unknown")
                ),
                system_out=_system_out(
                    evidence=failed_checks,
                    report_path=_safe_path(child or path),
                    paths=[],
                    metadata={
                        "task": data.get("task_id"),
                        "agent": agent,
                        "result": row.get("result"),
                        "score": row.get("score"),
                    },
                ),
                report_path=_safe_path(child or path),
            )
        )
    if not cases:
        raise UnsupportedExportInput("Benchmark summary report has no agent cases.")
    return ExportInputSummary(path, "benchmark", 1, [], cases)


def _normalize_diagnostic_summary(
    data: dict[str, Any],
    path: Path,
    report_type: str,
) -> ExportInputSummary:
    if report_type == "ablation":
        failed = bool(data.get("has_study_failures"))
        name = str(data.get("study_id") or path.stem)
        duration = _float_or_none(data.get("duration_seconds"))
    else:
        failed = not bool(data.get("integrity_passed", True))
        name = str(data.get("study_id") or path.stem)
        duration = _float_or_none(data.get("duration_seconds"))
    return ExportInputSummary(
        path,
        report_type,
        1,
        [],
        [
            ExportTestCase(
                classname=f"agentguard.diagnostics.{report_type}",
                name=name,
                passed=not failed,
                time_seconds=duration,
                failure_message=f"{report_type} diagnostic failed" if failed else None,
                system_out=_system_out(
                    evidence=[],
                    report_path=_safe_path(path),
                    paths=[],
                    metadata={"schema": data.get("schema")},
                ),
                report_path=_safe_path(path),
            )
        ],
    )


def _row_findings(
    row: dict[str, Any],
    report_path: Path,
    source_type: str,
    index: int,
) -> list[ExportFinding]:
    failed = _string_list(row.get("failed_checks"))
    warnings = set(_string_list(row.get("warning_checks")))
    evidence = _string_list(row.get("error"))
    diagnostic = _child_report_diagnostic(row.get("json_report_path"), report_path)
    if diagnostic is not None:
        evidence.append(diagnostic)
    findings = []
    for check in failed:
        severity = "warning" if check in warnings else "error"
        findings.append(
            ExportFinding(
                rule_id=_rule_id(check),
                rule_name=check,
                passed=False,
                severity=severity,
                message=f"{check} failed in {source_type} row.",
                evidence=evidence,
                paths=[],
                report_path=_safe_path(
                    _resolve_child_report(row.get("json_report_path"), report_path)
                    or report_path
                ),
                run_id=_string_or_none(row.get("execution_id")),
                task_id=_string_or_none(row.get("task_id")),
                agent=_string_or_none(row.get("agent")),
                source_type=source_type,
                fingerprint_seed=f"{source_type}|{check}",
            )
        )
    return findings


def _row_test_case(
    row: dict[str, Any],
    report_path: Path,
    source_type: str,
    index: int,
) -> ExportTestCase:
    task = str(row.get("task_id") or f"row-{index + 1}")
    agent = str(row.get("agent") or "unknown-agent")
    passed = str(row.get("result") or "").upper() == "PASS"
    child = _resolve_child_report(row.get("json_report_path"), report_path)
    failed_checks = _string_list(row.get("failed_checks"))
    error = _string_or_none(row.get("error"))
    evidence = [error] if error else failed_checks
    diagnostic = _child_report_diagnostic(row.get("json_report_path"), report_path)
    if diagnostic is not None:
        evidence.append(diagnostic)
    return ExportTestCase(
        classname=f"agentguard.{source_type}.{agent}",
        name=f"{task}::attempt-{row.get('trial_index', index + 1)}",
        passed=passed,
        time_seconds=None,
        failure_message=(
            None
            if passed
            else error or "Failed checks: " + (", ".join(failed_checks) or "unknown")
        ),
        system_out=_system_out(
            evidence=evidence,
            report_path=_safe_path(child or report_path),
            paths=[],
            metadata={
                "task": task,
                "agent": agent,
                "result": row.get("result"),
                "score": row.get("score"),
            },
        ),
        report_path=_safe_path(child or report_path),
    )


def _report_type(data: dict[str, Any], path: Path) -> str:
    schema = data.get("schema")
    if schema == "agentguard.mutation-audit":
        return "mutation"
    if schema == "agentguard.policy-ablation":
        return "ablation"
    if schema == "agentguard.matrix-stress":
        return "stress"
    if schema == "agentguard.trace-replay":
        return "replay"
    if schema == "agentguard.metamorphic-trace-study":
        return "metamorphic"
    if schema == "agentguard.execution-trace":
        return "trace"
    if "matrix_id" in data or path.name == "matrix.json":
        return "matrix"
    if "agents" in data and "total_agents" in data:
        return "benchmark"
    if "suite_id" in data and "average_score" in data:
        return "suite"
    if "check_results" in data and "diff_summary" in data:
        return "ci" if "agent" not in data else "run"
    return "unknown"


def _sarif_rule(
    rule_id: str,
    findings: list[ExportFinding],
) -> dict[str, Any]:
    first = findings[0]
    severity = _sarif_level(first.severity, first.passed)
    return {
        "id": rule_id,
        "name": first.rule_name,
        "shortDescription": {"text": first.rule_name},
        "fullDescription": {
            "text": f"AgentGuard policy check: {first.rule_name}."
        },
        "defaultConfiguration": {"level": severity},
        "properties": {
            "agentguardSeverity": first.severity,
            "tags": ["agentguard", "policy"],
        },
    }


def _sarif_result(finding: ExportFinding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity, finding.passed),
        "message": {"text": _result_message(finding)},
        "partialFingerprints": {
            "agentguardStableHash": _stable_hash(_fingerprint_material(finding))
        },
        "properties": {
            "agentguard": {
                "passed": finding.passed,
                "severity": finding.severity,
                "reportPath": finding.report_path,
                "runId": finding.run_id,
                "taskId": finding.task_id,
                "agent": finding.agent,
                "sourceType": finding.source_type,
                "evidence": [_bounded(_sanitize(item)) for item in finding.evidence][
                    :MAX_EVIDENCE_ITEMS
                ],
            }
        },
    }
    locations = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": _sarif_artifact_uri(path)},
                "region": {"startLine": 1},
            }
        }
        for path in finding.paths
    ]
    if locations:
        result["locations"] = locations
    if finding.passed:
        result["kind"] = "pass"
    return result


def _finding_sort_key(finding: ExportFinding) -> tuple[object, ...]:
    return (
        finding.rule_id,
        finding.task_id or "",
        finding.agent or "",
        tuple(sorted(finding.paths)),
        _fingerprint_material(finding),
    )


def _deduplicate_directory_sarif_findings(
    findings: list[ExportFinding],
) -> list[ExportFinding]:
    unique: dict[tuple[str, bool, str], ExportFinding] = {}
    for finding in findings:
        identity = _directory_sarif_finding_identity(finding)
        previous = unique.get(identity)
        if previous is None or _dedupe_preference_key(finding) < _dedupe_preference_key(
            previous
        ):
            unique[identity] = finding
    return sorted(unique.values(), key=_dedupe_preference_key)


def _unique_report_sources(sources: list[Path]) -> set[str]:
    unique = set()
    for source in sources:
        try:
            unique.add(source.expanduser().resolve().as_posix())
        except (OSError, RuntimeError):
            unique.add(source.expanduser().as_posix())
    return unique


def _directory_sarif_finding_identity(
    finding: ExportFinding,
) -> tuple[str, bool, str]:
    return (
        _fingerprint_material(finding),
        finding.passed,
        finding.severity.lower(),
    )


def _dedupe_preference_key(finding: ExportFinding) -> tuple[object, ...]:
    source_rank = {"suite": 0, "matrix": 1, "run": 2, "ci": 3}.get(
        finding.source_type,
        4,
    )
    return (
        _finding_sort_key(finding),
        source_rank,
        finding.source_type,
        finding.report_path or "",
        finding.run_id or "",
    )


def _fingerprint_material(finding: ExportFinding) -> str:
    material = {
        "version": 1,
        "rule_id": finding.rule_id,
        "task_id": finding.task_id or "",
        "agent": finding.agent or "",
        "locations": sorted(finding.paths),
        "evidence": _semantic_evidence(finding.evidence),
    }
    return json.dumps(material, sort_keys=True, separators=(",", ":"))


def _semantic_evidence(evidence: list[str]) -> list[str]:
    stable = []
    for item in evidence[:MAX_EVIDENCE_ITEMS]:
        normalized = _sanitize(item)
        normalized = " ".join(normalized.split())
        stable.append(_bounded(normalized))
    return sorted(stable)


def _group_rules(findings: list[ExportFinding]) -> list[tuple[str, list[ExportFinding]]]:
    grouped: dict[str, list[ExportFinding]] = {}
    for finding in findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return [(rule_id, grouped[rule_id]) for rule_id in sorted(grouped)]


def _result_message(finding: ExportFinding) -> str:
    state = "passed" if finding.passed else "failed"
    parts = [f"{finding.rule_name} {state}: {_sanitize(finding.message)}"]
    if finding.evidence:
        parts.append("Evidence: " + _bounded(_sanitize(finding.evidence[0])))
    if not finding.paths:
        parts.append("No file location was available in the report evidence.")
    return _bounded(" ".join(parts), 800)


def _sarif_level(severity: str, passed: bool) -> str:
    if passed:
        return "note"
    normalized = severity.lower()
    if normalized in {"critical", "error"}:
        return "error"
    if normalized == "warning":
        return "warning"
    return "note"


def _rule_id(name: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip().lower()).strip("-")
    return normalized or "agentguard-check"


def _changed_paths(value: Any, repo_root: Optional[Path]) -> list[str]:
    if not isinstance(value, dict):
        return []
    paths: list[str] = []
    for key in ("modified_files", "added_files", "deleted_files"):
        paths.extend(_string_list(value.get(key)))
    return [
        normalized
        for path in paths
        if (normalized := _normalize_repo_path(path, repo_root)) is not None
    ]


def _finding_paths(
    evidence: list[str],
    changed_paths: list[str],
    repo_root: Optional[Path],
) -> list[str]:
    paths = []
    for item in evidence:
        paths.extend(_extract_paths(item))
    paths.extend(changed_paths)
    unique = []
    for path in paths:
        normalized = _normalize_repo_path(path, repo_root)
        if normalized and normalized not in unique:
            unique.append(normalized)
    return unique[:5]


def _extract_paths(text: str) -> list[str]:
    candidates = []
    for match in re.finditer(r"(?<![^\s,;:'\")\]}])([^\s,;:'\")\]}]+)", text):
        candidate = match.group(1).strip("`'\"")
        if "/" not in candidate and "\\" not in candidate:
            continue
        if not re.search(r"\.[A-Za-z0-9]{1,8}$", candidate):
            continue
        candidates.append(candidate)
    return candidates


def _normalize_repo_path(path: str, repo_root: Optional[Path] = None) -> Optional[str]:
    if not path:
        return None
    cleaned = path.replace("\\", "/").strip().strip("`'\"")
    if (
        not cleaned
        or WINDOWS_DRIVE_PATH_PATTERN.match(cleaned)
        or cleaned.startswith("//")
        or URI_SCHEME_PATTERN.match(cleaned)
    ):
        return None
    pure = PurePosixPath(cleaned)
    parts = [part for part in pure.parts if part not in {"", ".", "/"}]
    if ".." in parts or not parts:
        return None
    if repo_root is None:
        if pure.is_absolute():
            return None
        return PurePosixPath(*parts).as_posix()
    try:
        root = repo_root.expanduser().resolve()
        candidate_path = Path(cleaned).expanduser()
        if not candidate_path.is_absolute():
            candidate_path = root.joinpath(*parts)
        candidate = candidate_path.resolve(strict=False)
        relative = candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    if ".." in relative.parts or not relative.parts:
        return None
    return PurePosixPath(*relative.parts).as_posix()


def _repo_root_for_report(path: Path) -> Optional[Path]:
    try:
        resolved = path.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return None
    for ancestor in resolved.parents:
        if ancestor.name == ".agentguard":
            return ancestor.parent
    return None


def _sarif_artifact_uri(path: str) -> str:
    return quote(path, safe="/")


def _sanitize(value: object) -> str:
    text = "" if value is None else str(value)
    text = SECRET_PATTERNS[0].sub(_redact_keyed_secret, text)
    for pattern in SECRET_PATTERNS[1:]:
        text = pattern.sub("<redacted>", text)
    text = URI_PATH_PATTERN.sub("<path>", text)
    text = UNC_PATH_PATTERN.sub("<path>", text)
    text = TRAVERSAL_PATH_PATTERN.sub("<path>", text)
    text = BACKSLASH_PATH_PATTERN.sub("<path>", text)
    text = ABSOLUTE_PATH_PATTERN.sub("<path>", text)
    return text.replace("\x00", "")


def _redact_keyed_secret(match: re.Match[str]) -> str:
    raw = match.group(0)
    separator = "=" if "=" in raw else ":"
    key = raw.split(separator, 1)[0].strip()
    return f"{key}{separator}<redacted>"


def _junit_xml_text(value: object) -> str:
    text = "" if value is None else str(value)
    if not text:
        return ""
    return "".join(
        char if _is_xml_10_char(ord(char)) else XML_ILLEGAL_REPLACEMENT
        for char in text
    )


def _is_xml_10_char(codepoint: int) -> bool:
    return (
        codepoint in {0x09, 0x0A, 0x0D}
        or 0x20 <= codepoint <= 0xD7FF
        or 0xE000 <= codepoint <= 0xFFFD
        or 0x10000 <= codepoint <= 0x10FFFF
    )


def _bounded(value: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 15].rstrip() + "... [truncated]"


def _system_out(
    *,
    evidence: list[str],
    report_path: Optional[str],
    paths: list[str],
    metadata: dict[str, object],
) -> str:
    lines = []
    for key in sorted(metadata):
        value = metadata[key]
        if value is not None:
            lines.append(f"{key}: {_sanitize(value)}")
    if report_path:
        lines.append(f"report: {_sanitize(report_path)}")
    if paths:
        lines.append("paths: " + ", ".join(_normalize_repo_path(path) or path for path in paths))
    if evidence:
        lines.append("evidence:")
        lines.extend(f"- {_bounded(_sanitize(item))}" for item in evidence[:MAX_EVIDENCE_ITEMS])
    return _bounded("\n".join(lines), MAX_SYSTEM_OUT_CHARS)


def _report_path(data: dict[str, Any], path: Path) -> str:
    report_paths = data.get("report_paths")
    if isinstance(report_paths, dict):
        value = report_paths.get("json")
        if value is not None:
            return _safe_path(Path(str(value)))
    value = data.get("json_report_path")
    if value is not None:
        return _safe_path(Path(str(value)))
    return _safe_path(path)


def _run_id(data: dict[str, Any], path: Path) -> Optional[str]:
    value = data.get("execution_id")
    if value is not None:
        return str(value)
    if path.parent.name == "reports":
        return path.parent.parent.name
    return path.parent.name


def _resolve_child_report(value: Any, parent_report: Path) -> Optional[Path]:
    if not isinstance(value, str) or not value:
        return None
    path = Path(value).expanduser()
    trusted_root = _trusted_report_root(parent_report)
    candidates = (
        [path]
        if path.is_absolute()
        else [parent_report.parent / path, Path.cwd() / path]
    )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(trusted_root)
        except (OSError, RuntimeError, ValueError):
            continue
        if resolved.is_file():
            return resolved
    return None


def _trusted_report_root(parent_report: Path) -> Path:
    resolved = parent_report.expanduser().resolve()
    for ancestor in resolved.parents:
        if ancestor.name == ".agentguard":
            return ancestor
    return resolved.parent


def _child_report_diagnostic(value: Any, parent_report: Path) -> Optional[str]:
    if (
        isinstance(value, str)
        and value
        and _resolve_child_report(value, parent_report) is None
    ):
        return "Child report unavailable or outside the trusted report tree."
    return None


def _safe_path(path: Path) -> str:
    expanded = path.expanduser()
    try:
        return expanded.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return _sanitize(expanded.as_posix())


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return []


def _string_or_none(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _float_or_none(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _with_source_type(finding: ExportFinding, source_type: str) -> ExportFinding:
    return ExportFinding(
        rule_id=finding.rule_id,
        rule_name=finding.rule_name,
        passed=finding.passed,
        severity=finding.severity,
        message=finding.message,
        evidence=finding.evidence,
        paths=finding.paths,
        report_path=finding.report_path,
        run_id=finding.run_id,
        task_id=finding.task_id,
        agent=finding.agent,
        source_type=source_type,
        fingerprint_seed=finding.fingerprint_seed,
    )


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _base_uri(value: str) -> str:
    return value if value.endswith("/") else value + "/"


def _format_time(value: float) -> str:
    return f"{value:.6f}".rstrip("0").rstrip(".") or "0"


def _default_suite_name(summary: ExportInputSummary) -> str:
    if summary.input_type == "directory":
        return f"AgentGuard reports: {summary.input_path.name}"
    return f"AgentGuard {summary.input_type}: {summary.input_path.stem}"


def _load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as error:
        raise UnsupportedExportInput(f"Invalid JSON: {error}") from error


def _write_output_json(path: Path, data: dict[str, Any], *, force: bool) -> None:
    output = path.expanduser()
    if output.exists() and not force:
        raise FileExistsError(f"Output already exists: {output}. Use --force.")
    atomic_write_json(output, data, sort_keys=False)


def _write_output_text(path: Path, content: str, *, force: bool) -> None:
    output = path.expanduser()
    if output.exists() and not force:
        raise FileExistsError(f"Output already exists: {output}. Use --force.")
    atomic_write_text(output, content)
