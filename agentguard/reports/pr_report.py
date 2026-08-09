from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from agentguard.checks.registry import resolve_check_registration
from agentguard.core.result import CheckResult, CiResult
from agentguard.io import atomic_write_json
from agentguard.provenance.manifest import sanitize_text
from agentguard.reports.markdown import markdown_inline_code, markdown_text


PR_REPORT_SCHEMA = "agentguard.pr-report"
PR_REPORT_VERSION = 1
MAX_BASELINE_BYTES = 5_000_000
MAX_FINDINGS = 1_000
MAX_SUMMARY_FINDINGS = 20
MAX_ANNOTATIONS = 10
MAX_FIELD_CHARS = 500
_LOCATION_PATTERN = re.compile(r"^(?P<path>.+?):(?P<line>[1-9][0-9]*) matched ")


@dataclass(frozen=True)
class PrFinding:
    id: str
    rule_id: str
    rule_name: str
    severity: str
    message: str
    evidence: str
    state: str = "new"
    path: Optional[str] = None
    line: Optional[int] = None


@dataclass(frozen=True)
class BaselineState:
    status: str
    source: Optional[str] = None
    sha256: Optional[str] = None
    diagnostic: Optional[str] = None


@dataclass(frozen=True)
class PrReport:
    schema: str
    schema_version: int
    task_id: str
    result: str
    score: int
    gate: str
    baseline: BaselineState
    counts: dict[str, int]
    findings: list[PrFinding] = field(default_factory=list)
    resolved: list[PrFinding] = field(default_factory=list)


def _bounded(value: Any, limit: int = MAX_FIELD_CHARS) -> str:
    text = sanitize_text(str(value), [])
    text = "\\n".join(text.splitlines())
    if len(text) <= limit:
        return text
    return text[: limit - len("...[truncated]")] + "...[truncated]"


def _rule_id(name: str) -> str:
    try:
        return resolve_check_registration(name).identifier
    except ValueError:
        normalized = "-".join(name.strip().lower().replace("_", "-").split())
        return normalized or "unknown-check"


def _safe_relative_path(raw: str) -> Optional[str]:
    if not raw or any(ord(character) < 32 or ord(character) == 127 for character in raw):
        return None
    path = PurePosixPath(raw.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        return None
    normalized = path.as_posix()
    return normalized if normalized not in {"", "."} else None


def _location(check: CheckResult, evidence: str) -> tuple[Optional[str], Optional[int], str]:
    rule_id = _rule_id(check.name)
    raw_path: Optional[str] = None
    line: Optional[int] = None
    identity_evidence = evidence
    if rule_id in {"forbidden-paths", "test-tampering"}:
        raw_path = evidence
    elif rule_id == "scope-adherence" and evidence.startswith("Outside allowed paths: "):
        raw_path = evidence.removeprefix("Outside allowed paths: ")
    elif rule_id == "secret-scan":
        match = _LOCATION_PATTERN.match(evidence)
        if match:
            raw_path = match.group("path")
            line = int(match.group("line"))
            identity_evidence = evidence[match.end("line") :]
        elif " matched pattern " in evidence:
            raw_path, identity_evidence = evidence.split(" matched pattern ", 1)
            identity_evidence = " matched pattern " + identity_evidence
    return _safe_relative_path(raw_path or ""), line, identity_evidence


def _finding_id(rule_id: str, path: Optional[str], identity_evidence: str) -> str:
    canonical = json.dumps(
        [PR_REPORT_VERSION, rule_id, path or "", _bounded(identity_evidence)],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def findings_from_checks(checks: list[CheckResult]) -> list[PrFinding]:
    findings: dict[str, PrFinding] = {}
    for check in checks:
        if check.passed:
            continue
        evidence_items = check.evidence or [check.message]
        for evidence_value in evidence_items:
            evidence = _bounded(evidence_value)
            path, line, identity_evidence = _location(check, evidence)
            rule_id = _rule_id(check.name)
            finding_id = _finding_id(rule_id, path, identity_evidence)
            candidate = PrFinding(
                id=finding_id,
                rule_id=rule_id,
                rule_name=_bounded(check.name),
                severity=_bounded(check.severity, 32),
                message=_bounded(check.message),
                evidence=evidence,
                path=path,
                line=line,
            )
            previous = findings.get(finding_id)
            if previous is not None:
                comparable_previous = asdict(previous)
                comparable_candidate = asdict(candidate)
                comparable_previous.pop("line")
                comparable_candidate.pop("line")
                comparable_previous.pop("evidence")
                comparable_candidate.pop("evidence")
                if comparable_previous != comparable_candidate:
                    raise ValueError(f"Finding identity collision for {finding_id}.")
                if candidate.line is not None and (
                    previous.line is None or candidate.line < previous.line
                ):
                    findings[finding_id] = candidate
            else:
                findings[finding_id] = candidate
            if len(findings) > MAX_FINDINGS:
                raise ValueError(f"Current report exceeds the {MAX_FINDINGS}-finding limit.")
    return sorted(findings.values(), key=lambda item: item.id)


def _validated_finding(data: Any) -> PrFinding:
    if not isinstance(data, dict):
        raise ValueError("Baseline finding must be an object.")
    finding_id = data.get("id")
    if not isinstance(finding_id, str) or not re.fullmatch(r"[0-9a-f]{64}", finding_id):
        raise ValueError("Baseline finding has an invalid id.")
    path = data.get("path")
    if path is not None and _safe_relative_path(path) != path:
        raise ValueError("Baseline finding has an unsafe path.")
    line = data.get("line")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        raise ValueError("Baseline finding has an invalid line.")
    finding = PrFinding(
        id=finding_id,
        rule_id=_bounded(data.get("rule_id", "")),
        rule_name=_bounded(data.get("rule_name", "")),
        severity=_bounded(data.get("severity", ""), 32),
        message=_bounded(data.get("message", "")),
        evidence=_bounded(data.get("evidence", "")),
        state="existing",
        path=path,
        line=line,
    )
    derived_path, derived_line, identity_evidence = _location(
        CheckResult(
            name=finding.rule_name,
            passed=False,
            severity=finding.severity,
            message=finding.message,
            evidence=[finding.evidence],
        ),
        finding.evidence,
    )
    if derived_path != finding.path or derived_line != finding.line:
        raise ValueError("Baseline finding location does not match its evidence.")
    if _finding_id(finding.rule_id, finding.path, identity_evidence) != finding.id:
        raise ValueError("Baseline finding id does not match its content.")
    return finding


def _checks_from_ci_report(data: dict[str, Any]) -> tuple[str, list[CheckResult]]:
    task_id = data.get("task_id")
    raw_checks = data.get("check_results")
    if not isinstance(task_id, str) or not isinstance(raw_checks, list):
        raise ValueError("Baseline is not an AgentGuard CI report.")
    checks: list[CheckResult] = []
    for raw in raw_checks:
        if not isinstance(raw, dict):
            raise ValueError("Baseline check result must be an object.")
        try:
            passed = raw["passed"]
            if not isinstance(passed, bool):
                raise TypeError
            raw_evidence = raw.get("evidence", [])
            if not isinstance(raw_evidence, list) or not all(
                isinstance(item, str) for item in raw_evidence
            ):
                raise TypeError
            checks.append(
                CheckResult(
                    name=str(raw["name"]),
                    passed=passed,
                    severity=str(raw["severity"]),
                    message=str(raw["message"]),
                    evidence=raw_evidence,
                )
            )
        except (KeyError, TypeError) as error:
            raise ValueError("Baseline check result is invalid.") from error
    return task_id, findings_from_checks(checks)


def _load_baseline(path: Optional[Path], task_id: str) -> tuple[BaselineState, list[PrFinding]]:
    if path is None:
        return BaselineState(status="unavailable", diagnostic="No baseline report was provided."), []
    source = path.expanduser()
    safe_source = source.name
    try:
        size = source.stat().st_size
        if size > MAX_BASELINE_BYTES:
            raise ValueError(f"Baseline exceeds the {MAX_BASELINE_BYTES}-byte limit.")
        raw = source.read_bytes()
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Baseline must be a JSON object.")
        if data.get("schema") == PR_REPORT_SCHEMA:
            if data.get("schema_version") != PR_REPORT_VERSION:
                raise ValueError(f"Baseline schema_version must be {PR_REPORT_VERSION}.")
            baseline_task = data.get("task_id")
            raw_findings = data.get("findings")
            if not isinstance(baseline_task, str) or not isinstance(raw_findings, list):
                raise ValueError("Baseline PR report is incomplete.")
            findings = [_validated_finding(item) for item in raw_findings]
        else:
            baseline_task, findings = _checks_from_ci_report(data)
        if baseline_task != task_id:
            raise ValueError("Baseline task_id does not match the current CI task.")
        if len(findings) > MAX_FINDINGS:
            raise ValueError(f"Baseline exceeds the {MAX_FINDINGS}-finding limit.")
        if len({finding.id for finding in findings}) != len(findings):
            raise ValueError("Baseline contains duplicate finding ids.")
        return (
            BaselineState(
                status="available",
                source=safe_source,
                sha256=hashlib.sha256(raw).hexdigest(),
            ),
            findings,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        diagnostic = _bounded(error)
        for candidate in {str(source), str(source.absolute())}:
            diagnostic = diagnostic.replace(candidate, safe_source)
        return BaselineState(
            status="invalid",
            source=safe_source,
            diagnostic=diagnostic,
        ), []


def build_pr_report(result: CiResult, baseline_path: Optional[Path] = None) -> PrReport:
    current = findings_from_checks(result.check_results)
    baseline, previous = _load_baseline(baseline_path, result.task_id)
    previous_by_id = {finding.id: finding for finding in previous}
    current_ids = {finding.id for finding in current}
    classified = [
        PrFinding(
            **{
                **asdict(finding),
                "state": (
                    "existing" if finding.id in previous_by_id else "new"
                )
                if baseline.status == "available"
                else "unclassified",
            }
        )
        for finding in current
    ]
    resolved = [
        PrFinding(**{**asdict(finding), "state": "resolved"})
        for finding in previous
        if finding.id not in current_ids
    ] if baseline.status == "available" else []
    counts = {
        "new": sum(item.state == "new" for item in classified),
        "existing": sum(item.state == "existing" for item in classified),
        "resolved": len(resolved),
        "unclassified": sum(item.state == "unclassified" for item in classified),
        "total": len(classified),
    }
    return PrReport(
        schema=PR_REPORT_SCHEMA,
        schema_version=PR_REPORT_VERSION,
        task_id=result.task_id,
        result=result.result,
        score=result.score,
        gate="all-blocking-findings",
        baseline=baseline,
        counts=counts,
        findings=classified,
        resolved=sorted(resolved, key=lambda item: item.id),
    )


def write_pr_report(report: PrReport, path: Path) -> Path:
    atomic_write_json(path.expanduser(), asdict(report))
    return path.expanduser()


def _finding_line(finding: PrFinding) -> str:
    location = f" ({markdown_inline_code(finding.path)})" if finding.path else ""
    return (
        f"- [{markdown_text(finding.severity)}] {markdown_text(finding.rule_name)}"
        f"{location}: {markdown_text(finding.message)}"
    )


def append_pr_summary(report: PrReport, summary_path: Path) -> Path:
    lines = [
        "## AgentGuard baseline comparison",
        "",
        f"- Baseline: **{markdown_text(report.baseline.status)}**",
        f"- New: **{report.counts['new']}**",
        f"- Existing: **{report.counts['existing']}**",
        f"- Resolved: **{report.counts['resolved']}**",
        f"- Unclassified: **{report.counts['unclassified']}**",
        "- Gate: all current blocking findings (baseline classification does not waive policy)",
    ]
    if report.baseline.diagnostic:
        lines.append(f"- Baseline detail: {markdown_text(report.baseline.diagnostic)}")
    for state, title in (("new", "New findings"), ("existing", "Existing findings")):
        selected = [item for item in report.findings if item.state == state]
        lines.extend(["", f"### {title}"])
        lines.extend(_finding_line(item) for item in selected[:MAX_SUMMARY_FINDINGS])
        if not selected:
            lines.append("- None")
        elif len(selected) > MAX_SUMMARY_FINDINGS:
            lines.append(f"- ...and {len(selected) - MAX_SUMMARY_FINDINGS} more")
    unclassified = [item for item in report.findings if item.state == "unclassified"]
    lines.extend(["", "### Unclassified current findings"])
    lines.extend(_finding_line(item) for item in unclassified[:MAX_SUMMARY_FINDINGS])
    if not unclassified:
        lines.append("- None")
    elif len(unclassified) > MAX_SUMMARY_FINDINGS:
        lines.append(f"- ...and {len(unclassified) - MAX_SUMMARY_FINDINGS} more")
    lines.extend(["", "### Resolved findings"])
    lines.extend(_finding_line(item) for item in report.resolved[:MAX_SUMMARY_FINDINGS])
    if not report.resolved:
        lines.append("- None")
    elif len(report.resolved) > MAX_SUMMARY_FINDINGS:
        lines.append(f"- ...and {len(report.resolved) - MAX_SUMMARY_FINDINGS} more")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
    return summary_path


def _safe_annotation_location(repo_dir: Path, finding: PrFinding) -> Optional[tuple[str, int]]:
    if finding.path is None or finding.line is None:
        return None
    relative = _safe_relative_path(finding.path)
    if relative is None:
        return None
    target = repo_dir.joinpath(*PurePosixPath(relative).parts)
    current = repo_dir
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            return None
    try:
        root = repo_dir.resolve(strict=True)
        resolved = target.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file():
            return None
        line_count = sum(1 for _ in resolved.open("rb"))
    except (OSError, ValueError):
        return None
    if finding.line > line_count:
        return None
    return relative, finding.line


def _workflow_escape(value: str, *, property_value: bool = False) -> str:
    escaped = _bounded(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        escaped = escaped.replace(":", "%3A").replace(",", "%2C")
    return escaped


def github_annotations(report: PrReport, repo_dir: Path) -> list[str]:
    annotations: list[str] = []
    seen: set[tuple[str, int, str]] = set()
    for finding in report.findings:
        if finding.state != "new":
            continue
        location = _safe_annotation_location(repo_dir, finding)
        if location is None:
            continue
        path, line = location
        key = (path, line, finding.rule_id)
        if key in seen:
            continue
        seen.add(key)
        level = "warning" if finding.severity == "warning" else "error"
        title = _workflow_escape(f"AgentGuard: {finding.rule_name}", property_value=True)
        message = _workflow_escape(finding.message)
        annotations.append(
            f"::{level} file={_workflow_escape(path, property_value=True)},"
            f"line={line},title={title}::{message}"
        )
        if len(annotations) >= MAX_ANNOTATIONS:
            break
    return annotations
