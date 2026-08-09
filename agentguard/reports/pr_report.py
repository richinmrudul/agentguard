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
from agentguard.reports.markdown import markdown_inline_code, markdown_text


PR_REPORT_SCHEMA = "agentguard.pr-report"
PR_REPORT_VERSION = 1
MAX_BASELINE_BYTES = 5_000_000
MAX_FINDINGS = 1_000
MAX_SUMMARY_FINDINGS = 20
MAX_ANNOTATIONS = 10
MAX_FIELD_CHARS = 500
MAX_PATH_CHARS = 500
MAX_PATH_BYTES = 500
MAX_PATH_COMPONENT_CHARS = 255
MAX_ANNOTATION_FILE_BYTES = 1_000_000
MAX_ANNOTATION_LINE = 10_000
MAX_ANNOTATION_LINE_BYTES = 16_384
_HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_RULE_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_LOCATION_PATTERN = re.compile(r"^(?P<path>.+?):(?P<line>[1-9][0-9]*) matched ")
_EXIT_PATTERN = re.compile(r" exited (?P<exit>-?[0-9]+)$")
_UNSAFE_STATUS_PATTERN = re.compile(r" \((?P<status>preflight blocked|blocked|audit|executed|simulated)\)$")
_KNOWN_SEVERITIES = {"warning", "error", "critical"}
_PR_REPORT_FIELDS = {
    "schema",
    "schema_version",
    "task_id",
    "result",
    "score",
    "gate",
    "baseline",
    "counts",
    "findings",
    "resolved",
}
_FINDING_FIELDS = {
    "id",
    "fingerprint",
    "rule_id",
    "rule_name",
    "severity",
    "message",
    "evidence",
    "state",
    "path",
    "line",
}


@dataclass(frozen=True)
class PrFinding:
    id: str
    fingerprint: str
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


@dataclass(frozen=True)
class _SafeEvidence:
    message: str
    display: str
    semantic: dict[str, Any]
    path: Optional[str] = None
    line: Optional[int] = None


def _display_text(value: str, limit: int = MAX_FIELD_CHARS) -> str:
    text = "\\n".join(value.splitlines())
    if len(text) <= limit:
        return text
    suffix = "...[truncated]"
    return text[: limit - len(suffix)] + suffix


def _safe_diagnostic(value: object) -> str:
    return _display_text(str(value))


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _rule_metadata(name: str) -> tuple[str, str]:
    try:
        registration = resolve_check_registration(name)
        return registration.identifier, registration.name
    except ValueError:
        return f"custom-{_sha256_text(name)[:16]}", "Custom check"


def _baseline_rule_name(rule_id: str) -> str:
    try:
        registration = resolve_check_registration(rule_id)
        if registration.identifier == rule_id:
            return registration.name
    except ValueError:
        pass
    return "Custom check"


def _safe_relative_path(raw: object) -> Optional[str]:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_PATH_CHARS:
        return None
    try:
        if len(raw.encode("utf-8")) > MAX_PATH_BYTES:
            return None
    except UnicodeEncodeError:
        return None
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        return None
    path = PurePosixPath(raw.replace("\\", "/"))
    if (
        path.is_absolute()
        or ".." in path.parts
        or any(len(part) > MAX_PATH_COMPONENT_CHARS for part in path.parts)
    ):
        return None
    normalized = path.as_posix()
    return normalized if normalized not in {"", "."} else None


def _path_evidence(
    evidence: str,
    *,
    message: str,
    display: str,
    semantic_type: str,
) -> _SafeEvidence:
    path = _safe_relative_path(evidence)
    if path is None:
        return _opaque_evidence(evidence, message=message)
    return _SafeEvidence(
        message=message,
        display=display,
        semantic={"type": semantic_type, "path": path},
        path=path,
    )


def _opaque_evidence(value: str, *, message: str) -> _SafeEvidence:
    digest = _sha256_text(value)
    return _SafeEvidence(
        message=message,
        display="Detailed evidence omitted; fingerprint recorded.",
        semantic={"type": "opaque", "sha256": digest},
    )


def _safe_evidence(rule_id: str, evidence: str) -> _SafeEvidence:
    if rule_id == "tests-passed":
        match = _EXIT_PATTERN.search(evidence)
        if match:
            exit_code = int(match.group("exit"))
            return _SafeEvidence(
                message="Configured test command failed.",
                display=f"Configured test command exited with code {exit_code}.",
                semantic={"type": "test-exit", "exit_code": exit_code},
            )
        return _opaque_evidence(
            evidence,
            message="Configured test command failed; command evidence omitted.",
        )
    if rule_id == "unsafe-commands":
        match = _UNSAFE_STATUS_PATTERN.search(evidence)
        status = match.group("status") if match else "observed"
        return _SafeEvidence(
            message="Unsafe command policy matched.",
            display=f"Unsafe command policy matched ({status}); command omitted.",
            semantic={
                "type": "unsafe-command",
                "status": status,
                "evidence_sha256": _sha256_text(evidence),
            },
        )
    if rule_id == "forbidden-paths":
        return _path_evidence(
            evidence,
            message="A forbidden repository path was modified.",
            display="Repository path matched the forbidden-path policy.",
            semantic_type="forbidden-path",
        )
    if rule_id == "test-tampering":
        return _path_evidence(
            evidence,
            message="A configured test path was modified.",
            display="Repository path matched the test-path policy.",
            semantic_type="test-path",
        )
    if rule_id == "scope-adherence" and evidence.startswith(
        "Outside allowed paths: "
    ):
        return _path_evidence(
            evidence.removeprefix("Outside allowed paths: "),
            message="A changed path was outside the configured scope.",
            display="Repository path was outside the configured scope.",
            semantic_type="outside-scope",
        )
    if rule_id == "secret-scan":
        match = _LOCATION_PATTERN.match(evidence)
        if match:
            path = _safe_relative_path(match.group("path"))
            line = int(match.group("line"))
            if path is not None:
                return _SafeEvidence(
                    message="Added content matched a secret detector.",
                    display="Repository content matched a secret detector.",
                    semantic={
                        "type": "secret-content",
                        "path": path,
                        "detector_sha256": _sha256_text(evidence[match.end() :]),
                    },
                    path=path,
                    line=line,
                )
        if " matched pattern " in evidence:
            raw_path, pattern = evidence.split(" matched pattern ", 1)
            path = _safe_relative_path(raw_path)
            if path is not None:
                return _SafeEvidence(
                    message="A repository path matched a secret-path policy.",
                    display="Repository path matched a secret-path policy.",
                    semantic={
                        "type": "secret-path",
                        "path": path,
                        "pattern_sha256": _sha256_text(pattern),
                    },
                    path=path,
                )
        return _opaque_evidence(
            evidence,
            message="Secret-scan evidence was recorded without raw payloads.",
        )
    if rule_id == "diff-size" and re.fullmatch(
        r"(?:Changed|Added|Deleted) [0-9]+ (?:files|lines); limit is [0-9]+\.",
        evidence,
    ):
        return _SafeEvidence(
            message="The repository diff exceeded a configured size limit.",
            display=evidence,
            semantic={"type": "diff-limit", "value": evidence},
        )
    return _opaque_evidence(
        evidence,
        message="A policy finding was recorded without raw evidence.",
    )


def _semantic_fingerprint(semantic: dict[str, Any]) -> str:
    canonical = json.dumps(
        semantic,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_text(canonical)


def _finding_id(rule_id: str, path: Optional[str], fingerprint: str) -> str:
    canonical = json.dumps(
        [PR_REPORT_VERSION, rule_id, path or "", fingerprint],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return _sha256_text(canonical)


def findings_from_checks(checks: list[CheckResult]) -> list[PrFinding]:
    findings: dict[str, PrFinding] = {}
    for check in checks:
        if check.passed:
            continue
        rule_id, rule_name = _rule_metadata(check.name)
        severity = check.severity if check.severity in _KNOWN_SEVERITIES else "error"
        evidence_items = check.evidence or [check.message]
        for raw_evidence in evidence_items:
            safe = _safe_evidence(rule_id, raw_evidence)
            fingerprint = _semantic_fingerprint(safe.semantic)
            finding_id = _finding_id(rule_id, safe.path, fingerprint)
            candidate = PrFinding(
                id=finding_id,
                fingerprint=fingerprint,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                message=safe.message,
                evidence=safe.display,
                path=safe.path,
                line=safe.line,
            )
            previous = findings.get(finding_id)
            if previous is not None:
                comparable_previous = asdict(previous)
                comparable_candidate = asdict(candidate)
                comparable_previous.pop("line")
                comparable_candidate.pop("line")
                if comparable_previous != comparable_candidate:
                    raise ValueError(f"Finding identity collision for {finding_id}.")
                if candidate.line is not None and (
                    previous.line is None or candidate.line < previous.line
                ):
                    findings[finding_id] = candidate
            else:
                findings[finding_id] = candidate
            if len(findings) > MAX_FINDINGS:
                raise ValueError(
                    f"Current report exceeds the {MAX_FINDINGS}-finding limit."
                )
    return sorted(findings.values(), key=lambda item: item.id)


def _required_string(
    data: dict[str, Any],
    field_name: str,
    *,
    max_length: int = MAX_FIELD_CHARS,
) -> str:
    value = data.get(field_name)
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"Baseline field '{field_name}' must be a bounded string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"Baseline field '{field_name}' contains control characters.")
    return value


def _optional_string(data: dict[str, Any], field_name: str) -> Optional[str]:
    value = data.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > MAX_FIELD_CHARS:
        raise ValueError(f"Baseline field '{field_name}' must be null or a string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"Baseline field '{field_name}' contains control characters.")
    return value


def _validated_finding(data: Any) -> PrFinding:
    if not isinstance(data, dict) or set(data) != _FINDING_FIELDS:
        raise ValueError("Baseline finding has missing or unknown fields.")
    finding_id = _required_string(data, "id", max_length=64)
    fingerprint = _required_string(data, "fingerprint", max_length=64)
    if _HASH_PATTERN.fullmatch(finding_id) is None:
        raise ValueError("Baseline finding has an invalid id.")
    if _HASH_PATTERN.fullmatch(fingerprint) is None:
        raise ValueError("Baseline finding has an invalid fingerprint.")
    rule_id = _required_string(data, "rule_id")
    if _RULE_ID_PATTERN.fullmatch(rule_id) is None:
        raise ValueError("Baseline finding has an invalid rule_id.")
    _required_string(data, "rule_name")
    severity = _required_string(data, "severity", max_length=32)
    if severity not in _KNOWN_SEVERITIES:
        raise ValueError("Baseline finding has an invalid severity.")
    _required_string(data, "message")
    _required_string(data, "evidence")
    state = _required_string(data, "state", max_length=32)
    if state not in {"new", "existing", "unclassified", "resolved"}:
        raise ValueError("Baseline finding has an invalid state.")
    raw_path = data.get("path")
    path = _safe_relative_path(raw_path) if raw_path is not None else None
    if raw_path is not None and path != raw_path:
        raise ValueError("Baseline finding has an unsafe path.")
    line = data.get("line")
    if line is not None and (
        not isinstance(line, int)
        or isinstance(line, bool)
        or not 1 <= line <= MAX_ANNOTATION_LINE
    ):
        raise ValueError("Baseline finding has an invalid line.")
    if _finding_id(rule_id, path, fingerprint) != finding_id:
        raise ValueError("Baseline finding id does not match its content.")
    rule_name = _baseline_rule_name(rule_id)
    return PrFinding(
        id=finding_id,
        fingerprint=fingerprint,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        message="Previously reported AgentGuard finding.",
        evidence="Baseline evidence omitted; fingerprint retained.",
        state=state,
        path=path,
        line=line,
    )


def _validated_counts(data: Any, findings: list[PrFinding], resolved: list[PrFinding]) -> None:
    expected_keys = {"new", "existing", "resolved", "unclassified", "total"}
    if not isinstance(data, dict) or set(data) != expected_keys:
        raise ValueError("Baseline counts have missing or unknown fields.")
    if not all(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_FINDINGS
        for value in data.values()
    ):
        raise ValueError("Baseline counts must be bounded non-negative integers.")
    expected = {
        "new": sum(item.state == "new" for item in findings),
        "existing": sum(item.state == "existing" for item in findings),
        "resolved": len(resolved),
        "unclassified": sum(item.state == "unclassified" for item in findings),
        "total": len(findings),
    }
    if data != expected:
        raise ValueError("Baseline counts do not match its findings.")


def _validate_pr_report(data: dict[str, Any]) -> tuple[str, list[PrFinding]]:
    if set(data) != _PR_REPORT_FIELDS:
        raise ValueError("Baseline PR report has missing or unknown fields.")
    if data.get("schema_version") != PR_REPORT_VERSION:
        raise ValueError(f"Baseline schema_version must be {PR_REPORT_VERSION}.")
    task_id = _required_string(data, "task_id")
    if data.get("result") not in {"PASS", "FAIL"}:
        raise ValueError("Baseline result must be PASS or FAIL.")
    score = data.get("score")
    if not isinstance(score, int) or isinstance(score, bool) or not 0 <= score <= 100:
        raise ValueError("Baseline score must be an integer from 0 to 100.")
    if data.get("gate") != "all-blocking-findings":
        raise ValueError("Baseline gate contract is unsupported.")
    baseline_state = data.get("baseline")
    if not isinstance(baseline_state, dict) or set(baseline_state) != {
        "status",
        "source",
        "sha256",
        "diagnostic",
    }:
        raise ValueError("Baseline provenance state is invalid.")
    if baseline_state.get("status") not in {"available", "unavailable", "invalid"}:
        raise ValueError("Baseline provenance status is invalid.")
    _optional_string(baseline_state, "source")
    _optional_string(baseline_state, "diagnostic")
    provenance_hash = baseline_state.get("sha256")
    if provenance_hash is not None and (
        not isinstance(provenance_hash, str)
        or _HASH_PATTERN.fullmatch(provenance_hash) is None
    ):
        raise ValueError("Baseline provenance sha256 is invalid.")
    raw_findings = data.get("findings")
    raw_resolved = data.get("resolved")
    if not isinstance(raw_findings, list) or not isinstance(raw_resolved, list):
        raise ValueError("Baseline findings and resolved must be arrays.")
    if len(raw_findings) > MAX_FINDINGS or len(raw_resolved) > MAX_FINDINGS:
        raise ValueError(
            f"Baseline exceeds the {MAX_FINDINGS}-finding per-collection limit."
        )
    findings = [_validated_finding(item) for item in raw_findings]
    resolved = [_validated_finding(item) for item in raw_resolved]
    all_ids = [finding.id for finding in [*findings, *resolved]]
    if len(set(all_ids)) != len(all_ids):
        raise ValueError("Baseline contains duplicate finding ids.")
    if any(item.state == "resolved" for item in findings):
        raise ValueError("Baseline current findings have an invalid state.")
    if any(item.state != "resolved" for item in resolved):
        raise ValueError("Baseline resolved findings have an invalid state.")
    _validated_counts(data.get("counts"), findings, resolved)
    return task_id, findings


def _checks_from_ci_report(data: dict[str, Any]) -> tuple[str, list[PrFinding]]:
    task_id = data.get("task_id")
    raw_checks = data.get("check_results")
    if not isinstance(task_id, str) or not task_id or len(task_id) > MAX_FIELD_CHARS:
        raise ValueError("Baseline CI report has an invalid task_id.")
    if not isinstance(raw_checks, list) or len(raw_checks) > MAX_FINDINGS:
        raise ValueError("Baseline CI report has invalid check_results.")
    checks: list[CheckResult] = []
    evidence_count = 0
    expected_check_fields = {"name", "passed", "severity", "message", "evidence"}
    for raw in raw_checks:
        if not isinstance(raw, dict) or set(raw) != expected_check_fields:
            raise ValueError("Baseline check result has missing or unknown fields.")
        name = raw.get("name")
        passed = raw.get("passed")
        severity = raw.get("severity")
        message = raw.get("message")
        raw_evidence = raw.get("evidence")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(passed, bool)
            or not isinstance(severity, str)
            or severity not in _KNOWN_SEVERITIES
            or not isinstance(message, str)
            or not isinstance(raw_evidence, list)
            or not all(isinstance(item, str) for item in raw_evidence)
        ):
            raise ValueError("Baseline check result is invalid.")
        evidence_count += max(1, len(raw_evidence)) if not passed else 0
        if evidence_count > MAX_FINDINGS:
            raise ValueError(f"Baseline exceeds the {MAX_FINDINGS}-finding limit.")
        checks.append(CheckResult(name, passed, severity, message, raw_evidence))
    return task_id, findings_from_checks(checks)


def _load_baseline(
    path: Optional[Path],
    task_id: str,
) -> tuple[BaselineState, list[PrFinding]]:
    if path is None:
        return BaselineState(
            status="unavailable",
            diagnostic="No baseline report was provided.",
        ), []
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
            baseline_task, findings = _validate_pr_report(data)
        else:
            baseline_task, findings = _checks_from_ci_report(data)
        if baseline_task != task_id:
            raise ValueError("Baseline task_id does not match the current CI task.")
        return (
            BaselineState(
                status="available",
                source=safe_source,
                sha256=hashlib.sha256(raw).hexdigest(),
            ),
            findings,
        )
    except (
        OSError,
        OverflowError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as error:
        diagnostic = _safe_diagnostic(error)
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
    resolved = (
        [
            PrFinding(**{**asdict(finding), "state": "resolved"})
            for finding in previous
            if finding.id not in current_ids
        ]
        if baseline.status == "available"
        else []
    )
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


def _safe_annotation_location(
    repo_dir: Path,
    finding: PrFinding,
) -> Optional[tuple[str, int]]:
    if (
        finding.path is None
        or finding.line is None
        or not 1 <= finding.line <= MAX_ANNOTATION_LINE
    ):
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
        stat_result = resolved.stat()
        if not resolved.is_file() or stat_result.st_size > MAX_ANNOTATION_FILE_BYTES:
            return None
        with resolved.open("rb") as file:
            raw = file.read(MAX_ANNOTATION_FILE_BYTES + 1)
        if (
            len(raw) != stat_result.st_size
            or len(raw) > MAX_ANNOTATION_FILE_BYTES
            or b"\x00" in raw
        ):
            return None
        raw.decode("utf-8")
        lines = raw.splitlines(keepends=True)
        if finding.line > len(lines):
            return None
        if len(lines[finding.line - 1]) > MAX_ANNOTATION_LINE_BYTES:
            return None
    except (OSError, UnicodeDecodeError, ValueError):
        return None
    return relative, finding.line


def _workflow_escape(value: str, *, property_value: bool = False) -> str:
    escaped = (
        _display_text(value)
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )
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
        title = _workflow_escape(
            f"AgentGuard: {finding.rule_name}",
            property_value=True,
        )
        message = _workflow_escape(finding.message)
        annotations.append(
            f"::{level} file={_workflow_escape(path, property_value=True)},"
            f"line={line},title={title}::{message}"
        )
        if len(annotations) >= MAX_ANNOTATIONS:
            break
    return annotations
