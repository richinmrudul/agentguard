import hashlib
import json
import math
import re
import shutil
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import datetime
from html import escape
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from agentguard.history.store import HistoryRecord, list_history
from agentguard.io import atomic_write_text
from agentguard.reports.exports import SECRET_PATTERNS


DEFAULT_HISTORY_DB_PATH = Path(".agentguard/history.db")
DEFAULT_REPORTS_ROOT = Path(".agentguard")
SAFE_RESULT_DOC_EXTENSIONS = {".json", ".md"}
MAX_DETAIL_ITEMS = 12
MAX_TEXT_CHARS = 600
MAX_INCIDENT_JSON_BYTES = 1024 * 1024
MAX_RENDERED_INCIDENT_VIOLATIONS = 50
SUPPORTED_INCIDENT_SCHEMA_VERSION = 1
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w.-])(?:/[^\s,;:'\")\]}<>]+|[A-Za-z]:\\[^\s,;:'\")\]}<>]+)"
)
RAW_DIFF_MARKER_PATTERN = re.compile(r"diff --git", re.IGNORECASE)
SITE_OUTPUT_MARKER = ".agentguard-static-site"
SITE_OUTPUT_MARKER_CONTENT = "agentguard-static-site-v1\n"


@dataclass(frozen=True)
class StaticSiteOptions:
    output: Path
    history_db: Path = DEFAULT_HISTORY_DB_PATH
    reports_root: Path = DEFAULT_REPORTS_ROOT
    include_traces: bool = False
    include_diagnostics: bool = False
    include_results_docs: bool = False
    title: str = "AgentGuard Report Site"
    force: bool = False


@dataclass(frozen=True)
class StaticSiteResult:
    output_path: Path
    page_count: int
    history_records: int
    reports: int
    matrices: int
    diagnostics: int
    traces: int
    results_docs: int
    unavailable: int
    incidents: int = 0


@dataclass(frozen=True)
class SiteRecord:
    id: str
    kind: str
    name: str
    result: str
    score: Optional[float]
    created_at: str
    path: Optional[Path] = None
    data: dict[str, Any] = field(default_factory=dict)
    source: str = "history"
    unavailable_reason: Optional[str] = None
    category: Optional[str] = None
    difficulty: Optional[str] = None
    benchmark_id: Optional[str] = None
    agent: Optional[str] = None
    failed_checks: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SiteIncidentViolation:
    guard_type: str = "-"
    policy: str = "-"
    severity: str = "-"
    action: str = "-"
    detected_at: str = "-"
    elapsed_ms: Optional[int] = None
    evidence_summary: str = "-"


@dataclass(frozen=True)
class SiteIncident:
    id: str
    run_id: str
    task_id: str
    agent: str
    guard_mode: str
    result: str
    blocked: bool
    blocking_guard: str
    started_at: str
    detected_at: str
    completed_at: str
    time_to_first_violation_ms: Optional[int]
    time_to_block_ms: Optional[int]
    violations: list[SiteIncidentViolation]
    violation_count: int
    guard_type_counts: dict[str, int]
    filter_guard_types: frozenset[str]
    filter_policies: frozenset[str]
    source_path: Path
    unavailable_reason: Optional[str] = None
    benchmark_id: Optional[str] = None
    category: Optional[str] = None
    run_detail_href: Optional[str] = None
    detail_filename: Optional[str] = None
    redaction_applied: Optional[bool] = None


def generate_static_report_site(options: StaticSiteOptions) -> StaticSiteResult:
    output = options.output.expanduser()
    reports_root = options.reports_root.expanduser()
    _validate_output_path(output, reports_root)
    output_has_entries = output.exists() and any(output.iterdir())
    if output_has_entries and not options.force:
        raise FileExistsError(f"output path already exists: {output}")

    if output_has_entries and options.force:
        _validate_owned_site_output(output)
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "assets").mkdir()
    (output / "details").mkdir()

    context = _load_context(options)
    pages: dict[Path, str] = {}
    pages[Path("index.html")] = _render_index(options, context)
    pages[Path("runs.html")] = _render_records_page(
        options, context, "Runs", [record for record in context.records if record.kind in {"run", "ci"}]
    )
    pages[Path("suites.html")] = _render_records_page(
        options, context, "Suites", [record for record in context.records if record.kind == "suite"]
    )
    pages[Path("matrices.html")] = _render_records_page(
        options, context, "Matrices", context.matrices
    )
    pages[Path("diagnostics.html")] = _render_records_page(
        options, context, "Diagnostics", context.diagnostics
    )
    pages[Path("incidents.html")] = _render_incidents_page(options, context)
    pages[Path("trends.html")] = _render_trends_page(options, context)
    if options.include_traces:
        pages[Path("traces.html")] = _render_records_page(
            options, context, "Traces", context.traces
        )
    if options.include_results_docs:
        pages[Path("results.html")] = _render_results_page(options, context)

    for record in [*context.records, *context.matrices, *context.diagnostics, *context.traces]:
        pages[Path("details") / f"{_slug(record.kind)}-{_slug(record.id)}.html"] = (
            _render_detail_page(options, context, record)
        )
    for result_doc in context.results_docs:
        pages[Path("details") / f"result-{_slug(result_doc.id)}.html"] = (
            _render_result_doc_detail(options, context, result_doc)
        )
    for incident in context.incidents:
        if incident.unavailable_reason is None and incident.detail_filename is not None:
            pages[Path("details") / incident.detail_filename] = (
                _render_incident_detail(options, context, incident)
            )

    pages[Path("assets/site.css")] = _site_css()
    pages[Path("assets/site.js")] = _site_js()

    for relative_path, content in pages.items():
        atomic_write_text(output / relative_path, content)
    atomic_write_text(output / SITE_OUTPUT_MARKER, SITE_OUTPUT_MARKER_CONTENT)

    return StaticSiteResult(
        output_path=output,
        page_count=sum(1 for path in pages if path.suffix == ".html"),
        history_records=context.history_record_count,
        reports=len(context.records),
        matrices=len(context.matrices),
        diagnostics=len(context.diagnostics),
        traces=len(context.traces),
        results_docs=len(context.results_docs),
        unavailable=context.unavailable_count,
        incidents=sum(
            incident.unavailable_reason is None for incident in context.incidents
        ),
    )


@dataclass(frozen=True)
class ResultDoc:
    id: str
    name: str
    path: Path
    content: str


@dataclass(frozen=True)
class SiteContext:
    records: list[SiteRecord]
    matrices: list[SiteRecord]
    diagnostics: list[SiteRecord]
    traces: list[SiteRecord]
    results_docs: list[ResultDoc]
    unavailable_count: int
    history_record_count: int
    incidents: list[SiteIncident] = field(default_factory=list)


def _load_context(options: StaticSiteOptions) -> SiteContext:
    base = Path.cwd()
    records = _history_records(options.history_db)
    report_records, unavailable_reports = _discover_known_reports(
        options.reports_root, base
    )
    keyed = {(record.kind, record.id): record for record in records}
    for record in report_records:
        keyed.setdefault((record.kind, record.id), record)
    resolved_records = sorted(
        keyed.values(),
        key=_record_sort_key,
        reverse=True,
    )
    incidents = _discover_incidents(
        options.reports_root,
        base,
        resolved_records,
    )

    matrices, unavailable_matrices = _discover_pattern_reports(
        options.reports_root,
        base,
        "matrix",
        "matrices/*/matrix.json",
    )
    diagnostics: list[SiteRecord] = []
    unavailable_diagnostics = 0
    if options.include_diagnostics:
        diagnostics, unavailable_diagnostics = _discover_pattern_reports(
            options.reports_root,
            base,
            "diagnostic",
            "diagnostics/**/*.json",
        )
    traces: list[SiteRecord] = []
    if options.include_traces:
        traces = _discover_traces(options.reports_root, base)
    result_docs: list[ResultDoc] = []
    if options.include_results_docs:
        result_docs = _discover_results_docs(base)

    history_unavailable = sum(1 for record in records if record.unavailable_reason)
    return SiteContext(
        records=resolved_records,
        matrices=sorted(matrices, key=_record_sort_key, reverse=True),
        diagnostics=sorted(diagnostics, key=_record_sort_key, reverse=True),
        traces=sorted(traces, key=_record_sort_key, reverse=True),
        results_docs=result_docs,
        unavailable_count=history_unavailable
        + unavailable_reports
        + unavailable_matrices
        + unavailable_diagnostics
        + sum(
            incident.unavailable_reason is not None for incident in incidents
        ),
        history_record_count=len(records),
        incidents=incidents,
    )


def _history_records(db_path: Path) -> list[SiteRecord]:
    try:
        history = list_history(db_path.expanduser(), limit=None)
    except Exception:
        return []
    return [_record_from_history(record) for record in history]


def _record_from_history(record: HistoryRecord) -> SiteRecord:
    data = _load_json_if_available(
        record.json_report_path,
        kind=record.run_type,
    )
    return SiteRecord(
        id=sanitize_text(record.id),
        kind=sanitize_text(record.run_type),
        name=sanitize_text(record.name),
        result=sanitize_text(record.result),
        score=record.score,
        created_at=sanitize_text(record.created_at),
        path=record.json_report_path,
        data=data if isinstance(data, dict) else {},
        source="history",
        category=sanitize_optional(record.category),
        difficulty=sanitize_optional(record.difficulty),
        benchmark_id=sanitize_optional(record.benchmark_id),
        agent=sanitize_optional(record.agent),
        failed_checks=[sanitize_text(item) for item in record.failed_checks],
        unavailable_reason=None if isinstance(data, dict) else "report unavailable",
    )


def _discover_known_reports(root: Path, base: Path) -> tuple[list[SiteRecord], int]:
    records: list[SiteRecord] = []
    unavailable = 0
    for kind, pattern in [
        ("run", "runs/*/reports/report.json"),
        ("suite", "suites/*/suite.json"),
        ("ci", "ci/*/report.json"),
    ]:
        discovered, missing = _discover_pattern_reports(root, base, kind, pattern)
        records.extend(discovered)
        unavailable += missing
    return records, unavailable


def _discover_pattern_reports(
    root: Path,
    base: Path,
    kind: str,
    pattern: str,
) -> tuple[list[SiteRecord], int]:
    report_root = _resolve_under_base(root, base)
    if not report_root.exists():
        return [], 0
    records: list[SiteRecord] = []
    unavailable = 0
    for path in sorted(report_root.glob(pattern)):
        if path.is_symlink():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("report JSON is not an object")
        except (OSError, ValueError, json.JSONDecodeError):
            unavailable += 1
            records.append(
                SiteRecord(
                    id=sanitize_text(path.parent.name),
                    kind=kind,
                    name=sanitize_text(path.parent.name),
                    result="unavailable",
                    score=None,
                    created_at="",
                    path=path,
                    source="report",
                    unavailable_reason="could not read report summary",
                )
            )
            continue
        records.append(_record_from_report(path, kind, data, base))
    return records, unavailable


def _record_from_report(
    path: Path,
    kind: str,
    data: dict[str, Any],
    base: Path,
) -> SiteRecord:
    sanitized_data = _sanitize_report_data(data, kind)
    return SiteRecord(
        id=sanitize_text(_report_id(path, kind)),
        kind=kind,
        name=sanitize_text(_report_name(path, kind, data)),
        result=sanitize_text(_report_result(kind, data)),
        score=_number(data.get("average_score") if kind == "suite" else data.get("score")),
        created_at=sanitize_text(str(data.get("created_at") or data.get("started_at") or "")),
        path=_relative_or_name(path, base),
        data=sanitized_data,
        source="report",
        category=sanitize_optional(data.get("category")),
        difficulty=sanitize_optional(data.get("difficulty")),
        benchmark_id=sanitize_optional(data.get("benchmark_id")),
        agent=sanitize_optional(data.get("agent")),
        failed_checks=_failed_checks_from_data(data),
    )


def _discover_incidents(
    root: Path,
    base: Path,
    records: list[SiteRecord],
) -> list[SiteIncident]:
    report_root = _resolve_under_base(root, base)
    if not report_root.exists():
        return []
    run_records = {
        record.id: record
        for record in records
        if record.kind == "run"
    }
    incidents = []
    for path in sorted(report_root.glob("runs/*/guard/incident.json")):
        if _path_has_symlink(path, report_root):
            continue
        run_id = path.parent.parent.name
        incident = _load_site_incident(path, run_id)
        record = run_records.get(sanitize_text(run_id))
        if record is not None:
            incident = replace(
                incident,
                benchmark_id=record.benchmark_id,
                category=record.category,
                run_detail_href=f"run-{_slug(record.id)}.html",
            )
        incidents.append(incident)
    ordered = sorted(incidents, key=_incident_sort_key, reverse=True)
    return _assign_incident_filenames(ordered)


def _load_site_incident(path: Path, fallback_run_id: str) -> SiteIncident:
    unavailable = _unavailable_incident(path, fallback_run_id)
    try:
        if not path.is_file():
            return unavailable
        if path.stat().st_size > MAX_INCIDENT_JSON_BYTES:
            return replace(
                unavailable,
                unavailable_reason="incident artifact exceeds the size limit",
            )
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return unavailable
    if not isinstance(data, dict):
        return unavailable
    schema_version = data.get("schema_version")
    if (
        schema_version is not None
        and (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != SUPPORTED_INCIDENT_SCHEMA_VERSION
        )
    ):
        return replace(
            unavailable,
            unavailable_reason="unsupported incident schema version",
        )
    raw_violations = data.get("violations")
    violation_items = raw_violations if isinstance(raw_violations, list) else []
    structured_violations = [
        item for item in violation_items if isinstance(item, dict)
    ]
    violations = [
        _site_incident_violation(item)
        for item in structured_violations[:MAX_RENDERED_INCIDENT_VIOLATIONS]
    ]
    guard_type_counts = Counter(
        _incident_text(item.get("guard_type"))
        for item in structured_violations
    )
    redaction = data.get("redaction")
    redaction_applied = (
        redaction.get("applied")
        if isinstance(redaction, dict)
        and isinstance(redaction.get("applied"), bool)
        else None
    )
    return SiteIncident(
        id=sanitize_text(fallback_run_id),
        run_id=_incident_text(data.get("run_id"), fallback_run_id),
        task_id=_incident_text(data.get("task_id")),
        agent=_incident_text(data.get("agent")),
        guard_mode=_incident_text(data.get("guard_mode")),
        result=_incident_text(data.get("result")),
        blocked=data.get("blocked") is True,
        blocking_guard=_incident_text(data.get("blocking_guard")),
        started_at=_incident_text(data.get("started_at")),
        detected_at=_incident_text(data.get("detected_at")),
        completed_at=_incident_text(data.get("completed_at")),
        time_to_first_violation_ms=_nonnegative_int(
            data.get("time_to_first_violation_ms")
        ),
        time_to_block_ms=_nonnegative_int(data.get("time_to_block_ms")),
        violations=violations,
        violation_count=len(violation_items),
        guard_type_counts=dict(guard_type_counts),
        filter_guard_types=frozenset(guard_type_counts),
        filter_policies=frozenset(
            _incident_text(item.get("policy"))
            for item in structured_violations
        ),
        source_path=path,
        redaction_applied=redaction_applied,
    )


def _unavailable_incident(path: Path, run_id: str) -> SiteIncident:
    safe_id = sanitize_text(run_id)
    return SiteIncident(
        id=safe_id,
        run_id=safe_id,
        task_id="-",
        agent="-",
        guard_mode="-",
        result="-",
        blocked=False,
        blocking_guard="-",
        started_at="-",
        detected_at="-",
        completed_at="-",
        time_to_first_violation_ms=None,
        time_to_block_ms=None,
        violations=[],
        violation_count=0,
        guard_type_counts={},
        filter_guard_types=frozenset(),
        filter_policies=frozenset(),
        source_path=path,
        unavailable_reason="incident artifact is unavailable or malformed",
    )


def _site_incident_violation(data: dict[str, Any]) -> SiteIncidentViolation:
    guard_type = _incident_text(data.get("guard_type"))
    return SiteIncidentViolation(
        guard_type=guard_type,
        policy=_incident_text(data.get("policy")),
        severity=_incident_text(data.get("severity")),
        action=_incident_text(data.get("action")),
        detected_at=_incident_text(data.get("detected_at")),
        elapsed_ms=_nonnegative_int(data.get("elapsed_ms")),
        evidence_summary=(
            "Command policy violation detected"
            if guard_type == "command"
            else _incident_text(data.get("evidence_summary"))
        ),
    )


def _incident_text(value: Any, fallback: str = "-") -> str:
    return sanitize_text(value) if isinstance(value, str) and value else fallback


def _path_has_symlink(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _incident_sort_key(incident: SiteIncident) -> tuple[float, str]:
    for value in (
        incident.detected_at,
        incident.completed_at,
        incident.started_at,
    ):
        try:
            return datetime.fromisoformat(value).timestamp(), incident.id
        except (TypeError, ValueError):
            continue
    return float("-inf"), incident.id


def _assign_incident_filenames(
    incidents: list[SiteIncident],
) -> list[SiteIncident]:
    used: set[str] = set()
    assigned = []
    for incident in incidents:
        if incident.unavailable_reason is not None:
            assigned.append(incident)
            continue
        base = f"incident-{_slug(incident.id)}"
        filename = f"{base}.html"
        if filename in used:
            suffix = hashlib.sha256(incident.id.encode("utf-8")).hexdigest()[:10]
            filename = f"{base}-{suffix}.html"
            counter = 2
            while filename in used:
                filename = f"{base}-{suffix}-{counter}.html"
                counter += 1
        used.add(filename)
        assigned.append(replace(incident, detail_filename=filename))
    return assigned


def _discover_traces(root: Path, base: Path) -> list[SiteRecord]:
    report_root = _resolve_under_base(root, base)
    if not report_root.exists():
        return []
    traces: list[SiteRecord] = []
    for path in sorted(report_root.glob("runs/*/trace.jsonl")):
        if path.is_symlink():
            continue
        traces.append(
            SiteRecord(
                id=sanitize_text(path.parent.name),
                kind="trace",
                name=sanitize_text(path.parent.name),
                result="available",
                score=None,
                created_at="",
                path=_relative_or_name(path, base),
                data=_trace_summary(path),
                source="trace",
            )
        )
    return traces


def _discover_results_docs(base: Path) -> list[ResultDoc]:
    docs_root = base / "docs" / "results"
    if not docs_root.exists():
        return []
    docs: list[ResultDoc] = []
    for path in sorted(docs_root.iterdir()):
        if path.is_symlink() or path.suffix not in SAFE_RESULT_DOC_EXTENSIONS:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        docs.append(
            ResultDoc(
                id=sanitize_text(path.stem),
                name=sanitize_text(path.name),
                path=Path("docs") / "results" / path.name,
                content=sanitize_text(content[:4000]),
            )
        )
    return docs


def _render_index(options: StaticSiteOptions, context: SiteContext) -> str:
    all_records = [*context.records, *context.matrices]
    counts = Counter(record.result.upper() for record in all_records)
    scores = [record.score for record in all_records if record.score is not None]
    average = sum(scores) / len(scores) if scores else None
    latest = sorted(all_records, key=_record_sort_key, reverse=True)[:8]
    category_counts = Counter(
        record.category or record.benchmark_id or "uncategorized"
        for record in all_records
    )
    reliability = [
        record
        for record in context.matrices
        if "reliability_summary" in record.data or "overall_reliability" in record.data
    ]
    body = [
        _hero(options.title, "Static local summary of AgentGuard history and reports."),
        '<section class="metrics">',
        _metric("Total records", str(len(all_records))),
        _metric("Passed", str(counts.get("PASS", 0))),
        _metric("Failed", str(counts.get("FAIL", 0))),
        _metric("Average score", _format_score(average)),
        "</section>",
        _section(
            "Latest runs",
            _records_table(latest, detail_prefix="details"),
        ),
        _section("Benchmark summaries", _counter_table(category_counts)),
        _section(
            "Reliability summaries",
            _records_table(reliability[:8], detail_prefix="details")
            if reliability
            else _empty("No reliability summaries found."),
        ),
        _section("Guard trends", _trend_preview(context)),
        _section(
            "Diagnostics summaries",
            _records_table(context.diagnostics[:8], detail_prefix="details")
            if context.diagnostics
            else _empty("No diagnostics included."),
        ),
        _section(
            "Artifacts",
            _artifact_links(options, context),
        ),
    ]
    return _page(options, context, "Dashboard", "".join(body))


def _render_trends_page(
    options: StaticSiteOptions,
    context: SiteContext,
) -> str:
    body = _trend_body(context, full=True)
    return _page(options, context, "Guard Trends", body)


def _render_records_page(
    options: StaticSiteOptions,
    context: SiteContext,
    heading: str,
    records: list[SiteRecord],
) -> str:
    search = (
        '<label class="filter">Filter '
        '<input data-filter="records" type="search" placeholder="name, result, agent"></label>'
    )
    body = _hero(heading, f"{len(records)} record(s)") + search + _records_table(
        records, detail_prefix="details"
    )
    return _page(options, context, heading, body)


def _render_incidents_page(
    options: StaticSiteOptions,
    context: SiteContext,
) -> str:
    available = [
        incident
        for incident in context.incidents
        if incident.unavailable_reason is None
    ]
    unavailable = [
        incident
        for incident in context.incidents
        if incident.unavailable_reason is not None
    ]
    violation_types: Counter[str] = Counter()
    for incident in available:
        violation_types.update(incident.guard_type_counts)
    body = [
        _hero("Guard Incidents", f"{len(available)} available incident(s)"),
        '<section class="metrics">',
        _metric("Total incidents", str(len(available))),
        _metric("Blocked incidents", str(sum(item.blocked for item in available))),
        _metric(
            "Audit-only incidents",
            str(sum(not item.blocked for item in available)),
        ),
        _metric(
            "Total violations",
            str(sum(item.violation_count for item in available)),
        ),
        _metric("Filesystem violations", str(violation_types["filesystem"])),
        _metric("Command violations", str(violation_types["command"])),
        "</section>",
        _incident_filter_controls(available),
        _incident_table(available),
    ]
    if unavailable:
        body.append(
            _section(
                "Unavailable incidents",
                _unavailable_incident_table(unavailable),
            )
        )
    return _page(options, context, "Guard Incidents", "".join(body))


def _available_incidents(context: SiteContext) -> list[SiteIncident]:
    return [
        incident
        for incident in context.incidents
        if incident.unavailable_reason is None
    ]


def _trend_body(context: SiteContext, *, full: bool) -> str:
    records = [*context.records, *context.matrices]
    incidents = _available_incidents(context)
    failed_checks = sum(len(record.failed_checks) for record in records)
    failed_records = sum(record.result.upper() == "FAIL" for record in records)
    passed_records = sum(record.result.upper() == "PASS" for record in records)
    total_violations = sum(incident.violation_count for incident in incidents)
    latest, previous = _latest_previous_incident_counts(incidents)
    delta = latest - previous
    body = []
    if full:
        body.append(
            _hero(
                "Guard Trends",
                "Static snapshot of guard and evaluation safety signals.",
            )
        )
    body.extend(
        [
            '<section class="metrics">',
            _metric("Runs represented", str(len(records))),
            _metric("Guard incidents", str(len(incidents))),
            _metric("Guard violations", str(total_violations)),
            _metric("Failed checks", str(failed_checks)),
            _metric("Failed evaluations", str(failed_records)),
            _metric("Safe passes", str(passed_records)),
            _metric("Latest incident violations", str(latest)),
            _metric("Previous incident violations", str(previous)),
            _metric("Incident delta", _format_delta(delta)),
            "</section>",
        ]
    )
    if not records and not incidents:
        body.append(
            _section(
                "Trend data",
                _empty(
                    "No trend data found. Generate reports or guard incidents under .agentguard before building the static site."
                ),
            )
        )
        return "".join(body)

    body.extend(
        [
            _section(
                "Incident Categories",
                _trend_counter_table(
                    _incident_policy_counts(incidents),
                    "Category",
                    incident_links=_incident_links_by_policy(incidents),
                    empty="No guard incident categories found.",
                ),
            ),
            _section(
                "Guard Type Breakdown",
                _trend_counter_table(
                    _incident_guard_type_counts(incidents),
                    "Guard type",
                    incident_links=_incident_links_by_guard_type(incidents),
                    empty="No guard incident types found.",
                ),
            ),
            _section(
                "Severity Breakdown",
                _trend_counter_table(
                    _incident_severity_counts(incidents),
                    "Severity",
                    empty="No guard incident severities found.",
                ),
            ),
            _section(
                "Guard Mode Breakdown",
                _trend_counter_table(
                    Counter(incident.guard_mode for incident in incidents),
                    "Guard mode",
                    empty="No guard modes found.",
                ),
            ),
            _section(
                "Benchmark / Task Breakdown",
                _trend_counter_table(
                    Counter(
                        incident.benchmark_id or incident.task_id
                        for incident in incidents
                    ),
                    "Benchmark or task",
                    incident_links=_incident_links_by_benchmark(incidents),
                    empty="No incident benchmark metadata found.",
                ),
            ),
            _section(
                "Agent / Profile Breakdown",
                _trend_counter_table(
                    Counter(incident.agent for incident in incidents),
                    "Agent or profile",
                    empty="No incident agent metadata found.",
                ),
            ),
        ]
    )
    if full:
        body.extend(
            [
                _section("Recent Incident Runs", _incident_trend_table(incidents)),
                _section("Recent Evaluation Runs", _run_trend_table(records)),
            ]
        )
    else:
        body.append(
            '<p><a href="trends.html">Open full trend analytics</a></p>'
        )
    return "".join(body)


def _trend_preview(context: SiteContext) -> str:
    return _trend_body(context, full=False)


def _latest_previous_incident_counts(
    incidents: list[SiteIncident],
) -> tuple[int, int]:
    ordered = sorted(incidents, key=_incident_sort_key, reverse=True)
    latest = ordered[0].violation_count if ordered else 0
    previous = ordered[1].violation_count if len(ordered) > 1 else 0
    return latest, previous


def _incident_policy_counts(incidents: list[SiteIncident]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for incident in incidents:
        counts.update(
            violation.policy
            for violation in incident.violations
            if violation.policy and violation.policy != "-"
        )
    return counts


def _incident_guard_type_counts(incidents: list[SiteIncident]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for incident in incidents:
        counts.update(incident.guard_type_counts)
    return counts


def _incident_severity_counts(incidents: list[SiteIncident]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for incident in incidents:
        counts.update(
            violation.severity
            for violation in incident.violations
            if violation.severity and violation.severity != "-"
        )
    return counts


def _incident_links_by_policy(
    incidents: list[SiteIncident],
) -> dict[str, str]:
    links: dict[str, str] = {}
    for incident in incidents:
        if incident.detail_filename is None:
            continue
        for violation in incident.violations:
            if violation.policy and violation.policy != "-":
                links.setdefault(
                    violation.policy,
                    f"details/{incident.detail_filename}",
                )
    return links


def _incident_links_by_guard_type(
    incidents: list[SiteIncident],
) -> dict[str, str]:
    links: dict[str, str] = {}
    for incident in incidents:
        if incident.detail_filename is None:
            continue
        for guard_type in incident.guard_type_counts:
            if guard_type and guard_type != "-":
                links.setdefault(
                    guard_type,
                    f"details/{incident.detail_filename}",
                )
    return links


def _incident_links_by_benchmark(
    incidents: list[SiteIncident],
) -> dict[str, str]:
    links: dict[str, str] = {}
    for incident in incidents:
        if incident.detail_filename is None:
            continue
        benchmark = incident.benchmark_id or incident.task_id
        if benchmark and benchmark != "-":
            links.setdefault(benchmark, f"details/{incident.detail_filename}")
    return links


def _trend_counter_table(
    counter: Counter[str],
    label: str,
    *,
    incident_links: Optional[dict[str, str]] = None,
    empty: str,
) -> str:
    items = [
        (name, count)
        for name, count in counter.items()
        if name and name != "-"
    ]
    if not items:
        return _empty(empty)
    links = incident_links or {}
    rows = []
    for name, count in sorted(items, key=lambda item: (-item[1], item[0])):
        display = html(name)
        href = links.get(name)
        if href is not None:
            display = f'<a href="{html(href)}">{display}</a>'
        rows.append(f"<tr><td>{display}</td><td>{count}</td></tr>")
    return (
        f'<table class="data"><thead><tr><th>{html(label)}</th><th>Count</th>'
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _incident_trend_table(incidents: list[SiteIncident]) -> str:
    if not incidents:
        return _empty("No guard incidents found.")
    rows = []
    for incident in sorted(incidents, key=_incident_sort_key, reverse=True)[:MAX_DETAIL_ITEMS]:
        benchmark = incident.benchmark_id or incident.task_id
        detail_href = (
            f"details/{incident.detail_filename}"
            if incident.detail_filename is not None
            else ""
        )
        detail = (
            f'<a href="{html(detail_href)}">Incident</a>'
            if detail_href
            else "-"
        )
        run_detail = (
            f'<a href="details/{html(incident.run_detail_href)}">Run</a>'
            if incident.run_detail_href is not None
            else "-"
        )
        rows.append(
            "<tr>"
            f"<td>{html(incident.detected_at if incident.detected_at != '-' else incident.completed_at)}</td>"
            f"<td>{html(benchmark)}</td>"
            f"<td>{html(incident.agent)}</td>"
            f"<td>{html(incident.guard_mode)}</td>"
            f"<td>{html(_incident_status(incident))}</td>"
            f"<td>{incident.violation_count}</td>"
            f"<td>{detail}</td>"
            f"<td>{run_detail}</td>"
            "</tr>"
        )
    return (
        '<table class="data"><thead><tr><th>Detected / completed</th>'
        "<th>Benchmark / task</th><th>Agent</th><th>Mode</th>"
        "<th>Status</th><th>Violations</th><th>Incident</th><th>Run</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _run_trend_table(records: list[SiteRecord]) -> str:
    if not records:
        return _empty("No evaluation runs found.")
    rows = []
    for record in sorted(records, key=_record_sort_key, reverse=True)[:MAX_DETAIL_ITEMS]:
        href = f"details/{_slug(record.kind)}-{_slug(record.id)}.html"
        rows.append(
            "<tr>"
            f"<td>{html(record.created_at or '-')}</td>"
            f"<td>{html(record.kind)}</td>"
            f"<td><a href=\"{href}\">{html(record.name or record.id)}</a></td>"
            f"<td>{html(record.result or '-')}</td>"
            f"<td>{html(_format_score(record.score))}</td>"
            f"<td>{html(record.agent or '-')}</td>"
            f"<td>{len(record.failed_checks)}</td>"
            "</tr>"
        )
    return (
        '<table class="data"><thead><tr><th>Created</th><th>Type</th>'
        "<th>Name</th><th>Result</th><th>Score</th><th>Agent</th>"
        f"<th>Failed checks</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _format_delta(value: int) -> str:
    if value > 0:
        return f"+{value}"
    return str(value)


def _incident_filter_controls(incidents: list[SiteIncident]) -> str:
    dimensions = [
        ("status", ["blocked", "audit-only"]),
        ("mode", [item.guard_mode for item in incidents]),
        (
            "guard-type",
            [
                guard_type
                for item in incidents
                for guard_type in item.filter_guard_types
            ],
        ),
        (
            "policy",
            [
                violation
                for item in incidents
                for violation in item.filter_policies
            ],
        ),
        ("agent", [item.agent for item in incidents]),
        (
            "benchmark",
            [
                item.benchmark_id or item.task_id
                for item in incidents
            ],
        ),
    ]
    controls = [
        '<div class="incident-filters">',
        '<label>Search <input data-incident-filter="search" type="search" '
        'placeholder="task, benchmark, agent, policy"></label>',
    ]
    for dimension, values in dimensions:
        displays = sorted(
            {value for value in values if value and value != "-"}
        )
        options = ['<option value="">All</option>']
        options.extend(
            f'<option value="{_filter_token(value)}">{html(value)}</option>'
            for value in displays
        )
        label = dimension.replace("-", " ").title()
        controls.append(
            f'<label>{html(label)} <select data-incident-filter="{dimension}">'
            f'{"".join(options)}</select></label>'
        )
    controls.append("</div>")
    return "".join(controls)


def _incident_table(incidents: list[SiteIncident]) -> str:
    if not incidents:
        return _empty("No guard incidents found.")
    rows = []
    for incident in incidents:
        guard_types = set(incident.filter_guard_types)
        policies = set(incident.filter_policies)
        benchmark = incident.benchmark_id or incident.task_id
        searchable = " ".join(
            [
                incident.run_id,
                incident.task_id,
                benchmark,
                incident.category or "",
                incident.agent,
                incident.guard_mode,
                incident.blocking_guard,
                *sorted(guard_types),
                *sorted(policies),
            ]
        )
        detail_href = f"details/{incident.detail_filename}"
        rows.append(
            "<tr data-incident-row "
            f'data-search="{html(searchable.lower())}" '
            f'data-status="{_filter_token(_incident_status(incident))}" '
            f'data-mode="{_filter_token(incident.guard_mode)}" '
            f'data-guard-type="{html(_filter_tokens(guard_types))}" '
            f'data-policy="{html(_filter_tokens(policies))}" '
            f'data-agent="{_filter_token(incident.agent)}" '
            f'data-benchmark="{_filter_token(benchmark)}">'
            f"<td>{html(incident.detected_at if incident.detected_at != '-' else incident.completed_at)}</td>"
            f"<td>{html(benchmark)}</td>"
            f"<td>{html(incident.agent)}</td>"
            f"<td>{html(incident.guard_mode)}</td>"
            f"<td>{html(_incident_status(incident))}</td>"
            f"<td>{html(incident.blocking_guard)}</td>"
            f"<td>{incident.violation_count}</td>"
            f"<td>{html(_format_ms(incident.time_to_first_violation_ms))}</td>"
            f'<td><a href="{detail_href}">View</a></td>'
            "</tr>"
        )
    return (
        '<table class="data"><thead><tr><th>Detected / completed</th>'
        "<th>Task / benchmark</th><th>Agent</th><th>Mode</th>"
        "<th>Status</th><th>Blocking guard</th><th>Violations</th>"
        "<th>First violation</th><th>Detail</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _unavailable_incident_table(incidents: list[SiteIncident]) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html(incident.id)}</td>"
        f"<td>{html(incident.unavailable_reason or 'incident unavailable')}</td>"
        "</tr>"
        for incident in incidents
    )
    return (
        '<table class="data"><thead><tr><th>Run</th><th>Status</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>"
    )


def _render_incident_detail(
    options: StaticSiteOptions,
    context: SiteContext,
    incident: SiteIncident,
) -> str:
    run_link = (
        f'<a href="{incident.run_detail_href}">Open run detail</a>'
        if incident.run_detail_href is not None
        else "Unavailable"
    )
    facts = {
        "Run ID": incident.run_id,
        "Task": incident.task_id,
        "Benchmark": incident.benchmark_id or "-",
        "Category": incident.category or "-",
        "Agent": incident.agent,
        "Result": incident.result,
        "Guard mode": incident.guard_mode,
        "Status": _incident_status(incident),
        "Blocking guard": incident.blocking_guard,
        "Started": incident.started_at,
        "Detected": incident.detected_at,
        "Completed": incident.completed_at,
        "Time to first violation": _format_ms(
            incident.time_to_first_violation_ms
        ),
        "Time to block": _format_ms(incident.time_to_block_ms),
        "Violation count": incident.violation_count,
        "Redaction": (
            "Applied"
            if incident.redaction_applied is True
            else (
                "Not applied"
                if incident.redaction_applied is False
                else "Not reported"
            )
        ),
    }
    body = [
        _hero(incident.task_id, "Guard incident detail"),
        _facts_table(facts),
        f"<p>Run detail: {run_link}</p>",
        _section("Violations", _incident_violations_table(incident)),
    ]
    return _page(
        options,
        context,
        f"Incident {incident.run_id}",
        "".join(body),
        prefix="../",
    )


def _incident_violations_table(incident: SiteIncident) -> str:
    if not incident.violations:
        return _empty("No structured violation details available.")
    rows = []
    for violation in incident.violations:
        rows.append(
            "<tr>"
            f"<td>{html(violation.guard_type)}</td>"
            f"<td>{html(violation.policy)}</td>"
            f"<td>{html(violation.severity)}</td>"
            f"<td>{html(violation.action)}</td>"
            f"<td>{html(violation.detected_at)}</td>"
            f"<td>{html(_format_ms(violation.elapsed_ms))}</td>"
            f"<td>{html(violation.evidence_summary)}</td>"
            "</tr>"
        )
    omitted = incident.violation_count - len(incident.violations)
    notice = (
        f"<p>{omitted} additional violation(s) omitted.</p>"
        if omitted > 0
        else ""
    )
    return (
        '<table class="data"><thead><tr><th>Guard type</th><th>Policy</th>'
        "<th>Severity</th><th>Action</th><th>Detected</th>"
        "<th>Elapsed</th><th>Evidence summary</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>{notice}"
    )


def _render_results_page(options: StaticSiteOptions, context: SiteContext) -> str:
    rows = []
    for doc in context.results_docs:
        href = f"details/result-{_slug(doc.id)}.html"
        rows.append(
            "<tr data-filter-row>"
            f"<td><a href=\"{href}\">{html(doc.name)}</a></td>"
            f"<td>{html(_display_path(doc.path))}</td>"
            "</tr>"
        )
    table = (
        '<table class="data"><thead><tr><th>Name</th><th>Source</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table>"
        if rows
        else _empty("No committed docs/results summaries found.")
    )
    body = _hero("Results", f"{len(context.results_docs)} document(s)") + table
    return _page(options, context, "Results", body)


def _render_detail_page(
    options: StaticSiteOptions,
    context: SiteContext,
    record: SiteRecord,
) -> str:
    facts = {
        "Type": record.kind,
        "ID": record.id,
        "Name": record.name,
        "Result": record.result,
        "Score": _format_score(record.score),
        "Created": record.created_at or "-",
        "Agent": record.agent or "-",
        "Category": record.category or "-",
        "Difficulty": record.difficulty or "-",
        "Benchmark": record.benchmark_id or "-",
        "Report path": _display_path(record.path) if record.path else "-",
    }
    sections = [
        _hero(record.name or record.id, f"{record.kind} detail"),
        _facts_table(facts),
    ]
    if record.unavailable_reason:
        sections.append(_section("Availability", _empty(record.unavailable_reason)))
    if record.failed_checks:
        sections.append(_section("Failed checks", _list(record.failed_checks)))
    if record.kind == "matrix":
        guard_summary = record.data.get("guard_summary")
        if isinstance(guard_summary, dict):
            sections.append(
                _section(
                    "Guard Incidents",
                    _render_matrix_guard_summary(guard_summary),
                )
            )
    sections.append(_section("Summary", _data_summary(record.data)))
    return _page(
        options,
        context,
        record.name or record.id,
        "".join(sections),
        prefix="../",
    )


def _render_result_doc_detail(
    options: StaticSiteOptions,
    context: SiteContext,
    doc: ResultDoc,
) -> str:
    body = (
        _hero(doc.name, "Committed docs/results summary")
        + _facts_table({"Source": _display_path(doc.path)})
        + f"<pre class=\"doc\">{html(doc.content)}</pre>"
    )
    return _page(options, context, doc.name, body, prefix="../")


def _page(
    options: StaticSiteOptions,
    context: SiteContext,
    page_title: str,
    body: str,
    *,
    prefix: str = "",
) -> str:
    title = html(options.title)
    nav = _nav(options, context, prefix=prefix)
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>{html(page_title)} - {title}</title>"
        f"<link rel=\"stylesheet\" href=\"{prefix}assets/site.css\">"
        "</head><body>"
        f"<header><a class=\"brand\" href=\"{prefix}index.html\">{title}</a>{nav}</header>"
        f"<main>{body}</main>"
        "<footer>Generated by AgentGuard. Static files only; no external assets.</footer>"
        f"<script src=\"{prefix}assets/site.js\"></script>"
        "</body></html>"
    )


def _nav(options: StaticSiteOptions, context: SiteContext, *, prefix: str) -> str:
    links = [
        ("index.html", "Dashboard"),
        ("runs.html", "Runs"),
        ("suites.html", "Suites"),
        ("matrices.html", "Matrices"),
        ("incidents.html", "Incidents"),
        ("trends.html", "Trends"),
        ("diagnostics.html", "Diagnostics"),
    ]
    if options.include_traces:
        links.append(("traces.html", "Traces"))
    if options.include_results_docs:
        links.append(("results.html", "Results"))
    return "<nav>" + "".join(
        f"<a href=\"{prefix}{href}\">{label}</a>" for href, label in links
    ) + "</nav>"


def _records_table(records: list[SiteRecord], *, detail_prefix: str) -> str:
    if not records:
        return _empty("No records found.")
    rows = []
    for record in records:
        href = f"{detail_prefix}/{_slug(record.kind)}-{_slug(record.id)}.html"
        row_text = " ".join(
            [
                record.kind,
                record.name,
                record.result,
                record.agent or "",
                record.category or "",
                record.benchmark_id or "",
            ]
        )
        rows.append(
            f"<tr data-filter-row=\"{html(row_text).lower()}\">"
            f"<td>{html(record.kind)}</td>"
            f"<td><a href=\"{href}\">{html(record.name or record.id)}</a></td>"
            f"<td>{html(record.result or '-')}</td>"
            f"<td>{html(_format_score(record.score))}</td>"
            f"<td>{html(record.agent or '-')}</td>"
            f"<td>{html(record.created_at or '-')}</td>"
            "</tr>"
        )
    return (
        '<table class="data"><thead><tr><th>Type</th><th>Name</th><th>Result</th>'
        '<th>Score</th><th>Agent</th><th>Created</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _data_summary(data: dict[str, Any]) -> str:
    if not data:
        return _empty("No structured summary available.")
    allowed = [
        "suite_id",
        "task_id",
        "matrix_id",
        "result",
        "score",
        "average_score",
        "total_runs",
        "passed",
        "failed",
        "pass_rate",
        "reliability_summary",
        "overall_reliability",
        "scaling_summary",
        "integrity_passed",
        "filters",
        "report_paths",
        "manifest_path",
        "trace_path",
        "runs",
        "check_results",
    ]
    items = [(key, data[key]) for key in allowed if key in data]
    if not items:
        items = list(data.items())[:MAX_DETAIL_ITEMS]
    rows = []
    for key, value in items[:MAX_DETAIL_ITEMS]:
        rows.append(
            f"<tr><th>{html(str(key))}</th><td>{html(_compact_value(value))}</td></tr>"
        )
    return f'<table class="facts"><tbody>{"".join(rows)}</tbody></table>'


def _render_matrix_guard_summary(summary: dict[str, Any]) -> str:
    count_metrics = [
        ("Runs evaluated", "runs_evaluated"),
        ("Incident runs", "incident_runs"),
        ("Blocked runs", "blocked_runs"),
        ("Audit-only runs", "audit_only_runs"),
        ("Total violations", "violations_total"),
        ("Filesystem violations", "filesystem_violations"),
        ("Command violations", "command_violations"),
    ]
    content = [
        '<div class="metrics">',
        *[
            _metric(label, _format_guard_count(summary.get(key)))
            for label, key in count_metrics
        ],
        "</div>",
        _facts_table(
            {
                "Time to first violation median": _guard_timing_value(
                    summary,
                    "time_to_first_violation",
                    "median_ms",
                ),
                "Time to first violation p95": _guard_timing_value(
                    summary,
                    "time_to_first_violation",
                    "p95_ms",
                ),
                "Time to block median": _guard_timing_value(
                    summary,
                    "time_to_block",
                    "median_ms",
                ),
                "Time to block p95": _guard_timing_value(
                    summary,
                    "time_to_block",
                    "p95_ms",
                ),
            }
        ),
    ]
    guard_types = summary.get("by_guard_type")
    if isinstance(guard_types, dict):
        rows = []
        for guard_type, values in list(guard_types.items())[:MAX_DETAIL_ITEMS]:
            if not isinstance(values, dict):
                continue
            rows.append(
                "<tr>"
                f"<td>{html(guard_type)}</td>"
                f"<td>{html(_format_guard_count(values.get('incident_runs')))}</td>"
                f"<td>{html(_format_guard_count(values.get('blocked_runs')))}</td>"
                f"<td>{html(_format_guard_count(values.get('violations_total')))}</td>"
                "</tr>"
            )
        if rows:
            content.extend(
                [
                    "<h3>By guard type</h3>",
                    '<table class="data"><thead><tr><th>Guard</th>'
                    "<th>Incident runs</th><th>Blocked runs</th>"
                    "<th>Violations</th></tr></thead>"
                    f"<tbody>{''.join(rows)}</tbody></table>",
                ]
            )
    return "".join(content)


def _sanitize_matrix_guard_summary(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, dict):
        return None
    summary: dict[str, Any] = {}
    for key in (
        "runs_evaluated",
        "incident_runs",
        "blocked_runs",
        "audit_only_runs",
        "violations_total",
        "filesystem_violations",
        "command_violations",
    ):
        if key in value:
            summary[key] = value[key]
    for key in ("time_to_first_violation", "time_to_block"):
        timing = value.get(key)
        if isinstance(timing, dict):
            summary[key] = {
                field: timing[field]
                for field in ("median_ms", "p95_ms")
                if field in timing
            }
    guard_types = value.get("by_guard_type")
    if isinstance(guard_types, dict):
        sanitized_types: dict[str, Any] = {}
        for guard_type, counts in list(guard_types.items())[:MAX_DETAIL_ITEMS]:
            if not isinstance(counts, dict):
                continue
            sanitized_types[sanitize_text(guard_type)] = {
                field: counts[field]
                for field in (
                    "incident_runs",
                    "blocked_runs",
                    "violations_total",
                )
                if field in counts
            }
        summary["by_guard_type"] = sanitized_types
    return summary


def _format_guard_count(value: Any) -> str:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return str(value)
    return "-"


def _guard_timing_value(
    summary: dict[str, Any],
    distribution_key: str,
    statistic_key: str,
) -> str:
    distribution = summary.get(distribution_key)
    if not isinstance(distribution, dict):
        return "-"
    value = distribution.get(statistic_key)
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    ):
        return f"{_format_score(float(value))} ms"
    return "-"


def _compact_value(value: Any) -> str:
    value = sanitize_data(value)
    if isinstance(value, list):
        rendered = [_compact_value(item) for item in value[:MAX_DETAIL_ITEMS]]
        extra = "" if len(value) <= MAX_DETAIL_ITEMS else f" ... +{len(value) - MAX_DETAIL_ITEMS}"
        return "; ".join(rendered) + extra
    if isinstance(value, dict):
        parts = []
        for key, item in list(value.items())[:MAX_DETAIL_ITEMS]:
            parts.append(f"{key}: {_compact_value(item)}")
        extra = "" if len(value) <= MAX_DETAIL_ITEMS else f" ... +{len(value) - MAX_DETAIL_ITEMS}"
        return "; ".join(parts) + extra
    text = str(value)
    return text if len(text) <= MAX_TEXT_CHARS else text[:MAX_TEXT_CHARS] + "..."


def sanitize_data(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_data(item) for item in value[:MAX_DETAIL_ITEMS]]
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in list(value.items())[:MAX_DETAIL_ITEMS]:
            key_text = sanitize_text(str(key))
            if _is_raw_output_key(key_text):
                sanitized[key_text] = "[omitted]"
            else:
                sanitized[key_text] = sanitize_data(item)
        return sanitized
    return value


def sanitize_text(value: object) -> str:
    text = str(value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = ABSOLUTE_PATH_PATTERN.sub(_absolute_path_replacement, text)
    text = RAW_DIFF_MARKER_PATTERN.sub("[diff omitted]", text)
    return text


def sanitize_optional(value: object) -> Optional[str]:
    if value is None:
        return None
    return sanitize_text(value)


def html(value: object) -> str:
    return escape(sanitize_text(value), quote=True)


def _validate_output_path(output: Path, reports_root: Path) -> None:
    resolved_output = output.resolve()
    resolved_reports = reports_root.resolve()
    resolved_cwd = Path.cwd().resolve()
    if resolved_output == Path(resolved_output.anchor):
        raise ValueError("output path cannot be a filesystem root")
    if resolved_output == resolved_cwd:
        raise ValueError("output path cannot be the current working directory")
    if (resolved_output / ".git").exists():
        raise ValueError("output path cannot be a repository root")
    if _is_relative_to(resolved_reports, resolved_output):
        raise ValueError(
            "output path cannot contain the reports root; choose a separate path"
        )
    if _is_relative_to(resolved_output, resolved_reports):
        raise ValueError(
            "output path cannot be inside reports root; choose a path outside "
            f"{reports_root}"
        )


def _validate_owned_site_output(output: Path) -> None:
    marker = output / SITE_OUTPUT_MARKER
    try:
        marker_content = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        marker_content = ""
    if marker.is_symlink() or marker_content != SITE_OUTPUT_MARKER_CONTENT:
        raise ValueError(
            "refusing to replace a non-empty directory without an "
            "AgentGuard static-site marker"
        )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _resolve_under_base(path: Path, base: Path) -> Path:
    expanded = path.expanduser()
    return expanded if expanded.is_absolute() else base / expanded


def _relative_or_name(path: Path, base: Path) -> Path:
    try:
        return path.resolve().relative_to(base.resolve())
    except ValueError:
        return Path(path.name)


def _display_path(path: Optional[Path]) -> str:
    if path is None:
        return "-"
    return sanitize_text(path.as_posix())


def _absolute_path_replacement(match: re.Match[str]) -> str:
    path = match.group(0).replace("\\", "/")
    return PurePosixPath(path).name or "[path]"


def _report_id(path: Path, kind: str) -> str:
    if kind == "run":
        return path.parent.parent.name
    return path.parent.name


def _report_name(path: Path, kind: str, data: dict[str, Any]) -> str:
    if kind == "suite":
        return str(data.get("suite_id") or path.parent.name)
    if kind == "matrix":
        return str(data.get("matrix_id") or path.parent.name)
    if kind == "diagnostic":
        return str(data.get("schema") or path.stem)
    return str(data.get("task_id") or data.get("suite_id") or path.parent.name)


def _report_result(kind: str, data: dict[str, Any]) -> str:
    if data.get("result") is not None:
        return str(data["result"])
    if kind in {"suite", "matrix"} and data.get("failed") is not None:
        return "PASS" if data.get("failed") == 0 else "FAIL"
    if data.get("integrity_passed") is not None:
        return "PASS" if data.get("integrity_passed") else "FAIL"
    return "-"


def _failed_checks_from_data(data: dict[str, Any]) -> list[str]:
    checks = data.get("check_results")
    if not isinstance(checks, list):
        return []
    failed = []
    for check in checks:
        if isinstance(check, dict) and not check.get("passed", True):
            failed.append(sanitize_text(check.get("name", "unnamed check")))
    return failed


def _trace_summary(path: Path) -> dict[str, Any]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"status": "unavailable"}
    header: dict[str, Any] = {}
    if lines:
        try:
            loaded = json.loads(lines[0])
            if isinstance(loaded, dict):
                header = sanitize_data(loaded)
        except json.JSONDecodeError:
            header = {"status": "invalid header"}
    return {"events": max(len(lines) - 1, 0), "header": header}


def _load_json_if_available(path: Path, *, kind: Optional[str] = None) -> Any:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if isinstance(loaded, dict):
        return _sanitize_report_data(loaded, kind)
    return sanitize_data(loaded)


def _sanitize_report_data(data: dict[str, Any], kind: Optional[str]) -> dict[str, Any]:
    sanitized_data = sanitize_data(data)
    guard_summary = _sanitize_matrix_guard_summary(data.get("guard_summary"))
    if kind == "matrix" and guard_summary is not None:
        sanitized_data["guard_summary"] = guard_summary
    return sanitized_data


def _record_sort_key(record: SiteRecord) -> str:
    return record.created_at or record.id


def _slug(value: object) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-").lower()
    return slug or "item"


def _number(value: object) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _format_score(value: Optional[float]) -> str:
    if value is None:
        return "-"
    return f"{value:.1f}".rstrip("0").rstrip(".")


def _nonnegative_int(value: Any) -> Optional[int]:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _format_ms(value: Optional[int]) -> str:
    return f"{value} ms" if value is not None else "-"


def _incident_status(incident: SiteIncident) -> str:
    return "blocked" if incident.blocked else "audit-only"


def _filter_token(value: str) -> str:
    return "v-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _filter_tokens(values: set[str]) -> str:
    return " ".join(_filter_token(value) for value in sorted(values))


def _hero(title: str, subtitle: str) -> str:
    return f"<section class=\"hero\"><h1>{html(title)}</h1><p>{html(subtitle)}</p></section>"


def _metric(label: str, value: str) -> str:
    return f"<div class=\"metric\"><span>{html(label)}</span><strong>{html(value)}</strong></div>"


def _section(title: str, content: str) -> str:
    return f"<section><h2>{html(title)}</h2>{content}</section>"


def _facts_table(facts: dict[str, object]) -> str:
    rows = "".join(
        f"<tr><th>{html(key)}</th><td>{html(value)}</td></tr>"
        for key, value in facts.items()
    )
    return f'<table class="facts"><tbody>{rows}</tbody></table>'


def _counter_table(counter: Counter[str]) -> str:
    if not counter:
        return _empty("No benchmark metadata found.")
    rows = "".join(
        f"<tr><td>{html(name)}</td><td>{count}</td></tr>"
        for name, count in sorted(counter.items())
    )
    return (
        '<table class="data"><thead><tr><th>Name</th><th>Records</th></tr></thead>'
        f"<tbody>{rows}</tbody></table>"
    )


def _artifact_links(options: StaticSiteOptions, context: SiteContext) -> str:
    items = [
        f"History records loaded: {context.history_record_count}",
        f"Unavailable or corrupt reports: {context.unavailable_count}",
        f"Traces included: {len(context.traces) if options.include_traces else 0}",
        (
            "Results docs included: "
            f"{len(context.results_docs) if options.include_results_docs else 0}"
        ),
    ]
    return _list(items)


def _list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{html(item)}</li>" for item in items) + "</ul>"


def _empty(message: str) -> str:
    return f"<p class=\"empty\">{html(message)}</p>"


def _is_raw_output_key(key: str) -> bool:
    return key.lower() in {"stdout", "stderr", "raw_stdout", "raw_stderr", "diff", "patch"}


def _site_css() -> str:
    return """
:root { color-scheme: light; --ink: #1f2933; --muted: #667085; --line: #d8dee8; --bg: #f7f8fb; --panel: #ffffff; --accent: #1f7a6d; --warn: #9a3412; }
* { box-sizing: border-box; }
body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: var(--bg); color: var(--ink); }
header { display: flex; align-items: center; justify-content: space-between; gap: 24px; padding: 18px 32px; background: var(--panel); border-bottom: 1px solid var(--line); position: sticky; top: 0; }
.brand { color: var(--ink); font-weight: 700; text-decoration: none; }
nav { display: flex; flex-wrap: wrap; gap: 12px; }
nav a { color: var(--accent); text-decoration: none; font-size: 14px; }
main { width: min(1120px, calc(100vw - 32px)); margin: 0 auto; padding: 28px 0 48px; }
.hero { margin-bottom: 24px; }
h1 { font-size: 34px; margin: 0 0 6px; letter-spacing: 0; }
h2 { font-size: 20px; margin: 30px 0 12px; letter-spacing: 0; }
p { color: var(--muted); }
.metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; }
.metric { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
.metric span { display: block; color: var(--muted); font-size: 13px; }
.metric strong { display: block; margin-top: 8px; font-size: 28px; }
.data, .facts { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: hidden; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; font-size: 14px; }
th { color: #344054; background: #eef2f6; font-weight: 650; }
td a { color: var(--accent); }
.facts th { width: 190px; }
.empty { background: var(--panel); border: 1px dashed var(--line); border-radius: 8px; padding: 14px; }
.filter { display: block; margin: 0 0 12px; color: var(--muted); }
.filter input { margin-left: 8px; width: min(360px, 100%); padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; }
.incident-filters { display: flex; flex-wrap: wrap; gap: 10px; margin: 18px 0 12px; }
.incident-filters label { color: var(--muted); font-size: 13px; }
.incident-filters input, .incident-filters select { display: block; min-width: 150px; margin-top: 4px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); color: var(--ink); }
.doc { white-space: pre-wrap; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; overflow-x: auto; }
footer { color: var(--muted); font-size: 13px; width: min(1120px, calc(100vw - 32px)); margin: 0 auto 32px; }
@media (max-width: 720px) { header { align-items: flex-start; flex-direction: column; padding: 16px; } main { width: calc(100vw - 20px); } th, td { padding: 8px; } }
"""


def _site_js() -> str:
    return """
(function () {
  var input = document.querySelector('[data-filter="records"]');
  if (input) {
    input.addEventListener('input', function () {
      var query = input.value.toLowerCase();
      document.querySelectorAll('[data-filter-row]').forEach(function (row) {
        row.hidden = query && row.textContent.toLowerCase().indexOf(query) === -1;
      });
    });
  }
  var incidentFilters = Array.prototype.slice.call(
    document.querySelectorAll('[data-incident-filter]')
  );
  function filterIncidents() {
    var values = {};
    incidentFilters.forEach(function (control) {
      values[control.dataset.incidentFilter] = control.value.toLowerCase();
    });
    document.querySelectorAll('[data-incident-row]').forEach(function (row) {
      var matches = incidentFilters.every(function (control) {
        var name = control.dataset.incidentFilter;
        var value = values[name];
        if (!value) return true;
        var rowValue = row.getAttribute('data-' + name) || '';
        if (name === 'search') return rowValue.indexOf(value) !== -1;
        return rowValue.split(' ').indexOf(value) !== -1;
      });
      row.hidden = !matches;
    });
  }
  incidentFilters.forEach(function (control) {
    var eventName = control.tagName === 'SELECT' ? 'change' : 'input';
    control.addEventListener(eventName, filterIncidents);
  });
}());
"""
