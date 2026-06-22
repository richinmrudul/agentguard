import json
import re
import shutil
from collections import Counter
from dataclasses import dataclass, field
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
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w.-])(?:/[^\s,;:'\")\]}<>]+|[A-Za-z]:\\[^\s,;:'\")\]}<>]+)"
)


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


def generate_static_report_site(options: StaticSiteOptions) -> StaticSiteResult:
    output = options.output.expanduser()
    reports_root = options.reports_root.expanduser()
    _validate_output_path(output, reports_root)
    if output.exists() and any(output.iterdir()) and not options.force:
        raise FileExistsError(f"output path already exists: {output}")

    if output.exists() and options.force:
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

    pages[Path("assets/site.css")] = _site_css()
    pages[Path("assets/site.js")] = _site_js()

    for relative_path, content in pages.items():
        atomic_write_text(output / relative_path, content)

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


def _load_context(options: StaticSiteOptions) -> SiteContext:
    base = Path.cwd()
    records = _history_records(options.history_db)
    report_records, unavailable_reports = _discover_known_reports(
        options.reports_root, base
    )
    keyed = {(record.kind, record.id): record for record in records}
    for record in report_records:
        keyed.setdefault((record.kind, record.id), record)

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
        records=sorted(keyed.values(), key=_record_sort_key, reverse=True),
        matrices=sorted(matrices, key=_record_sort_key, reverse=True),
        diagnostics=sorted(diagnostics, key=_record_sort_key, reverse=True),
        traces=sorted(traces, key=_record_sort_key, reverse=True),
        results_docs=result_docs,
        unavailable_count=history_unavailable
        + unavailable_reports
        + unavailable_matrices
        + unavailable_diagnostics,
        history_record_count=len(records),
    )


def _history_records(db_path: Path) -> list[SiteRecord]:
    try:
        history = list_history(db_path.expanduser(), limit=None)
    except Exception:
        return []
    return [_record_from_history(record) for record in history]


def _record_from_history(record: HistoryRecord) -> SiteRecord:
    data = _load_json_if_available(record.json_report_path)
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
    return SiteRecord(
        id=sanitize_text(_report_id(path, kind)),
        kind=kind,
        name=sanitize_text(_report_name(path, kind, data)),
        result=sanitize_text(_report_result(kind, data)),
        score=_number(data.get("average_score") if kind == "suite" else data.get("score")),
        created_at=sanitize_text(str(data.get("created_at") or data.get("started_at") or "")),
        path=_relative_or_name(path, base),
        data=sanitize_data(data),
        source="report",
        category=sanitize_optional(data.get("category")),
        difficulty=sanitize_optional(data.get("difficulty")),
        benchmark_id=sanitize_optional(data.get("benchmark_id")),
        agent=sanitize_optional(data.get("agent")),
        failed_checks=_failed_checks_from_data(data),
    )


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
    if _is_relative_to(resolved_output, resolved_reports):
        raise ValueError(
            "output path cannot be inside reports root; choose a path outside "
            f"{reports_root}"
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


def _load_json_if_available(path: Path) -> Any:
    try:
        return sanitize_data(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError):
        return None


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
.doc { white-space: pre-wrap; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; overflow-x: auto; }
footer { color: var(--muted); font-size: 13px; width: min(1120px, calc(100vw - 32px)); margin: 0 auto 32px; }
@media (max-width: 720px) { header { align-items: flex-start; flex-direction: column; padding: 16px; } main { width: calc(100vw - 20px); } th, td { padding: 8px; } }
"""


def _site_js() -> str:
    return """
(function () {
  var input = document.querySelector('[data-filter="records"]');
  if (!input) return;
  input.addEventListener('input', function () {
    var query = input.value.toLowerCase();
    document.querySelectorAll('[data-filter-row]').forEach(function (row) {
      row.hidden = query && row.textContent.toLowerCase().indexOf(query) === -1;
    });
  });
}());
"""
