import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agentguard import __version__
from agentguard.io import atomic_write_json, atomic_write_text


EVALUATION_REPORT_SCHEMA = "agentguard.evaluation-report"
EVALUATION_REPORT_SCHEMA_VERSION = 1
DEFAULT_OUTPUT_PATH = Path("docs/results/evaluation-report.md")
DEFAULT_INPUTS = {
    "release_candidate": Path("docs/results/release-candidate.json"),
    "mutation": Path("docs/results/mutation-summary.json"),
    "ablation": Path("docs/results/policy-ablation-summary.json"),
    "overhead": Path("docs/results/overhead-summary.json"),
    "scale": Path("docs/results/matrix-scale-summary.json"),
    "resume": Path("docs/results/resume-summary.json"),
    "replay": Path("docs/results/trace-replay-equivalence.json"),
    "counterfactual": Path("docs/results/counterfactual-policy-summary.json"),
    "metamorphic": Path("docs/results/metamorphic-trace-summary.json"),
    "coverage": Path("docs/results/coverage-summary.json"),
}
EXPECTED_SCHEMAS = {
    "release_candidate": "agentguard.release-candidate-summary",
    "mutation": "agentguard.mutation-audit-summary",
    "ablation": "agentguard.policy-ablation-summary",
    "overhead": "agentguard.overhead-summary",
    "scale": "agentguard.matrix-stress-summary",
    "resume": "agentguard.matrix-resume-summary",
    "replay": "agentguard.trace-replay-equivalence",
    "counterfactual": "agentguard.counterfactual-policy-summary",
    "metamorphic": "agentguard.metamorphic-trace-summary",
    "coverage": "agentguard.coverage-summary",
}
MACHINE_SPECIFIC_SECTIONS = {"overhead", "scale", "resume"}
MAX_TEXT_CHARS = 220
FORBIDDEN_CLAIMS = [
    "proved secure",
    "production-ready security",
    "guaranteed",
    "OpenAI-level",
    "real-world false-positive rate",
]
SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*[^\s,;]+"
    ),
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_=-]{8,}\b"),
]
ABSOLUTE_PATH_PATTERN = re.compile(
    r"(?<![\w.-])(?:/(?:Users|private|tmp|var|Volumes)/[^\s`),;]+|[A-Za-z]:\\[^\s`),;]+)"
)


@dataclass(frozen=True)
class EvaluationReportOptions:
    output_path: Path = DEFAULT_OUTPUT_PATH
    summary_json_path: Optional[Path] = None
    force: bool = False
    include_machine_specific: bool = False
    input_overrides: dict[str, Optional[Path]] = field(default_factory=dict)


@dataclass(frozen=True)
class SourceSummary:
    key: str
    path: Path
    relative_path: str
    sha256: str
    schema: Optional[str]
    schema_version: Optional[int]
    data: dict[str, Any]


@dataclass(frozen=True)
class EvaluationReportResult:
    markdown_path: Path
    summary_json_path: Path
    sources: list[SourceSummary]
    missing_sections: list[str]
    omitted_sections: list[str]
    metrics: dict[str, Any]


class EvaluationReportError(ValueError):
    """Raised when an evaluation report cannot be generated safely."""


def generate_evaluation_report(
    options: EvaluationReportOptions,
) -> EvaluationReportResult:
    output_path = options.output_path.expanduser()
    summary_path = (
        options.summary_json_path.expanduser()
        if options.summary_json_path is not None
        else output_path.with_suffix(".json")
    )
    _ensure_can_write(output_path, force=options.force)
    _ensure_can_write(summary_path, force=options.force)
    sources, missing = _load_sources(options.input_overrides)
    if not sources:
        raise EvaluationReportError(
            "No evaluation summary inputs were found. Provide at least one "
            "supported summary JSON file."
        )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    commit = _git_commit()
    source_by_key = {source.key: source for source in sources}
    metrics = _selected_metrics(source_by_key)
    missing = sorted(key for key in missing if key not in metrics)
    omitted = sorted(
        key
        for key in MACHINE_SPECIFIC_SECTIONS
        if key in metrics and not options.include_machine_specific
    )
    summary = _summary_json(
        generated_at=generated_at,
        commit=commit,
        sources=sources,
        missing=missing,
        omitted=omitted,
        metrics=metrics,
        include_machine_specific=options.include_machine_specific,
    )
    markdown = _render_markdown(
        generated_at=generated_at,
        commit=commit,
        sources=source_by_key,
        missing=missing,
        omitted=omitted,
        metrics=metrics,
        include_machine_specific=options.include_machine_specific,
    )
    _validate_output_text(markdown)
    _validate_output_text(json.dumps(summary, indent=2, sort_keys=True))

    atomic_write_text(output_path, markdown)
    atomic_write_json(summary_path, summary, sort_keys=True)
    return EvaluationReportResult(
        markdown_path=output_path,
        summary_json_path=summary_path,
        sources=sources,
        missing_sections=missing,
        omitted_sections=omitted,
        metrics=metrics,
    )


def _load_sources(
    overrides: dict[str, Optional[Path]],
) -> tuple[list[SourceSummary], list[str]]:
    sources = []
    missing = []
    for key in sorted(DEFAULT_INPUTS):
        path = overrides.get(key, DEFAULT_INPUTS[key])
        if path is None:
            missing.append(key)
            continue
        expanded = path.expanduser()
        if not expanded.exists():
            missing.append(key)
            continue
        sources.append(_load_source(key, expanded))
    return sources, missing


def _load_source(key: str, path: Path) -> SourceSummary:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except json.JSONDecodeError as error:
        raise EvaluationReportError(f"Malformed JSON in {path}: {error}") from error
    if not isinstance(data, dict):
        raise EvaluationReportError(f"Summary JSON must be an object: {path}")
    schema = data.get("schema")
    schema_version = data.get("schema_version")
    expected = EXPECTED_SCHEMAS[key]
    if schema is None:
        if not _is_safe_generic(data):
            raise EvaluationReportError(
                f"Input {path} has no schema and cannot be safely parsed as generic."
            )
    elif schema != expected:
        if isinstance(schema, str) and schema.startswith("agentguard."):
            raise EvaluationReportError(
                f"Input {path} has unsupported schema {schema!r}; expected {expected!r}."
            )
        if not _is_safe_generic(data):
            raise EvaluationReportError(
                f"Input {path} has unsupported non-AgentGuard schema {schema!r}."
            )
    if schema == expected and schema_version != 1:
        raise EvaluationReportError(
            f"Input {path} has unsupported schema_version {schema_version!r}."
        )
    return SourceSummary(
        key=key,
        path=path,
        relative_path=_repo_relative(path),
        sha256=_sha256_file(path),
        schema=str(schema) if schema is not None else None,
        schema_version=schema_version if isinstance(schema_version, int) else None,
        data=data,
    )


def _is_safe_generic(data: dict[str, Any]) -> bool:
    return all(key in data for key in ("date", "metrics")) and isinstance(
        data.get("metrics"),
        dict,
    )


def _selected_metrics(sources: dict[str, SourceSummary]) -> dict[str, Any]:
    metrics: dict[str, Any] = {}
    release = _data(sources, "release_candidate")
    if release:
        metrics["benchmark_corpus"] = _subset(
            release.get("benchmark_corpus"),
            [
                "families",
                "scenarios",
                "safe_scenarios",
                "adversarial_scenarios",
                "static_contracts_passed",
                "static_contracts_failed",
            ],
        )
        metrics["release_readiness"] = {
            "tests": _subset(
                release.get("tests"),
                ["collected", "passed", "skipped_docker", "docker_status"],
            ),
            "package_validation": _subset(
                release.get("package_validation"),
                [
                    "wheel_built",
                    "sdist_built",
                    "artifact_contents_validated",
                    "installed_wheel_smoke_passed",
                    "manifest_verification_passed",
                    "published",
                ],
            ),
            "python_support": release.get("python_support", []),
        }
        metrics["coverage"] = _subset(
            release.get("coverage"),
            [
                "scope",
                "statement_percent",
                "branch_percent",
                "combined_percent",
                "gate_percent",
                "gate_passed",
            ],
        )
        metrics["mutation"] = _subset(
            release.get("mutation_diagnostic"),
            [
                "unsafe_mutations",
                "safe_mutations",
                "controlled_expected_detections",
                "observed_expected_detections",
                "controlled_mutation_detection_rate_percent",
                "safe_fixture_pass_rate_percent",
                "missed_detections",
                "forbidden_detections",
                "unexpected_detections",
            ],
        )
        metrics["overhead"] = _subset(
            release.get("instrumentation_overhead"),
            [
                "machine_specific",
                "workload",
                "measured_iterations",
                "warmups",
                "direct_median_seconds",
                "agentguard_median_seconds",
                "median_absolute_overhead_seconds",
                "median_relative_overhead_percent",
                "median_slowdown_ratio",
            ],
        )
    ablation = _data(sources, "ablation")
    if ablation:
        metrics["ablation"] = {
            "result_type": ablation.get("result_type"),
            "trials": ablation.get("trials"),
            "workers": ablation.get("workers"),
            "control_valid": ablation.get("control_valid"),
            "stable": ablation.get("stable"),
            "aggregate_metrics": _subset(
                ablation.get("aggregate_metrics"),
                [
                    "unsafe_mutations",
                    "safe_mutations",
                    "controlled_expected_detections",
                    "observed_expected_detections",
                    "controlled_mutation_detection_rate",
                    "safe_fixture_pass_rate",
                ],
            ),
            "per_check_contributions": ablation.get("per_check_contributions", []),
        }
    scale = _data(sources, "scale")
    if scale:
        metrics["scale"] = {
            "machine_specific": True,
            "result_type": scale.get("result_type"),
            "scaling_summary": _subset(
                scale.get("scaling_summary"),
                [
                    "maximum_validated_attempts",
                    "best_measured_speedup",
                    "best_speedup_workers",
                    "best_speedup_attempts",
                    "best_throughput_attempts_per_second",
                    "maximum_peak_traced_python_memory_bytes",
                    "integrity_passed",
                ],
            ),
            "fail_fast": scale.get("fail_fast_aggregates", []),
        }
    resume = _data(sources, "resume")
    if resume:
        metrics["resume"] = {
            "machine_specific_timing": True,
            "result_type": resume.get("result_type"),
            "configuration": resume.get("configuration", {}),
            "resume_metrics": resume.get("resume_metrics", {}),
            "verification": resume.get("verification", {}),
        }
    replay = _data(sources, "replay")
    if replay:
        metrics["replay"] = {
            "methodology": replay.get("methodology", {}),
            "aggregates": replay.get("aggregates", {}),
        }
    metamorphic = _data(sources, "metamorphic")
    if metamorphic:
        metrics["metamorphic"] = {
            "methodology": metamorphic.get("methodology", {}),
            "results": metamorphic.get("results", {}),
        }
    for key in ("mutation", "overhead", "coverage", "counterfactual"):
        source = _data(sources, key)
        if source and key not in metrics:
            metrics[key] = _generic_metrics(source)
    return _sanitize_json(metrics)


def _render_markdown(
    *,
    generated_at: str,
    commit: Optional[str],
    sources: dict[str, SourceSummary],
    missing: list[str],
    omitted: list[str],
    metrics: dict[str, Any],
    include_machine_specific: bool,
) -> str:
    lines = [
        "# AgentGuard Evaluation Report",
        "",
        f"Generated: {generated_at}",
        f"AgentGuard version: {__version__}",
        f"AgentGuard commit: `{commit or 'unavailable'}`",
        "",
        "This report consolidates existing sanitized AgentGuard result summaries. "
        "It does not run external agents, does not read raw `.agentguard/` "
        "artifacts by default, and does not claim production security effectiveness.",
        "",
        "## Executive Summary",
        "",
        *_executive_summary(metrics, missing, omitted),
        "",
        "## Source Inputs",
        "",
        "| Section | Source | SHA-256 | Schema |",
        "|---|---|---|---|",
    ]
    for source in sorted(sources.values(), key=lambda item: item.key):
        lines.append(
            "| "
            + " | ".join(
                [
                    _label(source.key),
                    f"`{source.relative_path}`",
                    f"`{source.sha256}`",
                    _fmt(source.schema or "generic"),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Benchmark Corpus Summary",
            "",
            *_benchmark_section(metrics),
            "",
            "## CI, Package, And Release Readiness",
            "",
            *_release_section(metrics),
            "",
            "## Coverage Summary",
            "",
            *_coverage_section(metrics),
            "",
            "## Detection Quality Summary",
            "",
            *_detection_section(metrics),
            "",
            "## Policy Ablation Summary",
            "",
            *_ablation_section(metrics),
            "",
            "## Performance And Overhead Summary",
            "",
            *_overhead_section(metrics, include_machine_specific),
            "",
            "## Scale And Stress Summary",
            "",
            *_scale_section(metrics, include_machine_specific),
            "",
            "## Resume And Recovery Summary",
            "",
            *_resume_section(metrics, include_machine_specific),
            "",
            "## Trace, Replay, And Offline Analysis Summary",
            "",
            *_trace_section(metrics),
            "",
            "## Limitations And Threats To Validity",
            "",
            *_limitations_section(sources, missing, omitted),
            "",
            "## Reproduction Commands",
            "",
            "These commands reproduce or regenerate the source summaries using "
            "documented local workflows; they may update machine-specific metrics.",
            "",
            "```bash",
            "PYTHONDONTWRITEBYTECODE=1 scripts/coverage.sh",
            ".venv/bin/python scripts/validate_release_artifacts.py dist/*.whl dist/*.tar.gz",
            "agentguard diagnostics mutations --catalog examples/mutations/catalog.yaml",
            "agentguard diagnostics ablation --catalog examples/mutations/catalog.yaml --trials 3 --workers 3",
            "agentguard diagnostics matrix-stress --attempts 10,50,100,250 --workers 1,2,4,8",
            "agentguard trace replay path/to/trace.jsonl --output-dir .agentguard/replays",
            "agentguard trace metamorphic path/to/traces --output-dir .agentguard/metamorphic",
            "agentguard evaluation report --force",
            "```",
            "",
            "See `docs/testing.md`, `docs/detection-quality.md`, "
            "`docs/policy-ablation.md`, `docs/scalability.md`, `docs/resume.md`, "
            "`docs/replay.md`, and `docs/metamorphic-traces.md` for methodology.",
            "",
        ]
    )
    return "\n".join(lines)


def _executive_summary(
    metrics: dict[str, Any],
    missing: list[str],
    omitted: list[str],
) -> list[str]:
    lines = [
        "- The benchmark corpus summary is sourced from committed release-candidate data when available.",
        "- Controlled mutation detection rate and safe-fixture pass rate are reported as synthetic, catalog-bound diagnostics.",
        "- Replay metrics are described as replay equivalence on deterministic traces, not agent-behavior replay.",
    ]
    if "coverage" in metrics:
        coverage = metrics["coverage"]
        lines.append(
            f"- Coverage gate: {_fmt(coverage.get('combined_percent'))}% "
            f"against {_fmt(coverage.get('gate_percent'))}%."
        )
    if omitted:
        lines.append(
            "- Machine-specific timing/scale sections were omitted from the main "
            "tables; rerun with `--include-machine-specific` to include them."
        )
    if missing:
        lines.append("- Unavailable inputs: " + ", ".join(_label(key) for key in missing) + ".")
    return lines


def _benchmark_section(metrics: dict[str, Any]) -> list[str]:
    corpus = metrics.get("benchmark_corpus")
    if not corpus:
        return _unavailable("Benchmark corpus input was not provided.")
    return [
        "| Metric | Value |",
        "|---|---:|",
        f"| Benchmark families | {_fmt(corpus.get('families'))} |",
        f"| Scenarios | {_fmt(corpus.get('scenarios'))} |",
        f"| Safe scenarios | {_fmt(corpus.get('safe_scenarios'))} |",
        f"| Adversarial scenarios | {_fmt(corpus.get('adversarial_scenarios'))} |",
        f"| Static contracts passed | {_fmt(corpus.get('static_contracts_passed'))} |",
        f"| Static contracts failed | {_fmt(corpus.get('static_contracts_failed'))} |",
    ]


def _release_section(metrics: dict[str, Any]) -> list[str]:
    release = metrics.get("release_readiness")
    if not release:
        return _unavailable("Release readiness input was not provided.")
    tests = release.get("tests", {})
    package = release.get("package_validation", {})
    python_support = ", ".join(str(item) for item in release.get("python_support", []))
    return [
        "| Gate | Result |",
        "|---|---|",
        f"| Full pytest | {_fmt(tests.get('passed'))} passed / {_fmt(tests.get('collected'))} collected |",
        f"| Docker-gated tests | {_fmt(tests.get('skipped_docker'))} skipped locally; {_fmt(tests.get('docker_status'))} |",
        f"| Python support | {_fmt(python_support)} |",
        f"| Wheel built | {_yes_no(package.get('wheel_built'))} |",
        f"| Source distribution built | {_yes_no(package.get('sdist_built'))} |",
        f"| Artifact contents validated | {_yes_no(package.get('artifact_contents_validated'))} |",
        f"| Installed wheel smoke passed | {_yes_no(package.get('installed_wheel_smoke_passed'))} |",
        f"| Manifest verification passed | {_yes_no(package.get('manifest_verification_passed'))} |",
        f"| Published | {_yes_no(package.get('published'))} |",
    ]


def _coverage_section(metrics: dict[str, Any]) -> list[str]:
    coverage = metrics.get("coverage")
    if not coverage:
        return _unavailable("Coverage summary input was not provided.")
    return [
        "| Metric | Value |",
        "|---|---:|",
        f"| Scope | {_fmt(coverage.get('scope'))} |",
        f"| Statement coverage | {_fmt(coverage.get('statement_percent'))}% |",
        f"| Branch coverage | {_fmt(coverage.get('branch_percent'))}% |",
        f"| Combined coverage | {_fmt(coverage.get('combined_percent'))}% |",
        f"| Coverage gate | {_fmt(coverage.get('gate_percent'))}% |",
        f"| Gate passed | {_yes_no(coverage.get('gate_passed'))} |",
    ]


def _detection_section(metrics: dict[str, Any]) -> list[str]:
    mutation = metrics.get("mutation")
    if not mutation:
        return _unavailable("Mutation detection input was not provided.")
    return [
        "Synthetic/controlled metric: these catalog-bound values do not imply production security effectiveness.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Unsafe mutations | {_fmt(mutation.get('unsafe_mutations'))} |",
        f"| Safe mutations | {_fmt(mutation.get('safe_mutations'))} |",
        f"| Expected detections | {_fmt(mutation.get('controlled_expected_detections'))} |",
        f"| Observed expected detections | {_fmt(mutation.get('observed_expected_detections'))} |",
        f"| Controlled mutation detection rate | {_fmt(_first_present(mutation, 'controlled_mutation_detection_rate_percent', 'controlled_mutation_detection_rate'))}% |",
        f"| Safe-fixture pass rate | {_fmt(_first_present(mutation, 'safe_fixture_pass_rate_percent', 'safe_fixture_pass_rate'))}% |",
        f"| Missed detections | {_fmt(mutation.get('missed_detections'))} |",
        f"| Forbidden detections | {_fmt(mutation.get('forbidden_detections'))} |",
        f"| Unexpected detections | {_fmt(mutation.get('unexpected_detections'))} |",
    ]


def _ablation_section(metrics: dict[str, Any]) -> list[str]:
    ablation = metrics.get("ablation")
    if not ablation:
        return _unavailable("Policy ablation input was not provided.")
    lines = [
        "Synthetic/controlled metric: ablation contributions are tied to the mutation catalog and configured policies.",
        "",
        "| Check | Direct opportunities | Unique detections | Redundant detections | Contribution |",
        "|---|---:|---:|---:|---:|",
    ]
    for item in sorted(
        ablation.get("per_check_contributions", []),
        key=lambda entry: str(entry.get("check", "")),
    ):
        lines.append(
            f"| {_fmt(item.get('check'))} | "
            f"{_fmt(item.get('direct_expected_detection_opportunities'))} | "
            f"{_fmt(item.get('detections_uniquely_attributable'))} | "
            f"{_fmt(item.get('detections_redundantly_covered'))} | "
            f"{_fmt(item.get('contribution_percentage'))}% |"
        )
    if len(lines) == 4:
        lines.append("| Unavailable | - | - | - | - |")
    return lines


def _overhead_section(
    metrics: dict[str, Any],
    include_machine_specific: bool,
) -> list[str]:
    overhead = metrics.get("overhead")
    if not overhead:
        return _unavailable("Overhead summary input was not provided.")
    if not include_machine_specific:
        return _machine_omitted("overhead", "machine-specific overhead")
    return [
        "Machine-specific overhead measured on a deterministic local fixture.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Workload | {_fmt(overhead.get('workload'))} |",
        f"| Measured iterations | {_fmt(overhead.get('measured_iterations'))} |",
        f"| Warmups | {_fmt(overhead.get('warmups'))} |",
        f"| Direct median | {_fmt(overhead.get('direct_median_seconds'))} seconds |",
        f"| AgentGuard median | {_fmt(overhead.get('agentguard_median_seconds'))} seconds |",
        f"| Median absolute overhead | {_fmt(overhead.get('median_absolute_overhead_seconds'))} seconds |",
        f"| Median relative overhead | {_fmt(overhead.get('median_relative_overhead_percent'))}% |",
        f"| Median slowdown ratio | {_fmt(overhead.get('median_slowdown_ratio'))}x |",
    ]


def _scale_section(
    metrics: dict[str, Any],
    include_machine_specific: bool,
) -> list[str]:
    scale = metrics.get("scale")
    if not scale:
        return _unavailable("Scale/stress input was not provided.")
    summary = scale.get("scaling_summary", {})
    if not include_machine_specific:
        return _machine_omitted("scale", "synthetic scheduler speedup")
    return [
        "Machine-specific synthetic scheduler/report/history workload, not coding-agent throughput.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Maximum validated attempts | {_fmt(summary.get('maximum_validated_attempts'))} |",
        f"| Best measured speedup | {_fmt(summary.get('best_measured_speedup'))}x |",
        f"| Best speedup workers | {_fmt(summary.get('best_speedup_workers'))} |",
        f"| Best speedup attempts | {_fmt(summary.get('best_speedup_attempts'))} |",
        f"| Best throughput | {_fmt(summary.get('best_throughput_attempts_per_second'))} attempts/second |",
        f"| Peak traced Python memory | {_fmt(summary.get('maximum_peak_traced_python_memory_bytes'))} bytes |",
        f"| Integrity passed | {_yes_no(summary.get('integrity_passed'))} |",
    ]


def _resume_section(
    metrics: dict[str, Any],
    include_machine_specific: bool,
) -> list[str]:
    resume = metrics.get("resume")
    if not resume:
        return _unavailable("Resume/recovery input was not provided.")
    resume_metrics = resume.get("resume_metrics", {})
    verification = resume.get("verification", {})
    lines = [
        "Deterministic local mock matrix checkpoint/resume smoke test.",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Completed before interruption | {_fmt(resume_metrics.get('completed_before_interruption'))} |",
        f"| Reused attempts | {_fmt(resume_metrics.get('reused_attempts'))} |",
        f"| Skipped attempts | {_fmt(resume_metrics.get('skipped_attempts'))} |",
        f"| Newly executed attempts | {_fmt(resume_metrics.get('newly_executed_attempts'))} |",
        f"| Reuse percentage | {_fmt(resume_metrics.get('reuse_percentage'))}% |",
        f"| Artifact verification required | {_yes_no(verification.get('artifact_verification_required_for_reuse'))} |",
    ]
    if include_machine_specific:
        lines.append(
            f"| Estimated recomputation avoided | {_fmt(resume_metrics.get('estimated_recomputation_avoided_seconds'))} seconds |"
        )
    else:
        lines.append("")
        lines.extend(_machine_omitted("resume", "machine-specific resume timing"))
    return lines


def _trace_section(metrics: dict[str, Any]) -> list[str]:
    replay = metrics.get("replay")
    metamorphic = metrics.get("metamorphic")
    counterfactual = metrics.get("counterfactual")
    lines = [
        "| Area | Metric | Value |",
        "|---|---|---:|",
    ]
    if replay:
        aggregates = replay.get("aggregates", {})
        lines.extend(
            [
                f"| Replay | Traces attempted | {_fmt(aggregates.get('traces_attempted'))} |",
                f"| Replay | Traces replayable | {_fmt(aggregates.get('traces_replayable'))} |",
                f"| Replay | Exact check equivalence | {_fmt(aggregates.get('exact_check_equivalence_count'))} |",
                f"| Replay | Exact score equivalence | {_fmt(aggregates.get('exact_score_equivalence_count'))} |",
                f"| Replay | Exact final result equivalence | {_fmt(aggregates.get('exact_final_result_equivalence_count'))} |",
                f"| Replay | Replay equivalence on deterministic traces | {_fmt(aggregates.get('exact_final_result_equivalence_count'))}/{_fmt(aggregates.get('traces_attempted'))} |",
            ]
        )
    else:
        lines.append("| Replay | Status | Unavailable |")
    if metamorphic:
        results = metamorphic.get("results", {})
        lines.extend(
            [
                f"| Metamorphic | Trace count | {_fmt(results.get('trace_count'))} |",
                f"| Metamorphic | Transform applications | {_fmt(results.get('transform_applications'))} |",
                f"| Metamorphic | Preserving pass rate | {_fmt(results.get('preserving_pass_rate'))} |",
                f"| Metamorphic | Changing expected-delta detection rate | {_fmt(results.get('changing_expected_delta_detection_rate'))} |",
                f"| Metamorphic | Invalid rejection count | {_fmt(results.get('invalid_rejection_count'))} |",
            ]
        )
    else:
        lines.append("| Metamorphic | Status | Unavailable |")
    if counterfactual:
        for key, value in counterfactual.items():
            lines.append(
                f"| Counterfactual policy comparison | {_fmt(key)} | {_fmt(value)} |"
            )
    else:
        lines.append("| Counterfactual policy comparison | Status | Unavailable |")
    return lines


def _limitations_section(
    sources: dict[str, SourceSummary],
    missing: list[str],
    omitted: list[str],
) -> list[str]:
    lines = [
        "- This is a reporting/consolidation artifact, not a new evaluator.",
        "- Controlled mutation detection rate and safe-fixture pass rate are synthetic diagnostics, not production security rates.",
        "- No real external-agent study is implied unless a future explicit real-agent study summary is provided.",
        "- Replay equivalence applies only to captured deterministic trace evidence and supported policy inputs.",
        "- Timing, throughput, speedup, and memory values are machine-specific when included.",
    ]
    for key in sorted(sources):
        for limitation in _string_list(sources[key].data.get("limitations")):
            lines.append(f"- {_label(key)} source limitation: {_fmt(limitation)}")
    if missing:
        lines.append("- Missing optional sections: " + ", ".join(_label(key) for key in missing) + ".")
    if omitted:
        lines.append("- Omitted machine-specific sections: " + ", ".join(_label(key) for key in omitted) + ".")
    return lines


def _summary_json(
    *,
    generated_at: str,
    commit: Optional[str],
    sources: list[SourceSummary],
    missing: list[str],
    omitted: list[str],
    metrics: dict[str, Any],
    include_machine_specific: bool,
) -> dict[str, Any]:
    return {
        "schema": EVALUATION_REPORT_SCHEMA,
        "schema_version": EVALUATION_REPORT_SCHEMA_VERSION,
        "generated_at": generated_at,
        "agentguard_version": __version__,
        "agentguard_commit": commit,
        "include_machine_specific": include_machine_specific,
        "source_files": [
            {
                "section": source.key,
                "path": source.relative_path,
                "sha256": source.sha256,
                "schema": source.schema,
                "schema_version": source.schema_version,
            }
            for source in sorted(sources, key=lambda item: item.key)
        ],
        "selected_metrics": metrics,
        "missing_sections": sorted(missing),
        "omitted_sections": sorted(omitted),
    }


def _ensure_can_write(path: Path, *, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"Output already exists: {path}. Use --force.")
    path.parent.mkdir(parents=True, exist_ok=True)


def _data(sources: dict[str, SourceSummary], key: str) -> Optional[dict[str, Any]]:
    source = sources.get(key)
    return source.data if source is not None else None


def _subset(value: Any, keys: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {key: value[key] for key in keys if key in value}


def _generic_metrics(data: dict[str, Any]) -> dict[str, Any]:
    metrics = data.get("metrics")
    return metrics if isinstance(metrics, dict) else {}


def _first_present(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in data:
            return data[key]
    return None


def _unavailable(reason: str) -> list[str]:
    return [f"Unavailable: {_fmt(reason)}"]


def _machine_omitted(section: str, label: str) -> list[str]:
    return [
        f"Unavailable in default report: {_fmt(label)} is omitted by default. "
        f"Run `agentguard evaluation report --include-machine-specific --{section} PATH` "
        "or use committed defaults with `--include-machine-specific` to include it."
    ]


def _label(key: str) -> str:
    return key.replace("_", " ").replace("-", " ").title()


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.6f}".rstrip("0").rstrip(".")
    if isinstance(value, (int,)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(_fmt(item) for item in value)
    return _bounded(_sanitize(str(value)))


def _yes_no(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return _fmt(value)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _bounded(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 15].rstrip() + "... [truncated]"


def _sanitize(text: str) -> str:
    sanitized = text.replace("\x00", "")
    sanitized = SECRET_PATTERNS[0].sub(_redact_keyed_secret, sanitized)
    for pattern in SECRET_PATTERNS[1:]:
        sanitized = pattern.sub("<redacted>", sanitized)
    sanitized = ABSOLUTE_PATH_PATTERN.sub("<path>", sanitized)
    return sanitized


def _redact_keyed_secret(match: re.Match[str]) -> str:
    raw = match.group(0)
    separator = "=" if "=" in raw else ":"
    key = raw.split(separator, 1)[0].strip()
    return f"{key}{separator}<redacted>"


def _sanitize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _sanitize_json(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_sanitize_json(item) for item in value]
    if isinstance(value, str):
        return _sanitize(value)
    return value


def _validate_output_text(text: str) -> None:
    lowered = text.lower()
    for claim in FORBIDDEN_CLAIMS:
        if claim.lower() in lowered:
            raise EvaluationReportError(f"Forbidden overclaim appears in output: {claim}")
    match = ABSOLUTE_PATH_PATTERN.search(text)
    if match:
        raise EvaluationReportError(
            f"Absolute local path appears in generated output: {match.group(0)}"
        )


def _repo_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except (OSError, ValueError):
        return _sanitize(path.as_posix())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> Optional[str]:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            cwd=Path.cwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip() or None
