#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentguard import __version__  # noqa: E402
from agentguard.diagnostics.overhead import run_overhead_benchmark  # noqa: E402
from agentguard.io import atomic_write_json, atomic_write_text  # noqa: E402
from scripts.showcase_demo import DEFAULT_OUTPUT_DIR, DEFAULT_SUITE, SAFE_CATEGORY  # noqa: E402
from scripts.showcase_demo import run_showcase  # noqa: E402


DEFAULT_METRICS_JSON = Path("docs/results/showcase-metrics.json")
DEFAULT_OVERHEAD_OUTPUT = DEFAULT_OUTPUT_DIR / "showcase-overhead.json"
DEFAULT_OVERHEAD_CONFIG = Path("examples/showcase/configs/safe_fix.yaml")
FAKE_SHOWCASE_SECRET = "AGENTGUARD_SHOWCASE_SECRET_EXAMPLE"


def _portable_path(path: Path) -> str:
    cwd = Path.cwd().resolve()
    try:
        return path.resolve().relative_to(cwd).as_posix()
    except ValueError:
        return path.name


def _round(value: float) -> float:
    return round(float(value), 4)


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return _round((numerator / denominator) * 100.0)


def compute_detection_metrics(showcase_summary: dict[str, Any]) -> dict[str, Any]:
    scenarios = list(showcase_summary.get("scenarios", []))
    safe_scenarios = [
        scenario for scenario in scenarios if scenario.get("expected") == "allowed"
    ]
    unsafe_scenarios = [
        scenario for scenario in scenarios if scenario.get("expected") == "detected"
    ]
    safe_allowed = sum(1 for scenario in safe_scenarios if scenario.get("result") == "PASS")
    unsafe_detected = sum(
        1 for scenario in unsafe_scenarios if scenario.get("result") == "FAIL"
    )
    false_positives = [
        scenario["id"]
        for scenario in safe_scenarios
        if scenario.get("result") != "PASS"
    ]
    false_negatives = [
        scenario["id"]
        for scenario in unsafe_scenarios
        if scenario.get("result") != "FAIL"
    ]
    categories: dict[str, dict[str, Any]] = {}
    for scenario in scenarios:
        category = str(scenario.get("category") or "uncategorized")
        expected = str(scenario.get("expected"))
        result = str(scenario.get("result"))
        item = categories.setdefault(
            category,
            {
                "total": 0,
                "expected_safe": 0,
                "expected_unsafe": 0,
                "allowed": 0,
                "detected": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "failed_checks": [],
            },
        )
        item["total"] += 1
        if expected == "allowed":
            item["expected_safe"] += 1
        if expected == "detected":
            item["expected_unsafe"] += 1
        if result == "PASS":
            item["allowed"] += 1
        if result == "FAIL":
            item["detected"] += 1
        if expected == "allowed" and result != "PASS":
            item["false_positives"] += 1
        if expected == "detected" and result != "FAIL":
            item["false_negatives"] += 1
        item["failed_checks"] = sorted(
            set(item["failed_checks"]) | set(scenario.get("failed_checks", []))
        )

    report_formats = set(showcase_summary.get("report_formats_generated", []))
    return {
        "total_scenarios": len(scenarios),
        "safe_scenarios": len(safe_scenarios),
        "unsafe_scenarios": len(unsafe_scenarios),
        "safe_allowed": safe_allowed,
        "unsafe_detected": unsafe_detected,
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "false_positive_scenarios": false_positives,
        "false_negative_scenarios": false_negatives,
        "unsafe_detection_rate_percent": _rate(unsafe_detected, len(unsafe_scenarios)),
        "safe_allowance_rate_percent": _rate(safe_allowed, len(safe_scenarios)),
        "category_coverage": sorted(
            category for category in categories if category != SAFE_CATEGORY
        ),
        "categories": dict(sorted(categories.items())),
        "failed_check_counts": showcase_summary.get("failed_check_counts", {}),
        "guard_incident_count": showcase_summary.get("guard_incident_count", 0),
        "guard_incident_categories_observed": [],
        "report_availability": {
            "json_reports": len(scenarios) if "json_report" in report_formats else 0,
            "markdown_reports": (
                len(scenarios) if "markdown_report" in report_formats else 0
            ),
            "command_logs": len(scenarios) if "command_log" in report_formats else 0,
            "traces": len(scenarios) if "trace" in report_formats else 0,
            "suite_json": "suite_json" in report_formats,
            "suite_markdown": "suite_markdown" in report_formats,
            "manifest": "manifest" in report_formats,
        },
    }


def reduce_overhead_metrics(
    overhead_data: dict[str, Any],
    *,
    config_path: Path,
    iterations: int,
    warmups: int,
) -> dict[str, Any]:
    summary = overhead_data["summary"]
    direct = summary["direct_seconds"]
    agentguard = summary["agentguard_seconds"]
    overhead = summary["absolute_overhead_seconds"]
    relative = summary["relative_overhead_percent"]
    slowdown = summary["slowdown_ratio"]
    throughput = summary["throughput_runs_per_minute"]
    return {
        "method": "direct workload versus normal AgentGuard run on the showcase safe scenario",
        "config": _portable_path(config_path),
        "agent": overhead_data["agent"],
        "iterations": iterations,
        "warmups": warmups,
        "runs_measured": iterations,
        "baseline_median_seconds": _round(direct["median"]),
        "guard_enabled_median_seconds": _round(agentguard["median"]),
        "absolute_overhead_median_seconds": _round(overhead["median"]),
        "relative_overhead_median_percent": _round(relative["median"]),
        "slowdown_ratio_median": _round(slowdown["median"]),
        "direct_throughput_runs_per_minute": _round(throughput["direct_median"]),
        "agentguard_throughput_runs_per_minute": _round(
            throughput["agentguard_median"]
        ),
        "limitations": [
            "This is a local showcase measurement, not a benchmark-grade performance claim.",
            "Operating-system, interpreter, and filesystem caches can affect timings.",
            "External agents, network calls, larger repositories, and Docker runs can have different overhead profiles.",
        ],
    }


def build_metrics_report(
    showcase_summary: dict[str, Any],
    overhead_metrics: dict[str, Any],
    *,
    metrics_json_path: Path,
) -> dict[str, Any]:
    detection = compute_detection_metrics(showcase_summary)
    metrics_markdown_path = metrics_json_path.with_suffix(".md")
    return {
        "schema": "agentguard.showcase-metrics",
        "schema_version": 1,
        "name": "AgentGuard showcase metrics",
        "agentguard_version": __version__,
        "source_summary": "docs/results/showcase-summary.json",
        "generated_by": "scripts/showcase_metrics.py",
        "metrics_artifacts": {
            "json": _portable_path(metrics_json_path),
            "markdown": _portable_path(metrics_markdown_path),
        },
        "detection_quality": detection,
        "overhead": overhead_metrics,
        "sanitization": {
            "fake_secrets_only": True,
            "fake_secret_value_rendered": False,
            "raw_diffs_included": False,
            "absolute_workspace_paths_included": False,
            "environment_variables_included": False,
            "raw_stdout_stderr_included": False,
        },
        "supporting_artifacts": {
            "showcase_suite": "examples/showcase/showcase.yaml",
            "showcase_docs": "docs/showcase.md",
            "showcase_summary_json": "docs/results/showcase-summary.json",
            "showcase_summary_markdown": "docs/results/showcase-summary.md",
            "runtime_output_root": ".agentguard/showcase",
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    detection = report["detection_quality"]
    overhead = report["overhead"]
    category_names = ", ".join(detection["category_coverage"])
    lines = [
        "# AgentGuard Showcase Metrics",
        "",
        "## Detection Quality",
        "",
        f"- Total showcase scenarios: {detection['total_scenarios']}",
        f"- Unsafe scenarios detected: {detection['unsafe_detected']}/{detection['unsafe_scenarios']}",
        f"- Safe scenarios allowed: {detection['safe_allowed']}/{detection['safe_scenarios']}",
        f"- False positives: {detection['false_positive_count']}",
        f"- False negatives: {detection['false_negative_count']}",
        f"- Unsafe detection rate: {detection['unsafe_detection_rate_percent']:.2f}%",
        f"- Safe allowance rate: {detection['safe_allowance_rate_percent']:.2f}%",
        f"- Categories covered: {category_names}",
        f"- Guard incidents observed: {detection['guard_incident_count']}",
        "",
        "## Category Coverage",
        "",
        "| Category | Total | Expected unsafe | Detected | Allowed | Failed checks |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for category, values in detection["categories"].items():
        failed = ", ".join(values["failed_checks"]) or "-"
        lines.append(
            f"| {category} | {values['total']} | {values['expected_unsafe']} | "
            f"{values['detected']} | {values['allowed']} | {failed} |"
        )

    lines.extend(
        [
            "",
            "## Report And Trace Availability",
            "",
        ]
    )
    availability = detection["report_availability"]
    lines.extend(
        [
            f"- JSON reports: {availability['json_reports']}",
            f"- Markdown reports: {availability['markdown_reports']}",
            f"- Command logs: {availability['command_logs']}",
            f"- Traces: {availability['traces']}",
            f"- Suite JSON: {availability['suite_json']}",
            f"- Suite Markdown: {availability['suite_markdown']}",
            f"- Manifest: {availability['manifest']}",
            "",
            "## Local Overhead Measurement",
            "",
            f"- Method: {overhead['method']}",
            f"- Config: {overhead['config']}",
            f"- Iterations measured: {overhead['runs_measured']}",
            f"- Warmups: {overhead['warmups']}",
            f"- Direct median: {overhead['baseline_median_seconds']:.4f}s",
            f"- AgentGuard median: {overhead['guard_enabled_median_seconds']:.4f}s",
            f"- Median absolute overhead: {overhead['absolute_overhead_median_seconds']:.4f}s",
            f"- Median relative overhead: {overhead['relative_overhead_median_percent']:.2f}%",
            f"- Median slowdown ratio: {overhead['slowdown_ratio_median']:.4f}x",
            "",
            "## Sanitization",
            "",
            "- Metrics artifacts omit fake secret literals, raw diffs, stdout/stderr blobs, environment variables, and absolute workspace paths.",
            "- Supporting runtime artifacts live under `.agentguard/showcase` and are ignored by Git.",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in overhead["limitations"])
    lines.append("")
    return "\n".join(lines)


def run_metrics(
    *,
    suite_path: Path,
    output_dir: Path,
    metrics_json_path: Path,
    overhead_config: Path,
    overhead_output: Path,
    overhead_iterations: int,
    overhead_warmups: int,
) -> dict[str, Any]:
    showcase_summary, _, _ = run_showcase(suite_path, output_dir)
    overhead_result = run_overhead_benchmark(
        overhead_config,
        "local-command",
        iterations=overhead_iterations,
        warmups=overhead_warmups,
        output_path=overhead_output,
        force=True,
    )
    overhead_metrics = reduce_overhead_metrics(
        overhead_result.data,
        config_path=overhead_config,
        iterations=overhead_iterations,
        warmups=overhead_warmups,
    )
    report = build_metrics_report(
        showcase_summary,
        overhead_metrics,
        metrics_json_path=metrics_json_path,
    )
    atomic_write_json(metrics_json_path, report)
    atomic_write_text(metrics_json_path.with_suffix(".md"), render_markdown(report))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate sanitized detection-quality and overhead metrics for the AgentGuard showcase."
    )
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--metrics-json", type=Path, default=DEFAULT_METRICS_JSON)
    parser.add_argument("--overhead-config", type=Path, default=DEFAULT_OVERHEAD_CONFIG)
    parser.add_argument("--overhead-output", type=Path, default=DEFAULT_OVERHEAD_OUTPUT)
    parser.add_argument("--overhead-iterations", type=int, default=3)
    parser.add_argument("--overhead-warmups", type=int, default=1)
    args = parser.parse_args()

    report = run_metrics(
        suite_path=args.suite,
        output_dir=args.output_dir,
        metrics_json_path=args.metrics_json,
        overhead_config=args.overhead_config,
        overhead_output=args.overhead_output,
        overhead_iterations=args.overhead_iterations,
        overhead_warmups=args.overhead_warmups,
    )
    detection = report["detection_quality"]
    overhead = report["overhead"]
    print("AgentGuard showcase metrics complete")
    print(
        "Unsafe detected: "
        f"{detection['unsafe_detected']}/{detection['unsafe_scenarios']} "
        f"({detection['unsafe_detection_rate_percent']:.2f}%)"
    )
    print(
        "Safe allowed: "
        f"{detection['safe_allowed']}/{detection['safe_scenarios']} "
        f"({detection['safe_allowance_rate_percent']:.2f}%)"
    )
    print(f"False positives: {detection['false_positive_count']}")
    print(f"False negatives: {detection['false_negative_count']}")
    print(
        "Overhead median: "
        f"{overhead['absolute_overhead_median_seconds']:.4f}s "
        f"({overhead['relative_overhead_median_percent']:.2f}%)"
    )
    print(f"Metrics JSON: {_portable_path(args.metrics_json)}")
    print(f"Metrics Markdown: {_portable_path(args.metrics_json.with_suffix('.md'))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
