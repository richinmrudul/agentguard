#!/usr/bin/env python3
import argparse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agentguard import __version__
from agentguard.core.suite import SuiteResult, run_suite
from agentguard.guard.filesystem import GuardMode
from agentguard.io import atomic_write_json, atomic_write_text


DEFAULT_SUITE = Path("examples/showcase/showcase.yaml")
DEFAULT_OUTPUT_DIR = Path(".agentguard/showcase")
SAFE_CATEGORY = "source_fix"


def _portable_path(path: Path) -> str:
    cwd = Path.cwd().resolve()
    try:
        return path.resolve().relative_to(cwd).as_posix()
    except ValueError:
        return path.name


def _load_json(path: Path) -> dict[str, Any]:
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_expected(category: str) -> str:
    return "allowed" if category == SAFE_CATEGORY else "detected"


def _scenario_met_expectation(category: str, result: str) -> bool:
    if category == SAFE_CATEGORY:
        return result == "PASS"
    return result == "FAIL"


def build_showcase_summary(
    suite_result: SuiteResult,
    *,
    summary_json_path: Path,
    summary_markdown_path: Path,
) -> dict[str, Any]:
    scenarios: list[dict[str, Any]] = []
    categories: dict[str, dict[str, Any]] = {}
    failed_check_counts: Counter[str] = Counter()
    report_formats = {
        "json_report",
        "markdown_report",
        "suite_json",
        "suite_markdown",
        "manifest",
    }
    trace_count = 0
    guard_incident_count = 0

    for run in suite_result.runs:
        category = run.category or "uncategorized"
        expected = _scenario_expected(category)
        met_expectation = _scenario_met_expectation(category, run.result)
        failed_check_counts.update(run.failed_checks)
        run_report = _load_json(run.json_report_path)
        if run_report.get("trace_path"):
            trace_count += 1
            report_formats.add("trace")
        if run_report.get("command_log_path"):
            report_formats.add("command_log")
        if run_report.get("guard_incident_path"):
            guard_incident_count += 1
            report_formats.add("guard_incident")

        category_summary = categories.setdefault(
            category,
            {
                "total": 0,
                "detected": 0,
                "allowed": 0,
                "failed_checks": [],
            },
        )
        category_summary["total"] += 1
        if run.result == "FAIL":
            category_summary["detected"] += 1
        else:
            category_summary["allowed"] += 1
        category_summary["failed_checks"] = sorted(
            set(category_summary["failed_checks"]) | set(run.failed_checks)
        )

        scenarios.append(
            {
                "id": run.benchmark_id or run.task_id,
                "task_id": run.task_id,
                "category": category,
                "expected": expected,
                "met_expectation": met_expectation,
                "result": run.result,
                "score": run.score,
                "failed_checks": run.failed_checks,
                "report_json": _portable_path(run.json_report_path),
                "report_markdown": _portable_path(run.markdown_report_path),
            }
        )

    unsafe = [item for item in scenarios if item["expected"] == "detected"]
    safe = [item for item in scenarios if item["expected"] == "allowed"]
    summary = {
        "name": "AgentGuard showcase",
        "agentguard_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite": {
            "id": suite_result.suite_id,
            "description": suite_result.description,
            "config": _portable_path(suite_result.suite_path),
            "json_report": _portable_path(suite_result.json_report_path),
            "markdown_report": _portable_path(suite_result.markdown_report_path),
            "manifest": (
                _portable_path(suite_result.manifest_path)
                if suite_result.manifest_path is not None
                else None
            ),
        },
        "summary_artifacts": {
            "json": _portable_path(summary_json_path),
            "markdown": _portable_path(summary_markdown_path),
        },
        "total_scenarios": len(scenarios),
        "scenarios_passed_as_expected": sum(
            1 for item in scenarios if item["met_expectation"]
        ),
        "safe_scenarios_allowed": sum(
            1 for item in safe if item["result"] == "PASS"
        ),
        "unsafe_scenarios_detected": sum(
            1 for item in unsafe if item["result"] == "FAIL"
        ),
        "detection_categories_covered": sorted(
            category for category in categories if category != SAFE_CATEGORY
        ),
        "categories": dict(sorted(categories.items())),
        "failed_check_counts": dict(sorted(failed_check_counts.items())),
        "report_formats_generated": sorted(report_formats),
        "trace_replay_available": trace_count == len(scenarios),
        "guard_incident_count": guard_incident_count,
        "uses_fake_secrets_only": True,
        "fake_secret_value_rendered": False,
        "scenarios": scenarios,
    }
    return summary


def render_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# AgentGuard Showcase Summary",
        "",
        f"- Scenarios: {summary['total_scenarios']}",
        f"- Met expectations: {summary['scenarios_passed_as_expected']}",
        f"- Safe scenarios allowed: {summary['safe_scenarios_allowed']}",
        f"- Unsafe scenarios detected: {summary['unsafe_scenarios_detected']}",
        "- Categories: "
        + ", ".join(summary["detection_categories_covered"]),
        "- Reports: " + ", ".join(summary["report_formats_generated"]),
        f"- Trace/replay available: {summary['trace_replay_available']}",
        f"- Guard incidents: {summary['guard_incident_count']}",
        "",
        "## Scenario Results",
        "",
        "| Scenario | Category | Expected | Result | Score | Failed checks |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for scenario in summary["scenarios"]:
        failed = ", ".join(scenario["failed_checks"]) or "-"
        lines.append(
            f"| {scenario['id']} | {scenario['category']} | "
            f"{scenario['expected']} | {scenario['result']} | "
            f"{scenario['score']} | {failed} |"
        )
    lines.extend(
        [
            "",
            "## Artifacts",
            "",
            f"- Suite JSON: {summary['suite']['json_report']}",
            f"- Suite Markdown: {summary['suite']['markdown_report']}",
            f"- Summary JSON: {summary['summary_artifacts']['json']}",
            f"- Summary Markdown: {summary['summary_artifacts']['markdown']}",
            "",
            "Fake showcase secrets are configured test strings only; generated "
            "summary artifacts do not render the fake secret value.",
            "",
        ]
    )
    return "\n".join(lines)


def run_showcase(
    suite_path: Path,
    output_dir: Path,
) -> tuple[dict[str, Any], Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    suite_result = run_suite(
        suite_path,
        suites_root=output_dir / "suites",
        guard_mode=GuardMode.OFF,
    )
    summary_json_path = output_dir / "showcase-summary.json"
    summary_markdown_path = output_dir / "showcase-summary.md"
    summary = build_showcase_summary(
        suite_result,
        summary_json_path=summary_json_path,
        summary_markdown_path=summary_markdown_path,
    )
    atomic_write_json(summary_json_path, summary)
    atomic_write_text(summary_markdown_path, render_markdown(summary))
    return summary, summary_json_path, summary_markdown_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the local AgentGuard showcase suite and write a detection summary."
    )
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    summary, summary_json_path, summary_markdown_path = run_showcase(
        args.suite,
        args.output_dir,
    )
    print("AgentGuard showcase complete")
    print(f"Scenarios: {summary['total_scenarios']}")
    print(f"Safe allowed: {summary['safe_scenarios_allowed']}")
    print(f"Unsafe detected: {summary['unsafe_scenarios_detected']}")
    print("Categories: " + ", ".join(summary["detection_categories_covered"]))
    print(f"Summary JSON: {_portable_path(summary_json_path)}")
    print(f"Summary Markdown: {_portable_path(summary_markdown_path)}")
    return 0 if summary["scenarios_passed_as_expected"] == summary["total_scenarios"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
