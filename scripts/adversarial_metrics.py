#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
import sys
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentguard import __version__  # noqa: E402
from agentguard.benchmarks.contracts import load_benchmark_contract  # noqa: E402
from agentguard.benchmarks.registry import (  # noqa: E402
    find_benchmark,
    load_benchmark_registry,
)
from agentguard.config.loader import load_config  # noqa: E402
from agentguard.core.suite import load_suite_config  # noqa: E402
from agentguard.io import atomic_write_json, atomic_write_text  # noqa: E402


DEFAULT_PACK = "adversarial-core"
DEFAULT_PACK_PATH = Path("examples/benchmarks/adversarial-core.yaml")
DEFAULT_METRICS_JSON = Path("docs/results/adversarial-metrics.json")
KNOWN_GUARDS = {
    "diff_size",
    "forbidden_paths",
    "scope_adherence",
    "secret_scan",
    "test_tampering",
    "unsafe_commands",
}
KNOWN_MODES = {"post-hoc", "online"}
REQUIRED_SCENARIO_FIELDS = {
    "id",
    "category",
    "config",
    "repo",
    "contract",
    "description",
    "threat_model",
    "expected_safe_outcome",
    "expected_unsafe_behavior",
    "expected_guards",
    "mode",
    "notes",
}


def _portable_path(path: Path) -> str:
    try:
        return path.expanduser().resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict):
        raise ValueError(f"Expected mapping in {path}.")
    return data


def _metrics_paths(output_dir: Path | None, metrics_json: Path | None) -> tuple[Path, Path]:
    if output_dir is not None and metrics_json is not None:
        raise ValueError("--output-dir and --metrics-json cannot be used together.")
    if output_dir is not None:
        json_path = output_dir / "adversarial-metrics.json"
    else:
        json_path = metrics_json or DEFAULT_METRICS_JSON
    return json_path, json_path.with_suffix(".md")


def _validate_pack(pack: dict[str, Any], pack_path: Path) -> None:
    if pack.get("schema") != "agentguard.adversarial-benchmark-pack":
        raise ValueError(f"{pack_path} has unexpected schema.")
    if pack.get("schema_version") != 1:
        raise ValueError(f"{pack_path} has unsupported schema_version.")
    if pack.get("pack_id") != DEFAULT_PACK:
        raise ValueError(f"{pack_path} is not the {DEFAULT_PACK} pack.")
    scenarios = pack.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError(f"{pack_path} must define at least one scenario.")
    declared_categories = set(pack.get("categories") or [])
    declared_guards = set(pack.get("detection_surfaces") or [])
    if not declared_categories:
        raise ValueError(f"{pack_path} must declare categories.")
    unknown_guards = declared_guards - KNOWN_GUARDS
    if unknown_guards:
        raise ValueError(f"{pack_path} declares unknown guards: {sorted(unknown_guards)}")
    if not declared_guards:
        raise ValueError(f"{pack_path} must declare detection surfaces.")

    for scenario in scenarios:
        missing = REQUIRED_SCENARIO_FIELDS - set(scenario)
        if missing:
            raise ValueError(
                f"Scenario {scenario.get('id', '<unknown>')} missing fields: "
                f"{sorted(missing)}"
            )
        category = scenario["category"]
        if category not in declared_categories:
            raise ValueError(f"Scenario {scenario['id']} has undeclared category {category}.")
        expected_guards = set(scenario.get("expected_guards") or [])
        if not expected_guards:
            raise ValueError(f"Scenario {scenario['id']} must declare expected guards.")
        unknown_expected = expected_guards - KNOWN_GUARDS
        if unknown_expected:
            raise ValueError(
                f"Scenario {scenario['id']} declares unknown guards: "
                f"{sorted(unknown_expected)}"
            )
        modes = set(scenario.get("mode") or [])
        if not modes or modes - KNOWN_MODES:
            raise ValueError(f"Scenario {scenario['id']} has invalid mode values.")


def _validate_references(pack: dict[str, Any]) -> None:
    registry = load_benchmark_registry(Path(pack["registry"]))
    suite = load_suite_config(Path(pack["suite"]))
    suite_configs = {run.config_path for run in suite.runs}
    if {run.agent for run in suite.runs} != {"local-command"}:
        raise ValueError("adversarial-core suite must use local-command only.")

    for scenario in pack["scenarios"]:
        config_path = Path(scenario["config"])
        repo_path = Path(scenario["repo"])
        contract_path = Path(scenario["contract"])
        if config_path not in suite_configs:
            raise ValueError(f"{config_path} is not included in {pack['suite']}.")
        config = load_config(config_path)
        if config.sandbox.type != "local":
            raise ValueError(f"{config_path} must use the local sandbox.")
        if config.repo_template != repo_path.resolve():
            raise ValueError(f"{config_path} does not point at {repo_path}.")
        if not contract_path.is_file():
            raise ValueError(f"Missing contract: {contract_path}.")
        contract = load_benchmark_contract(contract_path)
        if find_benchmark(registry, contract.benchmark_id) is None:
            raise ValueError(
                f"Contract {contract_path} references unregistered benchmark "
                f"{contract.benchmark_id}."
            )


def build_metrics_report(
    *,
    pack_path: Path = DEFAULT_PACK_PATH,
    metrics_json_path: Path = DEFAULT_METRICS_JSON,
) -> dict[str, Any]:
    pack = _load_yaml(pack_path)
    _validate_pack(pack, pack_path)
    _validate_references(pack)

    scenarios = list(pack["scenarios"])
    category_counts = Counter(str(scenario["category"]) for scenario in scenarios)
    guard_counts = Counter(
        guard for scenario in scenarios for guard in scenario["expected_guards"]
    )
    mode_counts = Counter(mode for scenario in scenarios for mode in scenario["mode"])
    scenario_rows = [
        {
            "id": str(scenario["id"]),
            "category": str(scenario["category"]),
            "config": _portable_path(Path(scenario["config"])),
            "repo": _portable_path(Path(scenario["repo"])),
            "threat_model": str(scenario["threat_model"]),
            "expected_safe_outcome": str(scenario["expected_safe_outcome"]),
            "expected_unsafe_behavior": str(scenario["expected_unsafe_behavior"]),
            "expected_guards": sorted(str(item) for item in scenario["expected_guards"]),
            "validation_modes": sorted(str(item) for item in scenario["mode"]),
        }
        for scenario in scenarios
    ]
    metrics_markdown_path = metrics_json_path.with_suffix(".md")
    return {
        "schema": "agentguard.adversarial-metrics",
        "schema_version": 1,
        "name": "AgentGuard adversarial-core metrics",
        "agentguard_version": __version__,
        "generated_by": "scripts/adversarial_metrics.py",
        "pack": {
            "id": pack["pack_id"],
            "title": pack["title"],
            "version": str(pack["version"]),
            "status": pack["status"],
            "descriptor": _portable_path(pack_path),
            "registry": _portable_path(Path(pack["registry"])),
            "suite": _portable_path(Path(pack["suite"])),
            "run_command": pack["run_command"],
        },
        "metrics_artifacts": {
            "json": _portable_path(metrics_json_path),
            "markdown": _portable_path(metrics_markdown_path),
        },
        "validation": {
            "kind": "metadata validation",
            "runtime_validated": False,
            "runtime_smoke_command": pack["run_command"],
            "notes": [
                "Metrics validate pack metadata, references, expected detections, and docs artifacts.",
                "Runtime smoke is performed separately with the adversarial-core suite to avoid committing volatile run output.",
            ],
        },
        "coverage": {
            "total_scenarios": len(scenarios),
            "safe_scenarios": 0,
            "unsafe_scenarios": len(scenarios),
            "expected_unsafe_detections": len(scenarios),
            "expected_safe_allowances": 0,
            "scenario_ids": sorted(str(scenario["id"]) for scenario in scenarios),
            "categories": sorted(category_counts),
            "category_counts": dict(sorted(category_counts.items())),
            "threat_model_count": len(
                {str(scenario["threat_model"]) for scenario in scenarios}
            ),
            "detection_surfaces": sorted(str(item) for item in pack["detection_surfaces"]),
            "expected_guard_counts": dict(sorted(guard_counts.items())),
            "validation_mode_counts": dict(sorted(mode_counts.items())),
        },
        "scenarios": scenario_rows,
        "coverage_gaps": list(pack["limitations"]),
        "sanitization": {
            "fake_secrets_only": True,
            "fake_secret_values_rendered": False,
            "raw_diffs_included": False,
            "absolute_workspace_paths_included": False,
            "environment_variables_included": False,
            "raw_command_logs_included": False,
            "generated_agentguard_output_included": False,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    coverage = report["coverage"]
    pack = report["pack"]
    categories = ", ".join(coverage["categories"])
    guards = ", ".join(coverage["detection_surfaces"])
    lines = [
        "# AgentGuard Adversarial Metrics",
        "",
        "## Summary",
        "",
        f"- Pack: `{pack['id']}` ({pack['title']})",
        f"- Total scenarios: {coverage['total_scenarios']}",
        f"- Unsafe scenarios: {coverage['unsafe_scenarios']}",
        f"- Safe scenarios: {coverage['safe_scenarios']}",
        f"- Expected unsafe detections: {coverage['expected_unsafe_detections']}",
        f"- Expected safe allowances: {coverage['expected_safe_allowances']}",
        f"- Categories covered: {categories}",
        f"- Expected detection surfaces: {guards}",
        "",
        "## Validation Mode",
        "",
        "- Primary artifact: metadata validation",
        "- Runtime validation in this artifact: false",
        f"- Runtime smoke command: `{report['validation']['runtime_smoke_command']}`",
        "",
        "## How To Run",
        "",
        "```bash",
        "agentguard suite examples/suites/adversarial_core.yaml --allow-failures",
        ".venv/bin/python scripts/adversarial_metrics.py",
        ".venv/bin/python scripts/adversarial_metrics.py --check",
        "```",
        "",
        "## Scenario Coverage",
        "",
        "| Scenario | Category | Expected guards | Validation modes |",
        "| --- | --- | --- | --- |",
    ]
    for scenario in report["scenarios"]:
        lines.append(
            f"| `{scenario['id']}` | `{scenario['category']}` | "
            f"{', '.join(scenario['expected_guards'])} | "
            f"{', '.join(scenario['validation_modes'])} |"
        )

    lines.extend(
        [
            "",
            "## Guard Coverage",
            "",
            "| Guard | Scenario count |",
            "| --- | ---: |",
        ]
    )
    for guard, count in coverage["expected_guard_counts"].items():
        lines.append(f"| `{guard}` | {count} |")

    lines.extend(
        [
            "",
            "## Sanitization",
            "",
            "- Metrics artifacts use repo-relative paths and sanitized category/check IDs.",
            "- Metrics artifacts omit fake secret values, raw diffs, command logs, environment variables, generated `.agentguard` output, and absolute workspace paths.",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report["coverage_gaps"])
    lines.append("")
    return "\n".join(lines)


def write_metrics(report: dict[str, Any], metrics_json_path: Path) -> None:
    atomic_write_json(metrics_json_path, report)
    atomic_write_text(metrics_json_path.with_suffix(".md"), render_markdown(report))


def check_metrics(report: dict[str, Any], metrics_json_path: Path) -> list[str]:
    expected_json = json.dumps(report, indent=2) + "\n"
    expected_markdown = render_markdown(report)
    markdown_path = metrics_json_path.with_suffix(".md")
    failures: list[str] = []
    if not metrics_json_path.is_file():
        failures.append(f"missing {metrics_json_path}")
    elif metrics_json_path.read_text(encoding="utf-8") != expected_json:
        failures.append(f"stale {metrics_json_path}")
    if not markdown_path.is_file():
        failures.append(f"missing {markdown_path}")
    elif markdown_path.read_text(encoding="utf-8") != expected_markdown:
        failures.append(f"stale {markdown_path}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic adversarial-core benchmark metrics."
    )
    parser.add_argument("--pack", default=DEFAULT_PACK)
    parser.add_argument("--pack-path", type=Path, default=DEFAULT_PACK_PATH)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--metrics-json", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.pack != DEFAULT_PACK:
        print(f"Unsupported adversarial pack: {args.pack}", file=sys.stderr)
        return 2
    try:
        metrics_json_path, metrics_markdown_path = _metrics_paths(
            args.output_dir,
            args.metrics_json,
        )
        report = build_metrics_report(
            pack_path=args.pack_path,
            metrics_json_path=metrics_json_path,
        )
        if args.check:
            failures = check_metrics(report, metrics_json_path)
            if failures:
                print("Adversarial metrics check failed", file=sys.stderr)
                for failure in failures:
                    print(f"- {failure}", file=sys.stderr)
                return 1
            print("Adversarial metrics check passed")
        else:
            write_metrics(report, metrics_json_path)
            print("AgentGuard adversarial metrics complete")
        coverage = report["coverage"]
        print(f"Pack: {report['pack']['id']}")
        print(f"Scenarios: {coverage['total_scenarios']}")
        print(f"Categories: {', '.join(coverage['categories'])}")
        print(f"Expected guards: {', '.join(coverage['detection_surfaces'])}")
        print(f"Metrics JSON: {_portable_path(metrics_json_path)}")
        print(f"Metrics Markdown: {_portable_path(metrics_markdown_path)}")
        return 0
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
