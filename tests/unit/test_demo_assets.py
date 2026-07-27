import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from agentguard.config.loader import load_config
from agentguard.core.suite import load_suite_config
from scripts.showcase_metrics import check_metrics_artifacts, compute_detection_metrics


FAKE_SHOWCASE_SECRET = "AGENTGUARD_SHOWCASE_SECRET_EXAMPLE"
SHOWCASE_SUMMARY_JSON = Path("docs/results/showcase-summary.json")
SHOWCASE_METRICS_JSON = Path("docs/results/showcase-metrics.json")
SHOWCASE_METRICS_MD = Path("docs/results/showcase-metrics.md")
DOC_PATHS_FOR_PRESENTATION = [
    Path("README.md"),
    Path("docs/portfolio.md"),
    Path("docs/showcase.md"),
    Path("docs/detection-quality.md"),
    Path("docs/benchmark-packs.md"),
    Path("docs/online-guard.md"),
    Path("docs/architecture.md"),
]


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _load_yaml(path: str) -> dict:
    return yaml.safe_load(_read(path))


def _command_blocks(markdown: str) -> list[str]:
    return re.findall(r"```(?:bash|yaml)\n(.*?)```", markdown, flags=re.DOTALL)


def test_demo_assets_exist_and_reference_required_commands() -> None:
    demo_doc = Path("docs/demo.md")
    demo_script = Path("scripts/demo.sh")
    readme = Path("README.md")

    assert demo_doc.exists()
    assert demo_script.exists()
    assert Path("docs/showcase.md").exists()
    assert Path("examples/showcase/showcase.yaml").exists()
    assert Path("scripts/showcase_demo.sh").exists()
    assert Path("scripts/showcase_metrics.py").exists()

    script = demo_script.read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    assert "--allow-fail-result" in script
    assert "--allow-failures" in script

    assert "docs/demo.md" in readme.read_text(encoding="utf-8")
    assert "docs/showcase.md" in readme.read_text(encoding="utf-8")


def test_resume_demo_selects_a_portable_python_interpreter() -> None:
    script = _read("scripts/resume_demo.sh")

    assert "AGENTGUARD_PYTHON" in script
    assert ".venv/bin/python" in script
    assert "PYTHON_BIN=python3" in script
    assert '"$PYTHON_BIN" - <<' in script


def test_readme_links_core_docs() -> None:
    readme = _read("README.md")

    for doc_path in [
        "docs/architecture.md",
        "docs/portfolio.md",
        "docs/demo.md",
        "docs/benchmarks.md",
    ]:
        assert Path(doc_path).exists()
        assert f"({doc_path})" in readme


def test_readme_portfolio_first_screen_references_existing_proof() -> None:
    readme = _read("README.md")

    required_text = [
        "local-first safety and evaluation harness",
        "What AgentGuard Catches",
        "Current Proof",
        "docs/results/validation-summary.md",
        "Architecture At A Glance",
        "Screenshots And Demo Assets",
        "v0.2.1` is the latest published GitHub release",
    ]
    for text in required_text:
        assert text in readme

    for path in [
        "scripts/showcase_demo.sh",
        "scripts/showcase_metrics.py",
        "scripts/adversarial_metrics.py",
        "examples/suites/adversarial_core.yaml",
        "docs/results/showcase-metrics.md",
        "docs/results/adversarial-metrics.md",
        "docs/results/release-candidate-v0.2.0.md",
        "docs/results/validation-summary.md",
        "examples/github-actions/",
    ]:
        assert Path(path).exists()
        assert path in readme


def test_portfolio_summary_references_existing_artifacts() -> None:
    portfolio = _read("docs/portfolio.md")

    for text in [
        "2.0 is published on GitHub",
        "results/validation-summary.md",
        "5/5 unsafe scenarios",
        "1/1 safe scenario",
        "10 deterministic `adversarial-core` scenarios",
        "GitHub Actions",
    ]:
        assert text in portfolio

    for path in [
        "docs/results/showcase-metrics.json",
        "docs/results/adversarial-metrics.json",
        "examples/suites/adversarial_core.yaml",
        "examples/github-actions/agentguard-showcase.yml",
        "docs/results/validation-summary.json",
        "docs/results/validation-summary.md",
    ]:
        assert Path(path).exists()


def test_public_validation_metrics_match_authoritative_summary() -> None:
    summary = json.loads(_read("docs/results/validation-summary.json"))
    markdown = _read("docs/results/validation-summary.md")
    testing = _read("docs/testing.md")
    readme = _read("README.md")
    portfolio = _read("docs/portfolio.md")

    assert summary["commit"] == "4ab779307a96827e8f979e02cb9e08276a84bb26"
    assert summary["recorded_date"] == "2026-07-24"
    assert summary["full_test_suite"] == {
        "command": ".venv/bin/python -m pytest",
        "passed": 1146,
        "skipped": 15,
        "warnings": 1,
    }
    coverage = summary["non_docker_coverage"]
    assert coverage["statement_percent"] == 91.45
    assert coverage["branch_percent"] == 80.45
    assert coverage["combined_percent"] == 88.83
    for value in ("91.45%", "80.45%", "88.83%"):
        assert value in markdown
        assert value in testing
    assert "docs/results/validation-summary.md" in readme
    assert "results/validation-summary.md" in portfolio
    combined = "\n".join((readme, portfolio, testing))
    assert "987 passed" not in combined
    assert "89.60%" not in combined


def test_presentation_docs_are_sanitized() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in DOC_PATHS_FOR_PRESENTATION
    )

    forbidden_patterns = [
        FAKE_SHOWCASE_SECRET,
        r"AGENTGUARD_SECRET",
        r"diff --git",
        r"/Users/",
        r"/private/",
        r"[A-Za-z]:\\\\",
        r"\bHOME=",
        r"\bTMPDIR=",
        r"javascript:",
        r"file:",
    ]
    for pattern in forbidden_patterns:
        assert not re.search(pattern, combined)


def test_benchmark_docs_match_registry_ids_and_categories() -> None:
    docs = _read("docs/benchmarks.md")
    registry = _load_yaml("examples/benchmarks/registry.yaml")
    benchmarks = registry["benchmarks"]

    for benchmark in benchmarks:
        row_prefix = f"| `{benchmark['id']}` | `{benchmark['category']}` |"
        assert row_prefix in docs

    documented_rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \|", docs, re.M)
    documented = {(benchmark_id, category) for benchmark_id, category in documented_rows}
    registered = {
        (benchmark["id"], benchmark["category"]) for benchmark in benchmarks
    }

    assert documented == registered

    for benchmark in benchmarks:
        contract_path = Path(benchmark["contract"])
        assert contract_path.exists()
        relative_contract = Path("..") / contract_path
        assert f"({relative_contract.as_posix()})" in docs


def test_documented_core_suite_count_matches_suite_config() -> None:
    docs = _read("docs/benchmarks.md")
    suite = _load_yaml("examples/suites/core.yaml")
    runs = suite["runs"]
    expected_pass = sum(
        1 for run in runs if Path(run["config"]).name.endswith("_safe.yaml")
    )
    expected_fail = len(runs) - expected_pass

    assert f"contains {len(runs)}\nruns" in docs
    assert f"{expected_pass} pass and {expected_fail} fail" in docs


def test_documented_command_snippet_paths_exist_where_practical() -> None:
    markdown_paths = [
        "README.md",
        "docs/demo.md",
        "docs/showcase.md",
        "docs/benchmarks.md",
    ]
    path_flags = {"--registry", "--output", "--baseline", "--save-baseline"}

    for markdown_path in markdown_paths:
        for block in _command_blocks(_read(markdown_path)):
            for line in block.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                tokens = shlex.split(stripped)
                skip_next = False
                for token in tokens:
                    if skip_next:
                        skip_next = False
                        continue
                    if token in path_flags:
                        skip_next = True
                        continue
                    if token.startswith(("docs/", "examples/", "scripts/")):
                        assert Path(token).exists(), (
                            f"{markdown_path} references missing path {token!r}"
                        )


def test_showcase_suite_loads_and_covers_expected_categories() -> None:
    suite = load_suite_config(Path("examples/showcase/showcase.yaml"))

    assert suite.suite_id == "showcase"
    assert len(suite.runs) == 6
    categories = {
        load_config(run.config_path).benchmark.category
        for run in suite.runs
    }
    assert categories == {
        "source_fix",
        "unsafe_command",
        "filesystem_boundary",
        "test_tampering",
        "secret_content",
        "diff_limit",
    }
    assert {run.agent for run in suite.runs} == {"local-command"}


def test_showcase_references_existing_files_and_local_sandbox() -> None:
    for run in load_suite_config(Path("examples/showcase/showcase.yaml")).runs:
        config = load_config(run.config_path)
        assert config.sandbox.type == "local"
        assert config.repo_template is not None
        assert config.repo_template.exists()
        command = config.agent_command
        assert isinstance(command, str)
        argv = shlex.split(command)
        assert argv[0].startswith("python")
        if len(argv) > 1 and argv[1].endswith(".py"):
            assert (config.repo_template / argv[1]).exists()


def test_showcase_summary_sample_is_stable_and_sanitized() -> None:
    summary_path = Path("docs/results/showcase-summary.json")
    markdown_path = Path("docs/results/showcase-summary.md")
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    combined = (
        summary_path.read_text(encoding="utf-8")
        + "\n"
        + markdown_path.read_text(encoding="utf-8")
    )

    assert summary["total_scenarios"] == 6
    assert summary["safe_scenarios_allowed"] == 1
    assert summary["unsafe_scenarios_detected"] == 5
    assert summary["scenarios_passed_as_expected"] == 6
    assert set(summary["detection_categories_covered"]) == {
        "unsafe_command",
        "filesystem_boundary",
        "test_tampering",
        "secret_content",
        "diff_limit",
    }
    assert summary["fake_secret_value_rendered"] is False
    assert FAKE_SHOWCASE_SECRET not in combined
    assert not re.search(r"(/Users/|/private/|[A-Za-z]:\\\\)", combined)


def test_showcase_metrics_calculation_tracks_false_results() -> None:
    metrics = compute_detection_metrics(
        {
            "scenarios": [
                {
                    "id": "safe",
                    "category": "source_fix",
                    "expected": "allowed",
                    "result": "FAIL",
                    "failed_checks": ["Scope adherence"],
                },
                {
                    "id": "unsafe_hit",
                    "category": "unsafe_command",
                    "expected": "detected",
                    "result": "FAIL",
                    "failed_checks": ["Unsafe commands"],
                },
                {
                    "id": "unsafe_miss",
                    "category": "secret_content",
                    "expected": "detected",
                    "result": "PASS",
                    "failed_checks": [],
                },
            ],
            "failed_check_counts": {"Unsafe commands": 1},
            "report_formats_generated": ["json_report", "trace"],
            "guard_incident_count": 2,
        }
    )

    assert metrics["total_scenarios"] == 3
    assert metrics["safe_scenarios"] == 1
    assert metrics["unsafe_scenarios"] == 2
    assert metrics["safe_allowed"] == 0
    assert metrics["unsafe_detected"] == 1
    assert metrics["false_positive_count"] == 1
    assert metrics["false_negative_count"] == 1
    assert metrics["false_positive_scenarios"] == ["safe"]
    assert metrics["false_negative_scenarios"] == ["unsafe_miss"]
    assert metrics["unsafe_detection_rate_percent"] == 50.0
    assert metrics["safe_allowance_rate_percent"] == 0.0
    assert metrics["category_coverage"] == ["secret_content", "unsafe_command"]
    assert metrics["categories"]["source_fix"]["false_positives"] == 1
    assert metrics["categories"]["secret_content"]["false_negatives"] == 1
    assert metrics["report_availability"]["json_reports"] == 3
    assert metrics["report_availability"]["traces"] == 3


def test_showcase_metrics_artifacts_are_stable_and_sanitized() -> None:
    metrics_path = SHOWCASE_METRICS_JSON
    markdown_path = SHOWCASE_METRICS_MD
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    combined = (
        metrics_path.read_text(encoding="utf-8")
        + "\n"
        + markdown_path.read_text(encoding="utf-8")
    )
    detection = metrics["detection_quality"]
    overhead = metrics["overhead"]

    assert metrics["schema"] == "agentguard.showcase-metrics"
    assert metrics["schema_version"] == 1
    assert detection["total_scenarios"] == 6
    assert detection["safe_scenarios"] == 1
    assert detection["unsafe_scenarios"] == 5
    assert detection["safe_allowed"] == 1
    assert detection["unsafe_detected"] == 5
    assert detection["false_positive_count"] == 0
    assert detection["false_negative_count"] == 0
    assert detection["unsafe_detection_rate_percent"] == 100.0
    assert detection["safe_allowance_rate_percent"] == 100.0
    assert set(detection["category_coverage"]) == {
        "unsafe_command",
        "filesystem_boundary",
        "test_tampering",
        "secret_content",
        "diff_limit",
    }
    assert overhead["runs_measured"] >= 1
    assert overhead["baseline_median_seconds"] >= 0
    assert overhead["guard_enabled_median_seconds"] >= 0
    assert "Detection Quality" in markdown_path.read_text(encoding="utf-8")
    assert "Local Overhead Measurement" in markdown_path.read_text(encoding="utf-8")
    assert metrics["sanitization"]["fake_secret_value_rendered"] is False
    assert metrics["sanitization"]["raw_diffs_included"] is False
    assert metrics["sanitization"]["absolute_workspace_paths_included"] is False
    assert FAKE_SHOWCASE_SECRET not in combined
    assert "diff --git" not in combined
    assert "\n@@" not in combined
    assert not re.search(r"(/Users/|/private/|[A-Za-z]:\\\\)", combined)


def test_showcase_metrics_check_mode_does_not_rewrite_artifacts() -> None:
    before_json = SHOWCASE_METRICS_JSON.read_text(encoding="utf-8")
    before_markdown = SHOWCASE_METRICS_MD.read_text(encoding="utf-8")

    check_metrics_artifacts(
        summary_json_path=SHOWCASE_SUMMARY_JSON,
        metrics_json_path=SHOWCASE_METRICS_JSON,
    )

    assert SHOWCASE_METRICS_JSON.read_text(encoding="utf-8") == before_json
    assert SHOWCASE_METRICS_MD.read_text(encoding="utf-8") == before_markdown


def _copy_showcase_metrics(tmp_path: Path) -> Path:
    metrics_path = tmp_path / "showcase-metrics.json"
    markdown_path = tmp_path / "showcase-metrics.md"
    metrics = json.loads(SHOWCASE_METRICS_JSON.read_text(encoding="utf-8"))
    metrics["metrics_artifacts"] = {
        "json": metrics_path.name,
        "markdown": markdown_path.name,
    }
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(
        SHOWCASE_METRICS_MD.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return metrics_path


def test_showcase_metrics_check_mode_ignores_timing_only_differences(
    tmp_path: Path,
) -> None:
    metrics_path = _copy_showcase_metrics(tmp_path)
    markdown_path = metrics_path.with_suffix(".md")
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics["overhead"]["baseline_median_seconds"] = 123.4567
    metrics["overhead"]["guard_enabled_median_seconds"] = 234.5678
    metrics["overhead"]["absolute_overhead_median_seconds"] = 111.1111
    metrics["overhead"]["relative_overhead_median_percent"] = 99.9999
    metrics["overhead"]["slowdown_ratio_median"] = 2.2222
    metrics["overhead"]["direct_throughput_runs_per_minute"] = 3.3333
    metrics["overhead"]["agentguard_throughput_runs_per_minute"] = 4.4444
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")
    markdown = markdown.replace("- Direct median: 0.0578s", "- Direct median: 123.4567s")
    markdown = markdown.replace(
        "- AgentGuard median: 0.3093s",
        "- AgentGuard median: 234.5678s",
    )
    markdown = markdown.replace(
        "- Median absolute overhead: 0.2515s",
        "- Median absolute overhead: 111.1111s",
    )
    markdown = markdown.replace(
        "- Median relative overhead: 435.03%",
        "- Median relative overhead: 99.99%",
    )
    markdown = markdown.replace(
        "- Median slowdown ratio: 5.3503x",
        "- Median slowdown ratio: 2.2222x",
    )
    markdown_path.write_text(markdown, encoding="utf-8")

    check_metrics_artifacts(
        summary_json_path=SHOWCASE_SUMMARY_JSON,
        metrics_json_path=metrics_path,
    )


def test_showcase_metrics_check_mode_detects_stale_stable_metrics(
    tmp_path: Path,
) -> None:
    metrics_path = _copy_showcase_metrics(tmp_path)
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    metrics["detection_quality"]["unsafe_detected"] = 4
    metrics_path.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(AssertionError, match="stable fields"):
        check_metrics_artifacts(
            summary_json_path=SHOWCASE_SUMMARY_JSON,
            metrics_json_path=metrics_path,
        )


def test_showcase_script_help_works() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/showcase_demo.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Run the local AgentGuard showcase suite" in result.stdout


def test_showcase_metrics_script_help_works() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/showcase_metrics.py", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Generate sanitized detection-quality" in result.stdout
    assert "--check" in result.stdout


def test_showcase_metrics_check_cli_works_without_writes() -> None:
    before_json = SHOWCASE_METRICS_JSON.read_text(encoding="utf-8")
    before_markdown = SHOWCASE_METRICS_MD.read_text(encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "scripts/showcase_metrics.py", "--check"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Showcase metrics check passed" in result.stdout
    assert SHOWCASE_METRICS_JSON.read_text(encoding="utf-8") == before_json
    assert SHOWCASE_METRICS_MD.read_text(encoding="utf-8") == before_markdown
