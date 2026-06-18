import json
import re
from pathlib import Path

from typer.testing import CliRunner

from agentguard.cli.main import app


runner = CliRunner()
REPO_ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_CLAIMS = [
    "proved secure",
    "production-ready security",
    "guaranteed",
    "OpenAI-level",
    "real-world false-positive rate",
]


def test_report_generated_from_complete_fixture_inputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    paths = _write_complete_inputs(tmp_path)
    output = tmp_path / "evaluation-report.md"
    summary = tmp_path / "evaluation-report.json"

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--output",
            str(output),
            "--summary-json",
            str(summary),
            "--force",
            "--include-machine-specific",
            *_override_args(paths),
        ],
    )

    assert result.exit_code == 0
    markdown = output.read_text(encoding="utf-8")
    lowered_markdown = markdown.lower()
    data = json.loads(summary.read_text(encoding="utf-8"))
    assert "# AgentGuard Evaluation Report" in markdown
    assert "controlled mutation detection rate" in lowered_markdown
    assert "safe-fixture pass rate" in lowered_markdown
    assert "synthetic scheduler" in lowered_markdown
    assert "machine-specific overhead" in lowered_markdown
    assert "replay equivalence on deterministic traces" in lowered_markdown
    assert "| Benchmark families | 2 |" in markdown
    assert "| Controlled mutation detection rate | 100% |" in markdown
    assert "| Scope adherence | 2 | 1 | 1 | 50% |" in markdown
    assert "| Counterfactual policy comparison | policies_compared | 2 |" in markdown
    assert data["schema"] == "agentguard.evaluation-report"
    assert data["schema_version"] == 1
    assert data["missing_sections"] == []
    assert len(data["source_files"]) == 10


def test_report_generated_with_missing_optional_sections(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    release = _write_json(tmp_path / "release.json", _release_candidate())
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(release),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert "Unavailable" in text
    assert "Machine-specific timing/scale sections were omitted" in text
    summary = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
    assert "ablation" in summary["missing_sections"]
    assert "overhead" in summary["omitted_sections"]


def test_fails_when_all_inputs_missing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(
        app,
        ["evaluation", "report", "--output", str(tmp_path / "report.md")],
    )

    assert result.exit_code == 2
    assert "No evaluation summary inputs" in result.output


def test_fails_on_malformed_json(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("{bad", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(bad),
            "--output",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.exit_code == 2
    assert "Malformed JSON" in result.output


def test_fails_on_unsupported_known_schema(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    bad = _write_json(
        tmp_path / "bad-schema.json",
        {"schema": "agentguard.future-summary", "schema_version": 1},
    )

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(bad),
            "--output",
            str(tmp_path / "report.md"),
        ],
    )

    assert result.exit_code == 2
    assert "unsupported schema" in result.output


def test_summary_json_contains_input_hashes(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    release = _write_json(tmp_path / "release.json", _release_candidate())
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(release),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    data = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
    assert data["source_files"][0]["path"] == "release.json"
    assert re.fullmatch(r"[0-9a-f]{64}", data["source_files"][0]["sha256"])


def test_no_absolute_local_paths_or_forbidden_claims(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    release_data = _release_candidate()
    release_data["limitations"].append(f"temporary output {tmp_path}/secret.txt")
    release_data["mutation_diagnostic"]["note"] = "password=abc123"
    release = _write_json(tmp_path / "release.json", release_data)
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(release),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    text = output.read_text(encoding="utf-8")
    summary_text = output.with_suffix(".json").read_text(encoding="utf-8")
    assert str(tmp_path) not in text
    assert str(tmp_path) not in summary_text
    assert "abc123" not in text
    for claim in FORBIDDEN_CLAIMS:
        assert claim not in text


def test_force_overwrite_behavior_and_cli_exit_codes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    release = _write_json(tmp_path / "release.json", _release_candidate())
    output = tmp_path / "report.md"
    output.write_text("old", encoding="utf-8")

    conflict = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(release),
            "--output",
            str(output),
        ],
    )
    forced = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(release),
            "--output",
            str(output),
            "--force",
        ],
    )

    assert conflict.exit_code == 2
    assert "Use --force" in conflict.output
    assert forced.exit_code == 0
    assert "Evaluation report:" in forced.output


def test_reproduction_commands_reference_existing_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    release = _write_json(tmp_path / "release.json", _release_candidate())
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "evaluation",
            "report",
            "--release-candidate",
            str(release),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    text = output.read_text(encoding="utf-8")
    for path in [
        "scripts/coverage.sh",
        "scripts/validate_release_artifacts.py",
        "docs/testing.md",
        "docs/detection-quality.md",
        "docs/policy-ablation.md",
        "docs/scalability.md",
        "docs/resume.md",
        "docs/replay.md",
        "docs/metamorphic-traces.md",
    ]:
        assert path in text
        assert (REPO_ROOT / path).exists()


def test_readme_links_to_generated_evaluation_report() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "[Evaluation Results](docs/results/evaluation-report.md)" in readme


def _override_args(paths: dict[str, Path]) -> list[str]:
    args = []
    for key, path in sorted(paths.items()):
        args.extend([f"--{key.replace('_', '-')}", str(path)])
    return args


def _write_complete_inputs(tmp_path: Path) -> dict[str, Path]:
    return {
        "release_candidate": _write_json(tmp_path / "release.json", _release_candidate()),
        "mutation": _write_json(tmp_path / "mutation.json", _generic_metrics()),
        "ablation": _write_json(tmp_path / "ablation.json", _ablation()),
        "overhead": _write_json(tmp_path / "overhead.json", _generic_metrics()),
        "scale": _write_json(tmp_path / "scale.json", _scale()),
        "resume": _write_json(tmp_path / "resume.json", _resume()),
        "replay": _write_json(tmp_path / "replay.json", _replay()),
        "counterfactual": _write_json(tmp_path / "counterfactual.json", _generic_metrics()),
        "metamorphic": _write_json(tmp_path / "metamorphic.json", _metamorphic()),
        "coverage": _write_json(tmp_path / "coverage.json", _generic_metrics()),
    }


def _write_json(path: Path, data: dict[str, object]) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _release_candidate() -> dict[str, object]:
    return {
        "schema": "agentguard.release-candidate-summary",
        "schema_version": 1,
        "date": "2026-06-17",
        "benchmark_corpus": {
            "families": 2,
            "scenarios": 4,
            "safe_scenarios": 2,
            "adversarial_scenarios": 2,
            "static_contracts_passed": 4,
            "static_contracts_failed": 0,
        },
        "tests": {
            "collected": 10,
            "passed": 9,
            "skipped_docker": 1,
            "docker_status": "daemon unavailable locally",
        },
        "coverage": {
            "scope": "non-Docker",
            "statement_percent": 91.5,
            "branch_percent": 78.8,
            "combined_percent": 88.6,
            "gate_percent": 88.0,
            "gate_passed": True,
        },
        "mutation_diagnostic": {
            "unsafe_mutations": 2,
            "safe_mutations": 2,
            "controlled_expected_detections": 2,
            "observed_expected_detections": 2,
            "controlled_mutation_detection_rate_percent": 100.0,
            "safe_fixture_pass_rate_percent": 100.0,
            "missed_detections": 0,
            "forbidden_detections": 0,
            "unexpected_detections": 0,
        },
        "instrumentation_overhead": {
            "machine_specific": True,
            "workload": "deterministic mock fixture",
            "measured_iterations": 5,
            "warmups": 1,
            "direct_median_seconds": 0.1,
            "agentguard_median_seconds": 0.2,
            "median_absolute_overhead_seconds": 0.1,
            "median_relative_overhead_percent": 100.0,
            "median_slowdown_ratio": 2.0,
        },
        "python_support": ["3.9", "3.10"],
        "package_validation": {
            "wheel_built": True,
            "sdist_built": True,
            "artifact_contents_validated": True,
            "installed_wheel_smoke_passed": True,
            "manifest_verification_passed": True,
            "published": False,
        },
        "limitations": [
            "Controlled mutation and ablation results are synthetic.",
        ],
    }


def _ablation() -> dict[str, object]:
    return {
        "schema": "agentguard.policy-ablation-summary",
        "schema_version": 1,
        "result_type": "controlled synthetic mutations",
        "trials": 3,
        "workers": 2,
        "control_valid": True,
        "stable": True,
        "aggregate_metrics": {
            "unsafe_mutations": 2,
            "safe_mutations": 2,
            "controlled_expected_detections": 2,
            "observed_expected_detections": 2,
            "controlled_mutation_detection_rate": 100.0,
            "safe_fixture_pass_rate": 100.0,
        },
        "per_check_contributions": [
            {
                "check": "Scope adherence",
                "direct_expected_detection_opportunities": 2,
                "detections_uniquely_attributable": 1,
                "detections_redundantly_covered": 1,
                "contribution_percentage": 50.0,
            }
        ],
        "limitations": ["Synthetic catalog only."],
    }


def _scale() -> dict[str, object]:
    return {
        "schema": "agentguard.matrix-stress-summary",
        "schema_version": 1,
        "result_type": "synthetic scheduler/report/history workload",
        "scaling_summary": {
            "maximum_validated_attempts": 100,
            "best_measured_speedup": 4.0,
            "best_speedup_workers": 4,
            "best_speedup_attempts": 100,
            "best_throughput_attempts_per_second": 100.0,
            "maximum_peak_traced_python_memory_bytes": 12345,
            "integrity_passed": True,
        },
        "limitations": ["Synthetic scheduler workload."],
    }


def _resume() -> dict[str, object]:
    return {
        "schema": "agentguard.matrix-resume-summary",
        "schema_version": 1,
        "result_type": "deterministic local mock matrix checkpoint/resume smoke test",
        "configuration": {"planned_attempts": 4},
        "resume_metrics": {
            "completed_before_interruption": 2,
            "reused_attempts": 2,
            "skipped_attempts": 2,
            "newly_executed_attempts": 2,
            "reuse_percentage": 50.0,
            "estimated_recomputation_avoided_seconds": 0.5,
        },
        "verification": {"artifact_verification_required_for_reuse": True},
        "limitations": ["Local mock workload."],
    }


def _replay() -> dict[str, object]:
    return {
        "schema": "agentguard.trace-replay-equivalence",
        "schema_version": 1,
        "aggregates": {
            "traces_attempted": 4,
            "traces_replayable": 4,
            "exact_check_equivalence_count": 4,
            "exact_score_equivalence_count": 4,
            "exact_final_result_equivalence_count": 4,
        },
        "limitations": ["Replay equivalence only."],
    }


def _metamorphic() -> dict[str, object]:
    return {
        "schema": "agentguard.metamorphic-trace-summary",
        "schema_version": 1,
        "results": {
            "trace_count": 2,
            "transform_applications": 20,
            "preserving_pass_rate": 1.0,
            "changing_expected_delta_detection_rate": 1.0,
            "invalid_rejection_count": 2,
        },
        "limitations": ["Deterministic mock traces."],
    }


def _generic_metrics() -> dict[str, object]:
    return {
        "date": "2026-06-17",
        "metrics": {
            "policies_compared": 2,
        },
    }
