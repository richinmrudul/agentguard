import json
from pathlib import Path
from typing import Optional

from typer.testing import CliRunner

from agentguard.benchmarks.fuzz import (
    FUZZ_DIMENSION_NAMES,
    FUZZ_SCHEMA,
    FUZZ_SCHEMA_VERSION,
    FuzzExpectation,
    FuzzRunResult,
    FuzzVariant,
    _execute_variant,
    fuzz_complexity,
    generate_fuzz_variants,
    minimize_fuzz_failure,
    promote_minimized_failures,
    run_fuzz_study,
)
from agentguard.checks.registry import instantiate_checks
from agentguard.core.result import CheckResult
from agentguard.cli.main import app


runner = CliRunner()
CHECKS = instantiate_checks()


def _ids(seed: str, *, limit: Optional[int] = None) -> list[str]:
    return [variant.id for variant in generate_fuzz_variants(seed=seed, limit=limit)]


def test_deterministic_generation_for_same_seed() -> None:
    assert _ids("same-seed") == _ids("same-seed")


def test_different_seed_changes_order_but_remains_valid() -> None:
    first = _ids("alpha")
    second = _ids("bravo")

    assert first != second
    assert set(first) == set(second)


def test_dimension_filtering() -> None:
    variants = generate_fuzz_variants(
        seed="agentguard",
        dimensions=["secret-paths", "unsafe-commands"],
    )

    assert {variant.dimension for variant in variants} == {
        "secret-paths",
        "unsafe-commands",
    }


def test_limit_behavior() -> None:
    variants = generate_fuzz_variants(seed="agentguard", limit=5)

    assert len(variants) == 5
    assert variants == generate_fuzz_variants(seed="agentguard", limit=5)


def test_static_only_executes_no_checks(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["secret-paths"],
        output_dir=tmp_path,
        static_only=True,
        force=True,
    )

    assert result.static_only is True
    assert result.variants_failed == 0
    assert all(run.check_results == [] for run in result.runs)
    assert all(run.observed_result == "STATIC" for run in result.runs)
    assert not (result.json_report_path.parent / "workspaces").exists()


def test_secret_path_variants_detect_expected_checks(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["secret-paths"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.total_variants == 4
    assert result.variants_failed == 0
    assert any("secret-scan" in run.observed_checks for run in result.runs)
    assert any("forbidden-paths" in run.observed_checks for run in result.runs)


def test_scope_boundary_variants(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["scope-boundaries"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.total_variants == 4
    assert result.variants_failed == 0
    safe = next(run for run in result.runs if run.variant.id.endswith("allowed-source"))
    assert safe.observed_checks == []
    assert any("scope-adherence" in run.observed_checks for run in result.runs)


def test_test_tampering_variants(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["test-tampering"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.total_variants == 4
    assert result.variants_failed == 0
    assert all("test-tampering" in run.observed_checks for run in result.runs)


def test_unsafe_command_variants_include_benign_near_miss(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["unsafe-commands"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.total_variants == 4
    assert result.variants_failed == 0
    near_miss = next(run for run in result.runs if run.variant.id.endswith("near-miss"))
    assert near_miss.observed_checks == []
    assert near_miss.passed is True
    assert any("unsafe-commands" in run.observed_checks for run in result.runs)


def test_diff_size_boundary_variants(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["diff-size-boundaries"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.total_variants == 3
    assert result.variants_failed == 0
    above = next(run for run in result.runs if run.variant.id.endswith("above-threshold"))
    exact = next(run for run in result.runs if run.variant.id.endswith("exact-threshold"))
    assert "diff-size" in above.observed_checks
    assert "diff-size" not in exact.observed_checks


def test_path_traversal_variants(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["path-traversal"],
        output_dir=tmp_path,
        force=True,
    )

    assert result.total_variants == 4
    assert result.variants_failed == 0
    symlink_like = next(run for run in result.runs if run.variant.id.endswith("symlink-like"))
    assert symlink_like.observed_checks == []
    assert any("forbidden-paths" in run.observed_checks for run in result.runs)


def test_trials_workers_deterministic_aggregation(tmp_path: Path) -> None:
    first = run_fuzz_study(
        dimensions=["unsafe-commands", "diff-size-boundaries"],
        seed="deterministic",
        output_dir=tmp_path,
        trials=2,
        workers=2,
        force=True,
    )
    second = run_fuzz_study(
        dimensions=["unsafe-commands", "diff-size-boundaries"],
        seed="deterministic",
        output_dir=tmp_path,
        trials=2,
        workers=2,
        force=True,
    )

    assert [run.variant.id for run in first.runs] == [
        run.variant.id for run in second.runs
    ]
    assert first.per_dimension == second.per_dimension
    assert first.variants_failed == second.variants_failed == 0


def test_report_json_and_markdown(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=["secret-paths"],
        output_dir=tmp_path,
        force=True,
    )

    data = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")
    assert data["schema"] == FUZZ_SCHEMA
    assert data["schema_version"] == FUZZ_SCHEMA_VERSION
    assert "expected/observed check matrix".lower() in markdown.lower()
    assert "missed expected detections" in markdown.lower()


def test_cli_exit_codes(tmp_path: Path) -> None:
    ok = runner.invoke(
        app,
        [
            "benchmarks",
            "fuzz",
            "--dimension",
            "unsafe-commands",
            "--output-dir",
            str(tmp_path),
            "--force",
        ],
    )
    invalid = runner.invoke(
        app,
        ["benchmarks", "fuzz", "--dimension", "missing"],
    )

    assert ok.exit_code == 0
    assert "AgentGuard Benchmark Fuzz Study" in ok.output
    assert invalid.exit_code == 2
    assert "Traceback" not in invalid.output


def test_generated_files_stay_inside_output_dir(tmp_path: Path) -> None:
    result = run_fuzz_study(
        dimensions=list(FUZZ_DIMENSION_NAMES),
        output_dir=tmp_path,
        force=True,
    )

    for path in [result.json_report_path, result.markdown_report_path]:
        path.resolve().relative_to(tmp_path.resolve())
    for run in result.runs:
        assert run.variant.repo_path is not None
        run.variant.repo_path.resolve().relative_to(tmp_path.resolve())
        assert ".." not in str(run.variant.repo_path.relative_to(tmp_path))


def test_hand_authored_fixtures_unchanged(tmp_path: Path) -> None:
    fixture = Path("examples/repos/auth_bug/tests/test_auth.py")
    before = fixture.read_text(encoding="utf-8")

    run_fuzz_study(output_dir=tmp_path, limit=10, force=True)

    assert fixture.read_text(encoding="utf-8") == before


def test_no_docker_network_or_external_agent_required(tmp_path: Path) -> None:
    result = run_fuzz_study(
        output_dir=tmp_path,
        limit=10,
        force=True,
    )

    assert result.total_variants == 10
    assert all("docker" not in run.observed_result.lower() for run in result.runs)


def _safe_false_alarm_variant(**inputs) -> FuzzVariant:
    merged = {
        "changed_files": ["src/deep/keep.py", "docs/deep/unrelated/path/notes.md"],
        "lines_added": 1,
    }
    merged.update(inputs)
    return FuzzVariant(
        id="test:safe-false-alarm",
        dimension="scope-boundaries",
        description="Noisy safe false alarm.",
        inputs=merged,
        expectation=FuzzExpectation(
            required_checks=[],
            forbidden_checks=["scope-adherence"],
            expected_result="PASS",
            unsafe=False,
        ),
    )


def _failed_run(variant: FuzzVariant) -> FuzzRunResult:
    run = _execute_variant(variant, 1, CHECKS)
    assert not run.passed
    return run


def test_minimizer_preserves_failure_and_reduces_path_length() -> None:
    run = _failed_run(_safe_false_alarm_variant())

    minimized = minimize_fuzz_failure(run, checks=CHECKS)

    assert minimized.reproduced is True
    assert minimized.failure_preserved is True
    assert minimized.minimized_complexity.total_path_length < (
        minimized.original_complexity.total_path_length
    )
    assert minimized.final_observed_checks == ["scope-adherence"]


def test_minimizer_reduces_diff_size() -> None:
    variant = _safe_false_alarm_variant(
        changed_files=["src/agentguard/example.py"],
        lines_added=10,
        max_lines_added=5,
    )
    variant = FuzzVariant(
        id=variant.id,
        dimension="diff-size-boundaries",
        description=variant.description,
        inputs=variant.inputs,
        expectation=FuzzExpectation(
            required_checks=[],
            forbidden_checks=["diff-size"],
            expected_result="PASS",
            unsafe=False,
        ),
    )
    run = _failed_run(variant)

    minimized = minimize_fuzz_failure(run, checks=CHECKS)

    assert minimized.failure_preserved is True
    assert minimized.minimized_variant.inputs["lines_added"] == 6
    assert minimized.minimized_complexity.diff_line_count < (
        minimized.original_complexity.diff_line_count
    )


def test_minimizer_removes_unrelated_files() -> None:
    run = _failed_run(_safe_false_alarm_variant())

    minimized = minimize_fuzz_failure(run, checks=CHECKS)

    assert minimized.failure_preserved is True
    assert len(minimized.minimized_variant.inputs["changed_files"]) == 1
    assert minimized.minimized_variant.inputs["changed_files"][0] != "src/deep/keep.py"


def test_minimizer_stops_at_fixed_point() -> None:
    run = _failed_run(_safe_false_alarm_variant(changed_files=["x"]))

    first = minimize_fuzz_failure(run, checks=CHECKS)
    second_run = _failed_run(first.minimized_variant)
    second = minimize_fuzz_failure(second_run, checks=CHECKS)

    assert first.minimized_complexity == second.minimized_complexity
    assert second.steps_accepted == 0


def test_max_step_limit_honored() -> None:
    run = _failed_run(_safe_false_alarm_variant())

    minimized = minimize_fuzz_failure(run, max_steps=1, checks=CHECKS)

    assert minimized.steps_attempted <= 1


def test_non_reproducible_failure_reported() -> None:
    variant = _safe_false_alarm_variant(changed_files=["src/agentguard/example.py"])
    fake = FuzzRunResult(
        variant=variant,
        trial=1,
        passed=False,
        expected_checks=[],
        forbidden_checks=["scope-adherence"],
        observed_checks=["scope-adherence"],
        missed_expected_detections=[],
        forbidden_unexpected_detections=["scope-adherence"],
        safe_false_alarms=["scope-adherence"],
        unexpected_detections=[],
        expected_result="PASS",
        observed_result="FAIL",
        score=0,
        check_results=[
            CheckResult(
                name="Scope adherence",
                passed=False,
                severity="error",
                message="synthetic",
                evidence=["synthetic"],
            )
        ],
        duration_seconds=0.0,
    )

    minimized = minimize_fuzz_failure(fake, checks=CHECKS)

    assert minimized.reproduced is False
    assert minimized.failure_preserved is False
    assert minimized.runtime_error == "Original failure did not reproduce."


def test_complexity_metric_deterministic() -> None:
    variant = _safe_false_alarm_variant()

    assert fuzz_complexity(variant) == fuzz_complexity(variant)


def test_promotion_fixture_contains_required_files(tmp_path: Path) -> None:
    minimized = minimize_fuzz_failure(_failed_run(_safe_false_alarm_variant()), checks=CHECKS)

    promotions = promote_minimized_failures(
        [minimized],
        tmp_path / "promotions",
        promotion_format="fixture",
        force=True,
    )

    case_dir = promotions[0].path
    assert (case_dir / "variant.json").is_file()
    assert (case_dir / "contract-fragment.yaml").is_file()
    assert (case_dir / "README.md").is_file()
    assert (case_dir / "repo").is_dir()


def test_promotion_patch_contains_metadata_and_patch(tmp_path: Path) -> None:
    minimized = minimize_fuzz_failure(_failed_run(_safe_false_alarm_variant()), checks=CHECKS)

    promotions = promote_minimized_failures(
        [minimized],
        tmp_path / "promotions",
        promotion_format="patch",
        force=True,
    )

    case_dir = promotions[0].path
    assert (case_dir / "variant.json").is_file()
    assert "diff --git" in (case_dir / "regression.patch").read_text(
        encoding="utf-8"
    )


def test_promotion_has_no_absolute_paths(tmp_path: Path) -> None:
    minimized = minimize_fuzz_failure(_failed_run(_safe_false_alarm_variant()), checks=CHECKS)

    promotions = promote_minimized_failures(
        [minimized],
        tmp_path / "promotions",
        promotion_format="fixture",
        force=True,
    )

    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in promotions[0].path.rglob("*")
        if path.is_file()
    )
    assert str(tmp_path) not in combined
    assert "/Users/" not in combined


def test_promotion_does_not_edit_registry_or_core_suite(tmp_path: Path) -> None:
    registry = Path("examples/benchmarks/registry.yaml")
    core_suite = Path("examples/suites/core.yaml")
    before_registry = registry.read_text(encoding="utf-8")
    before_suite = core_suite.read_text(encoding="utf-8")
    minimized = minimize_fuzz_failure(_failed_run(_safe_false_alarm_variant()), checks=CHECKS)

    promote_minimized_failures([minimized], tmp_path / "promotions", force=True)

    assert registry.read_text(encoding="utf-8") == before_registry
    assert core_suite.read_text(encoding="utf-8") == before_suite


def test_cli_minimization_options_and_exit_codes(tmp_path: Path, monkeypatch) -> None:
    from agentguard.benchmarks import fuzz as fuzz_module

    def fake_run_fuzz_study(**kwargs):
        calls.append(kwargs)
        run = _failed_run(_safe_false_alarm_variant())
        return fuzz_module._build_study_result(
            study_id="fake",
            seed="agentguard",
            dimensions=["scope-boundaries"],
            trials=1,
            workers=1,
            static_only=False,
            variants=[run.variant],
            runs=[run],
            minimized_failures=[],
            promotions=[],
            duration_seconds=0.0,
            study_dir=tmp_path,
        )

    calls = []
    monkeypatch.setattr(fuzz_module, "run_fuzz_study", fake_run_fuzz_study)
    monkeypatch.setattr("agentguard.cli.main.run_fuzz_study", fake_run_fuzz_study)

    failing = runner.invoke(
        app,
        [
            "benchmarks",
            "fuzz",
            "--minimize-failures",
            "--promote-failures",
            str(tmp_path / "promote"),
            "--max-minimize-steps",
            "7",
        ],
    )
    allowed = runner.invoke(
        app,
        ["benchmarks", "fuzz", "--allow-fuzz-failures"],
    )

    assert failing.exit_code == 1
    assert allowed.exit_code == 0
    assert calls[0]["minimize_failures"] is True
    assert calls[0]["promote_failures"] == tmp_path / "promote"
    assert calls[0]["max_minimize_steps"] == 7


def test_fuzz_report_includes_minimization_data(tmp_path: Path) -> None:
    run = _failed_run(_safe_false_alarm_variant())
    minimized = minimize_fuzz_failure(run, checks=CHECKS)
    result = run_fuzz_study(
        dimensions=["scope-boundaries"],
        output_dir=tmp_path,
        force=True,
    )
    enriched = result.__class__(
        **{
            **result.__dict__,
            "minimized_failures": [minimized],
            "promotion_paths": [tmp_path / "promotion"],
            "non_minimizable_failures": [],
        }
    )
    markdown = Path(result.markdown_report_path)
    markdown.write_text(
        __import__("agentguard.benchmarks.fuzz").benchmarks.fuzz._render_markdown(
            enriched
        ),
        encoding="utf-8",
    )
    text = markdown.read_text(encoding="utf-8")

    assert "## Minimization" in text
    assert run.variant.id in text
    assert "Promotion paths" in text


def test_minimization_deterministic_for_same_seed() -> None:
    run = _failed_run(_safe_false_alarm_variant())

    first = minimize_fuzz_failure(run, checks=CHECKS)
    second = minimize_fuzz_failure(run, checks=CHECKS)

    assert first.minimized_variant.inputs == second.minimized_variant.inputs
    assert first.minimized_complexity == second.minimized_complexity
