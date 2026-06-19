import json
from pathlib import Path
from typing import Optional

from typer.testing import CliRunner

from agentguard.benchmarks.fuzz import (
    FUZZ_DIMENSION_NAMES,
    FUZZ_SCHEMA,
    FUZZ_SCHEMA_VERSION,
    generate_fuzz_variants,
    run_fuzz_study,
)
from agentguard.cli.main import app


runner = CliRunner()


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
