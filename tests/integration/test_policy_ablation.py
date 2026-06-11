import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.checks import registry as check_registry
from agentguard.cli.main import app
from agentguard.diagnostics.ablation import (
    AblationCondition,
    _run_trial,
    _unstable_mutations,
    run_policy_ablation,
)
from agentguard.diagnostics.mutations import load_mutation_catalog


CATALOG_PATH = Path("examples/mutations/catalog.yaml").resolve()
runner = CliRunner()


def _catalog_data() -> dict:
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


def _write_catalog(tmp_path: Path, data: dict, selected_id: str) -> Path:
    root = Path(__file__).resolve().parents[2]
    normalized = deepcopy(data)
    normalized["mutations"] = [
        item for item in normalized["mutations"] if item["id"] == selected_id
    ]
    for mutation in normalized["mutations"]:
        mutation["fixture"] = str(root / mutation["fixture"])
        mutation["config"] = str(root / mutation["config"])
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump(normalized, sort_keys=False), encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def full_ablation(tmp_path_factory):
    return run_policy_ablation(
        CATALOG_PATH,
        trials=1,
        workers=2,
        output_dir=tmp_path_factory.mktemp("policy-ablation"),
    )


def test_control_runs_first_and_conditions_are_deterministic(full_ablation) -> None:
    assert full_ablation.control_validity.valid
    assert full_ablation.studied_checks == [
        "Forbidden paths",
        "Test tampering",
        "Unsafe commands",
        "Scope adherence",
        "Diff size",
        "Secret scan",
    ]
    condition_ids = [item.condition_id for item in full_ablation.raw_trial_summaries]
    assert condition_ids[:16] == ["control"] * 16
    assert full_ablation.raw_trial_summaries[0].mutation_id == "unsafe_modify_test"
    assert full_ablation.raw_trial_summaries[15].mutation_id == (
        "safe_allowed_documentation"
    )


def test_control_metrics_ablation_deltas_and_score_recomputation(
    full_ablation,
) -> None:
    assert full_ablation.control_metrics["unsafe_mutations"] == 10
    assert full_ablation.control_metrics["safe_mutations"] == 6
    assert full_ablation.control_metrics["controlled_expected_detections"] == 20
    assert full_ablation.control_metrics["observed_expected_detections"] == 20
    assert full_ablation.control_metrics[
        "controlled_mutation_detection_rate"
    ] == 100.0
    assert full_ablation.control_metrics["safe_fixture_pass_rate"] == 100.0

    summaries = {
        item.disabled_check: item for item in full_ablation.conditions[1:]
    }
    assert summaries["Unsafe commands"].escaped_unsafe_mutations == [
        "unsafe_command_event"
    ]
    assert summaries["Unsafe commands"].newly_passing_unsafe_mutations == [
        "unsafe_command_event"
    ]
    assert summaries["Scope adherence"].escaped_unsafe_mutations == [
        "unsafe_outside_scope",
        "unsafe_workflow_change",
    ]
    assert summaries["Diff size"].escaped_unsafe_mutations == [
        "unsafe_oversized_diff"
    ]
    assert summaries["Forbidden paths"].detection_rate_delta_percentage_points == -20.0
    assert all(
        item.safe_fixture_pass_rate_delta_percentage_points == 0.0
        for item in summaries.values()
    )
    assert all(item.score_delta >= 0 for item in summaries.values())


def test_unique_redundant_contribution_and_overlap(full_ablation) -> None:
    contributions = {
        item.check: item for item in full_ablation.check_contributions
    }
    assert contributions["Unsafe commands"].detections_uniquely_attributable == 1
    assert contributions["Diff size"].detections_uniquely_attributable == 1
    assert contributions["Scope adherence"].detections_uniquely_attributable == 2
    assert contributions["Forbidden paths"].detections_redundantly_covered == 4
    assert contributions["Secret scan"].detections_redundantly_covered == 4

    overlap = full_ablation.overlap
    assert overlap.matrix["Forbidden paths"]["Secret scan"] == 4
    for left in overlap.checks:
        for right in overlap.checks:
            assert overlap.matrix[left][right] == overlap.matrix[right][left]
    assert set(overlap.exactly_one_check) == {
        "unsafe_outside_scope",
        "unsafe_oversized_diff",
        "unsafe_command_event",
        "unsafe_workflow_change",
    }
    assert len(overlap.multiple_checks) == 5
    assert overlap.no_checks == ["unsafe_delete_source"]


def test_disabled_check_is_not_invoked_and_other_checks_run(
    tmp_path: Path,
    monkeypatch,
) -> None:
    calls = 0

    def disabled_factory():
        nonlocal calls
        calls += 1
        raise AssertionError("disabled check factory was invoked")

    monkeypatch.setattr(
        check_registry,
        "CHECK_REGISTRY",
        tuple(
            replace(item, factory=disabled_factory)
            if item.identifier == "unsafe-commands"
            else item
            for item in check_registry.CHECK_REGISTRY
        ),
    )
    mutation = load_mutation_catalog(CATALOG_PATH).mutations[6]
    trial = _run_trial(
        (
            AblationCondition(
                "without-unsafe-commands",
                "unsafe-commands",
                "Unsafe commands",
            ),
            mutation,
            0,
            tmp_path,
        )
    )

    assert trial.mutation.runtime_error is None
    assert calls == 0
    names = [item.name for item in trial.mutation.check_results]
    assert "Unsafe commands" not in names
    assert "Tests passed" in names
    assert len(names) == 6


def test_filters_apply_before_expansion_and_trials_preserve_order(
    tmp_path: Path,
) -> None:
    result = run_policy_ablation(
        CATALOG_PATH,
        check_values=["unsafe-commands"],
        mutation_ids=["unsafe_command_event,safe_minimal_source_fix"],
        trials=2,
        workers=2,
        output_dir=tmp_path,
    )

    assert result.selected_mutation_ids == [
        "unsafe_command_event",
        "safe_minimal_source_fix",
    ]
    assert [
        (item.condition_id, item.mutation_id, item.trial_index)
        for item in result.raw_trial_summaries
    ] == [
        ("control", "unsafe_command_event", 0),
        ("control", "unsafe_command_event", 1),
        ("control", "safe_minimal_source_fix", 0),
        ("control", "safe_minimal_source_fix", 1),
        ("without-unsafe-commands", "unsafe_command_event", 0),
        ("without-unsafe-commands", "unsafe_command_event", 1),
        ("without-unsafe-commands", "safe_minimal_source_fix", 0),
        ("without-unsafe-commands", "safe_minimal_source_fix", 1),
    ]
    assert result.unstable_mutations == []


def test_invalid_control_suppresses_contribution_claims(tmp_path: Path) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "unsafe_modify_test"
    )
    mutation["expectation"]["expected_detections"].append("Diff size")
    path = _write_catalog(tmp_path, data, "unsafe_modify_test")

    result = run_policy_ablation(path, output_dir=tmp_path / "output")

    assert not result.control_validity.valid
    assert result.check_contributions is None
    assert result.overlap is None
    assert any("Diff size" in item for item in result.control_validity.control_failures)
    assert "suppressed because the control is invalid" in (
        result.markdown_report_path.read_text(encoding="utf-8")
    )


def test_runtime_failures_and_unstable_results_are_structured(
    tmp_path: Path,
    full_ablation,
) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "safe_minimal_source_fix"
    )
    mutation["action"] = {
        "type": "replace_text",
        "path": "src/auth_example/login.py",
        "old": "missing text",
        "new": "replacement",
    }
    path = _write_catalog(tmp_path, data, "safe_minimal_source_fix")
    failed = run_policy_ablation(
        path,
        check_values=["scope-adherence"],
        output_dir=tmp_path / "failed",
    )
    assert failed.failures
    assert failed.has_study_failures

    first = full_ablation.raw_trial_summaries[0]
    changed = replace(
        first,
        trial_index=1,
        mutation=replace(first.mutation, score=first.mutation.score - 1),
    )
    assert _unstable_mutations([first, changed]) == [
        f"{first.condition_id}:{first.mutation_id}"
    ]


def test_json_markdown_cli_and_validation(full_ablation, tmp_path: Path) -> None:
    data = json.loads(full_ablation.json_report_path.read_text(encoding="utf-8"))
    markdown = full_ablation.markdown_report_path.read_text(encoding="utf-8")
    assert data["schema"] == "agentguard.policy-ablation"
    assert data["schema_version"] == 1
    assert data["catalog_sha256"]
    assert "## Control Validity" in markdown
    assert "## Overlap Matrix" in markdown
    assert "not production security effectiveness" in markdown

    cli = runner.invoke(
        app,
        [
            "diagnostics",
            "ablation",
            "--catalog",
            str(CATALOG_PATH),
            "--check",
            "unsafe-commands",
            "--mutation",
            "unsafe_command_event",
            "--output-dir",
            str(tmp_path / "cli"),
        ],
    )
    assert cli.exit_code == 0
    assert "AgentGuard Policy Ablation Study" in cli.output
    assert "Control valid: yes" in cli.output
    assert "Unsafe commands | 1 | -100.00 pp | 1 | +0.00 pp" in cli.output

    for args, message in [
        (["--check", "missing"], "Unknown check"),
        (["--check", "scope-adherence,Scope adherence"], "Duplicate check"),
        (["--trials", "0"], "positive integer"),
        (["--workers", "0"], "positive integer"),
    ]:
        invalid = runner.invoke(
            app,
            [
                "diagnostics",
                "ablation",
                "--catalog",
                str(CATALOG_PATH),
                "--mutation",
                "unsafe_command_event",
                *args,
            ],
        )
        assert invalid.exit_code == 2
        assert message in invalid.output
