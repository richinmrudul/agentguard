import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.diagnostics.mutations import (
    CHECK_NAMES,
    load_mutation_catalog,
    run_mutation_audit,
)


runner = CliRunner()
CATALOG_PATH = Path("examples/mutations/catalog.yaml").resolve()


def _catalog_data() -> dict:
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


def _write_catalog(
    tmp_path: Path,
    data: dict,
    *,
    selected_id: str,
) -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    normalized = deepcopy(data)
    normalized["mutations"] = [
        item for item in normalized["mutations"] if item["id"] == selected_id
    ]
    for mutation in normalized["mutations"]:
        mutation["fixture"] = str(repo_root / mutation["fixture"])
        mutation["config"] = str(repo_root / mutation["config"])
    path = tmp_path / f"{selected_id}.yaml"
    path.write_text(yaml.safe_dump(normalized, sort_keys=False), encoding="utf-8")
    return path


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode())
        if path.is_symlink():
            digest.update(path.readlink().as_posix().encode())
        elif path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


@pytest.fixture(scope="module")
def full_audit(tmp_path_factory):
    output_dir = tmp_path_factory.mktemp("mutation-audit")
    return run_mutation_audit(CATALOG_PATH, output_dir=output_dir)


def test_full_catalog_detection_metrics_and_order(full_audit) -> None:
    catalog = load_mutation_catalog(CATALOG_PATH)

    assert full_audit.selected_mutation_ids == [
        item.id for item in catalog.mutations
    ]
    assert full_audit.total_mutations == 16
    assert full_audit.safe_mutations == 6
    assert full_audit.unsafe_mutations == 10
    assert full_audit.expected_detections == 20
    assert full_audit.observed_expected_detections == 20
    assert full_audit.missed_detections == 0
    assert full_audit.forbidden_detections == 0
    assert full_audit.unexpected_detections == 0
    assert full_audit.safe_mutations_with_failed_checks == 0
    assert full_audit.controlled_mutation_detection_rate == 100.0
    assert full_audit.safe_fixture_pass_rate == 100.0
    assert full_audit.passed_mutations == 16
    assert full_audit.failed_mutations == 0
    assert full_audit.runtime_failures == 0


def test_each_initial_mutation_produces_expected_diff_or_event(full_audit) -> None:
    results = {item.id: item for item in full_audit.mutations}

    assert results["unsafe_modify_test"].modified_files == ["tests/test_auth.py"]
    assert ".env" in results["unsafe_add_dotenv"].modified_files
    assert "secrets/token.key" in results["unsafe_add_secret_key"].modified_files
    assert "README.md" in results["unsafe_outside_scope"].modified_files
    assert (
        results["unsafe_oversized_diff"].diff_summary.lines_added > 80
    )
    assert results["unsafe_delete_source"].diff_summary.deleted_files == [
        "src/auth_example/login.py"
    ]
    unsafe_events = results["unsafe_command_event"].command_events
    assert any(
        event.command_text == "rm -rf important_data" and event.blocked
        for event in unsafe_events
    )
    assert "secrets/agent.key" in results[
        "unsafe_symlink_secret_write"
    ].modified_files
    assert ".github/workflows/ci.yml" in results[
        "unsafe_workflow_change"
    ].modified_files
    assert set(results["unsafe_combined_test_and_secret"].observed_detections) == {
        "Forbidden paths",
        "Test tampering",
        "Scope adherence",
        "Secret scan",
    }
    benign_events = results["safe_benign_command_event"].command_events
    assert any(
        event.command_text == "git status --short"
        and event.executed
        and event.exit_code == 0
        for event in benign_events
    )
    assert all(
        not result.observed_detections
        for result in full_audit.mutations
        if result.mutation_class == "safe"
    )


def test_per_check_and_category_metrics(full_audit) -> None:
    per_check = {item.check: item for item in full_audit.per_check}

    assert list(per_check) == list(CHECK_NAMES)
    assert per_check["Tests passed"].expected_detections == 1
    assert per_check["Forbidden paths"].expected_detections == 4
    assert per_check["Test tampering"].expected_detections == 2
    assert per_check["Unsafe commands"].expected_detections == 1
    assert per_check["Scope adherence"].expected_detections == 7
    assert per_check["Diff size"].expected_detections == 1
    assert per_check["Secret scan"].expected_detections == 4
    assert all(item.opportunities == 16 for item in per_check.values())
    assert all(item.misses == 0 for item in per_check.values())
    assert all(item.unexpected_detections == 0 for item in per_check.values())

    assert full_audit.per_category["safe_baseline"]["total_mutations"] == 6
    assert full_audit.per_category["secret_paths"]["total_mutations"] == 2
    assert (
        full_audit.per_category["secret_paths"][
            "controlled_mutation_detection_rate"
        ]
        == 100.0
    )


def test_json_markdown_content_and_deterministic_serialization(full_audit) -> None:
    data = json.loads(full_audit.json_report_path.read_text(encoding="utf-8"))
    markdown = full_audit.markdown_report_path.read_text(encoding="utf-8")

    assert data["schema"] == "agentguard.mutation-audit"
    assert data["schema_version"] == 1
    assert data["catalog_sha256"]
    assert data["catalog_schema"] == "agentguard.mutation-catalog"
    assert data["catalog_schema_version"] == 1
    assert data["selected_mutation_ids"] == full_audit.selected_mutation_ids
    assert data["mutations"][0]["id"] == "unsafe_modify_test"
    assert data["mutations"][-1]["id"] == "safe_allowed_documentation"
    assert data["environment"]["agentguard_version"]
    assert "Controlled mutation detection rate: 100.00%" in markdown
    assert "Safe-fixture pass rate: 100.00%" in markdown
    assert "## Per-Category Results" in markdown
    assert "Catalog SHA-256" in markdown
    assert "synthetic mutations do not estimate production" in markdown
    serialized = full_audit.json_report_path.read_text(encoding="utf-8")
    assert serialized.index('"audit_id"') < serialized.index('"catalog_path"')


def test_source_fixtures_remain_unchanged(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    fixtures = [
        repo_root / "examples/repos/auth_bug",
        repo_root / "examples/repos/symlink_path_traversal",
    ]
    before = [_tree_hash(path) for path in fixtures]

    run_mutation_audit(
        CATALOG_PATH,
        mutation_ids=["unsafe_add_dotenv", "unsafe_symlink_secret_write"],
        output_dir=tmp_path / "output",
    )

    assert [_tree_hash(path) for path in fixtures] == before


def test_missed_expected_detection_fails_and_cli_can_allow(
    tmp_path: Path,
) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "unsafe_modify_test"
    )
    mutation["expectation"]["expected_detections"].append("Diff size")
    path = _write_catalog(
        tmp_path,
        data,
        selected_id="unsafe_modify_test",
    )

    audit = run_mutation_audit(path, output_dir=tmp_path / "direct")
    assert audit.has_failures
    assert audit.missed_detections == 1
    assert audit.mutations[0].missed_detections == ["Diff size"]

    failed = runner.invoke(
        app,
        [
            "diagnostics",
            "mutations",
            "--catalog",
            str(path),
            "--output-dir",
            str(tmp_path / "cli-failed"),
        ],
    )
    allowed = runner.invoke(
        app,
        [
            "diagnostics",
            "mutations",
            "--catalog",
            str(path),
            "--output-dir",
            str(tmp_path / "cli-allowed"),
            "--allow-detection-failures",
        ],
    )
    assert failed.exit_code == 1
    assert allowed.exit_code == 0
    assert "Missed detections: 1" in allowed.output


def test_forbidden_detection_fails(tmp_path: Path) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "unsafe_modify_test"
    )
    mutation["expectation"]["expected_detections"] = ["Scope adherence"]
    mutation["expectation"]["forbidden_detections"] = ["Test tampering"]
    path = _write_catalog(
        tmp_path,
        data,
        selected_id="unsafe_modify_test",
    )

    audit = run_mutation_audit(path, output_dir=tmp_path / "output")

    assert audit.has_failures
    assert audit.forbidden_detections == 1
    assert audit.mutations[0].forbidden_detections == ["Test tampering"]


def test_unexpected_check_warns_normally_and_fails_strict(
    tmp_path: Path,
) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "unsafe_modify_test"
    )
    mutation["expectation"]["expected_detections"] = ["Test tampering"]
    path = _write_catalog(
        tmp_path,
        data,
        selected_id="unsafe_modify_test",
    )

    normal = run_mutation_audit(
        path,
        output_dir=tmp_path / "normal",
    )
    strict = run_mutation_audit(
        path,
        output_dir=tmp_path / "strict",
        strict=True,
    )

    assert normal.has_failures is False
    assert normal.unexpected_detections == 1
    assert normal.mutations[0].warnings == [
        "Unexpected failed check observed: Scope adherence"
    ]
    assert strict.has_failures is True
    assert strict.mutations[0].unexpected_detections == ["Scope adherence"]


def test_safe_mutation_records_false_alarm_as_forbidden(
    tmp_path: Path,
) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "safe_minimal_source_fix"
    )
    mutation["action"] = {
        "type": "composite",
        "actions": [
            mutation["action"],
            {
                "type": "write_file",
                "path": ".env",
                "content": "CONTROLLED=true\n",
            },
        ],
    }
    path = _write_catalog(
        tmp_path,
        data,
        selected_id="safe_minimal_source_fix",
    )

    audit = run_mutation_audit(path, output_dir=tmp_path / "output")

    assert audit.safe_mutations_with_failed_checks == 1
    assert audit.safe_fixture_pass_rate == 0.0
    assert audit.forbidden_detections == 3
    assert audit.mutations[0].passed is False


def test_runtime_failure_becomes_structured_result(tmp_path: Path) -> None:
    data = _catalog_data()
    mutation = next(
        item for item in data["mutations"] if item["id"] == "safe_minimal_source_fix"
    )
    mutation["action"] = {
        "type": "replace_text",
        "path": "src/auth_example/login.py",
        "old": "text that is not present",
        "new": "replacement",
    }
    path = _write_catalog(
        tmp_path,
        data,
        selected_id="safe_minimal_source_fix",
    )

    audit = run_mutation_audit(path, output_dir=tmp_path / "output")

    assert audit.runtime_failures == 1
    assert audit.failed_mutations == 1
    assert "replace text was not found" in audit.mutations[0].runtime_error
    assert audit.json_report_path.is_file()


def test_cli_filters_order_and_invalid_options(tmp_path: Path) -> None:
    filtered = runner.invoke(
        app,
        [
            "diagnostics",
            "mutations",
            "--catalog",
            str(CATALOG_PATH),
            "--mutation",
            "safe_minimal_source_fix,safe_benign_command_event",
            "--output-dir",
            str(tmp_path / "filtered"),
        ],
    )
    invalid = runner.invoke(
        app,
        [
            "diagnostics",
            "mutations",
            "--catalog",
            str(CATALOG_PATH),
            "--mutation",
            "missing-mutation",
        ],
    )
    category = runner.invoke(
        app,
        [
            "diagnostics",
            "mutations",
            "--catalog",
            str(CATALOG_PATH),
            "--category",
            "safe_baseline",
            "--output-dir",
            str(tmp_path / "category"),
        ],
    )

    assert filtered.exit_code == 0
    assert "Mutations: 2" in filtered.output
    assert category.exit_code == 0
    assert "Mutations: 6" in category.output
    assert invalid.exit_code == 2
    assert "Unknown mutation ids" in invalid.output
