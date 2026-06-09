from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from agentguard.diagnostics.mutations import (
    ACTION_TYPES,
    CATALOG_SCHEMA,
    CATALOG_SCHEMA_VERSION,
    CHECK_NAMES,
    _workspace_path,
    load_mutation_catalog,
)


CATALOG_PATH = Path("examples/mutations/catalog.yaml")


def _catalog_data() -> dict:
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


def _write_catalog(tmp_path: Path, data: dict) -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    normalized = deepcopy(data)
    for mutation in normalized["mutations"]:
        mutation["fixture"] = str(repo_root / mutation["fixture"])
        mutation["config"] = str(repo_root / mutation["config"])
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump(normalized, sort_keys=False), encoding="utf-8")
    return path


def test_catalog_schema_models_and_initial_scope() -> None:
    catalog = load_mutation_catalog(CATALOG_PATH)

    assert catalog.schema == CATALOG_SCHEMA
    assert catalog.schema_version == CATALOG_SCHEMA_VERSION
    assert len(catalog.mutations) == 16
    assert sum(item.mutation_class == "unsafe" for item in catalog.mutations) == 10
    assert sum(item.mutation_class == "safe" for item in catalog.mutations) == 6
    assert len({item.id for item in catalog.mutations}) == 16
    assert all(item.fixture.is_dir() for item in catalog.mutations)
    assert all(item.config.is_file() for item in catalog.mutations)
    assert {
        item.action["type"] for item in catalog.mutations
    }.issubset(ACTION_TYPES)


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    data = _catalog_data()
    data["mutations"][1]["id"] = data["mutations"][0]["id"]

    with pytest.raises(ValueError, match="Duplicate mutation id"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


def test_conflicting_expectations_are_rejected(tmp_path: Path) -> None:
    data = _catalog_data()
    expectation = data["mutations"][0]["expectation"]
    expectation["forbidden_detections"] = ["Test tampering"]

    with pytest.raises(ValueError, match="both expected and forbidden"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


@pytest.mark.parametrize("path", ["../outside.txt", "/tmp/outside.txt"])
def test_mutation_action_cannot_escape_workspace(
    tmp_path: Path,
    path: str,
) -> None:
    data = _catalog_data()
    data["mutations"][0]["action"]["path"] = path

    with pytest.raises(ValueError, match="stay within the workspace"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


def test_resolved_symlink_target_cannot_escape_workspace(tmp_path: Path) -> None:
    repo_dir = tmp_path / "repo"
    outside = tmp_path / "outside"
    repo_dir.mkdir()
    outside.mkdir()
    (repo_dir / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="escapes isolated workspace"):
        _workspace_path(repo_dir, "escape/file.txt")


def test_arbitrary_shell_action_is_rejected(tmp_path: Path) -> None:
    data = _catalog_data()
    data["mutations"][0]["action"] = {
        "type": "shell",
        "command": "rm -rf /",
    }

    with pytest.raises(ValueError, match="must be one of"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


def test_unknown_check_names_are_rejected(tmp_path: Path) -> None:
    data = _catalog_data()
    data["mutations"][0]["expectation"]["expected_detections"] = [
        "Imaginary check"
    ]

    with pytest.raises(ValueError, match="unknown checks"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


def test_positive_limits_and_non_empty_patterns_are_validated(
    tmp_path: Path,
) -> None:
    data = _catalog_data()
    oversized = next(
        item for item in data["mutations"] if item["id"] == "unsafe_oversized_diff"
    )
    oversized["action"]["actions"][1]["count"] = 0

    with pytest.raises(ValueError, match="positive integer"):
        load_mutation_catalog(_write_catalog(tmp_path, data))

    data = _catalog_data()
    oversized = next(
        item for item in data["mutations"] if item["id"] == "unsafe_oversized_diff"
    )
    oversized["action"]["actions"][1]["prefix"] = ""
    with pytest.raises(ValueError, match="non-empty string"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


def test_missing_fixture_and_mismatched_config_are_rejected(
    tmp_path: Path,
) -> None:
    data = _catalog_data()
    data["mutations"][0]["fixture"] = "examples/repos/missing"
    with pytest.raises(ValueError, match="fixture does not exist"):
        load_mutation_catalog(_write_catalog(tmp_path, data))

    data = _catalog_data()
    data["mutations"][0]["config"] = (
        "examples/mutations/configs/symlink_local.yaml"
    )
    with pytest.raises(ValueError, match="does not match fixture"):
        load_mutation_catalog(_write_catalog(tmp_path, data))


def test_safe_mutations_forbid_every_check() -> None:
    catalog = load_mutation_catalog(CATALOG_PATH)
    safe = [item for item in catalog.mutations if item.mutation_class == "safe"]

    assert safe
    assert all(
        item.expectation.expected_detections == []
        and item.expectation.forbidden_detections == list(CHECK_NAMES)
        for item in safe
    )
