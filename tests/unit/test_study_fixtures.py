import json
import os
import shutil
from importlib import resources
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

from agentguard.evaluation.study_fixtures import (
    DEFAULT_STUDY_FIXTURE_MANIFEST,
    load_study_fixture_set,
    materialize_study_fixture,
    serialize_study_fixture_set,
)


def _load_manifest_data() -> dict[str, object]:
    return yaml.safe_load(DEFAULT_STUDY_FIXTURE_MANIFEST.read_text(encoding="utf-8"))


def _write_manifest(tmp_path: Path, data: dict[str, object]) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return path


def _copy_fixture_tree(tmp_path: Path) -> Path:
    fixture_set = load_study_fixture_set()
    root = tmp_path / "fixtures"
    root.mkdir(parents=True)
    manifest_data = _load_manifest_data()
    for fixture in fixture_set.fixtures:
        destination = root / fixture.source.relative_path
        materialize_study_fixture(fixture, destination)
    manifest = root / "manifest.yaml"
    manifest.write_text(yaml.safe_dump(manifest_data, sort_keys=False), encoding="utf-8")
    return manifest


def test_default_fixture_set_is_deterministic_and_reviewed() -> None:
    first = load_study_fixture_set()
    second = load_study_fixture_set()

    assert [fixture.id for fixture in first.fixtures] == [
        "safe-bounded-edit",
        "read-only-control",
        "mutation-boundary",
        "failing-check-control",
    ]
    assert serialize_study_fixture_set(first) == serialize_study_fixture_set(second)
    assert all(not fixture.network_required for fixture in first.fixtures)
    assert first.fixtures[0].prompt.sha256
    assert first.fixtures[-1].expected.functional_success is False


def test_packaged_json_schema_accepts_manifest_and_rejects_unknown() -> None:
    schema_path = (
        resources.files("agentguard.schemas")
        / "contained-study-fixture-set-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    document = _load_manifest_data()
    validator.validate(document)

    invalid = dict(document)
    invalid["provider"] = "example"
    with pytest.raises(ValidationError):
        validator.validate(invalid)


def test_materialization_copies_without_mutating_sources(tmp_path: Path) -> None:
    fixture_set = load_study_fixture_set()
    before = serialize_study_fixture_set(fixture_set)

    destination = tmp_path / "materialized"
    materialize_study_fixture(fixture_set.fixtures[0], destination)

    assert (destination / "src/calc_tools/clamp.py").is_file()
    assert serialize_study_fixture_set(load_study_fixture_set()) == before


def test_tamper_detection(tmp_path: Path) -> None:
    manifest = _copy_fixture_tree(tmp_path)
    target = (
        tmp_path
        / "fixtures"
        / "sources/safe_bounded_edit/src/calc_tools/clamp.py"
    )
    target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        load_study_fixture_set(manifest)


def test_missing_and_extra_file_detection(tmp_path: Path) -> None:
    missing_manifest = _copy_fixture_tree(tmp_path / "missing")
    (
        tmp_path
        / "missing/fixtures/sources/read_only_control/guide/operator-guide.md"
    ).unlink()
    with pytest.raises(ValueError, match="missing source files"):
        load_study_fixture_set(missing_manifest)

    extra_manifest = _copy_fixture_tree(tmp_path / "extra")
    (
        tmp_path
        / "extra/fixtures/sources/read_only_control/extra.txt"
    ).write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected source files"):
        load_study_fixture_set(extra_manifest)


def test_path_symlink_and_hardlink_boundaries(tmp_path: Path) -> None:
    symlink_manifest = _copy_fixture_tree(tmp_path / "symlink")
    os.symlink(
        "README.md",
        tmp_path / "symlink/fixtures/sources/read_only_control/link.md",
    )
    with pytest.raises(ValueError, match="symlink|unexpected source files"):
        load_study_fixture_set(symlink_manifest)

    hardlink_manifest = _copy_fixture_tree(tmp_path / "hardlink")
    os.link(
        tmp_path / "hardlink/fixtures/sources/read_only_control/README.md",
        tmp_path / "hardlink/fixtures/sources/read_only_control/hardlink.md",
    )
    with pytest.raises(ValueError, match="hardlink|unexpected source files"):
        load_study_fixture_set(hardlink_manifest)


def test_prompt_manifest_and_expected_check_schema_validation(tmp_path: Path) -> None:
    data = _load_manifest_data()
    data["fixtures"][0]["prompt"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="prompt hash mismatch"):
        load_study_fixture_set(_write_manifest(tmp_path, data), validate_sources=False)

    bad_check = _load_manifest_data()
    bad_check["fixtures"][0]["checks"][0]["kind"] = "docker"
    with pytest.raises(ValueError, match="unsupported"):
        load_study_fixture_set(_write_manifest(tmp_path / "bad-check", bad_check))


def test_network_provider_and_traversal_inputs_are_rejected(tmp_path: Path) -> None:
    network = _load_manifest_data()
    network["fixtures"][0]["network_required"] = True
    with pytest.raises(ValueError, match="must not require network"):
        load_study_fixture_set(_write_manifest(tmp_path / "network", network))

    provider = _load_manifest_data()
    provider["fixtures"][0]["provider"] = "example"
    with pytest.raises(ValueError, match="provider"):
        load_study_fixture_set(_write_manifest(tmp_path / "provider", provider))

    traversal = _load_manifest_data()
    traversal["fixtures"][0]["source"]["files"][0]["path"] = "../README.md"
    with pytest.raises(ValueError, match="traversal"):
        load_study_fixture_set(_write_manifest(tmp_path / "traversal", traversal))


def test_clean_checkout_construction_and_safe_cleanup(tmp_path: Path) -> None:
    manifest = _copy_fixture_tree(tmp_path)
    fixture_set = load_study_fixture_set(manifest)

    assert serialize_study_fixture_set(fixture_set) == serialize_study_fixture_set(
        load_study_fixture_set(manifest)
    )
    assert len(list((tmp_path / "fixtures").rglob("*"))) > 0


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda data: data.update({"schema": "wrong"}), "Invalid"),
        (lambda data: data.update({"schema_version": 2}), "Unsupported"),
        (lambda data: data.update({"fixtures": []}), "non-empty list"),
        (lambda data: data.update({"fixtures": data["fixtures"] * 33}), "too many"),
        (lambda data: data["fixtures"].__setitem__(0, "bad"), "entry 0"),
        (
            lambda data: data["fixtures"][0].update({"network_required": "false"}),
            "network_required",
        ),
        (
            lambda data: data["fixtures"][0]["source"].update({"files": []}),
            "source.files",
        ),
        (
            lambda data: data["fixtures"][0]["source"]["files"][0].update(
                {"size": 1048577}
            ),
            "source file size",
        ),
        (
            lambda data: data["fixtures"][0]["mutation"].update(
                {"allowed_paths": ["same"], "forbidden_paths": ["same"]}
            ),
            "both allowed and forbidden",
        ),
        (
            lambda data: data["fixtures"][0]["mutation"].update(
                {"max_modified_files": -1}
            ),
            "max_modified_files",
        ),
        (lambda data: data["fixtures"][0].update({"checks": []}), "checks"),
        (
            lambda data: data["fixtures"][0]["checks"][0].update(
                {"expected_status": 300}
            ),
            "expected_status",
        ),
        (
            lambda data: data["fixtures"][0]["checks"][0].update(
                {"command": ["python", "-m", "x && y"]}
            ),
            "structured",
        ),
        (
            lambda data: data["fixtures"][0]["expected"].update(
                {"functional_success": "yes"}
            ),
            "functional_success",
        ),
        (
            lambda data: data["fixtures"][0].update(
                {"required_capabilities": "python-edit"}
            ),
            "required_capabilities",
        ),
        (
            lambda data: data["fixtures"][0].update({"id": "safe-bounded-edit\nbad"}),
            "control|portable",
        ),
        (
            lambda data: data["fixtures"][0]["source"].update({"hash": "not-a-hash"}),
            "sha256",
        ),
        (
            lambda data: data["fixtures"][0]["source"].update({"path": "/absolute"}),
            "relative",
        ),
        (
            lambda data: data["fixtures"][0]["source"]["files"][0].update(
                {"path": "CON"}
            ),
            "reserved",
        ),
        (
            lambda data: data["fixtures"][0]["source"]["files"][0].update(
                {"path": "dir/"}
            ),
            "file path",
        ),
    ],
)
def test_malformed_manifest_rejection(tmp_path: Path, mutation, match: str) -> None:
    data = _load_manifest_data()
    mutation(data)

    with pytest.raises(ValueError, match=match):
        load_study_fixture_set(
            _write_manifest(tmp_path, data),
            validate_sources=False,
        )


def test_source_hash_empty_and_dirty_artifact_detection(tmp_path: Path) -> None:
    manifest = _copy_fixture_tree(tmp_path / "hash")
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["fixtures"][0]["source"]["hash"] = "0" * 64
    manifest.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="source hash mismatch"):
        load_study_fixture_set(manifest)

    empty_manifest = _copy_fixture_tree(tmp_path / "empty")
    empty_root = tmp_path / "empty/fixtures/sources/read_only_control"
    shutil.rmtree(empty_root)
    empty_root.mkdir(parents=True)
    with pytest.raises(ValueError, match="no files"):
        load_study_fixture_set(empty_manifest)

    dirty_manifest = _copy_fixture_tree(tmp_path / "dirty")
    dirty_path = tmp_path / "dirty/fixtures/sources/read_only_control/.pytest_cache"
    dirty_path.mkdir()
    (dirty_path / "state").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ValueError, match="excluded path"):
        load_study_fixture_set(dirty_manifest)


def test_materialization_rejects_non_empty_destination(tmp_path: Path) -> None:
    fixture = load_study_fixture_set().fixtures[0]
    destination = tmp_path / "materialized"
    destination.mkdir()
    (destination / "existing.txt").write_text("occupied\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not empty"):
        materialize_study_fixture(fixture, destination)
