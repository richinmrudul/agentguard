import json
import os
import unicodedata
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.benchmarks import packs as packs_module
from agentguard.benchmarks.contracts import load_registry_contracts
from agentguard.benchmarks.packs import (
    MANIFEST_PATH,
    BenchmarkPackError,
    BenchmarkPackIntegrityError,
    export_benchmark_pack,
    import_benchmark_pack,
    inspect_benchmark_pack,
    verify_benchmark_pack,
)
from agentguard.benchmarks.registry import load_benchmark_registry
from agentguard.cli.main import app
from agentguard.core.suite import load_suite_config


runner = CliRunner()


def _export_pack(tmp_path: Path, *benchmark_ids: str, include_docs: bool = False) -> Path:
    output = tmp_path / "benchmarks.zip"
    export_benchmark_pack(
        registry_path=Path("examples/benchmarks/registry.yaml"),
        output_path=output,
        benchmark_values=list(benchmark_ids) or None,
        include_docs=include_docs,
        force=True,
    )
    return output


def _zip_map(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path, "r") as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def _rewrite_zip(path: Path, output: Path, files: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 & 0xFFFF) << 16
            archive.writestr(info, content)
    return output


def _append_zip_member(
    path: Path, output: Path, name: str, content: bytes = b"x"
) -> Path:
    with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(output, "w") as archive:
        for info in source.infolist():
            archive.writestr(info, source.read(info))
        archive.writestr(name, content)
    return output


def _manifest(files: dict[str, bytes]) -> dict:
    return json.loads(files[MANIFEST_PATH].decode("utf-8"))


def _write_manifest(files: dict[str, bytes], manifest: dict) -> dict[str, bytes]:
    updated = dict(files)
    updated[MANIFEST_PATH] = json.dumps(manifest, sort_keys=True).encode("utf-8")
    return updated


def _verify_with_manifest(
    tmp_path: Path,
    pack: Path,
    manifest: dict,
    name: str,
) -> None:
    files = _zip_map(pack)
    verify_benchmark_pack(
        _rewrite_zip(pack, tmp_path / name, _write_manifest(files, manifest))
    )


def _minimal_registry(tmp_path: Path) -> Path:
    repo = tmp_path / "repos" / "mini"
    repo.mkdir(parents=True)
    (repo / "src.py").write_text("print('ok')\n", encoding="utf-8")
    (repo / ".agentguard").mkdir()
    (repo / ".agentguard" / "run.db").write_text("db", encoding="utf-8")
    (repo / ".pytest_cache").mkdir()
    (repo / ".pytest_cache" / "cache").write_text("cache", encoding="utf-8")
    (repo / "report.log").write_text("log", encoding="utf-8")
    configs = tmp_path / "configs"
    configs.mkdir()
    for name in ("safe", "adversarial"):
        (configs / f"{name}.yaml").write_text(
            f"""
task_id: mini_{name}
description: Mini benchmark.
repo_template: {repo}
test_command: python src.py
expected_modified_files:
  min: 0
  max: 1
benchmark:
  id: mini
  version: 1
  category: test_tampering
  difficulty: easy
""",
            encoding="utf-8",
        )
    contracts = tmp_path / "contracts"
    contracts.mkdir()
    (contracts / "mini.yaml").write_text(
        f"""
schema: agentguard.benchmark-contract
schema_version: 1
benchmark_id: mini
benchmark_version: 1
variants:
  safe:
    config: {configs / "safe.yaml"}
    expected:
      result: PASS
      functional_tests: PASS
      score: {{min: 0, max: 100}}
      modified_paths:
        required: []
        allowed: []
        forbidden: []
      failed_checks:
        required: []
        forbidden: []
      evidence_patterns:
        required: []
        forbidden: []
  adversarial:
    config: {configs / "adversarial.yaml"}
    expected:
      result: FAIL
      functional_tests: PASS
      score: {{min: 0, max: 100}}
      modified_paths:
        required: []
        allowed: []
        forbidden: []
      failed_checks:
        required: []
        forbidden: []
      evidence_patterns:
        required: []
        forbidden: []
""",
        encoding="utf-8",
    )
    registry = tmp_path / "registry.yaml"
    registry.write_text(
        f"""
benchmarks:
  - id: mini
    version: 1
    name: Mini
    category: test_tampering
    difficulty: easy
    description: Mini benchmark.
    tags: [python]
    configs:
      safe: {configs / "safe.yaml"}
      adversarial: {configs / "adversarial.yaml"}
    contract: {contracts / "mini.yaml"}
""",
        encoding="utf-8",
    )
    return registry


def test_export_single_benchmark_pack_contains_required_files(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug", include_docs=True)
    result = verify_benchmark_pack(pack)

    paths = {file.path for file in result.files}
    assert "registry/registry.yaml" in paths
    assert "contracts/auth_bug.yaml" in paths
    assert "configs/fix_auth_bug_docker_command_safe.yaml" in paths
    assert "repos/auth_bug/src/auth_example/login.py" in paths
    assert "docs/benchmarks.md" in paths
    assert result.manifest["benchmarks"] == [{"id": "auth_bug", "version": 1}]


def test_export_refuses_overwrite_and_unknown_benchmark(tmp_path: Path) -> None:
    output = tmp_path / "pack.zip"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError, match="already exists"):
        export_benchmark_pack(
            registry_path=Path("examples/benchmarks/registry.yaml"),
            output_path=output,
            benchmark_values=["auth_bug"],
        )
    with pytest.raises(ValueError, match="benchmark not found"):
        export_benchmark_pack(
            registry_path=Path("examples/benchmarks/registry.yaml"),
            output_path=tmp_path / "missing.zip",
            benchmark_values=["missing"],
        )


def test_export_multiple_benchmarks_with_safe_symlink(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug,symlink_path_traversal")
    result = verify_benchmark_pack(pack)

    assert {item["id"] for item in result.manifest["benchmarks"]} == {
        "auth_bug",
        "symlink_path_traversal",
    }
    symlink = next(
        file for file in result.files if file.path.endswith("linked_secrets")
    )
    assert symlink.type == "symlink"


def test_export_rejects_portable_aliases_before_writing() -> None:
    with pytest.raises(BenchmarkPackError, match="filesystem-equivalent"):
        packs_module._dedupe_files(
            {
                "repos/example/Case.txt": b"first",
                "repos/example/case.txt": b"second",
            }
        )


def test_export_excludes_agentguard_caches_dbs_and_reports(tmp_path: Path) -> None:
    registry = _minimal_registry(tmp_path)
    output = tmp_path / "mini.zip"

    export_benchmark_pack(registry_path=registry, output_path=output, force=True)

    paths = {file.path for file in verify_benchmark_pack(output).files}
    assert "repos/mini/src.py" in paths
    assert not any(".agentguard" in path for path in paths)
    assert not any(".pytest_cache" in path for path in paths)
    assert not any(path.endswith(".db") or path.endswith(".log") for path in paths)


def test_verify_detects_hash_mismatch(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    files["configs/fix_auth_bug_docker_command_safe.yaml"] = b"tampered\n"
    tampered = _rewrite_zip(pack, tmp_path / "tampered.zip", files)

    with pytest.raises(BenchmarkPackIntegrityError, match="hash mismatch"):
        verify_benchmark_pack(tampered)


def test_verify_detects_missing_file(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    files.pop("contracts/auth_bug.yaml")
    missing = _rewrite_zip(pack, tmp_path / "missing.zip", files)

    with pytest.raises(BenchmarkPackIntegrityError, match="missing listed files"):
        verify_benchmark_pack(missing)


def test_verify_detects_missing_manifest(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    files.pop(MANIFEST_PATH)
    missing = _rewrite_zip(pack, tmp_path / "missing-manifest.zip", files)

    with pytest.raises(BenchmarkPackError, match="missing manifest"):
        verify_benchmark_pack(missing)


def test_verify_detects_unlisted_file(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    files["extra.txt"] = b"extra"
    extra = _rewrite_zip(pack, tmp_path / "extra.zip", files)

    with pytest.raises(BenchmarkPackError, match="unlisted files"):
        verify_benchmark_pack(extra)


def test_verify_detects_invalid_manifest_json(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    files[MANIFEST_PATH] = b"{"
    invalid = _rewrite_zip(pack, tmp_path / "invalid-json.zip", files)

    with pytest.raises(BenchmarkPackError, match="not valid JSON"):
        verify_benchmark_pack(invalid)


def test_verify_detects_root_digest_mismatch(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    manifest = _manifest(files)
    manifest["root_digest"] = "0" * 64
    bad = _rewrite_zip(pack, tmp_path / "bad-root.zip", _write_manifest(files, manifest))

    with pytest.raises(BenchmarkPackIntegrityError, match="root digest"):
        verify_benchmark_pack(bad)


def test_verify_detects_manifest_registry_mismatch(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    manifest = _manifest(files)
    manifest["benchmarks"] = [{"id": "other", "version": 1}]
    bad = _rewrite_zip(
        pack,
        tmp_path / "bad-registry-match.zip",
        _write_manifest(files, manifest),
    )

    with pytest.raises(BenchmarkPackError, match="do not match registry"):
        verify_benchmark_pack(bad)


def test_verify_detects_manifest_type_mismatch(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    manifest = _manifest(files)
    manifest["files"][0]["type"] = "symlink"
    bad = _rewrite_zip(
        pack,
        tmp_path / "bad-type.zip",
        _write_manifest(files, manifest),
    )

    with pytest.raises(BenchmarkPackError, match="type does not match"):
        verify_benchmark_pack(bad)


def test_verify_rejects_malformed_manifest_schema_fields(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    manifest = _manifest(files)

    missing = dict(manifest)
    missing.pop("pack_id")
    with pytest.raises(BenchmarkPackError, match="missing fields"):
        _verify_with_manifest(tmp_path, pack, missing, "missing-field.zip")

    wrong_schema = dict(manifest)
    wrong_schema["schema"] = "wrong"
    with pytest.raises(BenchmarkPackError, match="schema must"):
        _verify_with_manifest(tmp_path, pack, wrong_schema, "wrong-schema.zip")

    wrong_version = dict(manifest)
    wrong_version["schema_version"] = 2
    with pytest.raises(BenchmarkPackError, match="schema_version"):
        _verify_with_manifest(tmp_path, pack, wrong_version, "wrong-version.zip")

    bad_paths = dict(manifest)
    bad_paths["docs_paths"] = "../docs"
    with pytest.raises(BenchmarkPackError, match="docs_paths"):
        _verify_with_manifest(tmp_path, pack, bad_paths, "bad-path-list.zip")


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ([], "non-empty list"),
        ([None], "must be objects"),
        ([{"path": "x", "sha256": "bad", "size": 1}], "invalid hash"),
        ([{"path": "x", "sha256": "0" * 64, "size": -1}], "invalid size"),
        (
            [{"path": "x", "sha256": "0" * 64, "size": 1, "type": "device"}],
            "invalid type",
        ),
        (
            [
                {"path": "x", "sha256": "0" * 64, "size": 1},
                {"path": "x", "sha256": "0" * 64, "size": 1},
            ],
            "duplicate file path",
        ),
    ],
)
def test_verify_rejects_malformed_manifest_file_entries(
    tmp_path: Path,
    replacement: list,
    message: str,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    manifest = _manifest(_zip_map(pack))
    manifest["files"] = replacement

    with pytest.raises(BenchmarkPackError, match=message):
        _verify_with_manifest(tmp_path, pack, manifest, "bad-files.zip")


@pytest.mark.parametrize("bad_name", ["../evil.txt", "/tmp/evil.txt"])
def test_verify_detects_unsafe_archive_paths(tmp_path: Path, bad_name: str) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    files[bad_name] = b"evil"
    bad = _rewrite_zip(pack, tmp_path / "bad-path.zip", files)

    with pytest.raises(BenchmarkPackError, match="unsafe"):
        verify_benchmark_pack(bad)


def test_verify_detects_duplicate_normalized_path(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("same.txt", "one")
        archive.writestr("same.txt", "two")

    with pytest.raises(BenchmarkPackError, match="duplicate normalized path"):
        verify_benchmark_pack(duplicate)


@pytest.mark.parametrize(
    "alias",
    [
        "CONFIGS/fix_auth_bug_docker_command_safe.yaml",
        unicodedata.normalize(
            "NFD", "configs/caf\N{LATIN SMALL LETTER E WITH ACUTE}.yaml"
        ),
    ],
)
def test_verify_rejects_portable_case_and_unicode_aliases(
    tmp_path: Path,
    alias: str,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    if "caf" in alias:
        first = "configs/caf\N{LATIN SMALL LETTER E WITH ACUTE}.yaml"
        once = _append_zip_member(pack, tmp_path / "once.zip", first)
        bad = _append_zip_member(once, tmp_path / "alias.zip", alias)
    else:
        bad = _append_zip_member(pack, tmp_path / "alias.zip", alias)

    with pytest.raises(BenchmarkPackError, match="filesystem-equivalent"):
        verify_benchmark_pack(bad)


@pytest.mark.parametrize(
    "name",
    [
        "configs//alias.yaml",
        "configs/./alias.yaml",
        "configs/alias.yaml/",
        "configs\\alias.yaml",
        "C:/alias.yaml",
        "CON",
        "configs/CONOUT$.txt",
        "configs/COM\N{SUPERSCRIPT ONE}.txt",
        "configs/nul.txt",
        "configs/alias.",
        "configs/alias ",
    ],
)
def test_verify_rejects_nonportable_member_spellings(tmp_path: Path, name: str) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    bad = _append_zip_member(pack, tmp_path / "nonportable.zip", name)

    with pytest.raises(BenchmarkPackError, match="path|filesystem"):
        verify_benchmark_pack(bad)


def test_verify_rejects_file_directory_prefix_collision(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    once = _append_zip_member(pack, tmp_path / "file.zip", "prefix")
    bad = _append_zip_member(once, tmp_path / "prefix.zip", "prefix/child")

    with pytest.raises(BenchmarkPackError, match="filesystem-equivalent"):
        verify_benchmark_pack(bad)


def test_verify_rejects_symlink_path_alias_before_content_processing(
    tmp_path: Path,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    output = tmp_path / "symlink-alias.zip"
    with zipfile.ZipFile(pack, "r") as source, zipfile.ZipFile(output, "w") as archive:
        for info in source.infolist():
            archive.writestr(info, source.read(info))
        info = zipfile.ZipInfo("CONFIGS/fix_auth_bug_docker_command_safe.yaml")
        info.external_attr = (0o120777 & 0xFFFF) << 16
        archive.writestr(info, "target")

    with pytest.raises(BenchmarkPackError, match="filesystem-equivalent"):
        verify_benchmark_pack(output)


def test_verify_rejects_manifest_only_portable_alias(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    files = _zip_map(pack)
    manifest = _manifest(files)
    original = manifest["files"][0]
    manifest["files"].append({**original, "path": original["path"].upper()})
    bad = _rewrite_zip(
        pack,
        tmp_path / "manifest-alias.zip",
        _write_manifest(files, manifest),
    )

    with pytest.raises(BenchmarkPackError, match="filesystem-equivalent"):
        verify_benchmark_pack(bad)


def test_import_rejects_member_aliases_before_destination_writes(
    tmp_path: Path,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    bad = _append_zip_member(
        pack,
        tmp_path / "import-alias.zip",
        "CONFIGS/fix_auth_bug_docker_command_safe.yaml",
    )
    dest = tmp_path / "dest"

    with pytest.raises(BenchmarkPackError, match="filesystem-equivalent"):
        import_benchmark_pack(pack_path=bad, dest_path=dest, force=True)

    assert not dest.exists()


def test_verify_detects_symlink_escape(tmp_path: Path) -> None:
    manifest = {
        "schema": "agentguard.benchmark-pack",
        "schema_version": 1,
        "pack_id": "bad",
        "pack_version": 1,
        "created_at": "1970-01-01T00:00:00Z",
        "agentguard": {"version": "0", "commit": None},
        "benchmarks": [],
        "files": [
            {
                "path": "repos/x/link",
                "sha256": "1ec46f9559c020ee4aa752ed7d5a4813f2e820fb0c050e8a9729079f8d0af6ef",
                "size": 9,
                "type": "symlink",
            }
        ],
        "root_digest": "bad",
        "entrypoint_registry_fragment": "registry/registry.yaml",
        "contract_paths": [],
        "config_paths": [],
        "repo_fixture_paths": [],
        "docs_paths": [],
    }
    bad = tmp_path / "symlink.zip"
    with zipfile.ZipFile(bad, "w") as archive:
        info = zipfile.ZipInfo("repos/x/link", (1980, 1, 1, 0, 0, 0))
        info.external_attr = (0o120777 & 0xFFFF) << 16
        archive.writestr(info, "../escape")
        archive.writestr(MANIFEST_PATH, json.dumps(manifest))

    with pytest.raises(BenchmarkPackError, match="symlink"):
        verify_benchmark_pack(bad)


def test_inspect_output_reports_valid_contracts(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")

    result = inspect_benchmark_pack(pack)

    assert result["pack_id"].startswith("benchmark-pack-")
    assert result["contract_status"] == "valid"
    assert result["files"]


def test_dry_run_import_writes_nothing(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"

    plan = import_benchmark_pack(pack_path=pack, dest_path=dest, dry_run=True)

    assert plan.files
    assert not dest.exists()


def test_import_writes_files_registry_and_suite_validate(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    registry_out = tmp_path / "imported-registry.yaml"
    suite_out = tmp_path / "imported-suite.yaml"

    import_benchmark_pack(
        pack_path=pack,
        dest_path=dest,
        registry_out=registry_out,
        suite_out=suite_out,
    )

    assert (dest / "repos/auth_bug/src/auth_example/login.py").is_file()
    registry = load_benchmark_registry(registry_out)
    assert len(load_registry_contracts(registry)) == 1
    suite = load_suite_config(suite_out)
    assert len(suite.runs) == 2


def test_import_refuses_collisions_without_force(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    import_benchmark_pack(pack_path=pack, dest_path=dest)

    plan = import_benchmark_pack(pack_path=pack, dest_path=dest)

    assert plan.collisions


def test_import_force_overwrites_regular_files_and_registry_out(
    tmp_path: Path,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    registry_out = tmp_path / "registry.yaml"
    import_benchmark_pack(pack_path=pack, dest_path=dest, registry_out=registry_out)
    target = dest / "repos/auth_bug/src/auth_example/login.py"
    target.write_text("old", encoding="utf-8")
    registry_out.write_text("old", encoding="utf-8")

    import_benchmark_pack(
        pack_path=pack,
        dest_path=dest,
        registry_out=registry_out,
        force=True,
    )

    assert target.read_text(encoding="utf-8") != "old"
    assert "benchmarks:" in registry_out.read_text(encoding="utf-8")


def test_import_creates_safe_symlink(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "symlink_path_traversal")
    dest = tmp_path / "dest"

    import_benchmark_pack(pack_path=pack, dest_path=dest)

    link = dest / "repos/symlink_path_traversal/linked_secrets"
    assert link.is_symlink()
    assert link.readlink() == Path("secrets")


def test_import_preparation_failure_leaves_no_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    registry_out = tmp_path / "registry.yaml"
    suite_out = tmp_path / "suite.yaml"

    def fail_suite(*args, **kwargs) -> None:
        raise ValueError("controlled late failure")

    monkeypatch.setattr("agentguard.benchmarks.packs.generate_suite_data", fail_suite)
    with pytest.raises(ValueError, match="controlled late failure"):
        import_benchmark_pack(
            pack_path=pack,
            dest_path=dest,
            registry_out=registry_out,
            suite_out=suite_out,
        )

    assert not dest.exists()
    assert not registry_out.exists()
    assert not suite_out.exists()


def test_import_commit_failure_rolls_back_destination_and_side_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    registry_out = tmp_path / "registry.yaml"
    registry_out.write_text("original registry\n", encoding="utf-8")
    real_replace = os.replace

    def fail_once(source, destination) -> None:
        source_path = Path(source)
        if Path(destination) == registry_out and source_path.name.endswith(
            ".pack-import"
        ):
            monkeypatch.setattr("agentguard.benchmarks.packs.os.replace", real_replace)
            raise OSError("controlled replace failure")
        real_replace(source, destination)

    monkeypatch.setattr("agentguard.benchmarks.packs.os.replace", fail_once)
    with pytest.raises(OSError, match="controlled replace failure"):
        import_benchmark_pack(
            pack_path=pack,
            dest_path=dest,
            registry_out=registry_out,
            force=True,
        )

    assert not dest.exists()
    assert registry_out.read_text(encoding="utf-8") == "original registry\n"
    assert not list(tmp_path.rglob("*.pack-import"))
    assert not list(tmp_path.rglob("*.pack-backup"))


def test_import_non_force_race_preserves_new_output_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    registry_out = tmp_path / "registry.yaml"
    suite_out = tmp_path / "suite.yaml"
    real_prepare = packs_module._prepare_import_mutations

    def prepare_with_raced_output(*args, **kwargs):
        mutations = real_prepare(*args, **kwargs)
        registry_out.write_text("raced-in registry\n", encoding="utf-8")
        return mutations

    monkeypatch.setattr(
        "agentguard.benchmarks.packs._prepare_import_mutations",
        prepare_with_raced_output,
    )

    with pytest.raises(FileExistsError, match="appeared after collision validation"):
        import_benchmark_pack(
            pack_path=pack,
            dest_path=dest,
            registry_out=registry_out,
            suite_out=suite_out,
        )

    assert registry_out.read_text(encoding="utf-8") == "raced-in registry\n"
    assert not dest.exists()
    assert not suite_out.exists()
    assert not list(tmp_path.rglob("*.pack-import"))
    assert not list(tmp_path.rglob("*.pack-backup"))


def test_import_retains_recoverable_backup_when_final_restore_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    dest = tmp_path / "dest"
    suite_out = tmp_path / "suite.yaml"
    suite_out.write_text("original suite\n", encoding="utf-8")
    real_replace = os.replace

    def fail_final_install_and_restore(source, destination) -> None:
        source_path = Path(source)
        if Path(destination) == suite_out and source_path.name.endswith(
            (".pack-import", ".pack-backup")
        ):
            raise OSError("private path must not be reported")
        real_replace(source, destination)

    monkeypatch.setattr(
        "agentguard.benchmarks.packs.os.replace",
        fail_final_install_and_restore,
    )

    with pytest.raises(BenchmarkPackError, match="recoverable backup retained") as error:
        import_benchmark_pack(
            pack_path=pack,
            dest_path=dest,
            suite_out=suite_out,
            force=True,
        )

    assert str(tmp_path) not in str(error.value)
    assert not dest.exists()
    assert not suite_out.exists()
    assert not list(tmp_path.rglob("*.pack-import"))
    backups = list(tmp_path.rglob("*.pack-backup"))
    assert len(backups) == 1
    assert backups[0].read_text(encoding="utf-8") == "original suite\n"

    real_replace(backups[0], suite_out)
    assert suite_out.read_text(encoding="utf-8") == "original suite\n"


def test_export_is_deterministic_for_identical_inputs(tmp_path: Path) -> None:
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"

    export_benchmark_pack(
        registry_path=Path("examples/benchmarks/registry.yaml"),
        output_path=first,
        benchmark_values=["auth_bug"],
    )
    export_benchmark_pack(
        registry_path=Path("examples/benchmarks/registry.yaml"),
        output_path=second,
        benchmark_values=["auth_bug"],
    )

    assert first.read_bytes() == second.read_bytes()


def test_cli_exit_codes_for_verify_and_import_collision(tmp_path: Path) -> None:
    pack = _export_pack(tmp_path, "auth_bug")
    result = runner.invoke(app, ["benchmarks", "pack", "verify", str(pack)])
    assert result.exit_code == 0

    files = _zip_map(pack)
    files["configs/fix_auth_bug_docker_command_safe.yaml"] = b"tampered\n"
    tampered = _rewrite_zip(pack, tmp_path / "tampered-cli.zip", files)
    result = runner.invoke(app, ["benchmarks", "pack", "verify", str(tampered)])
    assert result.exit_code == 1

    malformed = tmp_path / "malformed.zip"
    malformed.write_text("not zip", encoding="utf-8")
    result = runner.invoke(app, ["benchmarks", "pack", "inspect", str(malformed)])
    assert result.exit_code == 2

    dest = tmp_path / "dest"
    result = runner.invoke(
        app,
        ["benchmarks", "pack", "import", "--pack", str(pack), "--dest", str(dest)],
    )
    assert result.exit_code == 0
    result = runner.invoke(
        app,
        ["benchmarks", "pack", "import", "--pack", str(pack), "--dest", str(dest)],
    )
    assert result.exit_code == 2
