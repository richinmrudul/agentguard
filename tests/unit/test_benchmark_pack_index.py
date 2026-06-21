import zipfile
from pathlib import Path
from typing import Optional

import pytest
import yaml
from typer.testing import CliRunner

import agentguard.benchmarks.index as pack_index
from agentguard.benchmarks.index import (
    BenchmarkPackError,
    BenchmarkPackIntegrityError,
    create_pack_index,
    install_index_pack,
    load_pack_index,
    resolve_index_pack,
    verify_pack_index,
)
from agentguard.benchmarks.packs import export_benchmark_pack
from agentguard.benchmarks.signing import (
    add_trusted_key,
    generate_hmac_keypair,
    init_trust_policy,
    sign_benchmark_pack,
)
from agentguard.cli.main import app


runner = CliRunner()


def _pack(tmp_path: Path, name: str = "auth.zip", *benchmark_ids: str) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    output = tmp_path / name
    export_benchmark_pack(
        registry_path=Path("examples/benchmarks/registry.yaml"),
        output_path=output,
        benchmark_values=list(benchmark_ids) or ["auth_bug"],
        force=True,
    )
    return output


def _signature(tmp_path: Path, pack: Path) -> tuple[Path, Path]:
    keys = generate_hmac_keypair(tmp_path / "keys", "Index Test Key")
    signature = tmp_path / f"{pack.stem}.sig.json"
    sign_benchmark_pack(pack, keys.private_key_path, signature)
    return signature, keys.public_key_path


def _policy(tmp_path: Path, public_key: Path) -> Path:
    policy = tmp_path / "trust.yaml"
    init_trust_policy(policy)
    add_trusted_key(policy, public_key)
    return policy


def _index(tmp_path: Path, *packs: Path, signature: Optional[Path] = None) -> Path:
    output = tmp_path / "pack-index.yaml"
    create_pack_index(
        pack_paths=list(packs),
        output_path=output,
        signature_paths=[signature] if signature else [],
        base_dir=tmp_path,
        force=True,
    )
    return output


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _tamper_pack(source: Path, target: Path) -> Path:
    with zipfile.ZipFile(source, "r") as src, zipfile.ZipFile(
        target,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as dst:
        for info in src.infolist():
            content = src.read(info.filename)
            if info.filename == "configs/fix_auth_bug_docker_command_safe.yaml":
                content += b"\n# tampered\n"
            dst.writestr(info, content)
    return target


def test_index_create_from_one_pack(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = load_pack_index(index)

    assert data["schema"] == "agentguard.benchmark-pack-index"
    assert len(data["packs"]) == 1
    assert data["packs"][0]["source"] == {"type": "file", "path": "auth.zip"}
    assert data["packs"][0]["pack_version"] == "1.0.0"


def test_index_create_multiple_packs_deterministic_order(tmp_path: Path) -> None:
    first = _pack(tmp_path, "z.zip", "symlink_path_traversal")
    second = _pack(tmp_path, "a.zip", "auth_bug")
    index = _index(tmp_path, first, second)
    data = load_pack_index(index)

    observed = [(item["pack_id"], item["pack_version"]) for item in data["packs"]]
    assert observed == sorted(observed)


def test_index_list_output(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)

    result = runner.invoke(app, ["benchmarks", "pack", "index", "list", str(index)])

    assert result.exit_code == 0
    assert "Benchmark pack index: agentguard-local" in result.output
    assert "benchmarks=1" in result.output
    assert "trust=unchecked" in result.output


def test_index_verify_valid_local_pack(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)

    result = verify_pack_index(index)

    assert result.messages == [f"{result.entries[0]['pack_id']}@1.0.0: verified"]


def test_index_verify_detects_digest_mismatch(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    pack.write_bytes(pack.read_bytes() + b"tamper")

    with pytest.raises(BenchmarkPackIntegrityError, match="digest mismatch"):
        verify_pack_index(index)


def test_index_verify_detects_missing_pack(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    pack.unlink()

    with pytest.raises(BenchmarkPackIntegrityError, match="missing"):
        verify_pack_index(index)


def test_index_verify_detects_malformed_index(tmp_path: Path) -> None:
    index = tmp_path / "bad.yaml"
    index.write_text("schema: nope\npacks: []\n", encoding="utf-8")

    with pytest.raises(BenchmarkPackError, match="schema"):
        load_pack_index(index)


def test_index_trust_policy_verification(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    signature, public_key = _signature(tmp_path, pack)
    policy = _policy(tmp_path, public_key)
    index = _index(tmp_path, pack, signature=signature)

    result = verify_pack_index(index, trust_policy=policy)

    assert "trust trusted" in result.messages[0]


def test_index_list_trust_policy_statuses(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    signature, public_key = _signature(tmp_path, pack)
    policy = _policy(tmp_path, public_key)
    signed_index = _index(tmp_path, pack, signature=signature)
    unsigned_index = _index(tmp_path / "unsigned", _pack(tmp_path / "unsigned"))
    data = _load_yaml(signed_index)
    data["packs"][0]["signature"]["signature_path"] = "missing.sig.json"
    invalid_index = tmp_path / "invalid-trust-index.yaml"
    _write_yaml(invalid_index, data)

    signed = "\n".join(pack_index.list_pack_index(signed_index, trust_policy=policy))
    unsigned = "\n".join(pack_index.list_pack_index(unsigned_index, trust_policy=policy))
    invalid = "\n".join(pack_index.list_pack_index(invalid_index, trust_policy=policy))

    assert "trust=trusted" in signed
    assert "trust=unsigned" in unsigned
    assert "trust=invalid" in invalid


def test_index_trust_policy_rejects_unsigned_pack(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    _, public_key = _signature(tmp_path, pack)
    policy = _policy(tmp_path, public_key)
    index = _index(tmp_path, pack)

    result = runner.invoke(
        app,
        ["benchmarks", "pack", "index", "verify", str(index), "--trust-policy", str(policy)],
    )

    assert result.exit_code == 1
    assert "requires signatures" in result.output


def test_index_install_dry_run_writes_nothing(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    dest = tmp_path / "imported"

    _, plan = install_index_pack(index, pack_id=load_pack_index(index)["packs"][0]["pack_id"], dest_path=dest, dry_run=True)

    assert plan.files
    assert not dest.exists()


def test_index_install_imports_expected_files(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    dest = tmp_path / "imported"

    install_index_pack(
        index,
        pack_id=load_pack_index(index)["packs"][0]["pack_id"],
        dest_path=dest,
    )

    assert (dest / "registry" / "registry.yaml").is_file()
    assert (dest / "contracts" / "auth_bug.yaml").is_file()


def test_index_install_with_signature_trust_policy(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    signature, public_key = _signature(tmp_path, pack)
    policy = _policy(tmp_path, public_key)
    index = _index(tmp_path, pack, signature=signature)

    _, plan = install_index_pack(
        index,
        pack_id=load_pack_index(index)["packs"][0]["pack_id"],
        dest_path=tmp_path / "trusted-import",
        trust_policy=policy,
        dry_run=True,
    )

    assert plan.trust_status == "trusted"


def test_index_install_detects_digest_mismatch_before_import(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    pack.write_bytes(pack.read_bytes() + b"tamper")

    with pytest.raises(BenchmarkPackIntegrityError, match="digest mismatch"):
        install_index_pack(
            index,
            pack_id=load_pack_index(index)["packs"][0]["pack_id"],
            dest_path=tmp_path / "dest",
        )


def test_index_version_selection_latest_semver(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    older = dict(data["packs"][0])
    older["pack_version"] = "0.9.0"
    data["packs"].append(older)
    _write_yaml(index, data)

    selected = resolve_index_pack(index, pack_id=data["packs"][0]["pack_id"])

    assert selected.entry["pack_version"] == "1.0.0"


def test_index_version_selection_explicit_version(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    older = dict(data["packs"][0])
    older["pack_version"] = "0.9.0"
    data["packs"].append(older)
    _write_yaml(index, data)

    selected = resolve_index_pack(
        index,
        pack_id=data["packs"][0]["pack_id"],
        version="0.9.0",
    )

    assert selected.entry["pack_version"] == "0.9.0"


def test_index_resolve_errors_for_missing_pack_and_version(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    pack_id = load_pack_index(index)["packs"][0]["pack_id"]

    with pytest.raises(BenchmarkPackError, match="pack not found"):
        resolve_index_pack(index, pack_id="missing")
    with pytest.raises(BenchmarkPackError, match="version not found"):
        resolve_index_pack(index, pack_id=pack_id, version="9.9.9")


def test_index_rejects_path_traversal_source(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0]["source"]["path"] = "../auth.zip"
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackError, match="path traversal"):
        load_pack_index(index)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("benchmark_versions", [], "benchmark_versions"),
        ("pack_digest", "bad", "SHA-256"),
        ("size_bytes", -1, "size_bytes"),
        ("categories", ["ok", 1], "categories"),
    ],
)
def test_index_rejects_malformed_entry_fields(
    tmp_path: Path,
    field: str,
    value,
    match: str,
) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0][field] = value
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackError, match=match):
        load_pack_index(index)


@pytest.mark.parametrize(
    ("source", "match"),
    [
        ([], "source must be a mapping"),
        ({"type": "ftp", "path": "pack.zip"}, "source type"),
        ({"type": "url", "path": "not-a-url"}, "URL source"),
        ({"type": "file", "path": "https://example.invalid/pack.zip"}, "must not be a URL"),
    ],
)
def test_index_rejects_malformed_sources(tmp_path: Path, source, match: str) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0]["source"] = source
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackError, match=match):
        load_pack_index(index)


def test_index_rejects_bad_json_and_non_mapping(tmp_path: Path) -> None:
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{", encoding="utf-8")
    list_yaml = tmp_path / "list.yaml"
    list_yaml.write_text("- nope\n", encoding="utf-8")

    with pytest.raises(BenchmarkPackError, match="not valid JSON"):
        load_pack_index(bad_json)
    with pytest.raises(BenchmarkPackError, match="must be a mapping"):
        load_pack_index(list_yaml)


def test_index_rejects_empty_create_and_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "index.yaml"
    output.write_text("exists", encoding="utf-8")

    with pytest.raises(BenchmarkPackError, match="at least one"):
        create_pack_index(pack_paths=[], output_path=tmp_path / "empty.yaml")
    with pytest.raises(FileExistsError, match="already exists"):
        create_pack_index(pack_paths=[_pack(tmp_path)], output_path=output)


def test_index_url_sources_are_listed_but_not_installed(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0]["source"] = {
        "type": "url",
        "path": "https://example.invalid/auth.zip",
    }
    _write_yaml(index, data)

    listed = runner.invoke(app, ["benchmarks", "pack", "index", "list", str(index)])
    installed = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "index",
            "install",
            str(index),
            "--pack",
            data["packs"][0]["pack_id"],
            "--dest",
            str(tmp_path / "dest"),
        ],
    )

    assert listed.exit_code == 0
    assert "source=url:https://example.invalid/auth.zip" in listed.output
    assert installed.exit_code == 2
    assert "URL pack installation is not supported" in installed.output


def test_index_verify_url_source_metadata_only(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0]["source"] = {
        "type": "url",
        "path": "https://example.invalid/auth.zip",
    }
    _write_yaml(index, data)

    result = verify_pack_index(index)

    assert "URL source metadata only" in result.messages[0]


def test_index_duplicate_pack_id_version_rejected(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"].append(dict(data["packs"][0]))
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackError, match="duplicate"):
        load_pack_index(index)


def test_index_compatibility_version_validation(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0]["compatibility"]["min_agentguard_version"] = "not-semver"
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackError, match="invalid strict semver"):
        load_pack_index(index)


def test_index_compatibility_bounds_validation(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    data = _load_yaml(index)
    data["packs"][0]["compatibility"] = {
        "min_agentguard_version": "2.0.0",
        "max_agentguard_version": "1.0.0",
    }
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackError, match="max is lower"):
        load_pack_index(index)


def test_index_signature_metadata_mismatches(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    signature, _ = _signature(tmp_path, pack)
    index = _index(tmp_path, pack, signature=signature)
    data = _load_yaml(index)
    data["packs"][0]["signature"]["pack_root_digest"] = "f" * 64
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackIntegrityError, match="signature root digest"):
        verify_pack_index(index)


def test_index_signature_file_mismatches_key_id(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    signature, _ = _signature(tmp_path, pack)
    index = _index(tmp_path, pack, signature=signature)
    data = _load_yaml(index)
    data["packs"][0]["signature"]["key_id"] = "wrong-key"
    _write_yaml(index, data)

    with pytest.raises(BenchmarkPackIntegrityError, match="key_id"):
        verify_pack_index(index)


def test_index_rejects_malformed_signature_metadata(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    signature, _ = _signature(tmp_path, pack)
    signature.write_text("{", encoding="utf-8")

    with pytest.raises(BenchmarkPackError, match="not valid JSON"):
        create_pack_index(
            pack_paths=[pack],
            output_path=tmp_path / "index.yaml",
            signature_paths=[signature],
        )


def test_index_rejects_unsafe_input_path_and_semver_type(tmp_path: Path) -> None:
    with pytest.raises(BenchmarkPackError, match="path traversal"):
        load_pack_index(Path("../index.yaml"))
    with pytest.raises(BenchmarkPackError, match="strict semver"):
        pack_index.parse_semver(1)  # type: ignore[arg-type]


def test_pack_version_and_display_path_helpers(tmp_path: Path) -> None:
    assert pack_index._pack_version_to_semver("2.3.4") == "2.3.4"
    assert pack_index._version_to_semver("v1.2") == "1.2.0"
    assert pack_index._version_to_semver("dev") == "0.0.0"
    outside = Path("/private/tmp/outside-pack.zip")
    assert pack_index._display_path(outside, tmp_path).endswith("outside-pack.zip")
    with pytest.raises(BenchmarkPackError, match="pack_version"):
        pack_index._pack_version_to_semver(False)


def test_index_cli_create_show_and_install(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = tmp_path / "cli-index.yaml"

    created = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "index",
            "create",
            "--pack",
            str(pack),
            "--output",
            str(index),
            "--base-dir",
            str(tmp_path),
        ],
    )
    pack_id = load_pack_index(index)["packs"][0]["pack_id"]
    shown = runner.invoke(
        app,
        ["benchmarks", "pack", "index", "show", str(index), "--pack", pack_id],
    )
    installed = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "index",
            "install",
            str(index),
            "--pack",
            pack_id,
            "--dest",
            str(tmp_path / "cli-import"),
            "--dry-run",
        ],
    )

    assert created.exit_code == 0
    assert "Packs: 1" in created.output
    assert shown.exit_code == 0
    assert "Signature:\n- none" in shown.output
    assert installed.exit_code == 0
    assert "Benchmark pack index install plan" in installed.output


def test_index_cli_exit_codes(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    index = _index(tmp_path, pack)
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema: nope\npacks: []\n", encoding="utf-8")
    pack.write_bytes(pack.read_bytes() + b"tamper")

    mismatch = runner.invoke(app, ["benchmarks", "pack", "index", "verify", str(index)])
    malformed = runner.invoke(app, ["benchmarks", "pack", "index", "verify", str(bad)])

    assert mismatch.exit_code == 1
    assert malformed.exit_code == 2
