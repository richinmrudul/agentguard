import json
import stat
import zipfile
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from agentguard.benchmarks.packs import (
    BenchmarkPackIntegrityError,
    export_benchmark_pack,
    import_benchmark_pack,
)
from agentguard.benchmarks.signing import (
    BenchmarkPackSignatureError,
    add_trusted_key,
    generate_hmac_keypair,
    init_trust_policy,
    load_trust_policy,
    sign_benchmark_pack,
    trust_policy_summary,
    verify_benchmark_pack_signature,
    verify_trust_policy,
)
from agentguard.cli.main import app


runner = CliRunner()


def _pack(tmp_path: Path) -> Path:
    output = tmp_path / "auth.zip"
    export_benchmark_pack(
        registry_path=Path("examples/benchmarks/registry.yaml"),
        output_path=output,
        benchmark_values=["auth_bug"],
        force=True,
    )
    return output


def _keys(tmp_path: Path, name: str = "CI Signing Key"):
    return generate_hmac_keypair(tmp_path / "keys", name)


def _signature(tmp_path: Path, pack: Path, private_key: Path) -> Path:
    output = tmp_path / "auth.sig.json"
    sign_benchmark_pack(pack, private_key, output)
    return output


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


def _tamper_signature(source: Path, target: Path) -> Path:
    data = json.loads(source.read_text(encoding="utf-8"))
    data["signature"] = "A" + data["signature"][1:]
    target.write_text(json.dumps(data), encoding="utf-8")
    return target


def _policy(tmp_path: Path, public_key: Path) -> Path:
    policy = tmp_path / "trust.yaml"
    init_trust_policy(policy)
    add_trusted_key(policy, public_key)
    return policy


def _load_yaml(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _write_yaml(path: Path, data: dict) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_key_generation_creates_files_and_restrictive_private_permissions(
    tmp_path: Path,
) -> None:
    keys = _keys(tmp_path)

    assert keys.private_key_path.is_file()
    assert keys.public_key_path.is_file()
    private = json.loads(keys.private_key_path.read_text(encoding="utf-8"))
    public = json.loads(keys.public_key_path.read_text(encoding="utf-8"))
    assert private["key_type"] == "private"
    assert public["key_type"] == "public"
    assert private["key_id"] == public["key_id"] == keys.key_id
    mode = stat.S_IMODE(keys.private_key_path.stat().st_mode)
    assert mode & 0o077 == 0


def test_keygen_refuses_overwrite(tmp_path: Path) -> None:
    keys = _keys(tmp_path)

    with pytest.raises(FileExistsError, match="already exists"):
        generate_hmac_keypair(keys.private_key_path.parent, keys.name)


def test_signature_verifies_valid_pack(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)

    result = verify_benchmark_pack_signature(pack, signature, keys.public_key_path)

    assert result.valid
    assert result.status == "valid"
    assert result.key_id == keys.key_id


def test_sign_refuses_invalid_pack_and_output_overwrite(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    output = _signature(tmp_path, pack, keys.private_key_path)

    with pytest.raises(FileExistsError, match="already exists"):
        sign_benchmark_pack(pack, keys.private_key_path, output)
    with pytest.raises(BenchmarkPackIntegrityError, match="hash mismatch"):
        sign_benchmark_pack(
            _tamper_pack(pack, tmp_path / "tampered-before-sign.zip"),
            keys.private_key_path,
            tmp_path / "bad.sig.json",
        )


def test_tampered_pack_fails_signature_verification(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    tampered = _tamper_pack(pack, tmp_path / "tampered.zip")

    with pytest.raises(BenchmarkPackIntegrityError, match="hash mismatch"):
        verify_benchmark_pack_signature(tampered, signature, keys.public_key_path)


def test_tampered_signature_fails(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    tampered = _tamper_signature(signature, tmp_path / "tampered.sig.json")

    result = verify_benchmark_pack_signature(pack, tampered, keys.public_key_path)

    assert not result.valid
    assert "cryptographic" in result.message


def test_wrong_public_key_fails(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path, "first")
    wrong = _keys(tmp_path / "wrong", "second")
    signature = _signature(tmp_path, pack, keys.private_key_path)

    result = verify_benchmark_pack_signature(pack, signature, wrong.public_key_path)

    assert not result.valid
    assert "key_id" in result.message


def test_malformed_key_and_signature_fail_with_cli_exit_2(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    bad_key = tmp_path / "bad-key.json"
    bad_key.write_text("{", encoding="utf-8")
    bad_signature = tmp_path / "bad-signature.json"
    bad_signature.write_text("{", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "verify-signature",
            str(pack),
            "--signature",
            str(signature),
            "--key",
            str(bad_key),
        ],
    )
    assert result.exit_code == 2


def test_cli_sign_and_verify_signature_happy_path(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = tmp_path / "cli.sig.json"

    sign_result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "sign",
            str(pack),
            "--key",
            str(keys.private_key_path),
            "--output",
            str(signature),
        ],
    )
    verify_result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "verify-signature",
            str(pack),
            "--signature",
            str(signature),
            "--key",
            str(keys.public_key_path),
        ],
    )

    assert sign_result.exit_code == 0
    assert "Algorithm: hmac-sha256" in sign_result.output
    assert verify_result.exit_code == 0
    assert "Status: valid" in verify_result.output


def test_cli_verify_signature_invalid_exits_1(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _tamper_signature(
        _signature(tmp_path, pack, keys.private_key_path),
        tmp_path / "bad.sig.json",
    )

    result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "verify-signature",
            str(pack),
            "--signature",
            str(signature),
            "--key",
            str(keys.public_key_path),
        ],
    )

    assert result.exit_code == 1
    assert "cryptographic" in result.output


def test_trust_policy_init_add_and_list(tmp_path: Path) -> None:
    keys = _keys(tmp_path)
    policy = _policy(tmp_path, keys.public_key_path)

    lines = trust_policy_summary(policy)

    assert any(keys.key_id in line for line in lines)
    assert _load_yaml(policy)["trusted_keys"][0]["key_id"] == keys.key_id


def test_trust_policy_refuses_overwrite_and_duplicate_key(tmp_path: Path) -> None:
    keys = _keys(tmp_path)
    policy = _policy(tmp_path, keys.public_key_path)

    with pytest.raises(FileExistsError, match="already exists"):
        init_trust_policy(policy)
    with pytest.raises(ValueError, match="already exists"):
        add_trusted_key(policy, keys.public_key_path)


def test_cli_trust_init_add_list_and_verify(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    policy = tmp_path / "cli-trust.yaml"

    init_result = runner.invoke(
        app,
        ["benchmarks", "pack", "trust", "init", str(policy)],
    )
    add_result = runner.invoke(
        app,
        ["benchmarks", "pack", "trust", "add-key", str(policy), str(keys.public_key_path)],
    )
    list_result = runner.invoke(
        app,
        ["benchmarks", "pack", "trust", "list", str(policy)],
    )
    verify_result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "trust",
            "verify",
            str(pack),
            "--policy",
            str(policy),
            "--signature",
            str(signature),
        ],
    )

    assert init_result.exit_code == 0
    assert add_result.exit_code == 0
    assert list_result.exit_code == 0
    assert keys.key_id in list_result.output
    assert verify_result.exit_code == 0
    assert "Trust status: trusted" in verify_result.output


def test_trust_verify_rejects_invalid_policy_by_cli_exit_2(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    policy = tmp_path / "bad-policy.yaml"
    policy.write_text("schema: wrong\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["benchmarks", "pack", "trust", "verify", str(pack), "--policy", str(policy)],
    )

    assert result.exit_code == 2


def test_trust_verify_accepts_trusted_signature(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    policy = _policy(tmp_path, keys.public_key_path)

    result = verify_trust_policy(pack, policy, [signature])

    assert result.valid
    assert result.status == "trusted"
    assert result.trusted_signatures == 1


def test_trust_verify_rejects_untrusted_key(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path, "trusted")
    untrusted = _keys(tmp_path / "untrusted", "untrusted")
    signature = _signature(tmp_path, pack, untrusted.private_key_path)
    policy = _policy(tmp_path, keys.public_key_path)

    result = verify_trust_policy(pack, policy, [signature])

    assert not result.valid
    assert result.signatures[0].status == "untrusted-key"


def test_trust_verify_enforces_required_signature_count(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    policy = _policy(tmp_path, keys.public_key_path)
    data = _load_yaml(policy)
    data["required_signatures"] = 2
    _write_yaml(policy, data)

    result = verify_trust_policy(pack, policy, [signature])

    assert not result.valid
    assert result.status == "insufficient-trusted-signatures"


def test_trust_policy_supports_inline_public_key(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    public_key = json.loads(keys.public_key_path.read_text(encoding="utf-8"))
    policy = tmp_path / "inline-policy.yaml"
    _write_yaml(
        policy,
        {
            "schema": "agentguard.pack-trust-policy",
            "schema_version": 1,
            "trusted_keys": [
                {
                    "key_id": keys.key_id,
                    "name": keys.name,
                    "public_key": public_key,
                }
            ],
            "required_signatures": 1,
            "allow_unsigned": False,
        },
    )

    result = verify_trust_policy(pack, policy, [signature])

    assert result.valid


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"schema": "wrong"}, "schema must"),
        ({"schema_version": 2}, "schema_version"),
        ({"trusted_keys": "bad"}, "trusted_keys"),
        ({"required_signatures": -1}, "required_signatures"),
        ({"allow_unsigned": "yes"}, "allow_unsigned"),
    ],
)
def test_load_trust_policy_rejects_malformed_policy(
    tmp_path: Path,
    patch: dict,
    message: str,
) -> None:
    policy = tmp_path / "policy.yaml"
    data = {
        "schema": "agentguard.pack-trust-policy",
        "schema_version": 1,
        "trusted_keys": [],
        "required_signatures": 1,
        "allow_unsigned": False,
    }
    data.update(patch)
    _write_yaml(policy, data)

    with pytest.raises(Exception, match=message):
        load_trust_policy(policy)


def test_load_trust_policy_rejects_bad_trusted_key_shapes(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    base = {
        "schema": "agentguard.pack-trust-policy",
        "schema_version": 1,
        "required_signatures": 1,
        "allow_unsigned": False,
    }

    for trusted_keys, message in [
        ([None], "must be a mapping"),
        ([{"key_id": "", "name": "x", "public_key_path": "key.json"}], "key_id"),
        (
            [{"key_id": "a", "name": "x", "public_key_path": "a", "public_key": {}}],
            "exactly one",
        ),
        ([{"key_id": "a", "name": "x", "public_key_path": "../key.json"}], "traversal"),
        ([{"key_id": "a", "name": "x", "public_key": "bad"}], "public_key"),
    ]:
        _write_yaml(policy, {**base, "trusted_keys": trusted_keys})
        with pytest.raises(Exception, match=message):
            load_trust_policy(policy)


def test_malformed_key_material_is_rejected(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    public = json.loads(keys.public_key_path.read_text(encoding="utf-8"))

    for index, (patch, message) in enumerate(
        [
        ({"schema": "wrong"}, "schema must"),
        ({"schema_version": 2}, "schema_version"),
        ({"algorithm": "none"}, "algorithm"),
        ({"key_type": "private"}, "key type"),
        ({"key": "not base64!"}, "base64"),
        ({"key": "AA=="}, "at least 32 bytes"),
        ({"key_id": "bad"}, "key_id does not match"),
        ],
        start=1,
    ):
        bad_key = tmp_path / f"bad-key-{index}.json"
        bad = dict(public)
        bad.update(patch)
        bad_key.write_text(json.dumps(bad), encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "benchmarks",
                "pack",
                "verify-signature",
                str(pack),
                "--signature",
                str(signature),
                "--key",
                str(bad_key),
            ],
        )
        assert result.exit_code == 2, message


def test_malformed_signature_fields_are_rejected(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    original = json.loads(signature.read_text(encoding="utf-8"))

    for patch, message in [
        ({"schema": "wrong"}, "schema must"),
        ({"schema_version": 2}, "schema_version"),
        ({"algorithm": "none"}, "algorithm"),
        ({"pack_version": 0}, "pack_version"),
        ({"pack_root_digest": "abc"}, "SHA-256"),
        ({"signature": "not base64!"}, "base64"),
        ({"signature": "AA=="}, "32 byte"),
    ]:
        bad_signature = tmp_path / f"bad-signature-{len(message)}.json"
        bad = dict(original)
        bad.update(patch)
        bad_signature.write_text(json.dumps(bad), encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "benchmarks",
                "pack",
                "verify-signature",
                str(pack),
                "--signature",
                str(bad_signature),
                "--key",
                str(keys.public_key_path),
            ],
        )
        assert result.exit_code == 2, message


def test_trust_policy_allow_unsigned_behavior(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    policy = _policy(tmp_path, keys.public_key_path)

    rejected = verify_trust_policy(pack, policy, [])
    data = _load_yaml(policy)
    data["allow_unsigned"] = True
    _write_yaml(policy, data)
    allowed = verify_trust_policy(pack, policy, [])

    assert rejected.status == "unsigned-rejected"
    assert not rejected.valid
    assert allowed.status == "unsigned-allowed"
    assert allowed.valid


def test_import_with_trust_policy_accepts_valid_trusted_pack(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    policy = _policy(tmp_path, keys.public_key_path)

    plan = import_benchmark_pack(
        pack_path=pack,
        dest_path=tmp_path / "dest",
        trust_policy=policy,
        signatures=[signature],
    )

    assert plan.trust_status == "trusted"
    assert (tmp_path / "dest/repos/auth_bug/src/auth_example/login.py").is_file()


def test_import_with_trust_policy_rejects_unsigned_or_untrusted_pack(
    tmp_path: Path,
) -> None:
    pack = _pack(tmp_path)
    trusted = _keys(tmp_path, "trusted")
    untrusted = _keys(tmp_path / "untrusted", "untrusted")
    signature = _signature(tmp_path, pack, untrusted.private_key_path)
    policy = _policy(tmp_path, trusted.public_key_path)

    with pytest.raises(BenchmarkPackSignatureError, match="requires signatures"):
        import_benchmark_pack(
            pack_path=pack,
            dest_path=tmp_path / "unsigned",
            trust_policy=policy,
        )
    with pytest.raises(BenchmarkPackSignatureError, match="not trusted"):
        import_benchmark_pack(
            pack_path=pack,
            dest_path=tmp_path / "untrusted",
            trust_policy=policy,
            signatures=[signature],
        )


def test_dry_run_reports_trust_status_without_writing(tmp_path: Path) -> None:
    pack = _pack(tmp_path)
    keys = _keys(tmp_path)
    signature = _signature(tmp_path, pack, keys.private_key_path)
    policy = _policy(tmp_path, keys.public_key_path)
    dest = tmp_path / "dry-run"

    result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "import",
            "--pack",
            str(pack),
            "--dest",
            str(dest),
            "--trust-policy",
            str(policy),
            "--signature",
            str(signature),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Trust status: trusted" in result.output
    assert not dest.exists()


def test_keygen_cli_prints_private_key_warning(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "benchmarks",
            "pack",
            "keygen",
            "--output-dir",
            str(tmp_path),
            "--name",
            "Docs Warning",
        ],
    )

    assert result.exit_code == 0
    assert "Do not commit private keys" in result.output
    assert "HMAC keys are shared secrets" in result.output
