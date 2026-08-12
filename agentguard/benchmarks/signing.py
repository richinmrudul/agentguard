import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from agentguard.benchmarks.packs import BenchmarkPackError, verify_benchmark_pack
from agentguard.config.yaml import load_yaml
from agentguard.io import atomic_write_json, atomic_write_text


KEY_SCHEMA = "agentguard.benchmark-pack-hmac-key"
KEY_SCHEMA_VERSION = 1
SIGNATURE_SCHEMA = "agentguard.benchmark-pack-signature"
SIGNATURE_SCHEMA_VERSION = 1
TRUST_POLICY_SCHEMA = "agentguard.pack-trust-policy"
TRUST_POLICY_SCHEMA_VERSION = 1
ALGORITHM = "hmac-sha256"
MAX_SIGNING_FILE_BYTES = 64 * 1024


class BenchmarkPackSignatureError(BenchmarkPackError):
    exit_code = 1


@dataclass(frozen=True)
class GeneratedKeyPair:
    private_key_path: Path
    public_key_path: Path
    key_id: str
    name: str


@dataclass(frozen=True)
class SignatureVerification:
    valid: bool
    trusted: bool
    status: str
    key_id: Optional[str]
    signer: Optional[str]
    message: str


@dataclass(frozen=True)
class TrustVerification:
    valid: bool
    status: str
    trusted_signatures: int
    required_signatures: int
    allow_unsigned: bool
    messages: list[str]
    signatures: list[SignatureVerification]


def generate_hmac_keypair(
    output_dir: Path,
    name: str,
    *,
    force: bool = False,
) -> GeneratedKeyPair:
    if not name.strip():
        raise ValueError("key name must be non-empty.")
    root = output_dir.expanduser()
    private_path = root / f"{_slug(name)}.private-key.json"
    public_path = root / f"{_slug(name)}.public-key.json"
    if not force:
        for path in (private_path, public_path):
            if path.exists():
                raise FileExistsError(f"key output already exists: {path}")
    root.mkdir(parents=True, exist_ok=True)
    secret = os.urandom(32)
    key_id = hashlib.sha256(secret).hexdigest()[:16]
    common = {
        "schema": KEY_SCHEMA,
        "schema_version": KEY_SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "name": name,
        "key": _b64encode(secret),
    }
    atomic_write_json(
        private_path,
        {
            **common,
            "key_type": "private",
            "created_at": _now(),
        },
        sort_keys=True,
    )
    try:
        private_path.chmod(0o600)
    except OSError:
        pass
    atomic_write_json(
        public_path,
        {
            **common,
            "key_type": "public",
            "created_at": _now(),
            "warning": (
                "HMAC verification keys are shared secrets. Do not commit this "
                "file unless your local trust model accepts that exposure."
            ),
        },
        sort_keys=True,
    )
    return GeneratedKeyPair(
        private_key_path=private_path,
        public_key_path=public_path,
        key_id=key_id,
        name=name,
    )


def sign_benchmark_pack(
    pack_path: Path,
    private_key_path: Path,
    signature_path: Path,
    *,
    force: bool = False,
) -> dict[str, Any]:
    output = signature_path.expanduser()
    if output.exists() and not force:
        raise FileExistsError(f"signature output already exists: {output}")
    pack = verify_benchmark_pack(pack_path)
    key = _load_key(private_key_path, expected_type="private")
    payload = _signature_payload(pack.manifest)
    signature = hmac.new(key["secret"], payload, hashlib.sha256).digest()
    data = {
        "schema": SIGNATURE_SCHEMA,
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "pack_id": pack.manifest["pack_id"],
        "pack_version": pack.manifest["pack_version"],
        "pack_root_digest": pack.root_digest,
        "key_id": key["key_id"],
        "signer": key["name"],
        "algorithm": ALGORITHM,
        "created_at": _now(),
        "signature": _b64encode(signature),
    }
    atomic_write_json(output, data, sort_keys=True)
    return data


def verify_benchmark_pack_signature(
    pack_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> SignatureVerification:
    pack = verify_benchmark_pack(pack_path)
    signature = _load_signature(signature_path)
    key = _load_key(public_key_path, expected_type="public")
    return _verify_signature_data(pack.manifest, pack.root_digest, signature, key)


def init_trust_policy(path: Path, *, force: bool = False) -> dict[str, Any]:
    output = path.expanduser()
    if output.exists() and not force:
        raise FileExistsError(f"trust policy already exists: {output}")
    data = {
        "schema": TRUST_POLICY_SCHEMA,
        "schema_version": TRUST_POLICY_SCHEMA_VERSION,
        "trusted_keys": [],
        "required_signatures": 1,
        "allow_unsigned": False,
    }
    atomic_write_text(output, _yaml_text(data))
    return data


def add_trusted_key(policy_path: Path, public_key_path: Path) -> dict[str, Any]:
    # A freshly initialized policy has no trusted keys yet, so it is necessarily
    # incomplete until the first key is added.
    policy = _load_trust_policy(policy_path, allow_incomplete=True)
    key = _load_key(public_key_path, expected_type="public")
    trusted = list(policy["trusted_keys"])
    if any(item["key_id"] == key["key_id"] for item in trusted):
        raise ValueError(f"trusted key already exists: {key['key_id']}")
    trusted.append(
        {
            "key_id": key["key_id"],
            "name": key["name"],
            "public_key_path": str(public_key_path.expanduser()),
        }
    )
    policy = {**policy, "trusted_keys": trusted}
    atomic_write_text(policy_path.expanduser(), _yaml_text(_public_policy(policy)))
    return policy


def load_trust_policy(path: Path) -> dict[str, Any]:
    return _load_trust_policy(path)


def _load_trust_policy(path: Path, *, allow_incomplete: bool = False) -> dict[str, Any]:
    policy_path = _safe_input_path(path)
    with policy_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}
    if not isinstance(data, dict):
        raise BenchmarkPackError("trust policy must be a YAML mapping")
    if data.get("schema") != TRUST_POLICY_SCHEMA:
        raise BenchmarkPackError(f"trust policy schema must be {TRUST_POLICY_SCHEMA}")
    if data.get("schema_version") != TRUST_POLICY_SCHEMA_VERSION:
        raise BenchmarkPackError(
            f"trust policy schema_version must be {TRUST_POLICY_SCHEMA_VERSION}"
        )
    trusted = data.get("trusted_keys")
    if not isinstance(trusted, list):
        raise BenchmarkPackError("trust policy trusted_keys must be a list")
    required = data.get("required_signatures", 1)
    if not isinstance(required, int) or isinstance(required, bool) or required < 0:
        raise BenchmarkPackError("trust policy required_signatures must be non-negative")
    allow_unsigned = data.get("allow_unsigned", False)
    if not isinstance(allow_unsigned, bool):
        raise BenchmarkPackError("trust policy allow_unsigned must be a boolean")
    seen: set[str] = set()
    normalized = []
    for index, item in enumerate(trusted):
        if not isinstance(item, dict):
            raise BenchmarkPackError(f"trusted key {index} must be a mapping")
        key_id = _required_string(item, "key_id", f"trusted key {index}")
        name = _required_string(item, "name", f"trusted key {index}")
        if key_id in seen:
            raise BenchmarkPackError(f"duplicate trusted key id: {key_id}")
        seen.add(key_id)
        if ("public_key_path" in item) == ("public_key" in item):
            raise BenchmarkPackError(
                f"trusted key {key_id} requires exactly one of public_key_path or public_key"
            )
        normalized_item = {"key_id": key_id, "name": name}
        if "public_key_path" in item:
            path_value = _required_string(item, "public_key_path", f"trusted key {index}")
            _reject_path_traversal(path_value)
            normalized_item["public_key_path"] = path_value
        else:
            inline = item["public_key"]
            if not isinstance(inline, dict):
                raise BenchmarkPackError(f"trusted key {key_id} public_key must be a mapping")
            normalized_item["public_key"] = inline
        normalized.append(normalized_item)
    if not allow_incomplete and required > len(normalized):
        raise BenchmarkPackError(
            "trust policy required_signatures cannot exceed the number of trusted keys"
        )
    return {
        "schema": TRUST_POLICY_SCHEMA,
        "schema_version": TRUST_POLICY_SCHEMA_VERSION,
        "trusted_keys": normalized,
        "required_signatures": required,
        "allow_unsigned": allow_unsigned,
        "_path": policy_path,
    }


def trust_policy_summary(policy_path: Path) -> list[str]:
    # Listing is non-enforcing and must remain usable for a freshly initialized
    # policy before its first trusted key is added.
    policy = _load_trust_policy(policy_path, allow_incomplete=True)
    lines = [
        f"Policy: {policy_path.expanduser()}",
        f"Required signatures: {policy['required_signatures']}",
        f"Allow unsigned: {'yes' if policy['allow_unsigned'] else 'no'}",
        "Trusted keys:",
    ]
    if not policy["trusted_keys"]:
        lines.append("- none")
    for item in policy["trusted_keys"]:
        location = item.get("public_key_path", "inline")
        lines.append(f"- {item['key_id']} {item['name']} ({location})")
    return lines


def verify_trust_policy(
    pack_path: Path,
    policy_path: Path,
    signature_paths: Optional[list[Path]] = None,
) -> TrustVerification:
    pack = verify_benchmark_pack(pack_path)
    policy = load_trust_policy(policy_path)
    signatures = signature_paths or []
    if not signatures:
        if policy["allow_unsigned"]:
            return TrustVerification(
                valid=True,
                status="unsigned-allowed",
                trusted_signatures=0,
                required_signatures=policy["required_signatures"],
                allow_unsigned=True,
                messages=["Unsigned pack accepted by local trust policy."],
                signatures=[],
            )
        return TrustVerification(
            valid=False,
            status="unsigned-rejected",
            trusted_signatures=0,
            required_signatures=policy["required_signatures"],
            allow_unsigned=False,
            messages=["Trust policy requires signatures, but none were provided."],
            signatures=[],
        )

    key_by_id = _load_trusted_keys(policy)
    results = []
    counted_key_ids: set[str] = set()
    for signature_path in signatures:
        signature = _load_signature(signature_path)
        key = key_by_id.get(signature["key_id"])
        if key is None:
            results.append(
                SignatureVerification(
                    valid=False,
                    trusted=False,
                    status="untrusted-key",
                    key_id=signature["key_id"],
                    signer=signature.get("signer"),
                    message=f"Signature key is not trusted: {signature['key_id']}",
                )
            )
            continue
        result = _verify_signature_data(pack.manifest, pack.root_digest, signature, key)
        if result.valid and result.trusted:
            key_id = signature["key_id"]
            if key_id in counted_key_ids:
                result = SignatureVerification(
                    valid=True,
                    trusted=True,
                    status="duplicate-trusted-key",
                    key_id=result.key_id,
                    signer=result.signer,
                    message=(
                        "Valid signature from a trusted key already counted "
                        "toward the threshold."
                    ),
                )
            else:
                counted_key_ids.add(key_id)
        results.append(result)
    trusted_count = len(counted_key_ids)
    valid = trusted_count >= policy["required_signatures"]
    status = "trusted" if valid else "insufficient-trusted-signatures"
    return TrustVerification(
        valid=valid,
        status=status,
        trusted_signatures=trusted_count,
        required_signatures=policy["required_signatures"],
        allow_unsigned=policy["allow_unsigned"],
        messages=[
            f"Trusted signatures: {trusted_count}/{policy['required_signatures']}",
            *[result.message for result in results],
        ],
        signatures=results,
    )


def _verify_signature_data(
    manifest: dict[str, Any],
    root_digest: str,
    signature: dict[str, Any],
    key: dict[str, Any],
) -> SignatureVerification:
    signer = signature.get("signer")
    key_id = signature["key_id"]
    if signature["pack_id"] != manifest["pack_id"]:
        return _invalid_signature(key_id, signer, "Signature pack_id does not match pack.")
    if signature["pack_version"] != manifest["pack_version"]:
        return _invalid_signature(key_id, signer, "Signature pack_version does not match pack.")
    if signature["pack_root_digest"] != root_digest:
        return _invalid_signature(
            key_id,
            signer,
            "Signature pack_root_digest does not match pack.",
        )
    if key_id != key["key_id"]:
        return _invalid_signature(key_id, signer, "Signature key_id does not match key.")
    payload = _signature_payload(manifest)
    expected = hmac.new(key["secret"], payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature["signature_bytes"], expected):
        return _invalid_signature(key_id, signer, "Signature cryptographic check failed.")
    return SignatureVerification(
        valid=True,
        trusted=True,
        status="valid",
        key_id=key_id,
        signer=signer,
        message=f"Valid signature from {signer or key_id}.",
    )


def _invalid_signature(
    key_id: Optional[str],
    signer: Optional[str],
    message: str,
) -> SignatureVerification:
    return SignatureVerification(
        valid=False,
        trusted=False,
        status="invalid",
        key_id=key_id,
        signer=signer,
        message=message,
    )


def _signature_payload(manifest: dict[str, Any]) -> bytes:
    payload = {
        "schema": "agentguard.benchmark-pack-signature-payload",
        "schema_version": 1,
        "pack_id": manifest["pack_id"],
        "pack_version": manifest["pack_version"],
        "pack_root_digest": manifest["root_digest"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_trusted_keys(policy: dict[str, Any]) -> dict[str, dict[str, Any]]:
    policy_path = policy["_path"]
    loaded = {}
    for item in policy["trusted_keys"]:
        if "public_key_path" in item:
            key_path = Path(item["public_key_path"]).expanduser()
            if not key_path.is_absolute():
                key_path = policy_path.parent / key_path
            key = _load_key(key_path, expected_type="public")
        else:
            key = _parse_key(item["public_key"], expected_type="public")
        if key["key_id"] != item["key_id"]:
            raise BenchmarkPackError(f"trusted key id mismatch: {item['key_id']}")
        loaded[key["key_id"]] = key
    return loaded


def _public_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in policy.items() if not key.startswith("_")}


def _load_key(path: Path, *, expected_type: str) -> dict[str, Any]:
    data = _load_json_file(path)
    return _parse_key(data, expected_type=expected_type)


def _parse_key(data: Any, *, expected_type: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise BenchmarkPackError("key file must be a JSON object")
    if data.get("schema") != KEY_SCHEMA:
        raise BenchmarkPackError(f"key schema must be {KEY_SCHEMA}")
    if data.get("schema_version") != KEY_SCHEMA_VERSION:
        raise BenchmarkPackError(f"key schema_version must be {KEY_SCHEMA_VERSION}")
    if data.get("algorithm") != ALGORITHM:
        raise BenchmarkPackError(f"key algorithm must be {ALGORITHM}")
    if data.get("key_type") != expected_type:
        raise BenchmarkPackError(f"key type must be {expected_type}")
    key_id = _required_string(data, "key_id", "key")
    name = _required_string(data, "name", "key")
    secret = _b64decode(_required_string(data, "key", "key"), "key material")
    if len(secret) < 32:
        raise BenchmarkPackError("key material must be at least 32 bytes")
    actual_key_id = hashlib.sha256(secret).hexdigest()[:16]
    if actual_key_id != key_id:
        raise BenchmarkPackError("key_id does not match key material")
    return {"key_id": key_id, "name": name, "secret": secret}


def _load_signature(path: Path) -> dict[str, Any]:
    data = _load_json_file(path)
    if not isinstance(data, dict):
        raise BenchmarkPackError("signature file must be a JSON object")
    if data.get("schema") != SIGNATURE_SCHEMA:
        raise BenchmarkPackError(f"signature schema must be {SIGNATURE_SCHEMA}")
    if data.get("schema_version") != SIGNATURE_SCHEMA_VERSION:
        raise BenchmarkPackError(
            f"signature schema_version must be {SIGNATURE_SCHEMA_VERSION}"
        )
    if data.get("algorithm") != ALGORITHM:
        raise BenchmarkPackError(f"signature algorithm must be {ALGORITHM}")
    pack_id = _required_string(data, "pack_id", "signature")
    pack_version = data.get("pack_version")
    if not isinstance(pack_version, int) or isinstance(pack_version, bool) or pack_version <= 0:
        raise BenchmarkPackError("signature pack_version must be a positive integer")
    root_digest = _required_string(data, "pack_root_digest", "signature")
    if len(root_digest) != 64:
        raise BenchmarkPackError("signature pack_root_digest must be a SHA-256 hex digest")
    key_id = _required_string(data, "key_id", "signature")
    signer = _required_string(data, "signer", "signature")
    signature_bytes = _b64decode(
        _required_string(data, "signature", "signature"),
        "signature",
    )
    if len(signature_bytes) != 32:
        raise BenchmarkPackError("signature must be a 32 byte HMAC-SHA256 value")
    return {
        "pack_id": pack_id,
        "pack_version": pack_version,
        "pack_root_digest": root_digest,
        "key_id": key_id,
        "signer": signer,
        "signature_bytes": signature_bytes,
    }


def _load_json_file(path: Path) -> Any:
    input_path = _safe_input_path(path)
    if input_path.stat().st_size > MAX_SIGNING_FILE_BYTES:
        raise BenchmarkPackError(f"signing file exceeds {MAX_SIGNING_FILE_BYTES} bytes: {input_path}")
    try:
        return json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BenchmarkPackError(f"signing file is not valid JSON: {input_path}") from error


def _safe_input_path(path: Path) -> Path:
    raw = str(path)
    if "\x00" in raw:
        raise BenchmarkPackError("input path contains a NUL byte")
    _reject_path_traversal(raw)
    return path.expanduser()


def _reject_path_traversal(value: str) -> None:
    parts = Path(value).parts
    if ".." in parts:
        raise BenchmarkPackError(f"path traversal is not allowed: {value}")


def _required_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkPackError(f"{label} field '{key}' must be a non-empty string")
    return value


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, label: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise BenchmarkPackError(f"{label} must be strict base64") from error


def _yaml_text(data: dict[str, Any]) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=False,
    )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(name: str) -> str:
    value = "".join(char if char.isalnum() or char in {"-", "_"} else "-" for char in name.lower())
    return value.strip("-_") or "agentguard-pack-key"
