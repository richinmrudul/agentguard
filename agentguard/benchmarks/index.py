import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Optional
from urllib.parse import urlparse

import yaml

from agentguard import __version__
from agentguard.benchmarks.packs import (
    BenchmarkPackError,
    BenchmarkPackIntegrityError,
    PackImportPlan,
    import_benchmark_pack,
    verify_benchmark_pack,
)
from agentguard.benchmarks.signing import (
    BenchmarkPackSignatureError,
    verify_trust_policy,
)
from agentguard.config.yaml import load_yaml
from agentguard.io import atomic_write_text


INDEX_SCHEMA = "agentguard.benchmark-pack-index"
INDEX_SCHEMA_VERSION = 1
DEFAULT_INDEX_ID = "agentguard-local"
MAX_INDEX_BYTES = 1024 * 1024
MAX_INDEX_PACK_BYTES = 50 * 1024 * 1024
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")


@dataclass(frozen=True)
class IndexPackResolution:
    entry: dict[str, Any]
    pack_path: Optional[Path]
    signature_paths: list[Path]


@dataclass(frozen=True)
class IndexVerification:
    index: dict[str, Any]
    entries: list[dict[str, Any]]
    messages: list[str]


def create_pack_index(
    *,
    pack_paths: list[Path],
    output_path: Path,
    signature_paths: Optional[list[Path]] = None,
    base_dir: Optional[Path] = None,
    force: bool = False,
) -> dict[str, Any]:
    if not pack_paths:
        raise BenchmarkPackError("at least one --pack is required")
    output = output_path.expanduser()
    if output.exists() and not force:
        raise FileExistsError(f"index output already exists: {output}. Use --force.")
    base = (base_dir or output.parent).expanduser().resolve()
    signatures = _signature_metadata(signature_paths or [], base)
    entries = []
    for pack_path in pack_paths:
        pack = pack_path.expanduser()
        verification = verify_benchmark_pack(pack)
        raw_digest = _sha256_file(pack)
        manifest = verification.manifest
        signature = _matching_signature(signatures, manifest, verification.root_digest)
        entries.append(
            {
                "pack_id": manifest["pack_id"],
                "pack_version": _pack_version_to_semver(manifest["pack_version"]),
                "title": _title(manifest),
                "description": f"AgentGuard benchmark pack {manifest['pack_id']}.",
                "categories": _registry_values(pack, "category"),
                "tags": _registry_tags(pack),
                "benchmark_ids": [item["id"] for item in manifest["benchmarks"]],
                "benchmark_versions": {
                    item["id"]: item["version"] for item in manifest["benchmarks"]
                },
                "pack_digest": raw_digest,
                "size_bytes": pack.stat().st_size,
                "source": {
                    "type": "file",
                    "path": _display_path(pack, base),
                },
                "signature": signature,
                "compatibility": {
                    "min_agentguard_version": "0.1.0",
                },
                "created_at": manifest["created_at"],
            }
        )
    index = {
        "schema": INDEX_SCHEMA,
        "schema_version": INDEX_SCHEMA_VERSION,
        "index_id": DEFAULT_INDEX_ID,
        "generated_at": _now(),
        "packs": sorted(entries, key=lambda item: (item["pack_id"], parse_semver(item["pack_version"]))),
    }
    _validate_index(index)
    atomic_write_text(output, _yaml_text(index))
    return index


def load_pack_index(index_path: Path) -> dict[str, Any]:
    path = _safe_input_path(index_path).expanduser()
    if path.stat().st_size > MAX_INDEX_BYTES:
        raise BenchmarkPackError(f"index exceeds {MAX_INDEX_BYTES} byte limit: {path}")
    try:
        if path.suffix.lower() == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
        else:
            with path.open("r", encoding="utf-8") as file:
                data = load_yaml(file) or {}
    except json.JSONDecodeError as error:
        raise BenchmarkPackError(f"index is not valid JSON: {path}") from error
    if not isinstance(data, dict):
        raise BenchmarkPackError("index must be a mapping")
    _validate_index(data)
    return data


def list_pack_index(
    index_path: Path,
    *,
    trust_policy: Optional[Path] = None,
) -> list[str]:
    index = load_pack_index(index_path)
    lines = [f"Benchmark pack index: {index['index_id']}"]
    for entry in index["packs"]:
        trust = "unchecked"
        if trust_policy is not None and entry["source"]["type"] == "file":
            resolution = _resolve_entry(index_path, entry)
            if resolution.signature_paths:
                try:
                    result = verify_trust_policy(
                        resolution.pack_path,
                        trust_policy,
                        resolution.signature_paths,
                    )
                    trust = result.status
                except (OSError, BenchmarkPackError):
                    trust = "invalid"
            else:
                trust = "unsigned"
        lines.append(
            f"- {entry['pack_id']}@{entry['pack_version']} "
            f"{entry['title']} categories={','.join(entry['categories']) or '-'} "
            f"tags={','.join(entry['tags']) or '-'} "
            f"benchmarks={len(entry['benchmark_ids'])} "
            f"source={entry['source']['type']}:{entry['source']['path']} "
            f"trust={trust}"
        )
    return lines


def verify_pack_index(
    index_path: Path,
    *,
    trust_policy: Optional[Path] = None,
) -> IndexVerification:
    index = load_pack_index(index_path)
    messages = []
    for entry in index["packs"]:
        if entry["source"]["type"] == "url":
            messages.append(
                f"{entry['pack_id']}@{entry['pack_version']}: URL source metadata only"
            )
            continue
        resolution = _resolve_entry(index_path, entry)
        pack_path = resolution.pack_path
        assert pack_path is not None
        if not pack_path.exists():
            raise BenchmarkPackIntegrityError(f"indexed pack is missing: {pack_path}")
        if pack_path.stat().st_size > MAX_INDEX_PACK_BYTES:
            raise BenchmarkPackError(
                f"indexed pack exceeds {MAX_INDEX_PACK_BYTES} byte limit: {pack_path}"
            )
        observed = _sha256_file(pack_path)
        if observed != entry["pack_digest"]:
            raise BenchmarkPackIntegrityError(
                f"indexed pack digest mismatch for {entry['pack_id']}@{entry['pack_version']}"
            )
        verification = verify_benchmark_pack(pack_path)
        if verification.manifest["pack_id"] != entry["pack_id"]:
            raise BenchmarkPackIntegrityError("indexed pack_id does not match pack")
        if _pack_version_to_semver(verification.manifest["pack_version"]) != entry["pack_version"]:
            raise BenchmarkPackIntegrityError("indexed pack_version does not match pack")
        _verify_signature_metadata(entry, verification.root_digest, resolution.signature_paths)
        if trust_policy is not None:
            trust = verify_trust_policy(pack_path, trust_policy, resolution.signature_paths)
            if not trust.valid:
                raise BenchmarkPackSignatureError("; ".join(trust.messages))
            messages.append(
                f"{entry['pack_id']}@{entry['pack_version']}: trust {trust.status}"
            )
        else:
            messages.append(f"{entry['pack_id']}@{entry['pack_version']}: verified")
    return IndexVerification(index=index, entries=index["packs"], messages=messages)


def resolve_index_pack(
    index_path: Path,
    *,
    pack_id: str,
    version: Optional[str] = None,
) -> IndexPackResolution:
    index = load_pack_index(index_path)
    matches = [entry for entry in index["packs"] if entry["pack_id"] == pack_id]
    if not matches:
        raise BenchmarkPackError(f"pack not found in index: {pack_id}")
    if version is not None:
        parse_semver(version)
        matches = [entry for entry in matches if entry["pack_version"] == version]
        if not matches:
            raise BenchmarkPackError(f"pack version not found in index: {pack_id}@{version}")
    else:
        matches = sorted(matches, key=lambda item: parse_semver(item["pack_version"]))
    entry = matches[-1]
    return _resolve_entry(index_path, entry)


def install_index_pack(
    index_path: Path,
    *,
    pack_id: str,
    version: Optional[str] = None,
    dest_path: Path,
    registry_out: Optional[Path] = None,
    suite_out: Optional[Path] = None,
    trust_policy: Optional[Path] = None,
    dry_run: bool = False,
    force: bool = False,
) -> tuple[IndexPackResolution, PackImportPlan]:
    resolution = resolve_index_pack(index_path, pack_id=pack_id, version=version)
    entry = resolution.entry
    if entry["source"]["type"] == "url":
        raise BenchmarkPackError("URL pack installation is not supported in this phase")
    pack_path = resolution.pack_path
    assert pack_path is not None
    if _sha256_file(pack_path) != entry["pack_digest"]:
        raise BenchmarkPackIntegrityError(
            f"indexed pack digest mismatch for {entry['pack_id']}@{entry['pack_version']}"
        )
    plan = import_benchmark_pack(
        pack_path=pack_path,
        dest_path=dest_path,
        registry_out=registry_out,
        suite_out=suite_out,
        trust_policy=trust_policy,
        signatures=resolution.signature_paths,
        dry_run=dry_run,
        force=force,
    )
    return resolution, plan


def parse_semver(value: str) -> tuple[int, int, int]:
    if not isinstance(value, str):
        raise BenchmarkPackError("pack_version must be a strict semver string")
    match = SEMVER_RE.match(value)
    if match is None:
        raise BenchmarkPackError(f"invalid strict semver: {value}")
    return tuple(int(part) for part in match.groups())


def _validate_index(index: dict[str, Any]) -> None:
    if index.get("schema") != INDEX_SCHEMA:
        raise BenchmarkPackError(f"index schema must be {INDEX_SCHEMA}")
    if index.get("schema_version") != INDEX_SCHEMA_VERSION:
        raise BenchmarkPackError(f"index schema_version must be {INDEX_SCHEMA_VERSION}")
    _required_string(index, "index_id", "index")
    _required_string(index, "generated_at", "index")
    packs = index.get("packs")
    if not isinstance(packs, list):
        raise BenchmarkPackError("index packs must be a list")
    seen: set[tuple[str, str]] = set()
    for offset, entry in enumerate(packs):
        if not isinstance(entry, dict):
            raise BenchmarkPackError(f"index pack {offset} must be a mapping")
        pack_id = _required_string(entry, "pack_id", f"pack {offset}")
        pack_version = _required_string(entry, "pack_version", f"pack {offset}")
        parse_semver(pack_version)
        key = (pack_id, pack_version)
        if key in seen:
            raise BenchmarkPackError(f"duplicate pack id/version in index: {pack_id}@{pack_version}")
        seen.add(key)
        _required_string(entry, "title", f"pack {offset}")
        _required_string(entry, "description", f"pack {offset}")
        _validate_string_list(entry, "categories", f"pack {offset}")
        _validate_string_list(entry, "tags", f"pack {offset}")
        _validate_string_list(entry, "benchmark_ids", f"pack {offset}")
        versions = entry.get("benchmark_versions")
        if not isinstance(versions, dict):
            raise BenchmarkPackError(f"pack {offset} benchmark_versions must be a mapping")
        digest = _required_string(entry, "pack_digest", f"pack {offset}")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise BenchmarkPackError(f"pack {offset} pack_digest must be a SHA-256 hex digest")
        size = entry.get("size_bytes")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BenchmarkPackError(f"pack {offset} size_bytes must be non-negative")
        _validate_source(entry.get("source"), f"pack {offset}")
        _validate_signature(entry.get("signature"), f"pack {offset}")
        _validate_compatibility(entry.get("compatibility"), f"pack {offset}")
        _required_string(entry, "created_at", f"pack {offset}")


def _validate_source(source: Any, label: str) -> None:
    if not isinstance(source, dict):
        raise BenchmarkPackError(f"{label} source must be a mapping")
    source_type = _required_string(source, "type", f"{label} source")
    path = _required_string(source, "path", f"{label} source")
    if source_type == "file":
        _validate_file_source_path(path)
    elif source_type == "url":
        parsed = urlparse(path)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise BenchmarkPackError(f"{label} URL source must be http(s)")
    else:
        raise BenchmarkPackError(f"{label} source type must be file or url")


def _validate_signature(signature: Any, label: str) -> None:
    if signature is None:
        return
    if not isinstance(signature, dict):
        raise BenchmarkPackError(f"{label} signature must be a mapping")
    _required_string(signature, "key_id", f"{label} signature")
    if "signature_path" in signature:
        _validate_file_source_path(_required_string(signature, "signature_path", f"{label} signature"))
    if "pack_root_digest" in signature:
        root = _required_string(signature, "pack_root_digest", f"{label} signature")
        if not re.fullmatch(r"[0-9a-f]{64}", root):
            raise BenchmarkPackError(f"{label} signature pack_root_digest must be SHA-256 hex")


def _validate_compatibility(compatibility: Any, label: str) -> None:
    if not isinstance(compatibility, dict):
        raise BenchmarkPackError(f"{label} compatibility must be a mapping")
    min_version = _required_string(compatibility, "min_agentguard_version", f"{label} compatibility")
    parse_semver(min_version)
    max_version = compatibility.get("max_agentguard_version")
    if max_version is not None:
        parse_semver(_required_string(compatibility, "max_agentguard_version", f"{label} compatibility"))
        if parse_semver(max_version) < parse_semver(min_version):
            raise BenchmarkPackError(f"{label} compatibility max is lower than min")
    current = parse_semver(_version_to_semver(__version__))
    if current < parse_semver(min_version):
        raise BenchmarkPackIntegrityError(f"{label} requires AgentGuard >= {min_version}")
    if max_version is not None and current > parse_semver(max_version):
        raise BenchmarkPackIntegrityError(f"{label} requires AgentGuard <= {max_version}")


def _validate_file_source_path(path: str) -> None:
    if "\x00" in path:
        raise BenchmarkPackError("source path contains a NUL byte")
    if "://" in path:
        raise BenchmarkPackError(f"file source path must not be a URL: {path}")
    pure = PurePosixPath(path.replace("\\", "/"))
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise BenchmarkPackError(f"path traversal is not allowed: {path}")


def _resolve_entry(index_path: Path, entry: dict[str, Any]) -> IndexPackResolution:
    source = entry["source"]
    signature_paths = _entry_signature_paths(index_path, entry)
    if source["type"] == "url":
        return IndexPackResolution(entry=entry, pack_path=None, signature_paths=signature_paths)
    path = Path(source["path"]).expanduser()
    if not path.is_absolute():
        path = index_path.expanduser().parent / path
    return IndexPackResolution(entry=entry, pack_path=path, signature_paths=signature_paths)


def _entry_signature_paths(index_path: Path, entry: dict[str, Any]) -> list[Path]:
    signature = entry.get("signature")
    if not signature or "signature_path" not in signature:
        return []
    path = Path(signature["signature_path"]).expanduser()
    if not path.is_absolute():
        path = index_path.expanduser().parent / path
    return [path]


def _verify_signature_metadata(
    entry: dict[str, Any],
    root_digest: str,
    signature_paths: list[Path],
) -> None:
    signature = entry.get("signature")
    if signature is None:
        return
    if signature.get("pack_root_digest") not in {None, root_digest}:
        raise BenchmarkPackIntegrityError("indexed signature root digest does not match pack")
    if signature_paths:
        data = _load_signature_metadata(signature_paths[0])
        if data["pack_id"] != entry["pack_id"]:
            raise BenchmarkPackIntegrityError("signature pack_id does not match index entry")
        if _pack_version_to_semver(data["pack_version"]) != entry["pack_version"]:
            raise BenchmarkPackIntegrityError("signature pack_version does not match index entry")
        if data["pack_root_digest"] != root_digest:
            raise BenchmarkPackIntegrityError("signature root digest does not match pack")
        if data["key_id"] != signature["key_id"]:
            raise BenchmarkPackIntegrityError("signature key_id does not match index entry")


def _signature_metadata(paths: list[Path], base: Path) -> list[dict[str, Any]]:
    items = []
    for path in paths:
        data = _load_signature_metadata(path)
        items.append(
            {
                "pack_id": data["pack_id"],
                "pack_version": data["pack_version"],
                "pack_root_digest": data["pack_root_digest"],
                "key_id": data["key_id"],
                "signer": data["signer"],
                "algorithm": data["algorithm"],
                "signature_path": _display_path(path.expanduser(), base),
            }
        )
    return items


def _matching_signature(
    signatures: list[dict[str, Any]],
    manifest: dict[str, Any],
    root_digest: str,
) -> Optional[dict[str, Any]]:
    for signature in signatures:
        if (
            signature["pack_id"] == manifest["pack_id"]
            and signature["pack_version"] == manifest["pack_version"]
            and signature["pack_root_digest"] == root_digest
        ):
            return {
                "key_id": signature["key_id"],
                "signer": signature["signer"],
                "algorithm": signature["algorithm"],
                "signature_path": signature["signature_path"],
                "pack_root_digest": root_digest,
            }
    return None


def _load_signature_metadata(path: Path) -> dict[str, Any]:
    input_path = _safe_input_path(path).expanduser()
    if input_path.stat().st_size > 64 * 1024:
        raise BenchmarkPackError(f"signature file exceeds 65536 bytes: {input_path}")
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BenchmarkPackError(f"signature file is not valid JSON: {input_path}") from error
    if not isinstance(data, dict):
        raise BenchmarkPackError("signature file must be a JSON object")
    for key in ("pack_id", "pack_root_digest", "key_id", "signer", "algorithm"):
        _required_string(data, key, "signature")
    if not isinstance(data.get("pack_version"), int) or data["pack_version"] <= 0:
        raise BenchmarkPackError("signature pack_version must be a positive integer")
    return data


def _registry_values(pack_path: Path, key: str) -> list[str]:
    data = _registry_fragment(pack_path)
    values = {
        str(entry[key])
        for entry in data.get("benchmarks", [])
        if isinstance(entry, dict) and isinstance(entry.get(key), str)
    }
    return sorted(values)


def _registry_tags(pack_path: Path) -> list[str]:
    data = _registry_fragment(pack_path)
    values: set[str] = set()
    for entry in data.get("benchmarks", []):
        if isinstance(entry, dict) and isinstance(entry.get("tags"), list):
            values.update(str(tag) for tag in entry["tags"] if isinstance(tag, str))
    return sorted(values)


def _registry_fragment(pack_path: Path) -> dict[str, Any]:
    import zipfile

    with zipfile.ZipFile(pack_path.expanduser(), "r") as archive:
        text = archive.read("registry/registry.yaml").decode("utf-8")
    data = yaml.safe_load(text) or {}
    return data if isinstance(data, dict) else {}


def _title(manifest: dict[str, Any]) -> str:
    ids = [item["id"] for item in manifest["benchmarks"]]
    if len(ids) == 1:
        return ids[0]
    return f"{len(ids)} benchmark pack"


def _pack_version_to_semver(version: Any) -> str:
    if isinstance(version, int) and not isinstance(version, bool) and version > 0:
        return f"{version}.0.0"
    if isinstance(version, str):
        parse_semver(version)
        return version
    raise BenchmarkPackError("pack_version must be a positive integer or semver string")


def _version_to_semver(version: str) -> str:
    match = re.search(r"\d+\.\d+\.\d+", version)
    if match:
        return match.group(0)
    match = re.search(r"\d+\.\d+", version)
    if match:
        return f"{match.group(0)}.0"
    return "0.0.0"


def _display_path(path: Path, base: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        return str(resolved)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.expanduser().open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_input_path(path: Path) -> Path:
    raw = str(path)
    if "\x00" in raw:
        raise BenchmarkPackError("input path contains a NUL byte")
    if ".." in Path(raw).parts:
        raise BenchmarkPackError(f"path traversal is not allowed: {raw}")
    return path


def _validate_string_list(mapping: dict[str, Any], key: str, label: str) -> None:
    value = mapping.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise BenchmarkPackError(f"{label} {key} must be a list of strings")


def _required_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BenchmarkPackError(f"{label} field '{key}' must be a non-empty string")
    return value


def _yaml_text(data: dict[str, Any]) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=False,
    )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
