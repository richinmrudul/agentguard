import hashlib
import json
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import yaml

from agentguard import __version__
from agentguard.benchmarks.contracts import (
    load_benchmark_contract,
    validate_contract_alignment,
)
from agentguard.benchmarks.registry import (
    BenchmarkRegistry,
    BenchmarkRegistryEntry,
    find_benchmark,
    generate_suite_data,
    load_benchmark_registry,
    normalize_registry_values,
    write_generated_suite,
)
from agentguard.config.loader import load_config
from agentguard.config.yaml import load_yaml
from agentguard.io import atomic_write_text


PACK_SCHEMA = "agentguard.benchmark-pack"
PACK_SCHEMA_VERSION = 1
PACK_VERSION = 1
MANIFEST_PATH = "manifest.json"
REGISTRY_FRAGMENT_PATH = "registry/registry.yaml"
DETERMINISTIC_CREATED_AT = "1970-01-01T00:00:00Z"
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_PACK_BYTES = 50 * 1024 * 1024
MAX_FILE_BYTES = 5 * 1024 * 1024
EXCLUDED_PARTS = {".agentguard", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
EXCLUDED_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".pyc", ".pyo"}
EXCLUDED_NAMES = {
    "agentguard-junit.xml",
    "coverage.xml",
    ".coverage",
}


class BenchmarkPackError(ValueError):
    exit_code = 2


class BenchmarkPackIntegrityError(BenchmarkPackError):
    exit_code = 1


@dataclass(frozen=True)
class PackFile:
    path: str
    sha256: str
    size: int
    type: str = "regular"


@dataclass(frozen=True)
class PackVerification:
    manifest: dict[str, Any]
    files: list[PackFile]
    root_digest: str


@dataclass(frozen=True)
class PackImportPlan:
    files: list[tuple[str, Path]]
    collisions: list[Path]
    registry_path: Optional[Path]
    suite_path: Optional[Path]
    trust_status: Optional[str] = None


def export_benchmark_pack(
    *,
    registry_path: Path,
    output_path: Path,
    benchmark_values: Optional[list[str]] = None,
    include_docs: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    output = output_path.expanduser()
    if output.exists() and not force:
        raise FileExistsError(f"pack output already exists: {output}. Use --force.")
    registry = load_benchmark_registry(registry_path)
    selected = _select_benchmarks(registry, benchmark_values)
    repo_root = _project_root(registry.path)
    files, symlink_paths = _collect_pack_files(registry, selected, repo_root, include_docs)
    file_entries = [
        {
            "path": path,
            "sha256": _sha256_bytes(content),
            "size": len(content),
            "type": "symlink" if path in symlink_paths else "regular",
        }
        for path, content in sorted(files.items())
    ]
    root_digest = _root_digest(file_entries)
    manifest = _manifest(
        selected,
        file_entries,
        root_digest,
        include_docs=include_docs,
        source_registry=registry.path,
    )
    manifest["pack_id"] = f"benchmark-pack-{root_digest[:16]}"
    files[MANIFEST_PATH] = _json_bytes(manifest)
    _write_zip(output, files, symlink_paths)
    return {
        "path": output,
        "benchmark_count": len(selected),
        "file_count": len(file_entries),
        "root_digest": root_digest,
        "pack_id": manifest["pack_id"],
        "manifest": manifest,
    }


def inspect_benchmark_pack(path: Path) -> dict[str, Any]:
    verification = verify_benchmark_pack(path)
    manifest = verification.manifest
    return {
        "pack_id": manifest["pack_id"],
        "pack_version": manifest["pack_version"],
        "benchmarks": manifest["benchmarks"],
        "files": [file.__dict__ for file in verification.files],
        "docs": manifest.get("docs_paths", []),
        "contract_status": "valid",
        "root_digest": verification.root_digest,
    }


def verify_benchmark_pack(path: Path) -> PackVerification:
    pack_path = path.expanduser()
    if pack_path.stat().st_size > MAX_PACK_BYTES:
        raise BenchmarkPackError(f"pack exceeds {MAX_PACK_BYTES} byte limit: {pack_path}")
    try:
        with zipfile.ZipFile(pack_path, "r") as archive:
            members = _safe_zip_members(archive)
            if MANIFEST_PATH not in members:
                raise BenchmarkPackError("pack is missing manifest.json")
            manifest = json.loads(archive.read(MANIFEST_PATH).decode("utf-8"))
            _validate_manifest_schema(manifest)
            listed = _manifest_file_map(manifest)
            actual_paths = set(members) - {MANIFEST_PATH}
            listed_paths = set(listed)
            missing = sorted(listed_paths - actual_paths)
            extra = sorted(actual_paths - listed_paths)
            if missing:
                raise BenchmarkPackIntegrityError(
                    "pack is missing listed files: " + ", ".join(missing)
                )
            if extra:
                raise BenchmarkPackError(
                    "pack contains unlisted files: " + ", ".join(extra)
                )
            files: list[PackFile] = []
            for relative_path in sorted(listed):
                info = members[relative_path]
                if info.file_size > MAX_FILE_BYTES:
                    raise BenchmarkPackError(
                        f"pack file exceeds {MAX_FILE_BYTES} byte limit: {relative_path}"
                    )
                content = archive.read(relative_path)
                actual = _sha256_bytes(content)
                expected = listed[relative_path]
                mode = (info.external_attr >> 16) & 0o170000
                expected_type = str(expected.get("type", "regular"))
                actual_type = "symlink" if mode == stat.S_IFLNK else "regular"
                if expected_type != actual_type:
                    raise BenchmarkPackError(
                        f"manifest type does not match archive member: {relative_path}"
                    )
                if actual_type == "symlink":
                    _validate_safe_symlink(relative_path, content.decode("utf-8"))
                if actual != expected["sha256"]:
                    raise BenchmarkPackIntegrityError(
                        f"hash mismatch for {relative_path}: expected "
                        f"{expected['sha256']}, observed {actual}"
                    )
                files.append(
                    PackFile(
                        path=relative_path,
                        sha256=actual,
                        size=len(content),
                        type=str(expected.get("type", "regular")),
                    )
                )
            root_digest = _root_digest(
                [
                    {
                        "path": file.path,
                        "sha256": file.sha256,
                        "size": file.size,
                        "type": file.type,
                    }
                    for file in files
                ]
            )
            if root_digest != manifest.get("root_digest"):
                raise BenchmarkPackIntegrityError("manifest root digest mismatch")
            _verify_registry_contract_config_consistency(archive, manifest)
    except zipfile.BadZipFile as error:
        raise BenchmarkPackError("pack is not a readable zip archive") from error
    except json.JSONDecodeError as error:
        raise BenchmarkPackError("pack manifest is not valid JSON") from error
    return PackVerification(manifest=manifest, files=files, root_digest=root_digest)


def import_benchmark_pack(
    *,
    pack_path: Path,
    dest_path: Path,
    registry_out: Optional[Path] = None,
    suite_out: Optional[Path] = None,
    trust_policy: Optional[Path] = None,
    signatures: Optional[list[Path]] = None,
    dry_run: bool = False,
    force: bool = False,
) -> PackImportPlan:
    verification = verify_benchmark_pack(pack_path)
    trust_status = None
    if trust_policy is not None:
        from agentguard.benchmarks.signing import (
            BenchmarkPackSignatureError,
            verify_trust_policy,
        )

        trust = verify_trust_policy(pack_path, trust_policy, signatures or [])
        trust_status = trust.status
        if not trust.valid:
            raise BenchmarkPackSignatureError("; ".join(trust.messages))
    dest = dest_path.expanduser()
    registry_output = registry_out.expanduser() if registry_out is not None else None
    suite_output = suite_out.expanduser() if suite_out is not None else None
    files = [
        (file.path, _safe_destination(dest, file.path))
        for file in verification.files
    ]
    extra_outputs = [path for path in (registry_output, suite_output) if path is not None]
    collisions = sorted(
        [target for _, target in files if target.exists() or target.is_symlink()]
        + [path for path in extra_outputs if path.exists()]
    )
    if collisions and not force:
        return PackImportPlan(
            files=files,
            collisions=collisions,
            registry_path=registry_output,
            suite_path=suite_output,
            trust_status=trust_status,
        )
    if dry_run:
        return PackImportPlan(
            files=files,
            collisions=collisions,
            registry_path=registry_output,
            suite_path=suite_output,
            trust_status=trust_status,
        )
    with zipfile.ZipFile(pack_path.expanduser(), "r") as archive:
        symlinks: list[tuple[str, Path, str]] = []
        file_types = {file.path: file.type for file in verification.files}
        for relative_path, target in files:
            target.parent.mkdir(parents=True, exist_ok=True)
            if (target.exists() or target.is_symlink()) and not force:
                raise FileExistsError(f"destination file already exists: {target}")
            content = archive.read(relative_path)
            if file_types[relative_path] == "symlink":
                symlinks.append((relative_path, target, content.decode("utf-8")))
            else:
                if target.exists() or target.is_symlink():
                    target.unlink()
                target.write_bytes(content)
        for relative_path, target, link_target in symlinks:
            _validate_safe_symlink(relative_path, link_target)
            if target.exists() or target.is_symlink():
                target.unlink()
            target.symlink_to(link_target)
    if registry_output is not None:
        source = dest / REGISTRY_FRAGMENT_PATH
        registry_output.parent.mkdir(parents=True, exist_ok=True)
        if registry_output.exists() and not force:
            raise FileExistsError(f"registry output already exists: {registry_output}")
        atomic_write_text(registry_output, _external_registry_text(source, dest), encoding="utf-8")
    if suite_output is not None:
        registry_for_suite = registry_output or (dest / REGISTRY_FRAGMENT_PATH)
        registry = load_benchmark_registry(registry_for_suite)
        suite_data = generate_suite_data(
            registry,
            suite_id=suite_output.stem or "imported_benchmarks",
            description="Generated from imported AgentGuard benchmark pack.",
            include=["safe", "adversarial"],
        )
        write_generated_suite(suite_data, suite_output, force=force)
    return PackImportPlan(
        files=files,
        collisions=collisions,
        registry_path=registry_output,
        suite_path=suite_output,
        trust_status=trust_status,
    )


def _select_benchmarks(
    registry: BenchmarkRegistry,
    benchmark_values: Optional[list[str]],
) -> list[BenchmarkRegistryEntry]:
    ids = normalize_registry_values(benchmark_values)
    if not ids:
        return list(registry.benchmarks)
    selected = []
    seen = set()
    for benchmark_id in ids:
        if benchmark_id in seen:
            continue
        entry = find_benchmark(registry, benchmark_id)
        if entry is None:
            raise ValueError(f"benchmark not found: {benchmark_id}")
        selected.append(entry)
        seen.add(benchmark_id)
    return selected


def _collect_pack_files(
    registry: BenchmarkRegistry,
    selected: list[BenchmarkRegistryEntry],
    repo_root: Path,
    include_docs: bool,
) -> tuple[dict[str, bytes], set[str]]:
    files: dict[str, bytes] = {}
    symlink_paths: set[str] = set()
    registry_data = {"benchmarks": []}
    for entry in selected:
        contract = load_benchmark_contract(entry.contract)
        validate_contract_alignment(entry, contract)
        config_paths: dict[str, str] = {}
        repo_paths: set[Path] = set()
        for label, config_path in sorted(entry.configs.items()):
            config = load_config(config_path)
            if config.repo_template is None:
                raise ValueError(f"Config {config_path} has no repo_template.")
            repo_path = config.repo_template
            repo_paths.add(repo_path)
            pack_config_path = f"configs/{config_path.name}"
            config_paths[label] = pack_config_path
            files[pack_config_path] = _rewritten_config_bytes(
                config_path,
                repo_path,
                f"repos/{repo_path.name}",
            )
        pack_contract_path = f"contracts/{entry.contract.name}"
        files[pack_contract_path] = _rewritten_contract_bytes(
            entry.contract,
            {label: config_paths[label] for label in entry.configs},
        )
        for repo_path in sorted(repo_paths):
            _add_repo_files(files, symlink_paths, repo_path, f"repos/{repo_path.name}")
        registry_data["benchmarks"].append(
            {
                "id": entry.id,
                "version": entry.version,
                "name": entry.name,
                "category": entry.category,
                "difficulty": entry.difficulty,
                "description": entry.description,
                "tags": list(entry.tags),
                "configs": {
                    label: config_paths[label]
                    for label in entry.configs
                },
                "contract": pack_contract_path,
            }
        )
    files[REGISTRY_FRAGMENT_PATH] = _yaml_bytes(registry_data)
    if include_docs:
        for doc in [Path("docs/benchmarks.md"), Path("docs/benchmark-fuzzing.md")]:
            source = repo_root / doc
            if source.exists():
                files[doc.as_posix()] = source.read_bytes()
    return _dedupe_files(files), symlink_paths


def _rewritten_config_bytes(config_path: Path, repo_path: Path, pack_repo_path: str) -> bytes:
    with config_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config {config_path} must be a YAML mapping.")
    data = dict(data)
    data["repo_template"] = pack_repo_path
    return _yaml_bytes(data)


def _rewritten_contract_bytes(contract_path: Path, config_paths: dict[str, str]) -> bytes:
    with contract_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Contract {contract_path} must be a YAML mapping.")
    variants = data.get("variants")
    if not isinstance(variants, dict):
        raise ValueError(f"Contract {contract_path} variants must be a mapping.")
    data = dict(data)
    rewritten_variants = {}
    for name, variant in variants.items():
        if not isinstance(variant, dict):
            raise ValueError(f"Contract {contract_path} variant {name} must be a mapping.")
        rewritten = dict(variant)
        rewritten["config"] = config_paths[str(name)]
        rewritten_variants[name] = rewritten
    data["variants"] = rewritten_variants
    return _yaml_bytes(data)


def _external_registry_text(registry_path: Path, dest: Path) -> str:
    with registry_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}
    if not isinstance(data, dict) or not isinstance(data.get("benchmarks"), list):
        raise ValueError(f"Imported registry fragment is malformed: {registry_path}")
    rewritten = {"benchmarks": []}
    for raw_entry in data["benchmarks"]:
        if not isinstance(raw_entry, dict):
            raise ValueError(f"Imported registry entry is malformed: {registry_path}")
        entry = dict(raw_entry)
        configs = entry.get("configs")
        if not isinstance(configs, dict):
            raise ValueError(f"Imported registry configs are malformed: {registry_path}")
        entry["configs"] = {
            label: str((dest / _validate_safe_relative(str(path))).resolve())
            for label, path in configs.items()
        }
        entry["contract"] = str(
            (dest / _validate_safe_relative(str(entry.get("contract", "")))).resolve()
        )
        rewritten["benchmarks"].append(entry)
    return _yaml_bytes(rewritten).decode("utf-8")


def _add_repo_files(
    files: dict[str, bytes],
    symlink_paths: set[str],
    repo_path: Path,
    pack_prefix: str,
) -> None:
    repo = repo_path.expanduser().resolve()
    for path in sorted(repo.rglob("*")):
        relative = path.relative_to(repo)
        if _excluded(relative):
            continue
        pack_path = PurePosixPath(pack_prefix, *relative.parts).as_posix()
        _validate_safe_relative(pack_path)
        if path.is_symlink():
            target = path.readlink().as_posix()
            _validate_safe_symlink(pack_path, target)
            files[pack_path] = target.encode("utf-8")
            symlink_paths.add(pack_path)
            continue
        if not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"Repo file exceeds {MAX_FILE_BYTES} byte limit: {path}")
        files[pack_path] = path.read_bytes()


def _excluded(relative: Path) -> bool:
    parts = set(relative.parts)
    if parts & EXCLUDED_PARTS:
        return True
    name = relative.name
    return name in EXCLUDED_NAMES or name.endswith(".log") or relative.suffix in EXCLUDED_SUFFIXES


def _dedupe_files(files: dict[str, bytes]) -> dict[str, bytes]:
    normalized: dict[str, bytes] = {}
    for path, content in files.items():
        safe = _validate_safe_relative(path)
        if safe in normalized and normalized[safe] != content:
            raise ValueError(f"duplicate pack path with different content: {safe}")
        normalized[safe] = content
    return normalized


def _manifest(
    selected: list[BenchmarkRegistryEntry],
    file_entries: list[dict[str, Any]],
    root_digest: str,
    *,
    include_docs: bool,
    source_registry: Path,
) -> dict[str, Any]:
    registry_fragment = REGISTRY_FRAGMENT_PATH
    return {
        "schema": PACK_SCHEMA,
        "schema_version": PACK_SCHEMA_VERSION,
        "pack_id": "",
        "pack_version": PACK_VERSION,
        "created_at": DETERMINISTIC_CREATED_AT,
        "agentguard": {
            "version": __version__,
            "commit": _git_commit(),
        },
        "benchmarks": [
            {"id": entry.id, "version": entry.version}
            for entry in selected
        ],
        "files": file_entries,
        "root_digest": root_digest,
        "entrypoint_registry_fragment": registry_fragment,
        "contract_paths": sorted(
            f"contracts/{entry.contract.name}" for entry in selected
        ),
        "config_paths": sorted(
            f"configs/{config.name}"
            for entry in selected
            for config in entry.configs.values()
        ),
        "repo_fixture_paths": sorted(
            {
                f"repos/{load_config(config).repo_template.name}"
                for entry in selected
                for config in entry.configs.values()
                if load_config(config).repo_template is not None
            }
        ),
        "docs_paths": sorted(
            path["path"]
            for path in file_entries
            if str(path["path"]).startswith("docs/")
        )
        if include_docs
        else [],
        "source_provenance": {
            "registry": str(source_registry),
        },
    }


def _safe_zip_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members: dict[str, zipfile.ZipInfo] = {}
    total = 0
    for info in archive.infolist():
        path = _validate_safe_relative(info.filename)
        if path in members:
            raise BenchmarkPackError(f"duplicate normalized path in pack: {path}")
        mode = (info.external_attr >> 16) & 0o170000
        if info.is_dir():
            raise BenchmarkPackError(f"directories are not allowed as pack members: {path}")
        if mode and mode not in {stat.S_IFREG, stat.S_IFLNK}:
            raise BenchmarkPackError(f"special files are not allowed in packs: {path}")
        total += info.file_size
        if total > MAX_PACK_BYTES:
            raise BenchmarkPackError(f"pack contents exceed {MAX_PACK_BYTES} byte limit")
        members[path] = info
    return members


def _validate_safe_relative(path: str) -> str:
    normalized = path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if normalized.startswith("/") or pure.is_absolute():
        raise BenchmarkPackError(f"unsafe absolute path in pack: {path}")
    if not normalized or normalized in {".", ""}:
        raise BenchmarkPackError("empty pack path")
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise BenchmarkPackError(f"unsafe relative path in pack: {path}")
    return pure.as_posix()


def _safe_destination(root: Path, relative_path: str) -> Path:
    safe = _validate_safe_relative(relative_path)
    dest = (root / safe).resolve()
    root_resolved = root.resolve()
    try:
        dest.relative_to(root_resolved)
    except ValueError as error:
        raise BenchmarkPackError(f"pack path escapes destination: {relative_path}") from error
    return dest


def _validate_safe_symlink(path: str, target: str) -> None:
    if not target or "\x00" in target:
        raise BenchmarkPackError(f"unsafe symlink target in pack: {path}")
    target_path = PurePosixPath(target.replace("\\", "/"))
    if target_path.is_absolute():
        raise BenchmarkPackError(f"absolute symlink target in pack: {path}")
    if any(part in {"", ".", ".."} for part in target_path.parts):
        raise BenchmarkPackError(f"traversing symlink target in pack: {path}")
    link_parent = PurePosixPath(path).parent
    resolved_parts = []
    for part in (*link_parent.parts, *target_path.parts):
        if part == "..":
            if not resolved_parts:
                raise BenchmarkPackError(f"symlink escapes pack root: {path}")
            resolved_parts.pop()
        elif part not in {"", "."}:
            resolved_parts.append(part)
    if not resolved_parts:
        raise BenchmarkPackError(f"symlink target resolves to pack root: {path}")


def _validate_manifest_schema(manifest: dict[str, Any]) -> None:
    if not isinstance(manifest, dict):
        raise BenchmarkPackError("pack manifest must be a JSON object")
    required = {
        "schema",
        "schema_version",
        "pack_id",
        "pack_version",
        "created_at",
        "agentguard",
        "benchmarks",
        "files",
        "root_digest",
        "entrypoint_registry_fragment",
        "contract_paths",
        "config_paths",
        "repo_fixture_paths",
        "docs_paths",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise BenchmarkPackError("manifest missing fields: " + ", ".join(missing))
    if manifest["schema"] != PACK_SCHEMA:
        raise BenchmarkPackError(f"manifest schema must be {PACK_SCHEMA}")
    if manifest["schema_version"] != PACK_SCHEMA_VERSION:
        raise BenchmarkPackError(f"manifest schema_version must be {PACK_SCHEMA_VERSION}")
    _validate_safe_relative(str(manifest["entrypoint_registry_fragment"]))
    for key in ("contract_paths", "config_paths", "repo_fixture_paths", "docs_paths"):
        values = manifest[key]
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise BenchmarkPackError(f"manifest {key} must be a list of strings")
        for item in values:
            _validate_safe_relative(item)


def _manifest_file_map(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise BenchmarkPackError("manifest files must be a non-empty list")
    mapped: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise BenchmarkPackError("manifest file entries must be objects")
        path = _validate_safe_relative(str(item.get("path", "")))
        sha256 = item.get("sha256")
        size = item.get("size")
        if not isinstance(sha256, str) or len(sha256) != 64:
            raise BenchmarkPackError(f"manifest file has invalid hash: {path}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BenchmarkPackError(f"manifest file has invalid size: {path}")
        file_type = item.get("type", "regular")
        if file_type not in {"regular", "symlink"}:
            raise BenchmarkPackError(f"manifest file has invalid type: {path}")
        if path in mapped:
            raise BenchmarkPackError(f"duplicate file path in manifest: {path}")
        mapped[path] = {"sha256": sha256, "size": size, "type": file_type}
    return mapped


def _verify_registry_contract_config_consistency(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
) -> None:
    with tempfile.TemporaryDirectory(prefix="agentguard-pack-verify-") as temp_name:
        temp_root = Path(temp_name)
        file_map = _manifest_file_map(manifest)
        for item in _manifest_file_map(manifest):
            target = _safe_destination(temp_root, item)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.read(item)
            if file_map[item]["type"] == "symlink":
                target.write_text(content.decode("utf-8"), encoding="utf-8")
            else:
                target.write_bytes(content)
        registry_path = temp_root / str(manifest["entrypoint_registry_fragment"])
        registry = load_benchmark_registry(registry_path)
        selected = {(item["id"], item["version"]) for item in manifest["benchmarks"]}
        loaded = {(entry.id, entry.version) for entry in registry.benchmarks}
        if selected != loaded:
            raise BenchmarkPackError("manifest benchmarks do not match registry fragment")
        for entry in registry.benchmarks:
            contract = load_benchmark_contract(entry.contract)
            validate_contract_alignment(entry, contract)


def _write_zip(path: Path, files: dict[str, bytes], symlink_paths: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    compression = zipfile.ZIP_DEFLATED
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for relative_path, content in sorted(files.items()):
            info = zipfile.ZipInfo(relative_path, ZIP_TIMESTAMP)
            info.compress_type = compression
            mode = 0o120777 if relative_path in symlink_paths else 0o100644
            info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, content)


def _yaml_bytes(data: dict[str, Any]) -> bytes:
    return (
        yaml.safe_dump(
            data,
            sort_keys=False,
            default_flow_style=False,
            allow_unicode=False,
        )
    ).encode("utf-8")


def _json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _root_digest(file_entries: list[dict[str, Any]]) -> str:
    material = json.dumps(
        sorted(file_entries, key=lambda item: item["path"]),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(material)


def _git_commit() -> Optional[str]:
    git = Path(".git")
    head = git / "HEAD"
    try:
        value = head.read_text(encoding="utf-8").strip()
        if value.startswith("ref: "):
            ref = git / value.split(" ", 1)[1]
            return ref.read_text(encoding="utf-8").strip()
        return value
    except OSError:
        return None


def _project_root(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    for parent in [resolved.parent, *resolved.parents]:
        if (parent / "pyproject.toml").exists() and (parent / "agentguard").is_dir():
            return parent
    return Path.cwd().resolve()
