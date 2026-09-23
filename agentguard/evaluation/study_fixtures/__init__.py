from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from agentguard.artifact_paths import validate_artifact_id
from agentguard.config.yaml import load_yaml, reject_unknown_keys


STUDY_FIXTURE_SET_SCHEMA = "agentguard.contained-study-fixture-set"
STUDY_FIXTURE_SET_SCHEMA_VERSION = 1
DEFAULT_STUDY_FIXTURE_MANIFEST = (
    Path(__file__).resolve().parent
    / "v1"
    / "manifest.yaml"
)
MAX_STUDY_FIXTURES = 32
MAX_STUDY_FIXTURE_FILES = 128
MAX_STUDY_FIXTURE_FILE_BYTES = 1024 * 1024
MAX_STUDY_FIXTURE_TOTAL_BYTES = 10 * 1024 * 1024
MAX_STUDY_FIXTURE_STRING_LENGTH = 2048
MAX_STUDY_FIXTURE_LIST_ITEMS = 64
FIXTURE_EXCLUDED_PARTS = {
    ".agentguard",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
}
FIXTURE_EXCLUDED_SUFFIXES = {".pyc", ".pyo", ".sqlite", ".sqlite3", ".db"}
FIXTURE_WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    "clock$",
    "conin$",
    "conout$",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}
_ALLOWED_SET_KEYS = {"schema", "schema_version", "fixtures"}
_ALLOWED_FIXTURE_KEYS = {
    "id",
    "task_id",
    "license",
    "provenance",
    "source",
    "prompt",
    "mutation",
    "checks",
    "expected",
    "required_capabilities",
    "exclusions",
    "limitations",
    "network_required",
}
_ALLOWED_SOURCE_KEYS = {"path", "hash", "files"}
_ALLOWED_SOURCE_FILE_KEYS = {"path", "sha256", "size"}
_ALLOWED_PROMPT_KEYS = {"text", "sha256"}
_ALLOWED_MUTATION_KEYS = {"allowed_paths", "forbidden_paths", "max_modified_files"}
_ALLOWED_CHECK_KEYS = {"id", "kind", "command", "expected_status"}
_ALLOWED_EXPECTED_KEYS = {
    "functional_success",
    "policy_compliant",
    "unsafe_functional_success",
    "expected_guard_incidents",
    "expected_policy_incidents",
}
_CHECK_KINDS = {"python-module", "read-only", "expected-failure"}


@dataclass(frozen=True)
class StudyFixtureFile:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class StudyFixtureSource:
    path: Path
    relative_path: str
    hash: str
    files: list[StudyFixtureFile]


@dataclass(frozen=True)
class StudyFixturePrompt:
    text: str
    sha256: str


@dataclass(frozen=True)
class StudyFixtureMutation:
    allowed_paths: list[str]
    forbidden_paths: list[str]
    max_modified_files: int


@dataclass(frozen=True)
class StudyFixtureCheck:
    id: str
    kind: str
    command: list[str]
    expected_status: int


@dataclass(frozen=True)
class StudyFixtureExpected:
    functional_success: bool
    policy_compliant: bool
    unsafe_functional_success: bool
    expected_guard_incidents: list[str]
    expected_policy_incidents: list[str]


@dataclass(frozen=True)
class StudyFixture:
    id: str
    task_id: str
    license: str
    provenance: str
    source: StudyFixtureSource
    prompt: StudyFixturePrompt
    mutation: StudyFixtureMutation
    checks: list[StudyFixtureCheck]
    expected: StudyFixtureExpected
    required_capabilities: list[str]
    exclusions: list[str]
    limitations: list[str]
    network_required: bool


@dataclass(frozen=True)
class StudyFixtureSet:
    path: Path
    fixtures: list[StudyFixture]
    schema: str = STUDY_FIXTURE_SET_SCHEMA
    schema_version: int = STUDY_FIXTURE_SET_SCHEMA_VERSION


def load_study_fixture_set(
    path: Optional[Path] = None,
    *,
    validate_sources: bool = True,
) -> StudyFixtureSet:
    manifest_path = (path or DEFAULT_STUDY_FIXTURE_MANIFEST).expanduser().resolve()
    with manifest_path.open("r", encoding="utf-8") as file:
        data = load_yaml(file) or {}
    if not isinstance(data, dict):
        raise ValueError("Study fixture manifest must be a YAML mapping.")
    reject_unknown_keys(data, _ALLOWED_SET_KEYS)
    if data.get("schema") != STUDY_FIXTURE_SET_SCHEMA:
        raise ValueError("Invalid contained study fixture set schema.")
    if data.get("schema_version") != STUDY_FIXTURE_SET_SCHEMA_VERSION:
        raise ValueError("Unsupported contained study fixture set schema version.")
    raw_fixtures = data.get("fixtures")
    if not isinstance(raw_fixtures, list) or not raw_fixtures:
        raise ValueError("Study fixture manifest field 'fixtures' must be a non-empty list.")
    if len(raw_fixtures) > MAX_STUDY_FIXTURES:
        raise ValueError("Study fixture manifest contains too many fixtures.")
    fixtures = [
        _load_fixture(item, manifest_path, index)
        for index, item in enumerate(raw_fixtures)
    ]
    fixture_ids = [fixture.id for fixture in fixtures]
    task_ids = [fixture.task_id for fixture in fixtures]
    _reject_duplicates(fixture_ids, "fixture ids")
    _reject_duplicates(task_ids, "fixture task ids")
    fixture_set = StudyFixtureSet(path=manifest_path, fixtures=fixtures)
    if validate_sources:
        validate_study_fixture_set(fixture_set)
    return fixture_set


def validate_study_fixture_set(fixture_set: StudyFixtureSet) -> None:
    for fixture in fixture_set.fixtures:
        actual_files = _collect_source_files(fixture.source.path)
        expected_paths = {file.path for file in fixture.source.files}
        actual_paths = {file.path for file in actual_files}
        missing = sorted(expected_paths - actual_paths)
        extra = sorted(actual_paths - expected_paths)
        if missing:
            raise ValueError(
                f"Study fixture {fixture.id} is missing source files: "
                + ", ".join(missing)
            )
        if extra:
            raise ValueError(
                f"Study fixture {fixture.id} has unexpected source files: "
                + ", ".join(extra)
            )
        expected_by_path = {file.path: file for file in fixture.source.files}
        for actual in actual_files:
            expected = expected_by_path[actual.path]
            if actual.sha256 != expected.sha256 or actual.size != expected.size:
                raise ValueError(
                    f"Study fixture {fixture.id} source file hash mismatch: "
                    f"{actual.path}"
                )
        actual_hash = _source_hash(actual_files)
        if actual_hash != fixture.source.hash:
            raise ValueError(f"Study fixture {fixture.id} source hash mismatch.")
        prompt_hash = _sha256_text(fixture.prompt.text)
        if prompt_hash != fixture.prompt.sha256:
            raise ValueError(f"Study fixture {fixture.id} prompt hash mismatch.")


def materialize_study_fixture(fixture: StudyFixture, destination: Path) -> Path:
    validate_study_fixture_set(
        StudyFixtureSet(path=fixture.source.path, fixtures=[fixture])
    )
    dest = destination.expanduser().resolve()
    if dest.exists() and any(dest.iterdir()):
        raise ValueError(f"Study fixture destination is not empty: {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    for file in fixture.source.files:
        source_file = fixture.source.path / file.path
        target = _safe_destination(dest, file.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, target)
        os.chmod(target, 0o600)
    return dest


def study_fixture_set_to_dict(fixture_set: StudyFixtureSet) -> dict[str, object]:
    return {
        "fixtures": [_fixture_to_dict(fixture) for fixture in fixture_set.fixtures],
        "schema": fixture_set.schema,
        "schema_version": fixture_set.schema_version,
    }


def serialize_study_fixture_set(fixture_set: StudyFixtureSet) -> str:
    return json.dumps(
        study_fixture_set_to_dict(fixture_set),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _load_fixture(
    value: object,
    manifest_path: Path,
    index: int,
) -> StudyFixture:
    if not isinstance(value, dict):
        raise ValueError(f"Study fixture entry {index} must be a mapping.")
    reject_unknown_keys(value, _ALLOWED_FIXTURE_KEYS, f"fixtures[{index}]")
    fixture_id = validate_artifact_id(
        _required_string(value, "id", f"fixtures[{index}]"),
        "Study fixture id",
    )
    task_id = validate_artifact_id(
        _required_string(value, "task_id", f"fixtures[{index}]"),
        "Study fixture task id",
    )
    network_required = value.get("network_required", False)
    if not isinstance(network_required, bool):
        raise ValueError(f"Study fixture {fixture_id} network_required must be boolean.")
    if network_required:
        raise ValueError(
            f"Study fixture {fixture_id} must not require network access in v1."
        )
    return StudyFixture(
        id=fixture_id,
        task_id=task_id,
        license=_required_string(value, "license", fixture_id),
        provenance=_required_string(value, "provenance", fixture_id),
        source=_load_source(value.get("source"), manifest_path, fixture_id),
        prompt=_load_prompt(value.get("prompt"), fixture_id),
        mutation=_load_mutation(value.get("mutation"), fixture_id),
        checks=_load_checks(value.get("checks"), fixture_id),
        expected=_load_expected(value.get("expected"), fixture_id),
        required_capabilities=_string_list(value, "required_capabilities", fixture_id),
        exclusions=_string_list(value, "exclusions", fixture_id),
        limitations=_string_list(value, "limitations", fixture_id),
        network_required=network_required,
    )


def _load_source(
    value: object,
    manifest_path: Path,
    fixture_id: str,
) -> StudyFixtureSource:
    mapping = _mapping(value, f"{fixture_id}.source")
    reject_unknown_keys(mapping, _ALLOWED_SOURCE_KEYS, f"{fixture_id}.source")
    relative_path = _safe_relative_dir(
        _required_string(mapping, "path", f"{fixture_id}.source"),
        f"{fixture_id}.source.path",
    )
    source_path = (manifest_path.parent / relative_path).resolve()
    try:
        source_path.relative_to(manifest_path.parent.resolve())
    except ValueError as error:
        raise ValueError(f"Study fixture {fixture_id} source path escapes manifest.") from error
    files = _load_source_files(mapping.get("files"), fixture_id)
    if len(files) > MAX_STUDY_FIXTURE_FILES:
        raise ValueError(f"Study fixture {fixture_id} has too many source files.")
    return StudyFixtureSource(
        path=source_path,
        relative_path=relative_path,
        hash=_sha256_string(mapping.get("hash"), f"{fixture_id}.source.hash"),
        files=files,
    )


def _load_source_files(value: object, fixture_id: str) -> list[StudyFixtureFile]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"Study fixture {fixture_id} source.files must be non-empty.")
    files: list[StudyFixtureFile] = []
    for index, item in enumerate(value):
        mapping = _mapping(item, f"{fixture_id}.source.files[{index}]")
        reject_unknown_keys(
            mapping,
            _ALLOWED_SOURCE_FILE_KEYS,
            f"{fixture_id}.source.files[{index}]",
        )
        path = _safe_relative_file(
            _required_string(
                mapping,
                "path",
                f"{fixture_id}.source.files[{index}]",
            ),
            f"{fixture_id}.source.files[{index}].path",
        )
        size = mapping.get("size")
        if (
            not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or size > MAX_STUDY_FIXTURE_FILE_BYTES
        ):
            raise ValueError(
                f"Study fixture {fixture_id} source file size is out of bounds."
            )
        files.append(
            StudyFixtureFile(
                path=path,
                sha256=_sha256_string(
                    mapping.get("sha256"),
                    f"{fixture_id}.source.files[{index}].sha256",
                ),
                size=size,
            )
        )
    _reject_duplicates([file.path for file in files], f"{fixture_id} source files")
    return sorted(files, key=lambda file: file.path)


def _load_prompt(value: object, fixture_id: str) -> StudyFixturePrompt:
    mapping = _mapping(value, f"{fixture_id}.prompt")
    reject_unknown_keys(mapping, _ALLOWED_PROMPT_KEYS, f"{fixture_id}.prompt")
    text = _required_string(mapping, "text", f"{fixture_id}.prompt")
    prompt_sha256 = _sha256_string(
        mapping.get("sha256"),
        f"{fixture_id}.prompt.sha256",
    )
    if _sha256_text(text) != prompt_sha256:
        raise ValueError(f"Study fixture {fixture_id} prompt hash mismatch.")
    return StudyFixturePrompt(
        text=text,
        sha256=prompt_sha256,
    )


def _load_mutation(value: object, fixture_id: str) -> StudyFixtureMutation:
    mapping = _mapping(value, f"{fixture_id}.mutation")
    reject_unknown_keys(mapping, _ALLOWED_MUTATION_KEYS, f"{fixture_id}.mutation")
    max_modified = mapping.get("max_modified_files")
    if (
        not isinstance(max_modified, int)
        or isinstance(max_modified, bool)
        or max_modified < 0
        or max_modified > MAX_STUDY_FIXTURE_FILES
    ):
        raise ValueError(
            f"Study fixture {fixture_id} mutation.max_modified_files is out of bounds."
        )
    allowed = _path_pattern_list(mapping, "allowed_paths", f"{fixture_id}.mutation")
    forbidden = _path_pattern_list(mapping, "forbidden_paths", f"{fixture_id}.mutation")
    overlap = sorted(set(allowed) & set(forbidden))
    if overlap:
        raise ValueError(
            f"Study fixture {fixture_id} mutation paths cannot be both allowed and "
            f"forbidden: {', '.join(overlap)}."
        )
    return StudyFixtureMutation(
        allowed_paths=allowed,
        forbidden_paths=forbidden,
        max_modified_files=max_modified,
    )


def _load_checks(value: object, fixture_id: str) -> list[StudyFixtureCheck]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"Study fixture {fixture_id} checks must be a non-empty list.")
    checks: list[StudyFixtureCheck] = []
    for index, item in enumerate(value):
        mapping = _mapping(item, f"{fixture_id}.checks[{index}]")
        reject_unknown_keys(mapping, _ALLOWED_CHECK_KEYS, f"{fixture_id}.checks[{index}]")
        check_id = validate_artifact_id(
            _required_string(mapping, "id", f"{fixture_id}.checks[{index}]"),
            "Study fixture check id",
        )
        kind = _required_string(mapping, "kind", f"{fixture_id}.checks[{index}]")
        if kind not in _CHECK_KINDS:
            raise ValueError(f"Study fixture {fixture_id} check kind is unsupported.")
        command = _check_command(mapping.get("command"), fixture_id, check_id)
        expected_status = mapping.get("expected_status")
        if (
            not isinstance(expected_status, int)
            or isinstance(expected_status, bool)
            or expected_status < 0
            or expected_status > 255
        ):
            raise ValueError(
                f"Study fixture {fixture_id} check expected_status is out of bounds."
            )
        checks.append(
            StudyFixtureCheck(
                id=check_id,
                kind=kind,
                command=command,
                expected_status=expected_status,
            )
        )
    _reject_duplicates([check.id for check in checks], f"{fixture_id} check ids")
    return sorted(checks, key=lambda check: check.id)


def _load_expected(value: object, fixture_id: str) -> StudyFixtureExpected:
    mapping = _mapping(value, f"{fixture_id}.expected")
    reject_unknown_keys(mapping, _ALLOWED_EXPECTED_KEYS, f"{fixture_id}.expected")
    return StudyFixtureExpected(
        functional_success=_required_bool(mapping, "functional_success", fixture_id),
        policy_compliant=_required_bool(mapping, "policy_compliant", fixture_id),
        unsafe_functional_success=_required_bool(
            mapping,
            "unsafe_functional_success",
            fixture_id,
        ),
        expected_guard_incidents=_string_list(
            mapping,
            "expected_guard_incidents",
            fixture_id,
        ),
        expected_policy_incidents=_string_list(
            mapping,
            "expected_policy_incidents",
            fixture_id,
        ),
    )


def _collect_source_files(root: Path) -> list[StudyFixtureFile]:
    if not root.is_dir():
        raise ValueError(f"Study fixture source root does not exist: {root}")
    files: list[StudyFixtureFile] = []
    total_bytes = 0
    seen_inodes: set[tuple[int, int]] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        _safe_relative_file(relative, f"source file {relative}")
        _reject_excluded_path(PurePosixPath(relative))
        info = path.lstat()
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(f"Study fixture source contains a symlink: {relative}")
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError(f"Study fixture source contains a non-regular file: {relative}")
        if info.st_nlink != 1:
            raise ValueError(f"Study fixture source contains a hardlink: {relative}")
        inode_key = (info.st_dev, info.st_ino)
        if inode_key in seen_inodes:
            raise ValueError(f"Study fixture source contains duplicate file identity: {relative}")
        seen_inodes.add(inode_key)
        if info.st_size > MAX_STUDY_FIXTURE_FILE_BYTES:
            raise ValueError(f"Study fixture source file is too large: {relative}")
        total_bytes += info.st_size
        if total_bytes > MAX_STUDY_FIXTURE_TOTAL_BYTES:
            raise ValueError("Study fixture source set is too large.")
        content = path.read_bytes()
        files.append(
            StudyFixtureFile(
                path=relative,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
            )
        )
    if not files:
        raise ValueError(f"Study fixture source root has no files: {root}")
    return files


def _source_hash(files: list[StudyFixtureFile]) -> str:
    entries = [
        {"path": file.path, "sha256": file.sha256, "size": file.size}
        for file in sorted(files, key=lambda item: item.path)
    ]
    return hashlib.sha256(_canonical_json(entries).encode("utf-8")).hexdigest()


def _fixture_to_dict(fixture: StudyFixture) -> dict[str, object]:
    return {
        "checks": [
            {
                "command": list(check.command),
                "expected_status": check.expected_status,
                "id": check.id,
                "kind": check.kind,
            }
            for check in fixture.checks
        ],
        "exclusions": list(fixture.exclusions),
        "expected": {
            "expected_guard_incidents": list(fixture.expected.expected_guard_incidents),
            "expected_policy_incidents": list(fixture.expected.expected_policy_incidents),
            "functional_success": fixture.expected.functional_success,
            "policy_compliant": fixture.expected.policy_compliant,
            "unsafe_functional_success": fixture.expected.unsafe_functional_success,
        },
        "id": fixture.id,
        "license": fixture.license,
        "limitations": list(fixture.limitations),
        "mutation": {
            "allowed_paths": list(fixture.mutation.allowed_paths),
            "forbidden_paths": list(fixture.mutation.forbidden_paths),
            "max_modified_files": fixture.mutation.max_modified_files,
        },
        "network_required": fixture.network_required,
        "prompt": {
            "sha256": fixture.prompt.sha256,
            "text": fixture.prompt.text,
        },
        "provenance": fixture.provenance,
        "required_capabilities": list(fixture.required_capabilities),
        "source": {
            "files": [
                {"path": file.path, "sha256": file.sha256, "size": file.size}
                for file in fixture.source.files
            ],
            "hash": fixture.source.hash,
            "path": fixture.source.relative_path,
        },
        "task_id": fixture.task_id,
    }


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Study fixture field '{field}' must be a mapping.")
    return value


def _required_string(mapping: dict[str, Any], key: str, field: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Study fixture field '{field}.{key}' must be a non-empty string.")
    if len(value) > MAX_STUDY_FIXTURE_STRING_LENGTH:
        raise ValueError(f"Study fixture field '{field}.{key}' is too long.")
    if any(ord(char) < 32 and char not in "\n\t" for char in value):
        raise ValueError(f"Study fixture field '{field}.{key}' has a control character.")
    return value


def _string_list(mapping: dict[str, Any], key: str, field: str) -> list[str]:
    value = mapping.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"Study fixture field '{field}.{key}' must be a list.")
    if len(value) > MAX_STUDY_FIXTURE_LIST_ITEMS:
        raise ValueError(f"Study fixture field '{field}.{key}' has too many items.")
    strings = [
        _bounded_string(item, f"{field}.{key}[{index}]")
        for index, item in enumerate(value)
    ]
    _reject_duplicates(strings, f"{field}.{key}")
    return sorted(strings)


def _path_pattern_list(mapping: dict[str, Any], key: str, field: str) -> list[str]:
    values = _string_list(mapping, key, field)
    for value in values:
        if value.startswith("/") or "\\" in value or ".." in PurePosixPath(value).parts:
            raise ValueError(f"Study fixture path pattern is not portable: {value}")
    return values


def _check_command(value: object, fixture_id: str, check_id: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"Study fixture {fixture_id} check {check_id} command must be a list.")
    if len(value) > MAX_STUDY_FIXTURE_LIST_ITEMS:
        raise ValueError(f"Study fixture {fixture_id} check {check_id} command is too long.")
    command = [
        _bounded_string(item, f"{fixture_id}.checks.{check_id}.command[{index}]")
        for index, item in enumerate(value)
    ]
    joined = " ".join(command)
    if any(marker in joined for marker in ("&&", "||", ";", "$(", "`", "|", ">")):
        raise ValueError(
            f"Study fixture {fixture_id} check {check_id} command must be structured."
        )
    return command


def _required_bool(mapping: dict[str, Any], key: str, fixture_id: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise ValueError(f"Study fixture {fixture_id} expected.{key} must be boolean.")
    return value


def _bounded_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Study fixture field '{label}' must be a non-empty string.")
    if len(value) > MAX_STUDY_FIXTURE_STRING_LENGTH:
        raise ValueError(f"Study fixture field '{label}' is too long.")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"Study fixture field '{label}' has a control character.")
    return value


def _sha256_string(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"Study fixture field '{label}' must be a sha256 hex digest.")
    try:
        int(value, 16)
    except ValueError as error:
        raise ValueError(
            f"Study fixture field '{label}' must be a sha256 hex digest."
        ) from error
    return value.lower()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_relative_dir(value: str, label: str) -> str:
    path = _safe_posix_path(value, label)
    if path.name == "":
        raise ValueError(f"Study fixture path '{label}' must not be empty.")
    return path.as_posix()


def _safe_relative_file(value: str, label: str) -> str:
    path = _safe_posix_path(value, label)
    if value.endswith("/"):
        raise ValueError(f"Study fixture path '{label}' must be a file path.")
    return path.as_posix()


def _safe_posix_path(value: str, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Study fixture path '{label}' must be non-empty.")
    if "\\" in value or value.startswith("/"):
        raise ValueError(f"Study fixture path '{label}' must be relative and portable.")
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"Study fixture path '{label}' must not contain traversal.")
    for part in path.parts:
        if part.lower() in FIXTURE_WINDOWS_RESERVED_NAMES:
            raise ValueError(f"Study fixture path '{label}' uses a reserved name.")
    return path


def _reject_excluded_path(path: PurePosixPath) -> None:
    for part in path.parts:
        if part in FIXTURE_EXCLUDED_PARTS:
            raise ValueError(f"Study fixture source contains excluded path: {path}")
    if path.suffix in FIXTURE_EXCLUDED_SUFFIXES:
        raise ValueError(f"Study fixture source contains excluded artifact: {path}")


def _safe_destination(root: Path, relative: str) -> Path:
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise ValueError("Study fixture materialization path escapes destination.") from error
    return target


def _reject_duplicates(values: list[str], label: str) -> None:
    if len(set(values)) != len(values):
        raise ValueError(f"Study fixture {label} contains duplicates.")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
