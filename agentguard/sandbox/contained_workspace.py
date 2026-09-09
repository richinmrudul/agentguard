from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from uuid import uuid4

from agentguard.artifact_paths import artifact_directory, validate_artifact_id
from agentguard.redaction import redact_credentials


CONTAINED_WORKSPACE_SCHEMA_VERSION = 1
DEFAULT_AGENT_WORKSPACE_PATH = "/agentguard-workspace"
DEFAULT_EVIDENCE_PATH = "/agentguard-evidence"
RESERVED_PATHS = (
    ".git",
    ".agentguard",
    ".agentguard_agent_events.jsonl",
)


class ContainedWorkspaceError(ValueError):
    """Raised when a source tree cannot be prepared as a contained workspace."""


class ContainedWorkspaceMutationError(ContainedWorkspaceError):
    """Raised when prepared workspace mutations cannot be captured safely."""


@dataclass(frozen=True)
class ContainedWorkspaceLimits:
    max_entries: int = 100_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_symlink_target_bytes: int = 4096


@dataclass(frozen=True)
class _ValidatedSourceEntry:
    path: Path
    info: os.stat_result


@dataclass(frozen=True)
class ContainedPathSnapshot:
    path: str
    kind: str
    size: int
    sha256: Optional[str]
    mode: int


@dataclass(frozen=True)
class ContainedGitStatusEntry:
    status: str
    path: str
    source_path: Optional[str] = None


@dataclass(frozen=True)
class ContainedBaselineSnapshot:
    source_kind: str
    git_head: Optional[str]
    git_status: tuple[ContainedGitStatusEntry, ...]
    files: tuple[ContainedPathSnapshot, ...]
    digest: str


@dataclass(frozen=True)
class ContainedWorkspaceMutations:
    modified_files: tuple[str, ...]
    added_files: tuple[str, ...]
    deleted_files: tuple[str, ...]
    renamed_files: tuple[tuple[str, str], ...]
    current_digest: str

    @property
    def changed_files(self) -> tuple[str, ...]:
        renamed_paths = [
            path for old_path, new_path in self.renamed_files for path in (old_path, new_path)
        ]
        return tuple(
            sorted(
                set(self.modified_files)
                | set(self.added_files)
                | set(self.deleted_files)
                | set(renamed_paths)
            )
        )


@dataclass(frozen=True)
class ContainedWorkspaceMetadata:
    schema_version: int
    workspace_id: str
    source_kind: str
    baseline: ContainedBaselineSnapshot
    agent_mount: str
    evidence_mount: str
    agent_visible_writable_paths: tuple[str, ...]
    agentguard_evidence: str
    cleanup_targets: tuple[str, ...]
    reserved_paths: tuple[str, ...]
    limits: ContainedWorkspaceLimits

    def to_dict(self) -> dict[str, Any]:
        return _stable_value(asdict(self))


@dataclass(frozen=True)
class ContainedWorkspaceCleanupResult:
    complete: bool
    message: str = ""


@dataclass(frozen=True)
class PreparedContainedWorkspace:
    workspace_id: str
    run_dir: Path
    workspace_dir: Path
    evidence_dir: Path
    metadata: ContainedWorkspaceMetadata

    def capture_mutations(
        self,
        *,
        limits: Optional[ContainedWorkspaceLimits] = None,
    ) -> ContainedWorkspaceMutations:
        return capture_contained_workspace_mutations(
            self,
            limits=self.metadata.limits if limits is None else limits,
        )

    def cleanup(self) -> ContainedWorkspaceCleanupResult:
        try:
            if self.run_dir.exists() or self.run_dir.is_symlink():
                shutil.rmtree(self.run_dir)
        except OSError as error:
            return ContainedWorkspaceCleanupResult(
                complete=False,
                message=(
                    "contained workspace cleanup incomplete: "
                    f"{redact_credentials(error.__class__.__name__)}"
                ),
            )
        return ContainedWorkspaceCleanupResult(
            complete=True,
            message="contained workspace cleanup complete",
        )


def prepare_contained_workspace(
    source_dir: Path,
    lifecycle_root: Path,
    *,
    workspace_id: Optional[str] = None,
    limits: ContainedWorkspaceLimits = ContainedWorkspaceLimits(),
    agent_mount: str = DEFAULT_AGENT_WORKSPACE_PATH,
    evidence_mount: str = DEFAULT_EVIDENCE_PATH,
    agent_visible_writable_paths: Iterable[str] = (".",),
) -> PreparedContainedWorkspace:
    """Prepare an isolated copy for future contained-agent execution.

    This function does not launch an agent or build a Docker invocation. It
    creates only lifecycle-owned host paths and records deterministic metadata
    describing what may later be mounted into a contained runner.
    """
    source_root = _source_root(source_dir)
    workspace_name = validate_artifact_id(
        workspace_id or f"contained-{uuid4().hex}",
        "workspace_id",
    )
    run_dir = artifact_directory(lifecycle_root, workspace_name)
    staging_dir = artifact_directory(lifecycle_root, f"{workspace_name}.preparing")
    workspace_dir = staging_dir / "workspace"
    evidence_dir = staging_dir / "evidence"
    final_workspace_dir = run_dir / "workspace"
    final_evidence_dir = run_dir / "evidence"

    if run_dir.exists() or staging_dir.exists():
        raise ContainedWorkspaceError("contained workspace id already exists")
    writable_paths = tuple(agent_visible_writable_paths)
    _validate_agent_paths(agent_mount, evidence_mount, writable_paths)

    normalized_writable_paths = _normalize_writable_paths(writable_paths)
    baseline = _baseline_snapshot(source_root, limits)
    metadata = ContainedWorkspaceMetadata(
        schema_version=CONTAINED_WORKSPACE_SCHEMA_VERSION,
        workspace_id=workspace_name,
        source_kind=baseline.source_kind,
        baseline=baseline,
        agent_mount=agent_mount,
        evidence_mount=evidence_mount,
        agent_visible_writable_paths=normalized_writable_paths,
        agentguard_evidence="evidence",
        cleanup_targets=(".",),
        reserved_paths=RESERVED_PATHS,
        limits=limits,
    )

    try:
        workspace_dir.mkdir(parents=True)
        evidence_dir.mkdir()
        _copy_validated_tree(source_root, workspace_dir, limits)
        _write_metadata(evidence_dir / "workspace-metadata.json", metadata)
        os.replace(staging_dir, run_dir)
    except ContainedWorkspaceError:
        _rollback_staging(staging_dir)
        raise
    except Exception as error:
        _rollback_staging(staging_dir)
        raise ContainedWorkspaceError(
            "contained workspace preparation failed during lifecycle-owned setup"
        ) from error

    return PreparedContainedWorkspace(
        workspace_id=workspace_name,
        run_dir=run_dir,
        workspace_dir=final_workspace_dir,
        evidence_dir=final_evidence_dir,
        metadata=metadata,
    )


def capture_contained_workspace_mutations(
    prepared: PreparedContainedWorkspace,
    *,
    limits: Optional[ContainedWorkspaceLimits] = None,
) -> ContainedWorkspaceMutations:
    """Capture post-agent workspace mutations without consulting live Git state."""
    scan_limits = prepared.metadata.limits if limits is None else limits
    try:
        if not prepared.workspace_dir.is_dir():
            raise ContainedWorkspaceMutationError("contained workspace is unavailable")
        current_files = tuple(
            _scan_tree(prepared.workspace_dir, scan_limits, reject_git_control=True)
        )
    except ContainedWorkspaceMutationError:
        raise
    except ContainedWorkspaceError as error:
        raise ContainedWorkspaceMutationError(str(error)) from error
    except Exception as error:
        raise ContainedWorkspaceMutationError(
            "contained workspace mutation capture failed during bounded scan"
        ) from error

    baseline_by_path = {entry.path: entry for entry in prepared.metadata.baseline.files}
    current_by_path = {entry.path: entry for entry in current_files}
    deleted = sorted(path for path in baseline_by_path if path not in current_by_path)
    added = sorted(path for path in current_by_path if path not in baseline_by_path)
    modified = sorted(
        path
        for path in baseline_by_path.keys() & current_by_path.keys()
        if _snapshot_identity(baseline_by_path[path])
        != _snapshot_identity(current_by_path[path])
    )
    renamed = _detect_renames(
        [baseline_by_path[path] for path in deleted],
        [current_by_path[path] for path in added],
    )
    renamed_old = {old_path for old_path, _new_path in renamed}
    renamed_new = {new_path for _old_path, new_path in renamed}
    deleted = [path for path in deleted if path not in renamed_old]
    added = [path for path in added if path not in renamed_new]

    digest = _baseline_digest(
        prepared.metadata.source_kind,
        prepared.metadata.baseline.git_head,
        prepared.metadata.baseline.git_status,
        current_files,
    )
    return ContainedWorkspaceMutations(
        modified_files=tuple(modified),
        added_files=tuple(added),
        deleted_files=tuple(deleted),
        renamed_files=tuple(renamed),
        current_digest=digest,
    )


def _source_root(source_dir: Path) -> Path:
    try:
        root = source_dir.expanduser().resolve()
    except OSError as error:
        raise ContainedWorkspaceError("source directory cannot be resolved") from error
    if not root.is_dir():
        raise ContainedWorkspaceError("source directory must be an existing directory")
    return root


def _validate_agent_paths(
    agent_mount: str,
    evidence_mount: str,
    agent_visible_writable_paths: Iterable[str],
) -> None:
    for value, field_name in (
        (agent_mount, "agent_mount"),
        (evidence_mount, "evidence_mount"),
    ):
        if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
            raise ContainedWorkspaceError(f"{field_name} must be an absolute path")
        normalized = value.rstrip("/") or "/"
        if normalized == "/" or "/.." in normalized or "/." in normalized or "//" in normalized:
            raise ContainedWorkspaceError(f"{field_name} must be normalized")
    normalized_agent_mount = agent_mount.rstrip("/") or "/"
    normalized_evidence_mount = evidence_mount.rstrip("/") or "/"
    if (
        normalized_agent_mount == normalized_evidence_mount
        or normalized_evidence_mount.startswith(f"{normalized_agent_mount}/")
        or normalized_agent_mount.startswith(f"{normalized_evidence_mount}/")
    ):
        raise ContainedWorkspaceError("evidence mount must be outside the agent workspace")
    _normalize_writable_paths(agent_visible_writable_paths)


def _normalize_writable_paths(
    agent_visible_writable_paths: Iterable[str],
) -> tuple[str, ...]:
    normalized_paths: list[str] = []
    for relative_path in agent_visible_writable_paths:
        _validate_relative_path(relative_path, allow_dot=True)
        normalized = relative_path.strip("/")
        if normalized == ".":
            normalized = "."
        _reject_reserved_path(normalized)
        normalized_paths.append(normalized)

    unique_paths = set(normalized_paths)
    if len(unique_paths) != len(normalized_paths):
        raise ContainedWorkspaceError("agent writable paths must be unique")
    if "." in unique_paths and len(unique_paths) > 1:
        raise ContainedWorkspaceError(
            "agent writable root must be the only writable path"
        )
    sorted_paths = tuple(sorted(unique_paths))
    for index, path in enumerate(sorted_paths):
        for other in sorted_paths[index + 1 :]:
            if other.startswith(f"{path}/"):
                raise ContainedWorkspaceError(
                    "agent writable paths must not overlap"
                )
    return sorted_paths


def _baseline_snapshot(
    source_root: Path,
    limits: ContainedWorkspaceLimits,
) -> ContainedBaselineSnapshot:
    source_kind, git_head, git_status = _git_baseline(source_root)
    files = tuple(_scan_tree(source_root, limits))
    digest = _baseline_digest(source_kind, git_head, git_status, files)
    return ContainedBaselineSnapshot(
        source_kind=source_kind,
        git_head=git_head,
        git_status=git_status,
        files=files,
        digest=digest,
    )


def _git_baseline(
    source_root: Path,
) -> tuple[str, Optional[str], tuple[ContainedGitStatusEntry, ...]]:
    if not _is_git_work_tree(source_root):
        return "directory", None, ()
    git_head = _git_output(source_root, "rev-parse", "--verify", "HEAD")
    source_kind = "git" if git_head is not None else "git-empty"
    status_output = _git_output(
        source_root,
        "status",
        "--porcelain=v1",
        "-z",
        "--ignored",
        "--untracked-files=all",
    )
    return source_kind, git_head, _parse_porcelain_status(status_output or "")


def _is_git_work_tree(source_root: Path) -> bool:
    result = _run_git(source_root, "rev-parse", "--is-inside-work-tree")
    return result is not None and result.returncode == 0 and result.stdout.strip() == "true"


def _git_output(source_root: Path, *args: str) -> Optional[str]:
    result = _run_git(source_root, *args)
    if result is None or result.returncode != 0:
        return None
    return result.stdout.strip()


def _run_git(source_root: Path, *args: str) -> Optional[subprocess.CompletedProcess[str]]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        return subprocess.run(
            ["git", *args],
            cwd=source_root,
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
    except (FileNotFoundError, OSError):
        return None


def _parse_porcelain_status(output: str) -> tuple[ContainedGitStatusEntry, ...]:
    entries: list[ContainedGitStatusEntry] = []
    fields = [field for field in output.split("\0") if field]
    index = 0
    while index < len(fields):
        field = fields[index]
        index += 1
        if len(field) < 4:
            continue
        status_code = field[:2]
        path_offset = 3 if len(field) > 2 and field[2] == " " else 2
        path = _normalize_git_path(field[path_offset:])
        source_path = None
        if status_code[0] in {"R", "C"} or status_code[1] in {"R", "C"}:
            if index < len(fields):
                source_path = _normalize_git_path(fields[index])
                index += 1
        entries.append(
            ContainedGitStatusEntry(
                status=status_code,
                path=path,
                source_path=source_path,
            )
        )
    return tuple(sorted(entries, key=lambda item: (item.path, item.status, item.source_path or "")))


def _normalize_git_path(path: str) -> str:
    return path.replace("\\", "/").strip("/")


def _scan_tree(
    source_root: Path,
    limits: ContainedWorkspaceLimits,
    *,
    reject_git_control: bool = False,
) -> list[ContainedPathSnapshot]:
    snapshots: list[ContainedPathSnapshot] = []
    entries_seen = 0
    total_bytes = 0
    for relative_path, source_path, info in _walk_source(
        source_root,
        reject_git_control=reject_git_control,
    ):
        entries_seen += 1
        if entries_seen > limits.max_entries:
            raise ContainedWorkspaceError("contained workspace entry limit exceeded")
        _validate_source_entry(source_root, relative_path, source_path, info, limits)
        if stat.S_ISREG(info.st_mode):
            size = info.st_size
            if size > limits.max_file_bytes:
                raise ContainedWorkspaceError("contained workspace file is too large")
            total_bytes += size
            if total_bytes > limits.max_total_bytes:
                raise ContainedWorkspaceError("contained workspace total size limit exceeded")
            snapshots.append(
                ContainedPathSnapshot(
                    path=relative_path,
                    kind="file",
                    size=size,
                    sha256=_hash_regular_file(source_path, info),
                    mode=stat.S_IMODE(info.st_mode),
                )
            )
        elif stat.S_ISLNK(info.st_mode):
            target = _read_validated_symlink(source_path, info)
            if len(target.encode("utf-8")) > limits.max_symlink_target_bytes:
                raise ContainedWorkspaceError(
                    "contained workspace symlink target is too large"
                )
            snapshots.append(
                ContainedPathSnapshot(
                    path=relative_path,
                    kind="symlink",
                    size=len(target.encode("utf-8")),
                    sha256=hashlib.sha256(target.encode("utf-8")).hexdigest(),
                    mode=stat.S_IMODE(info.st_mode),
                )
            )
    return sorted(snapshots, key=lambda item: item.path)


def _snapshot_identity(
    snapshot: ContainedPathSnapshot,
) -> tuple[str, int, Optional[str], int]:
    return snapshot.kind, snapshot.size, snapshot.sha256, snapshot.mode


def _detect_renames(
    deleted: list[ContainedPathSnapshot],
    added: list[ContainedPathSnapshot],
) -> list[tuple[str, str]]:
    added_by_identity: dict[tuple[str, int, Optional[str], int], list[ContainedPathSnapshot]] = {}
    for entry in sorted(added, key=lambda item: item.path):
        added_by_identity.setdefault(_snapshot_identity(entry), []).append(entry)

    renames: list[tuple[str, str]] = []
    for old_entry in sorted(deleted, key=lambda item: item.path):
        candidates = added_by_identity.get(_snapshot_identity(old_entry), [])
        if len(candidates) != 1:
            continue
        new_entry = candidates.pop(0)
        renames.append((old_entry.path, new_entry.path))
    return sorted(renames)


def _copy_validated_tree(
    source_root: Path,
    workspace_dir: Path,
    limits: ContainedWorkspaceLimits,
) -> None:
    entries_seen = 0
    total_bytes = 0
    for relative_path, source_path, info in _walk_source(source_root):
        entries_seen += 1
        if entries_seen > limits.max_entries:
            raise ContainedWorkspaceError("contained workspace entry limit exceeded")
        _validate_source_entry(source_root, relative_path, source_path, info, limits)
        destination = _destination_for(workspace_dir, relative_path)
        if stat.S_ISDIR(info.st_mode):
            _require_current_entry(source_path, info, expected_kind="directory")
            destination.mkdir(parents=True, exist_ok=True)
        elif stat.S_ISLNK(info.st_mode):
            target = _read_validated_symlink(
                source_path,
                info,
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(target, destination)
        elif stat.S_ISREG(info.st_mode):
            if info.st_size > limits.max_file_bytes:
                raise ContainedWorkspaceError("contained workspace file is too large")
            total_bytes += info.st_size
            if total_bytes > limits.max_total_bytes:
                raise ContainedWorkspaceError("contained workspace total size limit exceeded")
            destination.parent.mkdir(parents=True, exist_ok=True)
            _copy_regular_file(source_path, destination, info)
        else:
            raise ContainedWorkspaceError(
                "contained workspace contains unsupported file type"
            )


def _walk_source(
    source_root: Path,
    *,
    reject_git_control: bool = False,
) -> Iterator[tuple[str, Path, os.stat_result]]:
    for current, directory_names, file_names in os.walk(
        source_root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current)
        if reject_git_control and any(
            name.casefold() == ".git" for name in (*directory_names, *file_names)
        ):
            raise ContainedWorkspaceError("contained workspace contains reserved path")
        directory_names[:] = sorted(
            name
            for name in directory_names
            if reject_git_control or name.casefold() != ".git"
        )
        visible_files = sorted(
            name
            for name in file_names
            if reject_git_control or name.casefold() != ".git"
        )
        entries = sorted(directory_names) + visible_files
        for name in entries:
            source_path = current_path / name
            relative_path = _relative_to_root(source_root, source_path)
            info = source_path.lstat()
            yield relative_path, source_path, info


def _validate_source_entry(
    source_root: Path,
    relative_path: str,
    source_path: Path,
    info: os.stat_result,
    limits: ContainedWorkspaceLimits,
) -> None:
    _validate_relative_path(relative_path)
    _reject_reserved_path(relative_path)
    if len(relative_path.encode("utf-8")) > 4096:
        raise ContainedWorkspaceError("contained workspace path is too long")
    if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
        raise ContainedWorkspaceError("contained workspace contains unsafe hardlink")
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(source_path)
        if Path(target).is_absolute():
            raise ContainedWorkspaceError(
                "contained workspace contains escaping symlink"
            )
        if len(target.encode("utf-8")) > limits.max_symlink_target_bytes:
            raise ContainedWorkspaceError(
                "contained workspace symlink target is too large"
            )
        try:
            resolved = source_path.resolve(strict=True)
            relative_target = resolved.relative_to(source_root)
        except (OSError, RuntimeError, ValueError) as error:
            raise ContainedWorkspaceError(
                "contained workspace contains invalid symlink"
            ) from error
        if any(part.casefold() == ".git" for part in relative_target.parts):
            raise ContainedWorkspaceError(
                "contained workspace contains symlink to Git control metadata"
            )
    elif not (
        stat.S_ISDIR(info.st_mode)
        or stat.S_ISREG(info.st_mode)
    ):
        raise ContainedWorkspaceError(
            "contained workspace contains unsupported file type"
        )


def _require_current_entry(
    source_path: Path,
    expected: os.stat_result,
    *,
    expected_kind: str,
) -> _ValidatedSourceEntry:
    try:
        current = source_path.lstat()
    except OSError as error:
        raise ContainedWorkspaceError(
            "contained workspace source changed during preparation"
        ) from error
    if not _same_entry(expected, current) or _entry_kind(current) != expected_kind:
        raise ContainedWorkspaceError(
            "contained workspace source changed during preparation"
        )
    return _ValidatedSourceEntry(path=source_path, info=current)


def _copy_regular_file(
    source_path: Path,
    destination: Path,
    expected: os.stat_result,
) -> None:
    descriptor = _open_validated_regular_file(source_path, expected)
    try:
        with os.fdopen(descriptor, "rb") as source_handle:
            descriptor = -1
            with destination.open("xb") as destination_handle:
                shutil.copyfileobj(source_handle, destination_handle, length=1024 * 1024)
        os.chmod(destination, stat.S_IMODE(expected.st_mode))
        os.utime(destination, ns=(expected.st_atime_ns, expected.st_mtime_ns))
    except Exception:
        try:
            if destination.exists() or destination.is_symlink():
                destination.unlink()
        except OSError:
            pass
        raise
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _hash_regular_file(
    source_path: Path,
    expected: os.stat_result,
) -> str:
    descriptor = _open_validated_regular_file(source_path, expected)
    digest = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    return digest.hexdigest()


def _read_validated_symlink(
    source_path: Path,
    expected: os.stat_result,
) -> str:
    _require_current_entry(source_path, expected, expected_kind="symlink")
    try:
        target = os.readlink(source_path)
    except OSError as error:
        raise ContainedWorkspaceError(
            "contained workspace source changed during preparation"
        ) from error
    current = _require_current_entry(source_path, expected, expected_kind="symlink")
    if current.info.st_size != len(target.encode("utf-8")):
        raise ContainedWorkspaceError(
            "contained workspace source changed during preparation"
        )
    return target


def _open_validated_regular_file(
    source_path: Path,
    expected: os.stat_result,
) -> int:
    current = _require_current_entry(
        source_path,
        expected,
        expected_kind="file",
    ).info
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source_path, flags)
    except OSError as error:
        raise ContainedWorkspaceError(
            "contained workspace source changed during preparation"
        ) from error
    try:
        opened = os.fstat(descriptor)
        if (
            not _same_entry(current, opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
        ):
            raise ContainedWorkspaceError(
                "contained workspace source changed during preparation"
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _same_entry(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode)
        and left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
        and left.st_nlink == right.st_nlink
    )


def _entry_kind(info: os.stat_result) -> str:
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    return "other"


def _validate_relative_path(relative_path: str, *, allow_dot: bool = False) -> None:
    if relative_path == "." and allow_dot:
        return
    parts = relative_path.split("/")
    if (
        not relative_path
        or relative_path.startswith("/")
        or "\\" in relative_path
        or "\0" in relative_path
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ContainedWorkspaceError("contained workspace path must be normalized")


def _reject_reserved_path(relative_path: str) -> None:
    parts = relative_path.split("/")
    lowered_parts = [part.casefold() for part in parts]
    for reserved in RESERVED_PATHS:
        reserved_lower = reserved.casefold()
        if reserved_lower in lowered_parts:
            raise ContainedWorkspaceError("contained workspace contains reserved path")
    for part in lowered_parts:
        for reserved in RESERVED_PATHS:
            reserved_lower = reserved.casefold()
            if part != reserved_lower and (
                part.startswith(f"{reserved_lower}.")
                or part.startswith(f"{reserved_lower}-")
                or part.startswith(f"{reserved_lower}_")
            ):
                raise ContainedWorkspaceError(
                    "contained workspace contains reserved path prefix collision"
                )


def _relative_to_root(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _destination_for(workspace_dir: Path, relative_path: str) -> Path:
    destination = workspace_dir / relative_path
    try:
        destination.resolve(strict=False).relative_to(workspace_dir.resolve())
    except ValueError as error:
        raise ContainedWorkspaceError("contained workspace destination escapes root") from error
    return destination


def _baseline_digest(
    source_kind: str,
    git_head: Optional[str],
    git_status: tuple[ContainedGitStatusEntry, ...],
    files: tuple[ContainedPathSnapshot, ...],
) -> str:
    payload = _stable_value(
        {
            "source_kind": source_kind,
            "git_head": git_head,
            "git_status": [asdict(item) for item in git_status],
            "files": [asdict(item) for item in files],
        }
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_metadata(path: Path, metadata: ContainedWorkspaceMetadata) -> None:
    path.write_text(
        json.dumps(metadata.to_dict(), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _rollback_staging(staging_dir: Path) -> None:
    if not staging_dir.exists() and not staging_dir.is_symlink():
        return
    try:
        shutil.rmtree(staging_dir)
    except OSError as cleanup_error:
        raise RuntimeError(
            "Contained workspace preparation failed and cleanup was incomplete; "
            "partial lifecycle-owned artifacts remain."
        ) from cleanup_error


def _stable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _stable_value(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_stable_value(item) for item in value]
    if isinstance(value, list):
        return [_stable_value(item) for item in value]
    return value
