from __future__ import annotations

import hashlib
import codecs
import json
import os
import shutil
import stat
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from uuid import uuid4

from agentguard.artifact_paths import artifact_directory, validate_artifact_id
from agentguard.redaction import redact_credentials


CONTAINED_WORKSPACE_SCHEMA_VERSION = 1
CONTAINED_RUN_ARTIFACT_SCHEMA = "agentguard.contained-run-artifact"
CONTAINED_RUN_ARTIFACT_SCHEMA_VERSION = 1
CONTAINED_RUN_ARTIFACT_MARKER = "agentguard-contained-run-artifact.json"
CONTAINED_BASELINE_TEXT_MAX_BYTES = 8 * 1024 * 1024
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
class _SourceExclusions:
    roots: frozenset[str]


@dataclass(frozen=True)
class ContainedPathSnapshot:
    path: str
    kind: str
    size: int
    sha256: Optional[str]
    mode: int
    line_count: Optional[int] = None
    line_count_complete: bool = True
    content_kind: str = "not_applicable"


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
    baseline_files: tuple[ContainedPathSnapshot, ...] = ()
    current_files: tuple[ContainedPathSnapshot, ...] = ()
    baseline_text_files: dict[str, tuple[bytes, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )

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
    baseline_text_files: dict[str, tuple[bytes, ...]] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )

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
    agentguard_owned_artifact_roots: Iterable[Path] = (),
    agentguard_current_artifact_roots: Iterable[Path] = (),
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
    exclusions = _source_exclusions(
        source_root,
        agentguard_owned_artifact_roots,
        current_artifact_roots=agentguard_current_artifact_roots,
    )
    baseline = _baseline_snapshot(source_root, limits, exclusions=exclusions)
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
        _copy_validated_tree(source_root, workspace_dir, limits, exclusions=exclusions)
        baseline_text_files = _collect_baseline_text_files(
            workspace_dir,
            baseline.files,
            limits,
        )
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
        baseline_text_files=baseline_text_files,
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
        baseline_files=prepared.metadata.baseline.files,
        current_files=current_files,
        baseline_text_files=dict(prepared.baseline_text_files),
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
    *,
    exclusions: _SourceExclusions = _SourceExclusions(frozenset()),
) -> ContainedBaselineSnapshot:
    source_kind, git_head, git_status = _git_baseline(
        source_root,
        exclusions=exclusions,
    )
    files = tuple(_scan_tree(source_root, limits, exclusions=exclusions))
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
    *,
    exclusions: _SourceExclusions = _SourceExclusions(frozenset()),
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
    git_status = _parse_porcelain_status(status_output or "")
    if exclusions.roots:
        git_status = tuple(
            entry
            for entry in git_status
            if not _status_entry_excluded(source_root, entry, exclusions)
        )
    return source_kind, git_head, git_status


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


def _source_exclusions(
    source_root: Path,
    owned_artifact_roots: Iterable[Path],
    *,
    current_artifact_roots: Iterable[Path] = (),
) -> _SourceExclusions:
    roots: set[str] = set()
    for artifact_root in current_artifact_roots:
        relative_path = _relative_artifact_root(source_root, artifact_root)
        if relative_path is not None:
            roots.add(relative_path)
    for artifact_root in owned_artifact_roots:
        relative_path = _relative_artifact_root(source_root, artifact_root)
        if relative_path is None:
            continue
        try:
            resolved = artifact_root.expanduser().resolve()
        except (OSError, RuntimeError):
            continue
        if not _is_valid_owned_contained_run_artifact(resolved):
            continue
        roots.add(relative_path)
    return _SourceExclusions(frozenset(sorted(roots)))


def _relative_artifact_root(source_root: Path, artifact_root: Path) -> Optional[str]:
    try:
        resolved = artifact_root.expanduser().resolve(strict=False)
        relative = resolved.relative_to(source_root)
    except (OSError, RuntimeError, ValueError):
        return None
    relative_path = relative.as_posix().strip("/")
    if not relative_path or relative_path == ".":
        return None
    try:
        _validate_relative_path(relative_path)
    except ContainedWorkspaceError:
        return None
    return relative_path


def _read_bounded_json_file(path: Path, *, max_bytes: int) -> Optional[dict[str, Any]]:
    try:
        info = path.lstat()
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_nlink != 1
        or info.st_size > max_bytes
    ):
        return None
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if not _same_entry(info, opened) or not stat.S_ISREG(opened.st_mode):
            return None
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(max_bytes + 1)
    except (OSError, ValueError):
        return None
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(data) > max_bytes:
        return None
    try:
        decoded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _has_contained_run_evidence(artifact_root: Path) -> bool:
    report = _read_bounded_json_file(artifact_root / "contained-run.json", max_bytes=2 * 1024 * 1024)
    if (
        report is not None
        and report.get("schema") == "agentguard.contained-run"
        and report.get("schema_version") == 1
        and isinstance(report.get("task_id"), str)
        and isinstance(report.get("containment_evidence"), dict)
    ):
        return True
    metadata = _read_bounded_json_file(
        artifact_root
        / "workspace-lifecycle"
        / "agent-workspace"
        / "evidence"
        / "workspace-metadata.json",
        max_bytes=1024 * 1024,
    )
    return (
        metadata is not None
        and metadata.get("schema_version") == CONTAINED_WORKSPACE_SCHEMA_VERSION
        and metadata.get("workspace_id") == "agent-workspace"
        and isinstance(metadata.get("baseline"), dict)
        and metadata.get("agentguard_evidence") == "evidence"
    )


def _is_valid_owned_contained_run_artifact(artifact_root: Path) -> bool:
    try:
        root_info = artifact_root.lstat()
    except OSError:
        return False
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or stat.S_ISLNK(root_info.st_mode)
    ):
        return False
    if not _artifact_root_has_only_known_entries(artifact_root):
        return False
    marker_data = _read_bounded_json_file(
        artifact_root / CONTAINED_RUN_ARTIFACT_MARKER,
        max_bytes=8192,
    )
    if marker_data is None:
        return False
    run_id = marker_data.get("run_id")
    lifecycle_state = marker_data.get("lifecycle_state")
    if not isinstance(run_id, str) or run_id != artifact_root.name:
        return False
    try:
        validate_artifact_id(run_id, "run_id")
    except ValueError:
        return False
    return (
        marker_data.get("schema") == CONTAINED_RUN_ARTIFACT_SCHEMA
        and marker_data.get("schema_version") == CONTAINED_RUN_ARTIFACT_SCHEMA_VERSION
        and marker_data.get("owner") == "agentguard"
        and marker_data.get("artifact_kind") == "contained-run"
        and lifecycle_state in {"created", "complete", "retained", "failed"}
        and _has_contained_run_evidence(artifact_root)
    )


def _artifact_root_has_only_known_entries(artifact_root: Path) -> bool:
    allowed = {
        CONTAINED_RUN_ARTIFACT_MARKER,
        "contained-run.json",
        "workspace-lifecycle",
    }
    try:
        children = list(artifact_root.iterdir())
    except OSError:
        return False
    return all(child.name in allowed for child in children)


def _relative_path_excluded(
    relative_path: str,
    exclusions: _SourceExclusions,
) -> bool:
    return any(
        relative_path == root or relative_path.startswith(f"{root}/")
        for root in exclusions.roots
    )


def _relative_path_is_exclusion_container(
    relative_path: str,
    exclusions: _SourceExclusions,
) -> bool:
    return any(root.startswith(f"{relative_path}/") for root in exclusions.roots)


def _source_path_excluded(
    source_root: Path,
    source_path: Path,
    exclusions: _SourceExclusions,
) -> bool:
    if not exclusions.roots:
        return False
    try:
        relative_path = _relative_to_root(source_root, source_path)
    except ValueError:
        return False
    if _relative_path_excluded(relative_path, exclusions):
        return True
    if not _relative_path_is_exclusion_container(relative_path, exclusions):
        return False
    return _directory_contains_only_exclusions(
        source_root,
        source_path,
        relative_path,
        exclusions,
        budget=[1024],
    )


def _directory_contains_only_exclusions(
    source_root: Path,
    directory: Path,
    relative_path: str,
    exclusions: _SourceExclusions,
    *,
    budget: list[int],
) -> bool:
    try:
        directory_info = directory.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(directory_info.st_mode):
        return False
    try:
        with os.scandir(directory) as entries:
            children = sorted(entries, key=lambda entry: entry.name)
    except OSError:
        return False
    for child in children:
        budget[0] -= 1
        if budget[0] < 0:
            return False
        child_relative = f"{relative_path}/{child.name}"
        if _relative_path_excluded(child_relative, exclusions):
            continue
        if not _relative_path_is_exclusion_container(child_relative, exclusions):
            return False
        if not _directory_contains_only_exclusions(
            source_root,
            Path(child.path),
            child_relative,
            exclusions,
            budget=budget,
        ):
            return False
    return True


def _status_entry_excluded(
    source_root: Path,
    entry: ContainedGitStatusEntry,
    exclusions: _SourceExclusions,
) -> bool:
    paths = [entry.path]
    if entry.source_path is not None:
        paths.append(entry.source_path)
    return all(_status_path_excluded(source_root, path, exclusions) for path in paths)


def _status_path_excluded(
    source_root: Path,
    path: str,
    exclusions: _SourceExclusions,
) -> bool:
    if _relative_path_excluded(path, exclusions):
        return True
    if not _relative_path_is_exclusion_container(path, exclusions):
        return False
    return _directory_contains_only_exclusions(
        source_root,
        source_root / path,
        path,
        exclusions,
        budget=[1024],
    )


def _scan_tree(
    source_root: Path,
    limits: ContainedWorkspaceLimits,
    *,
    reject_git_control: bool = False,
    exclusions: _SourceExclusions = _SourceExclusions(frozenset()),
) -> list[ContainedPathSnapshot]:
    snapshots: list[ContainedPathSnapshot] = []
    entries_seen = 0
    total_bytes = 0
    for relative_path, source_path, info in _walk_source(
        source_root,
        reject_git_control=reject_git_control,
        exclusions=exclusions,
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
            digest = _hash_regular_file(source_path, info)
            line_count, line_complete, content_kind = _measure_file(source_path, info)
            snapshots.append(
                ContainedPathSnapshot(
                    path=relative_path,
                    kind="file",
                    size=size,
                    sha256=digest,
                    mode=stat.S_IMODE(info.st_mode),
                    line_count=line_count,
                    line_count_complete=line_complete,
                    content_kind=content_kind,
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
                    content_kind="symlink",
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
    *,
    exclusions: _SourceExclusions = _SourceExclusions(frozenset()),
) -> None:
    entries_seen = 0
    total_bytes = 0
    for relative_path, source_path, info in _walk_source(
        source_root,
        exclusions=exclusions,
    ):
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
    exclusions: _SourceExclusions = _SourceExclusions(frozenset()),
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
        directory_names[:] = [
            name
            for name in directory_names
            if not _source_path_excluded(
                source_root,
                current_path / name,
                exclusions,
            )
        ]
        visible_files = sorted(
            name
            for name in file_names
            if reject_git_control or name.casefold() != ".git"
        )
        visible_files = [
            name
            for name in visible_files
            if not _source_path_excluded(
                source_root,
                current_path / name,
                exclusions,
            )
        ]
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


def _measure_file(
    source_path: Path,
    expected: os.stat_result,
) -> tuple[Optional[int], bool, str]:
    descriptor = _open_validated_regular_file(source_path, expected)
    decoder = codecs.getincrementaldecoder("utf-8")()
    newline_count = 0
    saw_bytes = False
    last_byte = b""
    binary = False
    text_decodable = True
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                if chunk:
                    saw_bytes = True
                    last_byte = chunk[-1:]
                    newline_count += chunk.count(b"\n")
                    if b"\0" in chunk:
                        binary = True
                    if text_decodable:
                        try:
                            decoder.decode(chunk)
                        except UnicodeDecodeError:
                            text_decodable = False
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if text_decodable:
        try:
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            text_decodable = False
    if binary:
        return None, False, "binary"
    if not text_decodable:
        return None, False, "non_utf8"
    line_count = newline_count + (1 if saw_bytes and last_byte != b"\n" else 0)
    return line_count, True, "text"


def _collect_baseline_text_files(
    workspace_dir: Path,
    files: tuple[ContainedPathSnapshot, ...],
    limits: ContainedWorkspaceLimits,
) -> dict[str, tuple[bytes, ...]]:
    collected: dict[str, tuple[bytes, ...]] = {}
    total_bytes = 0
    for snapshot in files:
        if snapshot.kind != "file" or snapshot.content_kind != "text":
            continue
        if not snapshot.line_count_complete:
            continue
        total_bytes += snapshot.size
        if total_bytes > min(limits.max_total_bytes, CONTAINED_BASELINE_TEXT_MAX_BYTES):
            break
        path = _destination_for(workspace_dir, snapshot.path)
        try:
            content = path.read_bytes()
        except OSError:
            continue
        if len(content) != snapshot.size or b"\0" in content:
            continue
        collected[snapshot.path] = tuple(content.splitlines(keepends=True))
    return collected


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
