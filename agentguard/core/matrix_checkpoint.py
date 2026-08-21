from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4

from agentguard.config.schema import AgentGuardConfig
from agentguard.history.store import HistoryRecord, list_history, record_history
from agentguard.guard.filesystem import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    GuardMode,
)
from agentguard.provenance.manifest import (
    policy_identity,
    sha256_file,
    verify_manifest,
)

if TYPE_CHECKING:
    from agentguard.core.matrix import MatrixRowSummary


CHECKPOINT_SCHEMA = "agentguard.matrix-checkpoint"
CHECKPOINT_SCHEMA_VERSION = 1
CHECKPOINT_STATUSES = {"running", "interrupted", "completed"}
ATTEMPT_STATUSES = {"pending", "running", "completed"}


@dataclass(frozen=True)
class MatrixCheckpointAttempt:
    key: str
    ordinal: int
    task_id: str
    config_path: str
    config_sha256: str
    benchmark_id: Optional[str]
    benchmark_version: Optional[int]
    agent: str
    profile_id: Optional[str]
    profile_model: Optional[str]
    task_prompt_sha256: Optional[str]
    trial_index: int
    trial_count: int
    status: str = "pending"
    result: Optional[str] = None
    score: Optional[int] = None
    failed_checks: list[str] = field(default_factory=list)
    warning_checks: list[str] = field(default_factory=list)
    run_id: Optional[str] = None
    run_dir: Optional[str] = None
    json_report_path: Optional[str] = None
    markdown_report_path: Optional[str] = None
    manifest_path: Optional[str] = None
    json_report_sha256: Optional[str] = None
    markdown_report_sha256: Optional[str] = None
    manifest_sha256: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    error: Optional[str] = None
    functional_passed: bool = False
    category: Optional[str] = None
    difficulty: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    task_prompt_source: Optional[str] = None
    guard_violations_total: int = 0
    guard_blocked: bool = False
    filesystem_guard_violations: int = 0
    command_guard_violations: int = 0
    time_to_first_violation_ms: Optional[int] = None
    time_to_block_ms: Optional[int] = None
    guard_incident_json_path: Optional[str] = None
    guard_incident_markdown_path: Optional[str] = None
    blocking_guard: Optional[str] = None


@dataclass(frozen=True)
class MatrixCheckpoint:
    checkpoint_id: str
    created_at: str
    updated_at: str
    status: str
    matrix_id: str
    suite_id: str
    suite_path: str
    suite_sha256: str
    filters: dict[str, object]
    agents: list[str]
    trials: int
    requested_workers: int
    effective_workers: int
    fail_fast: bool
    benchmarks: list[dict[str, object]]
    profile_identity: dict[str, object]
    execution_compatibility: dict[str, object]
    attempts_planned: int
    attempts: list[MatrixCheckpointAttempt]
    matrix_json_report_path: str
    matrix_markdown_report_path: str
    matrix_manifest_path: str
    resumed_from: Optional[str] = None
    compatibility_warnings: list[str] = field(default_factory=list)
    schema: str = CHECKPOINT_SCHEMA
    schema_version: int = CHECKPOINT_SCHEMA_VERSION
    guard_mode: str = GuardMode.OFF.value
    guard_poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS


@dataclass(frozen=True)
class AttemptVerification:
    classification: str
    messages: list[str]
    row: Optional[MatrixRowSummary] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def checkpoint_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"matrix-checkpoint-{stamp}-{uuid4().hex[:8]}"


def stable_attempt_key(
    *,
    suite_sha256: str,
    config: AgentGuardConfig,
    config_sha256: str,
    agent: str,
    profile_id: Optional[str],
    profile_model: Optional[str],
    profile_identity: dict[str, object],
    task_prompt_sha256: Optional[str],
    trial_index: int,
) -> str:
    payload = {
        "suite_sha256": suite_sha256,
        "config_path": str(config.config_path.expanduser().resolve()),
        "config_sha256": config_sha256,
        "task_id": config.task_id,
        "benchmark_id": config.benchmark.id,
        "benchmark_version": config.benchmark.version,
        "agent": agent,
        "profile_id": profile_id,
        "profile_model": profile_model,
        "profile_identity": profile_identity,
        "task_prompt_sha256": task_prompt_sha256,
        "trial_index": trial_index,
        "policy": asdict(policy_identity(config)),
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def atomic_write_checkpoint(checkpoint: MatrixCheckpoint, path: Path) -> Path:
    output = path.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        asdict(checkpoint),
        indent=2,
        sort_keys=True,
    ) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, output)
        try:
            directory_descriptor = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            pass
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return output


def _nonnegative_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _nonnegative_optional_int(value: object) -> Optional[int]:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _attempt_from_dict(data: dict[str, Any], index: int) -> MatrixCheckpointAttempt:
    try:
        attempt = MatrixCheckpointAttempt(
            key=str(data["key"]),
            ordinal=int(data["ordinal"]),
            task_id=str(data["task_id"]),
            config_path=str(data["config_path"]),
            config_sha256=str(data["config_sha256"]),
            benchmark_id=(
                str(data["benchmark_id"])
                if data.get("benchmark_id") is not None
                else None
            ),
            benchmark_version=(
                int(data["benchmark_version"])
                if data.get("benchmark_version") is not None
                else None
            ),
            agent=str(data["agent"]),
            profile_id=(
                str(data["profile_id"])
                if data.get("profile_id") is not None
                else None
            ),
            profile_model=(
                str(data["profile_model"])
                if data.get("profile_model") is not None
                else None
            ),
            task_prompt_sha256=(
                str(data["task_prompt_sha256"])
                if data.get("task_prompt_sha256") is not None
                else None
            ),
            trial_index=int(data["trial_index"]),
            trial_count=int(data["trial_count"]),
            status=str(data.get("status", "pending")),
            result=data.get("result"),
            score=int(data["score"]) if data.get("score") is not None else None,
            failed_checks=list(data.get("failed_checks", [])),
            warning_checks=list(data.get("warning_checks", [])),
            run_id=data.get("run_id"),
            run_dir=data.get("run_dir"),
            json_report_path=data.get("json_report_path"),
            markdown_report_path=data.get("markdown_report_path"),
            manifest_path=data.get("manifest_path"),
            json_report_sha256=data.get("json_report_sha256"),
            markdown_report_sha256=data.get("markdown_report_sha256"),
            manifest_sha256=data.get("manifest_sha256"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            error=data.get("error"),
            functional_passed=bool(data.get("functional_passed", False)),
            category=data.get("category"),
            difficulty=data.get("difficulty"),
            tags=list(data.get("tags", [])),
            task_prompt_source=data.get("task_prompt_source"),
            guard_violations_total=_nonnegative_int(
                data.get("guard_violations_total")
            ),
            guard_blocked=bool(data.get("guard_blocked", False)),
            filesystem_guard_violations=_nonnegative_int(
                data.get("filesystem_guard_violations")
            ),
            command_guard_violations=_nonnegative_int(
                data.get("command_guard_violations")
            ),
            time_to_first_violation_ms=_nonnegative_optional_int(
                data.get("time_to_first_violation_ms")
            ),
            time_to_block_ms=_nonnegative_optional_int(
                data.get("time_to_block_ms")
            ),
            guard_incident_json_path=data.get("guard_incident_json_path"),
            guard_incident_markdown_path=data.get(
                "guard_incident_markdown_path"
            ),
            blocking_guard=(
                data.get("blocking_guard")
                if data.get("blocking_guard") in {"filesystem", "command"}
                else None
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"Invalid checkpoint attempt at index {index}.") from error
    if attempt.status not in ATTEMPT_STATUSES:
        raise ValueError(f"Invalid checkpoint attempt status at index {index}.")
    if attempt.ordinal != index:
        raise ValueError("Checkpoint attempt ordinals must be contiguous and ordered.")
    return attempt


def load_checkpoint(path: Path) -> MatrixCheckpoint:
    checkpoint_path = path.expanduser().resolve()
    try:
        data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"Could not read matrix checkpoint: {checkpoint_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError("Matrix checkpoint is not valid JSON.") from error
    if not isinstance(data, dict):
        raise ValueError("Matrix checkpoint root must be an object.")
    if data.get("schema") != CHECKPOINT_SCHEMA:
        raise ValueError(f"Matrix checkpoint schema must be '{CHECKPOINT_SCHEMA}'.")
    if data.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise ValueError("Matrix checkpoint schema_version must be 1.")
    attempts_data = data.get("attempts")
    if not isinstance(attempts_data, list):
        raise ValueError("Matrix checkpoint attempts must be a list.")
    try:
        checkpoint = MatrixCheckpoint(
            checkpoint_id=str(data["checkpoint_id"]),
            created_at=str(data["created_at"]),
            updated_at=str(data["updated_at"]),
            status=str(data["status"]),
            matrix_id=str(data["matrix_id"]),
            suite_id=str(data["suite_id"]),
            suite_path=str(data["suite_path"]),
            suite_sha256=str(data["suite_sha256"]),
            filters=dict(data["filters"]),
            agents=list(data["agents"]),
            trials=int(data["trials"]),
            requested_workers=int(data["requested_workers"]),
            effective_workers=int(data["effective_workers"]),
            fail_fast=bool(data["fail_fast"]),
            benchmarks=list(data["benchmarks"]),
            profile_identity=dict(data.get("profile_identity", {})),
            execution_compatibility=dict(data["execution_compatibility"]),
            attempts_planned=int(data["attempts_planned"]),
            attempts=[
                _attempt_from_dict(item, index)
                for index, item in enumerate(attempts_data)
                if isinstance(item, dict)
            ],
            matrix_json_report_path=str(data["matrix_json_report_path"]),
            matrix_markdown_report_path=str(data["matrix_markdown_report_path"]),
            matrix_manifest_path=str(data["matrix_manifest_path"]),
            guard_mode=str(data.get("guard_mode", GuardMode.OFF.value)),
            guard_poll_interval_seconds=float(
                data.get(
                    "guard_poll_interval_seconds",
                    DEFAULT_POLL_INTERVAL_SECONDS,
                )
            ),
            resumed_from=data.get("resumed_from"),
            compatibility_warnings=list(data.get("compatibility_warnings", [])),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Invalid matrix checkpoint structure.") from error
    if checkpoint.status not in CHECKPOINT_STATUSES:
        raise ValueError("Invalid matrix checkpoint status.")
    if len(checkpoint.attempts) != checkpoint.attempts_planned:
        raise ValueError("Checkpoint attempts_planned does not match attempt entries.")
    if len({attempt.key for attempt in checkpoint.attempts}) != len(
        checkpoint.attempts
    ):
        raise ValueError("Checkpoint attempt keys must be unique.")
    return checkpoint


class CheckpointStore:
    def __init__(
        self,
        path: Path,
        checkpoint: MatrixCheckpoint,
        checkpoint_every: int,
    ) -> None:
        if (
            isinstance(checkpoint_every, bool)
            or not isinstance(checkpoint_every, int)
            or checkpoint_every <= 0
        ):
            raise ValueError("checkpoint-every must be a positive integer.")
        self.path = path.expanduser().resolve()
        self.checkpoint = checkpoint
        self.checkpoint_every = checkpoint_every
        self._lock = threading.Lock()
        self._completions_since_write = 0

    def write(self) -> None:
        with self._lock:
            self._write_locked()

    def _write_locked(self) -> None:
        self.checkpoint = replace(self.checkpoint, updated_at=utc_now_iso())
        atomic_write_checkpoint(self.checkpoint, self.path)
        self._completions_since_write = 0

    def mark_running(self, ordinal: int) -> None:
        with self._lock:
            attempts = list(self.checkpoint.attempts)
            attempts[ordinal] = replace(
                attempts[ordinal],
                status="running",
                started_at=utc_now_iso(),
                completed_at=None,
                duration_seconds=0.0,
                error=None,
            )
            self.checkpoint = replace(
                self.checkpoint,
                status="running",
                attempts=attempts,
            )

    def mark_completed(
        self,
        ordinal: int,
        row: MatrixRowSummary,
        duration_seconds: float,
    ) -> None:
        json_path = row.json_report_path
        markdown_path = row.markdown_report_path
        manifest_path = row.manifest_path
        if json_path is not None and not json_path.is_file():
            raise ValueError("Completed attempt artifacts are missing.")
        if markdown_path is not None and not markdown_path.is_file():
            raise ValueError("Completed attempt Markdown report is missing.")
        if manifest_path is not None and not manifest_path.is_file():
            raise ValueError("Completed attempt manifest is missing.")
        with self._lock:
            attempts = list(self.checkpoint.attempts)
            attempts[ordinal] = replace(
                attempts[ordinal],
                status="completed",
                result=row.result,
                score=row.score,
                failed_checks=list(row.failed_checks),
                warning_checks=list(row.warning_checks),
                run_id=row.execution_id,
                run_dir=str(row.run_dir) if row.run_dir is not None else None,
                json_report_path=str(json_path),
                markdown_report_path=(
                    str(markdown_path) if markdown_path is not None else None
                ),
                manifest_path=str(manifest_path),
                json_report_sha256=(
                    sha256_file(json_path) if json_path is not None else None
                ),
                markdown_report_sha256=(
                    sha256_file(markdown_path)
                    if markdown_path is not None
                    else None
                ),
                manifest_sha256=(
                    sha256_file(manifest_path)
                    if manifest_path is not None
                    else None
                ),
                completed_at=utc_now_iso(),
                duration_seconds=round(max(duration_seconds, 0.0), 6),
                error=row.error,
                functional_passed=row.functional_passed,
                category=row.category,
                difficulty=row.difficulty,
                tags=list(row.tags),
                task_prompt_source=row.task_prompt_source,
                task_prompt_sha256=row.task_prompt_sha256,
                guard_violations_total=row.guard_violations_total,
                guard_blocked=row.guard_blocked,
                filesystem_guard_violations=row.filesystem_guard_violations,
                command_guard_violations=row.command_guard_violations,
                time_to_first_violation_ms=row.time_to_first_violation_ms,
                time_to_block_ms=row.time_to_block_ms,
                guard_incident_json_path=(
                    str(row.guard_incident_json_path)
                    if row.guard_incident_json_path is not None
                    else None
                ),
                guard_incident_markdown_path=(
                    str(row.guard_incident_markdown_path)
                    if row.guard_incident_markdown_path is not None
                    else None
                ),
                blocking_guard=row.blocking_guard,
            )
            self.checkpoint = replace(self.checkpoint, attempts=attempts)
            self._completions_since_write += 1
            if self._completions_since_write >= self.checkpoint_every:
                self._write_locked()

    def mark_interrupted(self) -> None:
        with self._lock:
            attempts = [
                replace(attempt, status="pending", started_at=None)
                if attempt.status == "running"
                else attempt
                for attempt in self.checkpoint.attempts
            ]
            self.checkpoint = replace(
                self.checkpoint,
                status="interrupted",
                attempts=attempts,
            )
            self._write_locked()

    def mark_completed_checkpoint(self) -> None:
        with self._lock:
            self.checkpoint = replace(self.checkpoint, status="completed")
            self._write_locked()


def _path_and_hash(
    path_value: Optional[str],
    expected_hash: Optional[str],
    label: str,
) -> tuple[Optional[Path], list[str]]:
    if not path_value or not expected_hash:
        return None, [f"Missing {label} path or hash."]
    path = Path(path_value).expanduser()
    if not path.is_file():
        return None, [f"Missing {label}: {path}"]
    try:
        actual = sha256_file(path)
    except OSError as error:
        return None, [f"Could not hash {label}: {error}"]
    if actual != expected_hash:
        return None, [f"Hash mismatch for {label}: {path}"]
    return path, []


def _row_from_report(
    attempt: MatrixCheckpointAttempt,
    report_path: Path,
) -> MatrixRowSummary:
    from agentguard.core.matrix import MatrixRowSummary
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Invalid attempt report: {error}") from error
    benchmark = data.get("benchmark", {})
    checks = data.get("check_results", [])
    if not isinstance(benchmark, dict) or not isinstance(checks, list):
        raise ValueError("Attempt report has invalid benchmark/check data.")
    failed_checks = [
        str(check["name"])
        for check in checks
        if isinstance(check, dict) and not bool(check.get("passed"))
    ]
    warning_checks = [
        str(check["name"])
        for check in checks
        if isinstance(check, dict)
        and not bool(check.get("passed"))
        and check.get("severity") == "warning"
    ]
    try:
        row = MatrixRowSummary(
            task_id=str(data["task_id"]),
            config_path=Path(str(data["config_path"])),
            agent=str(data["agent"]),
            result=str(data["result"]),
            score=int(data["score"]),
            failed_checks=failed_checks,
            warning_checks=warning_checks,
            json_report_path=report_path,
            markdown_report_path=(
                Path(attempt.markdown_report_path)
                if attempt.markdown_report_path
                else None
            ),
            run_dir=Path(str(data["run_dir"])),
            execution_id=data.get("execution_id"),
            manifest_path=(
                Path(attempt.manifest_path) if attempt.manifest_path else None
            ),
            benchmark_id=benchmark.get("id"),
            benchmark_version=benchmark.get("version"),
            category=benchmark.get("category"),
            difficulty=benchmark.get("difficulty"),
            tags=list(benchmark.get("tags", [])),
            error=attempt.error,
            trial_index=attempt.trial_index,
            trial_count=attempt.trial_count,
            functional_passed=int(data["test_result"]["exit_code"]) == 0,
            task_prompt_source=data.get("task_prompt_source"),
            task_prompt_sha256=data.get("task_prompt_sha256"),
            profile_id=data.get("profile_id"),
            guard_violations_total=attempt.guard_violations_total,
            guard_blocked=(
                attempt.guard_blocked and attempt.guard_violations_total > 0
            ),
            filesystem_guard_violations=attempt.filesystem_guard_violations,
            command_guard_violations=attempt.command_guard_violations,
            time_to_first_violation_ms=attempt.time_to_first_violation_ms,
            time_to_block_ms=attempt.time_to_block_ms,
            guard_incident_json_path=(
                Path(attempt.guard_incident_json_path)
                if attempt.guard_incident_json_path
                else None
            ),
            guard_incident_markdown_path=(
                Path(attempt.guard_incident_markdown_path)
                if attempt.guard_incident_markdown_path
                else None
            ),
            blocking_guard=attempt.blocking_guard,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Attempt report is missing required result fields.") from error
    return row


def _history_conflict(row: MatrixRowSummary, db_path: Path) -> Optional[str]:
    if row.execution_id is None or not db_path.exists():
        return None
    matches = [
        record
        for record in list_history(db_path, limit=None)
        if record.id == row.execution_id
    ]
    if len(matches) > 1:
        return f"Duplicate history identity for {row.execution_id}."
    if not matches:
        return None
    record = matches[0]
    expected = (
        row.task_id,
        row.agent,
        row.result,
        row.score,
        row.benchmark_id,
        row.benchmark_version,
    )
    actual = (
        record.name,
        record.agent,
        record.result,
        record.score,
        record.benchmark_id,
        record.benchmark_version,
    )
    if actual != expected:
        return f"Conflicting history identity for {row.execution_id}."
    return None


def upsert_reused_history(row: MatrixRowSummary, db_path: Path) -> None:
    if row.execution_id is None or row.json_report_path is None:
        return
    record_history(
        HistoryRecord(
            id=row.execution_id,
            run_type="run",
            name=row.task_id,
            result=row.result,
            score=row.score,
            created_at=utc_now_iso(),
            json_report_path=row.json_report_path,
            markdown_report_path=row.markdown_report_path,
            manifest_path=row.manifest_path,
            category=row.category,
            difficulty=row.difficulty,
            benchmark_id=row.benchmark_id,
            benchmark_version=row.benchmark_version,
            agent=row.agent,
            failed_checks=list(row.failed_checks),
        ),
        db_path,
    )


def verify_completed_attempt(
    attempt: MatrixCheckpointAttempt,
    *,
    history_db_path: Path,
) -> AttemptVerification:
    if attempt.status != "completed":
        return AttemptVerification("rerun_required", ["Attempt is not completed."])
    if attempt.error and (
        not attempt.json_report_path
        or not attempt.json_report_sha256
        or not attempt.manifest_path
        or not attempt.manifest_sha256
    ):
        return AttemptVerification(
            "rerun_required",
            ["Failed attempt has no complete reusable artifacts."],
        )
    report_path, messages = _path_and_hash(
        attempt.json_report_path,
        attempt.json_report_sha256,
        "JSON report",
    )
    manifest_path, manifest_messages = _path_and_hash(
        attempt.manifest_path,
        attempt.manifest_sha256,
        "manifest",
    )
    messages.extend(manifest_messages)
    if attempt.markdown_report_path or attempt.markdown_report_sha256:
        _, markdown_messages = _path_and_hash(
            attempt.markdown_report_path,
            attempt.markdown_report_sha256,
            "Markdown report",
        )
        messages.extend(markdown_messages)
    if messages:
        return AttemptVerification("corrupted", messages)
    assert report_path is not None and manifest_path is not None
    config_path = Path(attempt.config_path)
    verification = verify_manifest(
        manifest_path,
        trusted_references={
            f"external/{config_path.name}": config_path,
        },
    )
    if verification.status != "valid":
        return AttemptVerification(
            "corrupted",
            [f"Manifest verification {verification.status}: {message}"
             for message in verification.messages],
        )
    try:
        row = _row_from_report(attempt, report_path)
    except ValueError as error:
        return AttemptVerification("corrupted", [str(error)])
    mismatches = []
    for label, actual, expected in [
        ("task", row.task_id, attempt.task_id),
        ("agent", row.agent, attempt.agent),
        ("result", row.result, attempt.result),
        ("score", row.score, attempt.score),
        ("benchmark id", row.benchmark_id, attempt.benchmark_id),
        ("benchmark version", row.benchmark_version, attempt.benchmark_version),
        ("run id", row.execution_id, attempt.run_id),
        ("failed checks", row.failed_checks, attempt.failed_checks),
        ("warning checks", row.warning_checks, attempt.warning_checks),
        ("task prompt hash", row.task_prompt_sha256, attempt.task_prompt_sha256),
    ]:
        if actual != expected:
            mismatches.append(
                f"Attempt {label} does not match checkpoint: {actual!r} != {expected!r}"
            )
    if mismatches:
        return AttemptVerification("corrupted", mismatches)
    conflict = _history_conflict(row, history_db_path)
    if conflict:
        return AttemptVerification("corrupted", [conflict])
    return AttemptVerification("reusable", verification.messages, row)
