import json
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.core.matrix_checkpoint import (
    MatrixCheckpoint,
    MatrixCheckpointAttempt,
    atomic_write_checkpoint,
    load_checkpoint,
    stable_attempt_key,
)
from agentguard.provenance.manifest import sha256_file


def _checkpoint(tmp_path: Path) -> MatrixCheckpoint:
    now = "2026-06-12T00:00:00+00:00"
    attempt = MatrixCheckpointAttempt(
        key="key",
        ordinal=0,
        task_id="task",
        config_path="/tmp/config.yaml",
        config_sha256="config",
        benchmark_id="benchmark",
        benchmark_version=1,
        agent="mock-safe",
        profile_id=None,
        profile_model=None,
        task_prompt_sha256=None,
        trial_index=1,
        trial_count=1,
    )
    return MatrixCheckpoint(
        checkpoint_id="checkpoint",
        created_at=now,
        updated_at=now,
        status="running",
        matrix_id="matrix",
        suite_id="suite",
        suite_path="/tmp/suite.yaml",
        suite_sha256="suite",
        filters={},
        agents=["mock-safe"],
        trials=1,
        requested_workers=1,
        effective_workers=1,
        fail_fast=False,
        benchmarks=[],
        profile_identity={},
        execution_compatibility={},
        attempts_planned=1,
        attempts=[attempt],
        matrix_json_report_path=str(tmp_path / "matrix.json"),
        matrix_markdown_report_path=str(tmp_path / "matrix.md"),
        matrix_manifest_path=str(tmp_path / "manifest.json"),
    )


def test_checkpoint_round_trip_uses_typed_schema(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    expected = _checkpoint(tmp_path)

    atomic_write_checkpoint(expected, path)

    assert load_checkpoint(path) == expected
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "agentguard.matrix-checkpoint"
    assert data["schema_version"] == 1


def test_checkpoint_round_trip_preserves_guard_row_fields(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    checkpoint = _checkpoint(tmp_path)
    attempt = replace(
        checkpoint.attempts[0],
        guard_violations_total=3,
        guard_blocked=True,
        filesystem_guard_violations=1,
        command_guard_violations=2,
        time_to_first_violation_ms=10,
        time_to_block_ms=12,
        guard_incident_json_path="run/guard/incident.json",
        guard_incident_markdown_path="run/guard/incident.md",
        blocking_guard="command",
    )
    expected = replace(checkpoint, attempts=[attempt])

    atomic_write_checkpoint(expected, path)

    assert load_checkpoint(path) == expected


def test_legacy_checkpoint_attempt_uses_empty_guard_defaults(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    atomic_write_checkpoint(_checkpoint(tmp_path), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    for field_name in (
        "guard_violations_total",
        "guard_blocked",
        "filesystem_guard_violations",
        "command_guard_violations",
        "time_to_first_violation_ms",
        "time_to_block_ms",
        "guard_incident_json_path",
        "guard_incident_markdown_path",
        "blocking_guard",
    ):
        data["attempts"][0].pop(field_name)
    path.write_text(json.dumps(data), encoding="utf-8")

    attempt = load_checkpoint(path).attempts[0]

    assert attempt.guard_violations_total == 0
    assert attempt.guard_blocked is False
    assert attempt.time_to_first_violation_ms is None
    assert attempt.guard_incident_json_path is None


def test_checkpoint_rejects_schema_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "checkpoint.json"
    atomic_write_checkpoint(_checkpoint(tmp_path), path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema_version"] = 99
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="schema_version"):
        load_checkpoint(path)


def test_atomic_write_preserves_previous_file_on_replace_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "checkpoint.json"
    original = _checkpoint(tmp_path)
    atomic_write_checkpoint(original, path)
    original_bytes = path.read_bytes()

    def fail_replace(_source, _destination) -> None:
        raise OSError("replace failed")

    monkeypatch.setattr("agentguard.core.matrix_checkpoint.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        atomic_write_checkpoint(replace(original, status="completed"), path)

    assert path.read_bytes() == original_bytes


def test_stable_attempt_key_ignores_workers_and_changes_resolved_inputs() -> None:
    config = load_config(Path("examples/configs/fix_auth_bug.yaml"))
    config_hash = sha256_file(config.config_path)
    values = {
        "suite_sha256": "suite",
        "config": config,
        "config_sha256": config_hash,
        "agent": "mock-safe",
        "profile_id": None,
        "profile_model": None,
        "profile_identity": {},
        "task_prompt_sha256": None,
        "trial_index": 1,
    }

    baseline = stable_attempt_key(**values)

    assert stable_attempt_key(**values) == baseline
    assert stable_attempt_key(**(values | {"trial_index": 2})) != baseline
    assert stable_attempt_key(**(values | {"agent": "mock-risky"})) != baseline
    assert stable_attempt_key(
        **(values | {"profile_model": "different-model"})
    ) != baseline
    assert stable_attempt_key(
        **(values | {"task_prompt_sha256": "different-prompt"})
    ) != baseline
    assert stable_attempt_key(
        **(values | {"config_sha256": "different-config"})
    ) != baseline
    changed_benchmark = replace(
        config,
        benchmark=replace(config.benchmark, version=999),
    )
    assert stable_attempt_key(
        **(values | {"config": changed_benchmark})
    ) != baseline
    changed_policy = replace(
        config,
        sandbox=replace(config.sandbox, type="docker", network="host"),
    )
    assert stable_attempt_key(
        **(values | {"config": changed_policy})
    ) != baseline
