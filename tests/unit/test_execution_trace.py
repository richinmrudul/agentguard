import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import CheckResult
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.provenance.manifest import sha256_file
from agentguard.traces import execution as trace_module
from agentguard.traces.execution import (
    TraceExportOptions,
    build_execution_trace,
    canonical_json,
    export_execution_trace,
    load_execution_trace,
    serialize_execution_trace,
    verify_execution_trace,
    write_execution_trace,
)


runner = CliRunner()


@pytest.fixture(scope="module")
def benchmark_result():
    return run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-safe",
    )


def _rebuilt_trace(result, path: Path, *, include_diff: bool = False):
    return build_execution_trace(
        result,
        created_at="2026-06-14T12:00:00+00:00",
        configuration_hash=sha256_file(result.config_path),
        agentguard_version="0.1.0",
        agentguard_commit="a" * 40,
        agent_version=None,
        policy_summary='{"mode":"audit"}',
        sandbox_summary='{"type":"local"}',
        source_report_id="report.json",
        source_manifest_id="manifest.json",
        include_diff=include_diff,
    )


def _records(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _write_records(path: Path, records: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(canonical_json(record) for record in records) + "\n",
        encoding="utf-8",
    )


def test_canonical_serialization_and_hashes_are_deterministic(
    benchmark_result,
    tmp_path: Path,
) -> None:
    first = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    second = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")

    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert [event.event_hash for event in first.events] == [
        event.event_hash for event in second.events
    ]
    assert first.header.integrity.root_hash == second.header.integrity.root_hash
    assert serialize_execution_trace(first) == serialize_execution_trace(second)


def test_generated_pass_and_fail_traces_have_expected_order() -> None:
    passed = run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-safe",
    )
    failed = run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-test-cheater",
    )

    for result in (passed, failed):
        assert result.report_paths.trace is not None
        trace = load_execution_trace(result.report_paths.trace)
        types = [event.event_type for event in trace.events]
        assert types[0] == "execution_started"
        assert types[-1] == "execution_completed"
        assert types.count("test_result") == 1
        assert types.count("check_result") == len(result.check_results)
        assert verify_execution_trace(result.report_paths.trace).exit_code == 0
    assert load_execution_trace(failed.report_paths.trace).events[-1].payload[
        "result"
    ] == "FAIL"


@pytest.mark.parametrize(
    "mutation",
    ["payload", "header", "delete", "insert", "reorder", "duplicate_sequence"],
)
def test_tampering_is_detected(
    benchmark_result,
    tmp_path: Path,
    mutation: str,
) -> None:
    path = tmp_path / f"{mutation}.jsonl"
    write_execution_trace(_rebuilt_trace(benchmark_result, path), path)
    records = _records(path)
    if mutation == "payload":
        records[1]["payload"]["task_id"] = "changed"
    elif mutation == "header":
        records[0]["task_id"] = "changed"
    elif mutation == "delete":
        del records[2]
    elif mutation == "insert":
        records.insert(2, dict(records[1]))
    elif mutation == "reorder":
        records[2], records[3] = records[3], records[2]
    else:
        records[2]["sequence"] = records[1]["sequence"]
    _write_records(path, records)

    assert verify_execution_trace(path).exit_code == 2


def test_truncated_file_is_rejected(
    benchmark_result,
    tmp_path: Path,
) -> None:
    path = tmp_path / "truncated.jsonl"
    write_execution_trace(_rebuilt_trace(benchmark_result, path), path)
    path.write_bytes(path.read_bytes()[:-1])

    result = verify_execution_trace(path)
    assert result.exit_code == 2
    assert "truncated" in result.messages[0].lower()


def test_source_status_strict_and_changed_behavior(
    benchmark_result,
    tmp_path: Path,
) -> None:
    path = benchmark_result.report_paths.trace
    assert path is not None

    assert verify_execution_trace(path).exit_code == 0
    assert verify_execution_trace(path, strict_sources=True).exit_code == 0

    report = benchmark_result.report_paths.json
    original = report.read_bytes()
    report.write_bytes(original + b"\n")
    try:
        assert verify_execution_trace(path).exit_code == 1
    finally:
        report.write_bytes(original)

    relocated = tmp_path / "relocated" / "trace.jsonl"
    relocated.parent.mkdir()
    relocated.write_bytes(path.read_bytes())
    assert verify_execution_trace(relocated).exit_code == 0
    assert verify_execution_trace(relocated, strict_sources=True).exit_code == 1


def test_paths_symlinks_and_portable_commands(
    benchmark_result,
    tmp_path: Path,
) -> None:
    link = benchmark_result.repo_dir / "absolute-link"
    os.symlink("/private/secret-target", link)
    changed = replace(
        benchmark_result.diff_summary,
        added_files=[*benchmark_result.diff_summary.added_files, "absolute-link"],
    )
    result = replace(benchmark_result, diff_summary=changed)
    try:
        trace = _rebuilt_trace(result, tmp_path / "trace.jsonl")
    finally:
        link.unlink()
    symlink = next(
        event
        for event in trace.events
        if event.event_type == "file_change"
        and event.payload["path"] == "absolute-link"
    )
    assert symlink.payload["change_type"] == "symlink"
    assert symlink.payload["symlink_target"] == "[ABSOLUTE_TARGET]"
    serialized = serialize_execution_trace(trace)
    assert str(Path.cwd()) not in serialized
    with pytest.raises(ValueError, match="repository-relative"):
        trace_module._normalized_path("../escape")


def test_canary_secrets_and_raw_content_are_absent(
    benchmark_result,
    tmp_path: Path,
) -> None:
    canary = "AGENTGUARD-CANARY-SECRET-28A"
    command = CommandEvent(
        command=["tool", "--api-key", canary],
        command_text=f"tool --api-key {canary}",
        cwd=str(benchmark_result.repo_dir),
        exit_code=1,
        stdout=f"stdout {canary}",
        stderr=f"Authorization: Bearer {canary}",
        duration_seconds=0.1,
        executed=True,
        blocked=False,
        reason=None,
    )
    checks = [
        CheckResult(
            name="Canary",
            passed=False,
            severity="warning",
            message=f"message {canary}",
            evidence=[f"evidence {canary}"],
        )
    ]
    result = replace(
        benchmark_result,
        command_events=[command],
        check_results=checks,
    )
    trace = build_execution_trace(
        result,
        created_at="2026-06-14T12:00:00+00:00",
        configuration_hash=sha256_file(result.config_path),
        agentguard_version="0.1.0",
        agentguard_commit=None,
        agent_version=None,
        policy_summary="audit",
        sandbox_summary="local",
        source_report_id="report.json",
        source_manifest_id=None,
        sensitive_values=[canary],
    )
    serialized = serialize_execution_trace(trace)

    assert canary not in serialized
    assert "[REDACTED]" in serialized
    assert "stdout AGENTGUARD" not in serialized
    assert "def login" not in serialized


def test_include_diff_is_bounded_and_sanitized(
    benchmark_result,
    tmp_path: Path,
) -> None:
    canary = "DIFF-CANARY-SECRET-28A"
    changed_path = benchmark_result.repo_dir / "src/auth_example/login.py"
    original = changed_path.read_text(encoding="utf-8")
    changed_path.write_text(original + f"\n# {canary}\n", encoding="utf-8")
    try:
        trace = build_execution_trace(
            benchmark_result,
            created_at="2026-06-14T12:00:00+00:00",
            configuration_hash=sha256_file(benchmark_result.config_path),
            agentguard_version="0.1.0",
            agentguard_commit=None,
            agent_version=None,
            policy_summary="audit",
            sandbox_summary="local",
            source_report_id="report.json",
            source_manifest_id=None,
            include_diff=True,
            sensitive_values=[canary],
        )
    finally:
        changed_path.write_text(original, encoding="utf-8")
    file_event = next(
        event for event in trace.events if event.event_type == "file_change"
    )
    assert file_event.payload["diff_included"] is True
    assert len(file_event.payload["unified_diff"]) <= trace_module.MAX_DIFF_CHARS
    assert canary not in serialize_execution_trace(trace)


def test_existing_run_export_and_cli_commands(
    benchmark_result,
    tmp_path: Path,
) -> None:
    output = tmp_path / "exported.jsonl"
    export_execution_trace(
        benchmark_result.run_dir,
        output,
        TraceExportOptions(),
    )

    assert verify_execution_trace(output).exit_code == 0
    assert runner.invoke(app, ["trace", "show", str(output)]).exit_code == 0
    assert runner.invoke(app, ["trace", "verify", str(output)]).exit_code == 0
    duplicate = runner.invoke(
        app,
        [
            "trace",
            "export",
            str(benchmark_result.run_dir),
            "--output",
            str(output),
        ],
    )
    assert duplicate.exit_code == 2
    forced = runner.invoke(
        app,
        [
            "trace",
            "export",
            str(benchmark_result.run_dir),
            "--output",
            str(output),
            "--force",
        ],
    )
    assert forced.exit_code == 0
    from_report = tmp_path / "from-report.jsonl"
    export_execution_trace(
        benchmark_result.report_paths.json,
        from_report,
        TraceExportOptions(include_diff=True),
    )
    report_trace = load_execution_trace(from_report)
    assert any(
        event.event_type == "file_change"
        and event.payload["diff_included"] is True
        for event in report_trace.events
    )
    from_manifest = tmp_path / "from-manifest.jsonl"
    export_execution_trace(
        benchmark_result.report_paths.manifest,
        from_manifest,
    )
    assert verify_execution_trace(from_manifest).exit_code == 0


def test_export_validates_manifest_artifact_hashes(
    benchmark_result,
    tmp_path: Path,
) -> None:
    report = benchmark_result.report_paths.json
    original = report.read_bytes()
    report.write_bytes(original + b"\n")
    try:
        with pytest.raises(ValueError, match="report evidence has changed"):
            export_execution_trace(
                benchmark_result.run_dir,
                tmp_path / "trace.jsonl",
            )
    finally:
        report.write_bytes(original)


def test_export_refuses_incomplete_evidence(tmp_path: Path) -> None:
    source = tmp_path / "old-run"
    (source / "reports").mkdir(parents=True)
    (source / "reports" / "report.json").write_text(
        '{"task_id":"incomplete"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Required report evidence"):
        export_execution_trace(source, tmp_path / "trace.jsonl")


def test_atomic_failure_preserves_previous_file(
    benchmark_result,
    tmp_path: Path,
    monkeypatch,
) -> None:
    path = tmp_path / "trace.jsonl"
    path.write_text("previous\n", encoding="utf-8")

    def fail_write(*args, **kwargs):
        raise OSError("simulated")

    monkeypatch.setattr(trace_module, "atomic_write_text", fail_write)
    with pytest.raises(OSError, match="simulated"):
        write_execution_trace(_rebuilt_trace(benchmark_result, path), path)
    assert path.read_text(encoding="utf-8") == "previous\n"


def test_run_trace_failure_warns_without_replacing_result(monkeypatch) -> None:
    def fail_trace(*args, **kwargs):
        raise OSError("simulated trace failure")

    monkeypatch.setattr(
        "agentguard.core.orchestrator.write_execution_trace",
        fail_trace,
    )
    with pytest.warns(RuntimeWarning, match="trace write failed"):
        result = run_benchmark(
            Path("examples/configs/fix_auth_bug.yaml"),
            "mock-safe",
        )

    assert result.result == "PASS"
    assert result.report_paths.json.is_file()
    assert result.report_paths.trace is None
