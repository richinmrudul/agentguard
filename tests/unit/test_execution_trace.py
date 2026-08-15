import json
import os
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.orchestrator import run_benchmark
from agentguard.core.result import CheckResult
from agentguard.instrumentation.command_tracker import CommandEvent
from agentguard.provenance.manifest import sha256_file
from agentguard.traces import execution as trace_module
from agentguard.traces.execution import (
    TraceExportOptions,
    build_execution_trace,
    build_policy_snapshot,
    canonical_json,
    export_execution_trace,
    load_execution_trace,
    serialize_execution_trace,
    verify_execution_trace,
    write_execution_trace,
)


runner = CliRunner()


def test_legacy_guard_summary_defaults_to_complete_scan() -> None:
    legacy = trace_module._guard_summary_from_dict({"mode": "audit"})
    malformed = trace_module._guard_summary_from_dict(
        {"mode": "audit", "scan_complete": "yes"}
    )

    assert legacy.scan_complete is True
    assert legacy.incomplete_scan_count == 0
    assert legacy.scan_error is None
    assert malformed.scan_complete is False


@pytest.fixture(scope="module")
def benchmark_result():
    return run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-safe",
    )


def _rebuilt_trace(result, path: Path, *, include_diff: bool = False):
    snapshot = build_policy_snapshot(load_config(result.config_path))
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
        policy_snapshot=snapshot,
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
        policy_snapshot=build_policy_snapshot(load_config(result.config_path)),
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
            policy_snapshot=build_policy_snapshot(
                load_config(benchmark_result.config_path)
            ),
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


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("enabled_checks", [1], "lists must contain strings"),
        ("severities", {"tests-passed": "invalid"}, "severities are invalid"),
        ("score_weights", {"error": True}, "score weights"),
        ("expected_modified_files_min", True, "modified-file bounds"),
        ("expected_modified_files_max", -1, "modified-file bounds"),
        ("max_files_changed", True, "diff thresholds"),
        ("max_lines_added", -1, "diff thresholds"),
        ("command_policy_mode", "invalid", "command policy mode"),
    ],
)
def test_policy_snapshot_validation_rejects_invalid_values(
    benchmark_result,
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    snapshot = build_policy_snapshot(load_config(benchmark_result.config_path))
    invalid = replace(snapshot, **{field: value})

    with pytest.raises(ValueError, match=message):
        trace_module._validate_policy_snapshot(invalid)


@pytest.mark.parametrize(
    ("event_type", "field", "value", "message"),
    [
        ("file_change", "path", 1, "path must be a string"),
        ("file_change", "change_type", "unknown", "change type"),
        ("file_change", "new_content_sha256", "bad", "content_sha256"),
        ("file_change", "new_mode", "777", "file mode"),
        ("file_change", "lines_added", -1, "lines_added"),
        ("file_change", "diff_included", "yes", "diff_included"),
        ("test_result", "exit_code", "zero", "exit code"),
        ("test_result", "stdout", "raw", "identity"),
        ("test_result", "duration_seconds", -1, "duration_seconds"),
        ("execution_completed", "score", 101, "score"),
        ("execution_completed", "modified_files", "raw", "modified_files"),
        (
            "execution_completed",
            "source_report_sha256",
            "bad",
            "source_report_sha256",
        ),
    ],
)
def test_event_payload_validation_rejects_invalid_values(
    benchmark_result,
    tmp_path: Path,
    event_type: str,
    field: str,
    value: object,
    message: str,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    event = next(item for item in trace.events if item.event_type == event_type)
    invalid = replace(event, payload={**event.payload, field: value})

    with pytest.raises(ValueError, match=message):
        trace_module._validate_payload(invalid)


def test_trace_helper_validation_rejects_malformed_values() -> None:
    with pytest.raises(ValueError, match="missing b; 1 unknown field"):
        trace_module._require_exact_fields({"a": 1, "c": 2}, {"a", "b"}, "x")
    with pytest.raises(ValueError, match="2 unknown fields") as excinfo:
        trace_module._require_exact_fields(
            {"CANARY-KEY-1": 1, "CANARY-KEY-2": 2},
            {"a"},
            "x",
        )
    assert "CANARY" not in str(excinfo.value)
    with pytest.raises(ValueError, match="source artifact must be an object"):
        trace_module._parse_source_artifact("raw")
    with pytest.raises(ValueError, match="paths must be relative"):
        trace_module._parse_source_artifact(
            {
                "role": "report",
                "path": "/absolute/report.json",
                "sha256": "a" * 64,
                "required": True,
            }
        )
    with pytest.raises(ValueError, match="Invalid hash"):
        trace_module._validate_sha256("bad", "hash")
    with pytest.raises(ValueError, match="exceeds the"):
        trace_module._validate_bounds("x" * (trace_module.MAX_STRING_CHARS + 1))
    with pytest.raises(ValueError, match="keys must be strings"):
        trace_module._validate_bounds({1: "value"})
    with pytest.raises(ValueError, match="exceeds the") as excinfo:
        trace_module._validate_bounds(
            {"CANARY-" + "k" * trace_module.MAX_STRING_CHARS: "value"}
        )
    assert "CANARY" not in str(excinfo.value)
    with pytest.raises(ValueError, match="exceeds the") as excinfo:
        trace_module._validate_bounds(
            {"field": "CANARY-" + "v" * trace_module.MAX_STRING_CHARS}
        )
    assert "CANARY" not in str(excinfo.value)
    with pytest.raises(ValueError, match="byte count"):
        trace_module._validate_output_identity(
            {"sha256": "a" * 64, "bytes": -1, "truncated": False},
            "output",
        )


def test_trace_and_report_reject_malformed_docker_identity(
    benchmark_result,
    tmp_path: Path,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    test_event = next(event for event in trace.events if event.event_type == "test_result")
    malformed = replace(
        test_event,
        payload={
            **test_event.payload,
            "docker_image": {
                "configured_reference": "example/app:latest",
                "local_image_id": "sha256:" + "1" * 64,
                "executed_image_id": "sha256:" + "2" * 64,
                "registry_digest": None,
                "platform": "linux/amd64",
                "pull_policy": "docker-default",
                "cache_status": "present",
            },
        },
    )
    with pytest.raises(ValueError, match="does not match"):
        trace_module._validate_payload(malformed)

    report = json.loads(benchmark_result.report_paths.json.read_text(encoding="utf-8"))
    report["test_result"]["docker_image"] = {"unexpected": True}
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="fields are invalid"):
        trace_module._result_from_report(report_path, None)
    with pytest.raises(ValueError, match="flag must be boolean"):
        trace_module._validate_output_identity(
            {"sha256": "a" * 64, "bytes": 0, "truncated": "no"},
            "output",
        )


def test_trace_parser_rejects_malformed_records(
    benchmark_result,
    tmp_path: Path,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    header = {"record_type": "header", **asdict(trace.header)}
    event = {"record_type": "event", **asdict(trace.events[0])}
    with pytest.raises(ValueError, match="First trace record"):
        trace_module._parse_header({**header, "record_type": "event"})
    with pytest.raises(ValueError, match="integrity must be an object"):
        trace_module._parse_header({**header, "integrity": "raw"})
    with pytest.raises(ValueError, match="source_artifacts must be a list"):
        trace_module._parse_header({**header, "source_artifacts": "raw"})
    with pytest.raises(ValueError, match="policy snapshot must be an object"):
        trace_module._parse_header({**header, "policy_snapshot": "raw"})
    with pytest.raises(ValueError, match="must be events"):
        trace_module._parse_event({**event, "record_type": "header"})
    with pytest.raises(ValueError, match="payload must be an object"):
        trace_module._parse_event({**event, "payload": "raw"})

    unreadable = tmp_path / "missing" / "trace.jsonl"
    with pytest.raises(ValueError, match="Unable to read trace"):
        load_execution_trace(unreadable)
    short = tmp_path / "short.jsonl"
    short.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="header and events"):
        load_execution_trace(short)
    invalid_json = tmp_path / "invalid.jsonl"
    invalid_json.write_text("{}\n{\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid trace JSON"):
        load_execution_trace(invalid_json)
    scalar = tmp_path / "scalar.jsonl"
    scalar.write_text("[]\n{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        load_execution_trace(scalar)


def test_trace_loader_enforces_byte_line_event_and_complexity_limits(
    benchmark_result,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    path = tmp_path / "bounded.jsonl"
    write_execution_trace(trace, path)

    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", 8)
    with pytest.raises(ValueError, match="8-byte limit"):
        load_execution_trace(path)

    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", 16 * 1024 * 1024)
    monkeypatch.setattr(trace_module, "MAX_TRACE_LINE_BYTES", 8)
    with pytest.raises(ValueError, match="line 1 exceeds the 8-byte limit"):
        load_execution_trace(path)

    monkeypatch.setattr(trace_module, "MAX_TRACE_LINE_BYTES", 1024 * 1024)
    monkeypatch.setattr(trace_module, "MAX_TRACE_EVENTS", 0)
    with pytest.raises(ValueError, match="0-event limit"):
        load_execution_trace(path)

    monkeypatch.setattr(trace_module, "MAX_TRACE_EVENTS", 10000)
    deeply_nested: object = "leaf"
    for _ in range(trace_module.MAX_TRACE_NESTING + 1):
        deeply_nested = {"child": deeply_nested}
    deep = tmp_path / "deep.jsonl"
    deep.write_text(
        canonical_json({"value": deeply_nested}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="nesting limit"):
        load_execution_trace(deep)

    monkeypatch.setattr(trace_module, "MAX_TRACE_NODES", 2)
    with pytest.raises(ValueError, match="node limit"):
        load_execution_trace(path)


def test_trace_loader_accepts_exact_boundary_and_rejects_one_above(
    benchmark_result,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    path = tmp_path / "boundary.jsonl"
    write_execution_trace(trace, path)
    raw_lines = path.read_bytes().splitlines(keepends=True)
    total_bytes = sum(len(line) for line in raw_lines)
    longest_line = max(len(line) for line in raw_lines)
    event_count = len(raw_lines) - 1

    # Total trace bytes: exact size is accepted, one byte less is rejected.
    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", total_bytes)
    load_execution_trace(path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", total_bytes - 1)
    with pytest.raises(ValueError, match="byte limit"):
        load_execution_trace(path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", 16 * 1024 * 1024)

    # Per-line bytes counts the raw physical line, terminator included:
    # the exact longest-line length is accepted, one byte less is rejected.
    monkeypatch.setattr(trace_module, "MAX_TRACE_LINE_BYTES", longest_line)
    load_execution_trace(path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_LINE_BYTES", longest_line - 1)
    with pytest.raises(ValueError, match="byte limit"):
        load_execution_trace(path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_LINE_BYTES", 1024 * 1024)

    # Event count: header plus exactly event_count events is accepted;
    # capping the limit one below the actual event count is rejected.
    monkeypatch.setattr(trace_module, "MAX_TRACE_EVENTS", event_count)
    load_execution_trace(path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_EVENTS", event_count - 1)
    with pytest.raises(ValueError, match="event limit"):
        load_execution_trace(path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_EVENTS", 10000)


def test_validate_bounds_accepts_exact_nesting_and_node_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nesting: a value wrapped exactly MAX_TRACE_NESTING levels deep is
    # accepted; one level deeper is rejected.
    at_limit: object = "leaf"
    for _ in range(trace_module.MAX_TRACE_NESTING):
        at_limit = {"child": at_limit}
    trace_module._validate_bounds(at_limit)

    with pytest.raises(ValueError, match="nesting limit"):
        trace_module._validate_bounds({"child": at_limit})

    # Node count: the container itself counts as a node, so a 4-item list
    # under a limit of 5 is exactly at the boundary; a 5-item list is not.
    monkeypatch.setattr(trace_module, "MAX_TRACE_NODES", 5)
    trace_module._validate_bounds([1, 2, 3, 4])
    with pytest.raises(ValueError, match="node limit"):
        trace_module._validate_bounds([1, 2, 3, 4, 5])


def test_loader_rejects_on_byte_limit_before_reading_rest_of_hostile_trace(
    benchmark_result,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    header_line = (
        serialize_execution_trace(trace).splitlines()[0].encode("utf-8") + b"\n"
    )
    hostile = tmp_path / "hostile.jsonl"
    # Everything after the header is invalid UTF-8. If the loader ever read
    # past line 1, it would fail on that instead with a UTF-8 decode error.
    # It must not need to: the byte budget below is already exhausted by the
    # header line alone, so the hostile remainder is never read or buffered.
    with hostile.open("wb") as handle:
        handle.write(header_line)
        for _ in range(5000):
            handle.write(b"\xff" * 64 + b"\n")

    monkeypatch.setattr(trace_module, "MAX_TRACE_BYTES", len(header_line) - 1)

    with pytest.raises(ValueError, match="byte limit") as excinfo:
        load_execution_trace(hostile)
    assert "UTF-8" not in str(excinfo.value)


@pytest.mark.parametrize("command", ["show", "verify", "replayability", "replay"])
def test_trace_commands_never_echo_untrusted_field_names_or_values(
    benchmark_result,
    tmp_path: Path,
    command: str,
) -> None:
    canary = "AGENTGUARD-FAKE-CREDENTIAL-CANARY-9F3B"
    trace = _rebuilt_trace(benchmark_result, tmp_path / f"trace-{command}.jsonl")
    base_path = tmp_path / f"base-{command}.jsonl"
    write_execution_trace(trace, base_path)
    records = _records(base_path)
    # An unknown header field named after the canary: `_require_exact_fields`
    # must report only a count, never the offending key.
    records[0][canary] = "value"
    path = tmp_path / f"canary-key-{command}.jsonl"
    _write_records(path, records)

    result = runner.invoke(app, ["trace", command, str(path)])

    assert result.exit_code == 2
    assert canary not in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize("command", ["show", "verify", "replayability", "replay"])
def test_trace_commands_never_echo_oversized_field_value(
    benchmark_result,
    tmp_path: Path,
    command: str,
) -> None:
    canary = "AGENTGUARD-FAKE-CREDENTIAL-CANARY-9F3B-"
    oversized = canary + "x" * trace_module.MAX_STRING_CHARS
    trace = _rebuilt_trace(benchmark_result, tmp_path / f"trace-{command}.jsonl")
    base_path = tmp_path / f"base-{command}.jsonl"
    write_execution_trace(trace, base_path)
    records = _records(base_path)
    event_record = next(
        record
        for record in records
        if record.get("record_type") == "event"
        and record["event_type"] == "execution_completed"
    )
    event_record["payload"]["result"] = oversized
    path = tmp_path / f"canary-value-{command}.jsonl"
    _write_records(path, records)

    result = runner.invoke(app, ["trace", command, str(path)])

    assert result.exit_code == 2
    assert canary not in result.output
    assert "Traceback" not in result.output


def test_trace_loader_normalizes_invalid_utf8_and_json_recursion(
    benchmark_result,
    tmp_path: Path,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    valid = serialize_execution_trace(trace).encode("utf-8")
    first_newline = valid.index(b"\n")
    invalid_utf8 = tmp_path / "invalid-utf8.jsonl"
    invalid_utf8.write_bytes(
        valid[: first_newline + 1] + b"\xff" + valid[first_newline + 2 :]
    )
    with pytest.raises(ValueError, match="Invalid trace UTF-8 on line 2"):
        load_execution_trace(invalid_utf8)

    recursive = tmp_path / "recursive.jsonl"
    recursive.write_text("[" * 1500 + "]" * 1500 + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid trace JSON on line 1"):
        load_execution_trace(recursive)

    records = [
        json.loads(line)
        for line in serialize_execution_trace(trace).splitlines()
    ]
    records[0]["source_artifacts"] = [
        {
            "role": "report",
            "path": [],
            "sha256": "a" * 64,
            "required": True,
        }
    ]
    wrong_shape = tmp_path / "wrong-shape.jsonl"
    _write_records(wrong_shape, records)
    with pytest.raises(ValueError, match="Invalid trace record on line 1"):
        load_execution_trace(wrong_shape)
    assert verify_execution_trace(wrong_shape).exit_code == 2


# Markers seeded into every hostile trace below. Each stands for one class of
# thing an attacker controls and a diagnostic must never reproduce: a
# credential-shaped value, a field name, a bulk fragment, and an absolute path
# belonging to whoever authored the trace.
_HOSTILE_CANARY = "AGENTGUARD-FAKE-CREDENTIAL-CANARY-4D7A-"
_HOSTILE_KEY = "agentguard_attacker_controlled_key"
_HOSTILE_ABSOLUTE_PATH = "/private/attacker-home/.ssh/id_rsa"

_HOSTILE_KINDS = ("invalid_utf8", "malformed_json", "deep_json", "wrong_shape")


def _hostile_trace_file(
    kind: str,
    benchmark_result,
    tmp_path: Path,
) -> tuple[Path, str]:
    """Write one hostile trace of `kind`, seeded with the leak markers.

    Returns the path and the bulk filler, so a caller can assert that no large
    fragment of the input is echoed back.
    """
    filler = "y" * (trace_module.MAX_STRING_CHARS + 64)
    path = tmp_path / f"hostile-{kind}.jsonl"

    if kind == "invalid_utf8":
        trace = _rebuilt_trace(benchmark_result, tmp_path / f"src-{kind}.jsonl")
        base = tmp_path / f"base-{kind}.jsonl"
        write_execution_trace(trace, base)
        records = _records(base)
        records[0][_HOSTILE_KEY] = _HOSTILE_CANARY + filler
        payload = "\n".join(json.dumps(record) for record in records).encode("utf-8")
        newline = payload.index(b"\n")
        # Corrupt the byte after the first newline so line 2 is undecodable.
        path.write_bytes(payload[: newline + 1] + b"\xff" + payload[newline + 2 :])
    elif kind == "malformed_json":
        truncated = json.dumps(
            {_HOSTILE_KEY: _HOSTILE_CANARY + filler, "path": _HOSTILE_ABSOLUTE_PATH}
        )[:-1]
        path.write_text(truncated + "\n", encoding="utf-8")
    elif kind == "deep_json":
        nested = json.dumps(_HOSTILE_CANARY + filler)
        path.write_text("[" * 1500 + nested + "]" * 1500 + "\n", encoding="utf-8")
    elif kind == "wrong_shape":
        trace = _rebuilt_trace(benchmark_result, tmp_path / f"src-{kind}.jsonl")
        base = tmp_path / f"base-{kind}.jsonl"
        write_execution_trace(trace, base)
        records = _records(base)
        records[0]["source_artifacts"] = [
            {
                "role": _HOSTILE_CANARY,
                "path": [_HOSTILE_ABSOLUTE_PATH],
                "sha256": "a" * 64,
                "required": True,
                _HOSTILE_KEY: filler,
            }
        ]
        _write_records(path, records)
    else:  # pragma: no cover - guards the parametrisation itself
        raise AssertionError(f"unknown hostile kind {kind!r}")

    return path, filler


@pytest.mark.parametrize("command", ["show", "verify", "replayability", "replay"])
@pytest.mark.parametrize("kind", _HOSTILE_KINDS)
def test_trace_commands_reject_hostile_input_without_leaking(
    benchmark_result,
    tmp_path: Path,
    command: str,
    kind: str,
) -> None:
    """Every public command against every hostile-input category.

    The loader-level tests above prove the parse is rejected; this proves each
    command surface rejects it the same way and says nothing about the contents
    while doing so.
    """
    path, filler = _hostile_trace_file(kind, benchmark_result, tmp_path)

    result = runner.invoke(app, ["trace", command, str(path)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert _HOSTILE_CANARY not in result.output
    assert _HOSTILE_KEY not in result.output
    # A bounded structural position may be reported; a slice of the input
    # itself may not.
    assert filler[:64] not in result.output
    assert _HOSTILE_ABSOLUTE_PATH not in result.output


@pytest.mark.parametrize("command", ["show", "verify", "replayability", "replay"])
def test_trace_commands_reject_hostile_modified_path_without_echoing_it(
    benchmark_result,
    tmp_path: Path,
    command: str,
) -> None:
    """An attacker-owned absolute path in modified_files.paths.

    load_execution_trace validates every event payload, and an
    execution_completed event's modified_files.paths list flows into
    _normalized_path. The record is otherwise well-shaped, so the only thing
    that refuses it is the repository-relative check -- which must report why
    without echoing the path it rejected.
    """
    # Absolute, so it trips the repository-relative check that is the leak
    # site -- and short, so it reaches that check rather than a length bound
    # first. The earlier version buried the path in oversized filler, which
    # was rejected at a non-echoing stage and made the test vacuous.
    canary = "AGENTGUARD-FAKE-CREDENTIAL-CANARY-PATH-4E1A"
    hostile = f"/private/attacker-home/.ssh/{canary}/id_rsa"

    trace = _rebuilt_trace(benchmark_result, tmp_path / f"mp-src-{command}.jsonl")
    base = tmp_path / f"mp-base-{command}.jsonl"
    write_execution_trace(trace, base)
    records = _records(base)
    completed = next(
        record
        for record in records
        if record.get("record_type") == "event"
        and record["event_type"] == "execution_completed"
    )
    modified = completed["payload"].setdefault(
        "modified_files",
        {"count": 1, "paths": [], "truncated": False,
         "lines_added": 0, "lines_deleted": 0},
    )
    modified["paths"] = [hostile]

    path = tmp_path / f"mp-hostile-{command}.jsonl"
    _write_records(path, records)

    result = runner.invoke(app, ["trace", command, str(path)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert canary not in result.output
    assert "/private/attacker-home" not in result.output


@pytest.mark.parametrize("command", ["show", "verify", "replayability", "replay"])
def test_trace_commands_share_bounded_loader(
    benchmark_result,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    path = tmp_path / "oversized-line.jsonl"
    write_execution_trace(trace, path)
    monkeypatch.setattr(trace_module, "MAX_TRACE_LINE_BYTES", 8)

    result = runner.invoke(app, ["trace", command, str(path)])

    assert result.exit_code == 2
    assert "line 1 exceeds the 8-byte limit" in result.output


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("schema", "schema identifier"),
        ("version", "schema version"),
        ("source_type", "source execution type"),
        ("algorithm", "hash algorithm"),
        ("event_count", "event count"),
        ("empty", "contain events"),
        ("sequence", "sequences"),
        ("event_type", "unsupported event type"),
        ("start", "start/completion"),
        ("duplicate_start", "one execution_started"),
        ("no_test", "one test_result"),
        ("duplicate_completion", "one execution_completed"),
        ("order", "type ordering"),
        ("offset", "relative offsets"),
    ],
)
def test_trace_structure_rejects_invalid_shapes(
    benchmark_result,
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    trace = _rebuilt_trace(benchmark_result, tmp_path / "trace.jsonl")
    header = trace.header
    events = trace.events
    if mutation == "schema":
        header = replace(header, schema="unknown")
    elif mutation == "version":
        header = replace(header, schema_version=99)
    elif mutation == "source_type":
        header = replace(header, source_execution_type="unknown")
    elif mutation == "algorithm":
        header = replace(
            header,
            integrity=replace(header.integrity, hash_algorithm="unknown"),
        )
    elif mutation == "event_count":
        header = replace(header, event_count=header.event_count + 1)
    elif mutation == "empty":
        events = []
        header = replace(header, event_count=0)
    elif mutation == "sequence":
        events = [replace(events[0], sequence=2), *events[1:]]
    elif mutation == "event_type":
        events = [replace(events[0], event_type="unknown"), *events[1:]]
    elif mutation == "start":
        events = [replace(events[0], event_type="agent_command"), *events[1:]]
    elif mutation == "duplicate_start":
        events = [
            events[0],
            replace(events[1], event_type="execution_started"),
            *events[2:],
        ]
    elif mutation == "no_test":
        events = [event for event in events if event.event_type != "test_result"]
        events = [
            replace(event, sequence=index)
            for index, event in enumerate(events, start=1)
        ]
        header = replace(header, event_count=len(events))
    elif mutation == "duplicate_completion":
        events = [
            *events[:-2],
            replace(events[-2], event_type="execution_completed"),
            events[-1],
        ]
    elif mutation == "order":
        events = [
            events[0],
            replace(events[1], event_type="check_result"),
            *events[2:],
        ]
    else:
        events = [replace(events[0], relative_offset_seconds=-1), *events[1:]]

    with pytest.raises(ValueError, match=message):
        trace_module._validate_structure(
            replace(trace, header=header, events=events)
        )
