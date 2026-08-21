import json
import os
import shutil
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
    with pytest.raises(ValueError, match="missing b; unknown c"):
        trace_module._require_exact_fields({"a": 1, "c": 2}, {"a", "b"}, "x")
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
    with pytest.raises(ValueError, match="too long"):
        trace_module._validate_bounds("x" * (trace_module.MAX_STRING_CHARS + 1))
    with pytest.raises(ValueError, match="keys must be strings"):
        trace_module._validate_bounds({1: "value"})
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


def test_result_from_report_rehydrates_repository_in_moved_run_bundle(
    benchmark_result,
    tmp_path: Path,
) -> None:
    moved_run = tmp_path / "moved" / "run"
    shutil.copytree(benchmark_result.run_dir, moved_run)
    report_path = moved_run / "reports" / "report.json"

    result, _ = trace_module._result_from_report(report_path, None)

    assert result.run_dir == moved_run
    assert result.repo_dir == moved_run / "repo"


def test_result_from_standalone_report_refuses_missing_repository_bundle(
    benchmark_result,
    tmp_path: Path,
) -> None:
    reports_dir = tmp_path / "standalone" / "reports"
    reports_dir.mkdir(parents=True)
    report_path = reports_dir / "report.json"
    report_path.write_bytes(benchmark_result.report_paths.json.read_bytes())

    with pytest.raises(
        ValueError,
        match="Required repository evidence is unavailable",
    ):
        trace_module._result_from_report(report_path, None)


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
