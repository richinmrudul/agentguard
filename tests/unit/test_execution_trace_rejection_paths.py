import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.config.loader import load_config
from agentguard.core.orchestrator import run_benchmark
from agentguard.provenance.manifest import sha256_file
from agentguard.traces import execution as trace_module
from agentguard.traces.execution import (
    build_execution_trace,
    build_policy_snapshot,
    canonical_json,
    load_execution_trace,
    serialize_execution_trace,
)


runner = CliRunner()
CANARY = "AGENTGUARD-ROUTE-CANARY-7C91"
COMMANDS = ("show", "verify", "replayability", "replay")
KINDS = ("invalid_utf8", "malformed_json", "deep_json", "wrong_shape")


@pytest.fixture(scope="module")
def benchmark_result():
    return run_benchmark(
        Path("examples/configs/fix_auth_bug.yaml"),
        "mock-safe",
    )


def _trace(result):
    return build_execution_trace(
        result,
        created_at="2026-08-20T20:00:00+00:00",
        configuration_hash=sha256_file(result.config_path),
        agentguard_version="0.1.0",
        agentguard_commit="a" * 40,
        agent_version=None,
        policy_summary='{"mode":"audit"}',
        sandbox_summary='{"type":"local"}',
        source_report_id="report.json",
        source_manifest_id="manifest.json",
        policy_snapshot=build_policy_snapshot(load_config(result.config_path)),
    )


def _records(trace):
    return [json.loads(line) for line in serialize_execution_trace(trace).splitlines()]


def _write_records(path: Path, records):
    path.write_text(
        "\n".join(canonical_json(record) for record in records) + "\n",
        encoding="utf-8",
    )


def _hostile_file(kind: str, benchmark_result, tmp_path: Path) -> Path:
    """Build a bounded fixture that reaches exactly the advertised failure class."""
    path = tmp_path / f"hostile-{kind}.jsonl"

    if kind == "invalid_utf8":
        lines = serialize_execution_trace(_trace(benchmark_result)).encode("utf-8").splitlines(keepends=True)
        # Header remains valid and bounded. Line 2 itself carries the bounded
        # canary before one undecodable byte, so the UTF-8 decoder -- not a
        # string-size or unknown-field guard -- must be the rejecting layer.
        lines[1] = b'{"record_type":"event","marker":"' + CANARY.encode() + b'","bad":"\xff"}\n'
        path.write_bytes(b"".join(lines))
    elif kind == "malformed_json":
        # Bounded and syntactically incomplete; no size bound is involved.
        path.write_text('{"marker":"' + CANARY + '"\n', encoding="utf-8")
    elif kind == "deep_json":
        # ~3 KiB, below the normal line bound: JSON recursion is the reason.
        leaf = json.dumps(CANARY)
        path.write_text("[" * 1500 + leaf + "]" * 1500 + "\n", encoding="utf-8")
    elif kind == "wrong_shape":
        records = _records(_trace(benchmark_result))
        # Keep the header keys exact and values bounded. Only the source path's
        # type is wrong, so header/source parsing owns the rejection.
        records[0]["source_artifacts"] = [
            {
                "role": "report",
                "path": [CANARY],
                "sha256": "a" * 64,
                "required": True,
            }
        ]
        _write_records(path, records)
    else:  # pragma: no cover
        raise AssertionError(kind)
    return path


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("invalid_utf8", "Invalid trace UTF-8 on line 2"),
        ("malformed_json", "Invalid trace JSON on line 1"),
        ("deep_json", "Invalid trace JSON on line 1"),
        ("wrong_shape", "Invalid trace record on line 1"),
    ],
)
def test_bounded_hostile_fixtures_reach_the_intended_rejection(
    benchmark_result,
    tmp_path: Path,
    kind: str,
    expected: str,
) -> None:
    path = _hostile_file(kind, benchmark_result, tmp_path)
    with pytest.raises(ValueError, match=expected):
        load_execution_trace(path)


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("kind", KINDS)
def test_every_trace_command_rejects_each_bounded_hostile_class_without_disclosure(
    benchmark_result,
    tmp_path: Path,
    command: str,
    kind: str,
) -> None:
    path = _hostile_file(kind, benchmark_result, tmp_path)
    result = runner.invoke(app, ["trace", command, str(path)])

    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert CANARY not in result.output


@pytest.mark.parametrize(
    "hostile",
    [
        f"/private/{CANARY}/secret.txt",
        rf"C:\\Users\\{CANARY}\\secret.txt",
        rf"\\\\server\\{CANARY}\\share\\secret.txt",
        f"../{CANARY}/secret.txt",
    ],
)
def test_normalized_path_rejects_absolute_drive_unc_and_traversal_without_echo(
    hostile: str,
) -> None:
    with pytest.raises(ValueError, match="repository-relative") as excinfo:
        trace_module._normalized_path(hostile)
    assert CANARY not in str(excinfo.value)
    assert hostile not in str(excinfo.value)


@pytest.mark.parametrize(
    "valid",
    [
        "docs/notes 2026/café.txt",
        "src/agentguard_trace.py",
        "fixtures/日本語/trace.jsonl",
    ],
)
def test_normalized_path_preserves_valid_relative_unicode_and_spaces(valid: str) -> None:
    assert trace_module._normalized_path(valid) == valid


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(
    "hostile",
    [
        f"/private/{CANARY}/secret.txt",
        rf"C:\\Users\\{CANARY}\\secret.txt",
        rf"\\\\server\\{CANARY}\\share\\secret.txt",
        f"../{CANARY}/secret.txt",
    ],
)
def test_public_commands_reject_each_hostile_path_form_without_echo(
    benchmark_result,
    tmp_path: Path,
    command: str,
    hostile: str,
) -> None:
    trace = _trace(benchmark_result)
    records = _records(trace)
    completed = next(
        record
        for record in records
        if record.get("record_type") == "event"
        and record["event_type"] == "execution_completed"
    )
    completed["payload"]["modified_files"]["paths"] = [hostile]
    completed["payload"]["modified_files"]["count"] = 1
    path = tmp_path / "hostile-path.jsonl"
    _write_records(path, records)

    result = runner.invoke(app, ["trace", command, str(path)])
    assert result.exit_code == 2
    assert "Traceback" not in result.output
    assert CANARY not in result.output
    assert hostile not in result.output
