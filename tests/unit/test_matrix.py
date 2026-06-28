import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

import agentguard.cli.main as cli_main
import agentguard.core.matrix as matrix_module
from agentguard.cli.main import app
from agentguard.core.matrix import run_matrix
from agentguard.guard.filesystem import DEFAULT_POLL_INTERVAL_SECONDS, GuardMode


ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


def _suite(tmp_path: Path) -> Path:
    path = tmp_path / "suite.yaml"
    config = ROOT / "examples/configs/fix_auth_bug.yaml"
    path.write_text(
        "suite_id: guard_matrix\n"
        "description: Guard matrix fixture.\n"
        "runs:\n"
        f"  - config: {config}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("interval", [0, -1, float("nan"), float("inf")])
def test_matrix_api_rejects_invalid_guard_interval(
    tmp_path: Path,
    interval: float,
) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        run_matrix(
            _suite(tmp_path),
            matrices_root=tmp_path / "out",
            guard_poll_interval_seconds=interval,
        )


def test_parallel_default_children_receive_identical_guard_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = matrix_module.run_benchmark
    calls = []
    lock = threading.Lock()

    def recording_runner(*args, **kwargs):
        with lock:
            calls.append(
                (
                    kwargs["guard_mode"],
                    kwargs["guard_poll_interval_seconds"],
                )
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(matrix_module, "run_benchmark", recording_runner)
    result = run_matrix(
        _suite(tmp_path),
        matrices_root=tmp_path / "out",
        trials=2,
        workers=2,
        guard_mode=GuardMode.AUDIT,
        guard_poll_interval_seconds=0.05,
    )

    assert calls == [(GuardMode.AUDIT, 0.05), (GuardMode.AUDIT, 0.05)]
    report = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")
    assert report["guard_mode"] == "audit"
    assert report["guard_poll_interval_seconds"] == 0.05
    assert "Guard mode: audit" in markdown
    assert "Guard poll interval: 0.05 seconds" in markdown
    assert manifest["matrix"]["guard_mode"] == "audit"
    assert manifest["guard"]["guard_poll_interval_seconds"] == 0.05
    assert all(
        json.loads(row.json_report_path.read_text(encoding="utf-8"))[
            "guard_summary"
        ]["mode"]
        == "audit"
        for row in result.runs
        if row.json_report_path is not None
    )


def test_matrix_cli_defaults_and_forwards_guard_settings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def invoke_matrix(path: Path, **kwargs):
        calls.append(kwargs)
        return run_matrix(path, **kwargs)

    monkeypatch.setattr(cli_main, "run_matrix", invoke_matrix)
    default = runner.invoke(
        app,
        [
            "matrix",
            str(_suite(tmp_path)),
            "--output-dir",
            str(tmp_path / "default"),
        ],
    )
    custom = runner.invoke(
        app,
        [
            "matrix",
            str(_suite(tmp_path)),
            "--output-dir",
            str(tmp_path / "custom"),
            "--guard-mode",
            "audit",
            "--guard-poll-interval",
            "0.05",
        ],
    )

    assert default.exit_code == 0
    assert custom.exit_code == 0
    assert calls[0]["guard_mode"] == GuardMode.OFF
    assert calls[0]["guard_poll_interval_seconds"] == DEFAULT_POLL_INTERVAL_SECONDS
    assert calls[1]["guard_mode"] == GuardMode.AUDIT
    assert calls[1]["guard_poll_interval_seconds"] == 0.05
    assert "Guard mode: off" in default.output
    assert "Guard mode: audit" in custom.output


def test_custom_benchmark_runner_contract_is_unchanged(tmp_path: Path) -> None:
    calls = []

    def custom_runner(path: Path, agent: str, matrix_id: str):
        calls.append((path, agent, matrix_id))
        return matrix_module.run_benchmark(path, agent)

    result = run_matrix(
        _suite(tmp_path),
        matrices_root=tmp_path / "out",
        benchmark_runner=custom_runner,
        guard_mode=GuardMode.AUDIT,
        guard_poll_interval_seconds=0.05,
    )
    assert result.total_runs == 1
    assert len(calls) == 1


def test_audit_incident_does_not_independently_change_batch_result(
    tmp_path: Path,
) -> None:
    def custom_runner(path: Path, agent: str, _matrix_id: str):
        child = matrix_module.run_benchmark(
            path,
            agent,
            guard_mode=GuardMode.AUDIT,
            guard_poll_interval_seconds=0.05,
        )
        incident_dir = child.run_dir / "guard"
        incident_dir.mkdir()
        incident_json = incident_dir / "incident.json"
        incident_markdown = incident_dir / "incident.md"
        incident_json.write_text('{"blocked": false}\n', encoding="utf-8")
        incident_markdown.write_text("# Audit incident\n", encoding="utf-8")
        return replace(
            child,
            report_paths=replace(
                child.report_paths,
                guard_incident_json=incident_json,
                guard_incident_markdown=incident_markdown,
            ),
        )

    result = run_matrix(
        _suite(tmp_path),
        matrices_root=tmp_path / "out",
        benchmark_runner=custom_runner,
        guard_mode=GuardMode.AUDIT,
        guard_poll_interval_seconds=0.05,
    )
    assert result.passed == 1
    assert result.failed == 0
