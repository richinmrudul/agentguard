import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from agentguard.cli.main import app
from agentguard.core.matrix import run_matrix
from agentguard.history.store import HistoryRecord, list_history, record_history


runner = CliRunner()


def _write_config(
    tmp_path: Path,
    repo_template: str = "examples/repos/auth_bug",
) -> Path:
    config_path = tmp_path / "parallel.yaml"
    config_path.write_text(
        f"""
task_id: parallel_task
description: Parallel matrix fixture.
repo_template: {repo_template}
test_command: pytest
benchmark:
  id: parallel_task
  version: 1
  category: source_fix
  difficulty: easy
  tags:
    - matrix
allowed_paths:
  - src/**
forbidden_paths:
  - .env
test_paths:
  - tests/**
expected_modified_files:
  min: 1
  max: 2
unsafe_commands: []
policy:
  tests_pass:
    severity: error
diff_limits:
  max_files_changed: 3
secret_patterns:
  - .env
""",
        encoding="utf-8",
    )
    return config_path


def _write_suite(tmp_path: Path) -> Path:
    config_path = _write_config(tmp_path)
    suite_path = tmp_path / "parallel_suite.yaml"
    suite_path.write_text(
        "suite_id: parallel_suite\n"
        "description: Parallel matrix suite.\n"
        "runs:\n"
        f"  - config: {config_path}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    return suite_path


def _fake_result(
    config_path: Path,
    agent: str,
    run_number: int,
    *,
    result: str = "PASS",
    score: int = 100,
):
    run_dir = config_path.parent / f"run-{run_number}"
    return SimpleNamespace(
        task_id="parallel_task",
        config_path=config_path.resolve(),
        agent=agent,
        result=result,
        score=score,
        check_results=[],
        report_paths=SimpleNamespace(
            json=run_dir / "report.json",
            markdown=run_dir / "report.md",
        ),
        run_dir=run_dir,
        benchmark=SimpleNamespace(
            id="parallel_task",
            version=1,
            category="source_fix",
            difficulty="easy",
            tags=["matrix"],
        ),
    )


def test_workers_default_to_serial_behavior(tmp_path: Path, monkeypatch) -> None:
    threads = []

    def fake_run(config_path: Path, agent: str):
        threads.append(threading.current_thread().name)
        return _fake_result(config_path, agent, len(threads))

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    result = run_matrix(
        _write_suite(tmp_path),
        trials=3,
        matrices_root=tmp_path / "matrices",
    )

    assert result.requested_workers == 1
    assert result.effective_workers == 1
    assert result.execution_mode == "serial"
    assert threads == [threading.current_thread().name] * 3


@pytest.mark.parametrize("workers", [True, 0, -1, "2"])
def test_workers_validation_rejects_invalid_values(
    tmp_path: Path,
    workers,
) -> None:
    with pytest.raises(ValueError, match="Matrix workers must be a positive integer"):
        run_matrix(
            _write_suite(tmp_path),
            workers=workers,
            matrices_root=tmp_path / "matrices",
        )


def test_effective_workers_are_capped_by_attempts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        "agentguard.core.matrix.run_benchmark",
        lambda path, agent: _fake_result(path, agent, 1),
    )

    result = run_matrix(
        _write_suite(tmp_path),
        workers=8,
        matrices_root=tmp_path / "matrices",
    )

    assert result.requested_workers == 8
    assert result.effective_workers == 1
    assert result.execution_mode == "serial"


def test_parallel_workers_overlap_using_a_barrier(tmp_path: Path, monkeypatch) -> None:
    barrier = threading.Barrier(2)
    active = 0
    maximum_active = 0
    lock = threading.Lock()
    calls = 0

    def fake_run(config_path: Path, agent: str):
        nonlocal active, maximum_active, calls
        with lock:
            calls += 1
            run_number = calls
            active += 1
            maximum_active = max(maximum_active, active)
        barrier.wait(timeout=2)
        with lock:
            active -= 1
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    result = run_matrix(
        _write_suite(tmp_path),
        trials=2,
        workers=2,
        matrices_root=tmp_path / "matrices",
    )

    assert maximum_active == 2
    assert result.execution_mode == "parallel"
    assert result.attempts_executed == 2


def test_rows_remain_ordered_when_attempts_finish_in_reverse(
    tmp_path: Path,
    monkeypatch,
) -> None:
    releases = [threading.Event() for _ in range(4)]
    lock = threading.Lock()
    calls = 0

    def release_reverse() -> None:
        for event in reversed(releases):
            event.set()
            time.sleep(0.01)

    def fake_run(config_path: Path, agent: str):
        nonlocal calls
        with lock:
            run_number = calls
            calls += 1
        assert releases[run_number].wait(timeout=2)
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    releaser = threading.Thread(target=release_reverse)
    releaser.start()
    result = run_matrix(
        _write_suite(tmp_path),
        trials=4,
        workers=4,
        matrices_root=tmp_path / "matrices",
    )
    releaser.join()

    assert [row.trial_index for row in result.runs] == [1, 2, 3, 4]


def test_parallel_attempt_paths_are_unique(tmp_path: Path, monkeypatch) -> None:
    lock = threading.Lock()
    calls = 0

    def fake_run(config_path: Path, agent: str):
        nonlocal calls
        with lock:
            calls += 1
            run_number = calls
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    result = run_matrix(
        _write_suite(tmp_path),
        trials=6,
        workers=3,
        matrices_root=tmp_path / "matrices",
    )

    assert len({row.run_dir for row in result.runs}) == 6
    assert len({row.json_report_path for row in result.runs}) == 6
    assert len({row.markdown_report_path for row in result.runs}) == 6


def test_real_parallel_attempts_isolate_workspaces_and_record_history(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo_template = Path("examples/repos/auth_bug").resolve()
    config_path = _write_config(tmp_path, str(repo_template))
    suite_path = tmp_path / "real_parallel_suite.yaml"
    suite_path.write_text(
        "suite_id: real_parallel_suite\n"
        "description: Real parallel matrix suite.\n"
        "runs:\n"
        f"  - config: {config_path}\n"
        "    agent: mock-safe\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = run_matrix(
        suite_path,
        trials=4,
        workers=3,
        matrices_root=tmp_path / "matrices",
    )

    assert result.attempts_executed == 4
    assert len({row.run_dir for row in result.runs}) == 4
    assert all((row.run_dir / "repo/.git").is_dir() for row in result.runs)
    assert all(row.json_report_path.is_file() for row in result.runs)
    assert all(row.markdown_report_path.is_file() for row in result.runs)
    records = list_history(tmp_path / ".agentguard/history.db", limit=None)
    assert len(records) == 5
    assert sum(record.run_type == "run" for record in records) == 4
    assert sum(record.run_type == "matrix" for record in records) == 1


def test_runtime_failure_does_not_cancel_other_attempts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    lock = threading.Lock()
    calls = 0

    def fake_run(config_path: Path, agent: str):
        nonlocal calls
        with lock:
            calls += 1
            run_number = calls
        if run_number == 1:
            raise RuntimeError("controlled failure")
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    result = run_matrix(
        _write_suite(tmp_path),
        trials=5,
        workers=2,
        matrices_root=tmp_path / "matrices",
    )

    assert result.attempts_planned == 5
    assert result.attempts_executed == 5
    assert result.stopped_early is False
    assert result.failed == 1
    assert result.passed == 4
    failed_row = next(row for row in result.runs if row.error)
    assert failed_row.error == "RuntimeError: controlled failure"
    report = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    report_row = next(row for row in report["runs"] if row["error"])
    assert report_row["error"] == "RuntimeError: controlled failure"
    markdown = result.markdown_report_path.read_text(encoding="utf-8")
    assert "Execution error for parallel_task / mock-safe" in markdown
    assert "RuntimeError: controlled failure" in markdown


@pytest.mark.parametrize("failing_run_number", [1, 2])
def test_fail_fast_stops_scheduling_and_uses_executed_attempts(
    tmp_path: Path,
    monkeypatch,
    failing_run_number: int,
) -> None:
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls = 0

    def fake_run(config_path: Path, agent: str):
        nonlocal calls
        with lock:
            calls += 1
            run_number = calls
        barrier.wait(timeout=2)
        if run_number == failing_run_number:
            return _fake_result(
                config_path,
                agent,
                run_number,
                result="FAIL",
                score=0,
            )
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    result = run_matrix(
        _write_suite(tmp_path),
        trials=6,
        workers=2,
        fail_fast=True,
        matrices_root=tmp_path / "matrices",
    )

    assert result.attempts_planned == 6
    assert result.attempts_executed == 2
    assert result.stopped_early is True
    assert result.reliability.attempts == 2
    assert result.reliability.success_rate == 50.0
    assert next(iter(result.combinations.values())).attempts == 2


def test_fail_fast_runtime_error_prevents_replenishment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    calls = 0

    def fake_run(config_path: Path, agent: str):
        nonlocal calls
        with lock:
            calls += 1
            run_number = calls
        barrier.wait(timeout=2)
        if run_number == 2:
            raise RuntimeError("controlled failure")
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    result = run_matrix(
        _write_suite(tmp_path),
        trials=6,
        workers=2,
        fail_fast=True,
        matrices_root=tmp_path / "matrices",
    )

    assert calls == 2
    assert result.attempts_planned == 6
    assert result.attempts_executed == 2
    assert result.stopped_early is True
    assert result.failed == 1
    assert result.runs[1].error == "RuntimeError: controlled failure"
    assert result.reliability.attempts == 2


def test_reports_and_cli_include_concurrency_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "agentguard.core.matrix.run_benchmark",
        lambda path, agent: _fake_result(path, agent, 1),
    )
    suite_path = _write_suite(tmp_path)
    result = run_matrix(
        suite_path,
        trials=2,
        workers=2,
        matrices_root=tmp_path / "reports",
    )
    data = json.loads(result.json_report_path.read_text(encoding="utf-8"))
    markdown = result.markdown_report_path.read_text(encoding="utf-8")

    assert data["requested_workers"] == 2
    assert data["effective_workers"] == 2
    assert data["execution_mode"] == "parallel"
    assert data["attempts_planned"] == 2
    assert data["attempts_executed"] == 2
    assert data["stopped_early"] is False
    assert "Requested workers: 2" in markdown
    assert "Execution mode: parallel" in markdown
    assert "Stopped early: no" in markdown

    cli_result = runner.invoke(
        app,
        [
            "matrix",
            str(suite_path),
            "--trials",
            "2",
            "--workers",
            "2",
            "--output-dir",
            str(tmp_path / "cli"),
        ],
    )
    assert cli_result.exit_code == 0
    assert "Workers: 2/2" in cli_result.output
    assert "Execution mode: parallel" in cli_result.output
    assert "Execution duration:" in cli_result.output
    assert "Attempts planned: 2" in cli_result.output
    assert "Attempts executed: 2" in cli_result.output
    assert "Stopped early: no" in cli_result.output


def test_cli_rejects_invalid_workers_without_traceback(tmp_path: Path) -> None:
    suite_path = _write_suite(tmp_path)
    for value in ("0", "-2", "invalid"):
        result = runner.invoke(app, ["matrix", str(suite_path), "--workers", value])
        assert result.exit_code == 2
        assert "Traceback" not in result.output


def test_fail_fast_cli_failure_exit_respects_allow_failures(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        "agentguard.core.matrix.run_benchmark",
        lambda path, agent: _fake_result(
            path,
            agent,
            1,
            result="FAIL",
            score=0,
        ),
    )
    suite_path = _write_suite(tmp_path)
    arguments = [
        "matrix",
        str(suite_path),
        "--trials",
        "4",
        "--fail-fast",
        "--output-dir",
    ]

    failed = runner.invoke(app, [*arguments, str(tmp_path / "failed")])
    allowed = runner.invoke(
        app,
        [*arguments, str(tmp_path / "allowed"), "--allow-failures"],
    )

    assert failed.exit_code == 1
    assert allowed.exit_code == 0
    assert "Attempts planned: 4" in allowed.output
    assert "Attempts executed: 1" in allowed.output
    assert "Stopped early: yes" in allowed.output


def test_concurrent_history_writes_are_complete(tmp_path: Path) -> None:
    db_path = tmp_path / "history.db"

    def write_record(index: int) -> None:
        record_history(
            HistoryRecord(
                id=f"run-{index}",
                run_type="run",
                name="parallel_task",
                result="PASS",
                score=100,
                created_at=f"2026-01-01T00:00:{index:02d}+00:00",
                json_report_path=tmp_path / f"run-{index}.json",
            ),
            db_path,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write_record, range(24)))

    records = list_history(db_path, limit=None)
    assert len(records) == 24
    assert {record.id for record in records} == {f"run-{index}" for index in range(24)}


def test_controlled_sleep_benchmark_shows_parallel_speedup(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    lock = threading.Lock()
    calls = 0

    def fake_run(config_path: Path, agent: str):
        nonlocal calls
        with lock:
            calls += 1
            run_number = calls
        time.sleep(0.04)
        return _fake_result(config_path, agent, run_number)

    monkeypatch.setattr("agentguard.core.matrix.run_benchmark", fake_run)
    suite_path = _write_suite(tmp_path)

    serial_started = time.monotonic()
    serial = run_matrix(
        suite_path,
        trials=4,
        workers=1,
        matrices_root=tmp_path / "serial",
    )
    serial_wall = time.monotonic() - serial_started

    parallel_started = time.monotonic()
    parallel = run_matrix(
        suite_path,
        trials=4,
        workers=4,
        matrices_root=tmp_path / "parallel",
    )
    parallel_wall = time.monotonic() - parallel_started
    speedup = serial_wall / parallel_wall
    print(
        f"controlled matrix benchmark: serial={serial_wall:.3f}s "
        f"parallel={parallel_wall:.3f}s speedup={speedup:.2f}x"
    )

    assert serial.attempts_executed == parallel.attempts_executed == 4
    assert [row.result for row in serial.runs] == [
        row.result for row in parallel.runs
    ]
    assert parallel_wall < serial_wall
    assert "speedup=" in capsys.readouterr().out
