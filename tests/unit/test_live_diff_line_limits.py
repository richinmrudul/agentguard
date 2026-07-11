import json
import os
import shlex
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agentguard.config.loader import load_config
from agentguard.config.schema import DiffLimits
from agentguard.core.matrix import MatrixRowSummary
from agentguard.core.orchestrator import run_benchmark
from agentguard.guard.aggregation import aggregate_matrix_guard
from agentguard.guard.filesystem import (
    GuardMode,
    ProcessController,
    RuntimeFilesystemGuard,
)
from agentguard.guard.watcher import FilesystemWatchEvent
from agentguard.repo.git_diff import collect_diff
from agentguard.repo.live_diff import (
    LiveDiffCandidate,
    LiveLineMeasurement,
    measure_live_line_diff,
)
from agentguard.traces import execution as trace_execution
from agentguard.traces.execution import load_execution_trace, verify_execution_trace


ROOT = Path(__file__).resolve().parents[2]


def test_no_thresholds_skip_line_measurer(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    config = _config(repo)

    def unexpected(*args):
        raise AssertionError("line measurement should be skipped")

    guard = _guard(repo, config, line_measurer=unexpected)
    (repo / "src/app.py").write_text("one\ntwo\n", encoding="utf-8")

    guard.scan_once()

    assert guard.summary().live_lines_added == 0
    assert guard.summary().line_measurement_complete is True


def test_unchanged_metadata_skips_configured_line_measurement(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    config = _config(repo, DiffLimits(max_lines_added=1))

    def unexpected(*args):
        raise AssertionError("unchanged files should not be measured")

    guard = _guard(repo, config, line_measurer=unexpected)

    assert guard.scan_once() == []
    assert guard.summary().line_measurement_complete is True


@pytest.mark.parametrize(
    ("measured", "limit", "violates"),
    [(1, 2, False), (2, 2, False), (3, 2, True)],
)
def test_added_threshold_is_strictly_greater_than(
    tmp_path: Path,
    measured: int,
    limit: int,
    violates: bool,
) -> None:
    summary = _scan_with_measurement(
        tmp_path,
        LiveLineMeasurement(lines_added=measured),
        DiffLimits(max_lines_added=limit),
    )

    assert ("diff_lines_added" in _types(summary)) is violates


@pytest.mark.parametrize(
    ("measured", "limit", "violates"),
    [(1, 2, False), (2, 2, False), (3, 2, True)],
)
def test_deleted_threshold_is_strictly_greater_than(
    tmp_path: Path,
    measured: int,
    limit: int,
    violates: bool,
) -> None:
    summary = _scan_with_measurement(
        tmp_path,
        LiveLineMeasurement(lines_deleted=measured),
        DiffLimits(max_lines_deleted=limit),
    )

    assert ("diff_lines_deleted" in _types(summary)) is violates


def test_both_thresholds_are_retained_without_duplicates(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    config = _config(
        repo,
        DiffLimits(max_lines_added=1, max_lines_deleted=1),
    )
    measurement = LiveLineMeasurement(lines_added=2, lines_deleted=3)
    guard = _guard(repo, config, line_measurer=lambda *_: measurement)
    (repo / "src/app.py").write_text("changed\n", encoding="utf-8")

    guard.scan_once()
    guard.scan_once()

    assert [item.violation_type for item in guard.summary().violations] == [
        "diff_lines_added",
        "diff_lines_deleted",
    ]


def test_current_delta_is_not_cumulative_edit_churn(tmp_path: Path) -> None:
    repo = _repo(tmp_path, content="base\n")
    config = _config(repo, DiffLimits(max_lines_added=2))
    guard = _guard(repo, config)

    (repo / "src/app.py").write_text("base\none\ntwo\nthree\n", encoding="utf-8")
    guard.scan_once()
    assert guard.summary().live_lines_added == 3

    (repo / "src/app.py").write_text("base\none\n", encoding="utf-8")
    guard.scan_once()
    assert guard.summary().live_lines_added == 1
    assert "diff_lines_added" in _types(guard.summary())


def test_initial_guard_baseline_survives_agent_git_commit(tmp_path: Path) -> None:
    repo = _repo(tmp_path, content="base\n")
    config = _config(repo, DiffLimits(max_lines_added=100))
    guard = _guard(repo, config)

    (repo / "src/app.py").write_text("base\nadded\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "agent commit")
    guard.scan_once()

    assert guard.summary().live_lines_added == 1


def test_new_deleted_modified_and_missing_newline_match_post_hoc_diff(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path, content="one\ntwo\nthree\n")
    (repo / "delete.txt").write_text("alpha\nbeta\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "add deletion fixture")
    config = _config(
        repo,
        DiffLimits(max_lines_added=100, max_lines_deleted=100),
    )
    guard = _guard(repo, config)

    (repo / "src/app.py").write_text("one\nchanged\nthree\nfour", encoding="utf-8")
    (repo / "new.txt").write_text("new\nwithout-final-newline", encoding="utf-8")
    (repo / "empty.txt").write_bytes(b"")
    (repo / "delete.txt").unlink()
    guard.scan_once()
    post_hoc = collect_diff(repo)

    assert guard.summary().live_lines_added == post_hoc.lines_added
    assert guard.summary().live_lines_deleted == post_hoc.lines_deleted


def test_rename_follows_existing_post_hoc_semantics(tmp_path: Path) -> None:
    repo = _repo(tmp_path, content="one\ntwo\n")
    config = _config(
        repo,
        DiffLimits(max_lines_added=100, max_lines_deleted=100),
    )
    guard = _guard(repo, config)

    (repo / "src/app.py").rename(repo / "src/renamed.py")
    guard.scan_once()
    post_hoc = collect_diff(repo)

    assert guard.summary().live_lines_added == post_hoc.lines_added
    assert guard.summary().live_lines_deleted == post_hoc.lines_deleted


def test_invalid_utf8_is_counted_without_decoding(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "invalid.bin"
    path.write_bytes(b"\xff\ntext")
    measurement = measure_live_line_diff(
        repo,
        [LiveDiffCandidate("invalid.bin", None, path.stat().st_size)],
    )

    assert measurement.lines_added == 2
    assert measurement.complete is True


def test_binary_file_marks_measurement_incomplete(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "binary.bin"
    path.write_bytes(b"prefix\x00suffix")
    measurement = measure_live_line_diff(
        repo,
        [LiveDiffCandidate("binary.bin", None, path.stat().st_size)],
    )

    assert measurement.complete is False
    assert measurement.skipped_files == 1
    assert "binary or unreadable" in measurement.error


def test_file_and_total_bounds_mark_measurement_incomplete(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    first = repo / "first.txt"
    second = repo / "second.txt"
    first.write_text("12345", encoding="utf-8")
    second.write_text("67890", encoding="utf-8")
    candidates = [
        LiveDiffCandidate("first.txt", None, 5),
        LiveDiffCandidate("second.txt", None, 5),
    ]

    file_bound = measure_live_line_diff(repo, candidates, max_file_bytes=4)
    total_bound = measure_live_line_diff(repo, candidates, max_total_bytes=5)
    file_count_bound = measure_live_line_diff(repo, candidates, max_files=1)

    assert file_bound.complete is False
    assert file_bound.skipped_files == 2
    assert total_bound.complete is False
    assert total_bound.skipped_files == 1
    assert file_count_bound.complete is False
    assert file_count_bound.skipped_files == 1


def test_disappearing_and_unreadable_files_are_incomplete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repo = _repo(tmp_path)
    disappearing = repo / "gone.txt"
    disappearing.write_text("gone\n", encoding="utf-8")
    candidate = LiveDiffCandidate("gone.txt", None, disappearing.stat().st_size)
    disappearing.unlink()

    disappeared = measure_live_line_diff(repo, [candidate])
    monkeypatch.setattr(
        "agentguard.repo.live_diff._bounded_untracked_line_count",
        lambda *args, **kwargs: None,
    )
    unreadable_path = repo / "unreadable.txt"
    unreadable_path.write_text("hidden", encoding="utf-8")
    unreadable = measure_live_line_diff(
        repo,
        [LiveDiffCandidate("unreadable.txt", None, 6)],
    )

    assert disappeared.complete is False
    assert unreadable.complete is False


def test_git_failure_is_incomplete_without_raw_stderr(tmp_path: Path) -> None:
    repo = tmp_path / "not-a-repository"
    repo.mkdir()
    (repo / "file.txt").write_text("line\n", encoding="utf-8")

    measurement = measure_live_line_diff(
        repo,
        [LiveDiffCandidate("file.txt", None, 5)],
    )

    assert measurement.complete is False
    assert measurement.lines_added == 0
    assert measurement.error == "Line measurement incomplete: Git diff unavailable."
    assert "fatal:" not in measurement.error


def test_option_like_filename_cannot_inject_git_arguments(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    path = repo / "--no-index"
    path.write_text("one\ntwo\n", encoding="utf-8")

    measurement = measure_live_line_diff(
        repo,
        [LiveDiffCandidate("--no-index", None, path.stat().st_size)],
    )

    assert measurement.lines_added == 2
    assert measurement.complete is True


def test_ignored_files_do_not_contribute_but_adjacent_files_do(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    config = replace(
        _config(repo, DiffLimits(max_lines_added=100)),
        guard_ignore_paths=["coverage/**"],
    )
    guard = _guard(repo, config)

    (repo / "coverage").mkdir()
    (repo / "coverage/ignored.txt").write_text("a\nb\nc\n", encoding="utf-8")
    (repo / "visible.txt").write_text("one\ntwo\n", encoding="utf-8")
    guard.scan_once()

    assert guard.summary().live_lines_added == 2


def test_measurement_failure_does_not_hide_other_guard_evidence(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    config = _config(repo, DiffLimits(max_lines_added=1))

    def unavailable(*args):
        raise OSError("sensitive stderr")

    guard = _guard(repo, config, line_measurer=unavailable)
    (repo / "tests").mkdir()
    (repo / "tests/test_app.py").write_text("tampered\n", encoding="utf-8")

    guard.scan_once()

    assert guard.summary().line_measurement_complete is False
    assert guard.summary().line_measurement_error == (
        "Line measurement incomplete: measurement unavailable."
    )
    assert "test_tampering" in _types(guard.summary())
    assert "sensitive stderr" not in guard.summary().line_measurement_error


def test_audit_records_and_enforce_terminates_supported_agent(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    config = _config(repo, DiffLimits(max_lines_added=1))
    measurement = LiveLineMeasurement(lines_added=2)
    audit_controller = ProcessController()
    audit = _guard(
        repo,
        config,
        mode=GuardMode.AUDIT,
        process_controller=audit_controller,
        line_measurer=lambda *_: measurement,
    )
    (repo / "src/app.py").write_text("changed\n", encoding="utf-8")
    audit.scan_once()

    enforce_controller = ProcessController()
    enforce = _guard(
        repo,
        config,
        mode=GuardMode.ENFORCE,
        process_controller=enforce_controller,
        line_measurer=lambda *_: measurement,
    )
    (repo / "src/app.py").write_text("changed again\n", encoding="utf-8")
    enforce.scan_once()

    assert audit.summary().terminated_agent is False
    assert audit.summary().violations[0].action == "recorded"
    assert enforce.summary().terminated_agent is True
    assert enforce.summary().violations[0].action == "terminated"


def test_max_files_changed_and_symlink_escape_remain_active(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    config = replace(
        _config(
            repo,
            DiffLimits(max_files_changed=0, max_lines_added=100),
        ),
        guard_ignore_paths=["coverage/**"],
    )
    guard = _guard(repo, config)
    (repo / "coverage").mkdir()
    os.symlink(tmp_path.parent, repo / "coverage/escape")

    guard.scan_once()

    assert {"diff_size", "symlink_escape"} <= _types(guard.summary())


def test_reports_manifest_trace_and_incident_include_live_measurement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    agent_script = tmp_path / "agent.py"
    agent_script.write_text(
        "import pathlib\n"
        "path = pathlib.Path('src/app.py')\n"
        "path.write_text('one\\ntwo\\nthree\\n')\n",
        encoding="utf-8",
    )
    config_path = _write_run_config(tmp_path, agent_script)

    result = run_benchmark(
        config_path,
        "local-command",
        guard_mode=GuardMode.AUDIT,
        guard_poll_interval_seconds=0.01,
    )

    report = json.loads(result.report_paths.json.read_text(encoding="utf-8"))
    manifest = json.loads(result.report_paths.manifest.read_text(encoding="utf-8"))
    markdown = result.report_paths.markdown.read_text(encoding="utf-8")
    trace = load_execution_trace(result.report_paths.trace)
    guard_event = next(
        event for event in trace.events if event.event_type == "guard_summary"
    )
    incident = json.loads(
        result.report_paths.guard_incident_json.read_text(encoding="utf-8")
    )

    assert report["guard_summary"]["live_lines_added"] == 3
    assert report["guard_summary"]["live_lines_deleted"] == 3
    assert report["guard_summary"]["line_measurement_complete"] is True
    assert manifest["guard"]["live_lines_added"] == 3
    assert guard_event.payload["live_lines_added"] == 3
    assert "Current lines added: 3" in markdown
    assert {
        item["policy"]
        for item in incident["violations"]
        if item["guard_type"] == "filesystem"
    } == {"diff_size"}
    assert {
        item["evidence_summary"].split(" ", 1)[0]
        for item in incident["violations"]
    } == {"Added", "Deleted"}
    assert verify_execution_trace(result.report_paths.trace).exit_code == 0


def test_old_report_guard_summary_defaults_are_safe() -> None:
    summary = trace_execution._guard_summary_from_dict({"mode": "audit"})

    assert summary.live_lines_added == 0
    assert summary.live_lines_deleted == 0
    assert summary.line_measurement_complete is True
    assert summary.line_measurement_skipped_files == 0
    assert summary.line_measurement_error is None
    assert summary.watcher_mode == "auto"
    assert summary.watcher_events_observed == 0
    assert summary.watcher_events == []
    assert summary.watcher_event_limit_exceeded is False
    assert summary.watcher_event_error is None


def test_watcher_event_retention_cap_reports_sanitized_overflow(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    guard = _guard(repo, _config(repo))
    events = [
        FilesystemWatchEvent(
            path=f"src/generated_{index}.py",
            event_type="created",
            observed_at_sequence=index + 1,
            source="polling",
        )
        for index in range(205)
    ]

    guard._record_scan(
        guard._baseline,
        [],
        LiveLineMeasurement(),
        events,
    )
    summary = guard.summary()

    assert summary.watcher_events_observed == 205
    assert len(summary.watcher_events) == 200
    assert summary.watcher_event_limit_exceeded is True
    assert summary.watcher_event_error == "filesystem watcher event limit exceeded"


def test_matrix_aggregation_counts_both_line_violations(tmp_path: Path) -> None:
    row = MatrixRowSummary(
        task_id="live-lines",
        config_path=Path("config.yaml"),
        agent="local-command",
        result="FAIL",
        score=90,
        failed_checks=[],
        warning_checks=["Diff size"],
        json_report_path=None,
        markdown_report_path=None,
        run_dir=None,
        guard_violations_total=2,
        filesystem_guard_violations=2,
        guard_blocked=False,
    )

    summary = aggregate_matrix_guard([row], tmp_path / "matrix.md")

    assert summary.violations_total == 2
    assert summary.filesystem_violations == 2
    assert summary.incident_runs == 1
    assert summary.audit_only_runs == 1


def _scan_with_measurement(
    tmp_path: Path,
    measurement: LiveLineMeasurement,
    limits: DiffLimits,
):
    repo = _repo(tmp_path)
    guard = _guard(
        repo,
        _config(repo, limits),
        line_measurer=lambda *_: measurement,
    )
    (repo / "src/app.py").write_text("changed\n", encoding="utf-8")
    guard.scan_once()
    return guard.summary()


def _guard(
    repo: Path,
    config,
    *,
    mode: GuardMode = GuardMode.AUDIT,
    process_controller=None,
    line_measurer=measure_live_line_diff,
) -> RuntimeFilesystemGuard:
    guard = RuntimeFilesystemGuard(
        repo_dir=repo,
        config=config,
        mode=mode,
        process_controller=process_controller,
        time_source=lambda: 0.0,
        line_measurer=line_measurer,
    )
    guard._baseline = guard._scan_tree()
    return guard


def _types(summary) -> set[str]:
    return {item.violation_type for item in summary.violations}


def _repo(tmp_path: Path, *, content: str = "base\n") -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src/app.py").write_text(content, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "agentguard@example.com")
    _git(repo, "config", "user.name", "AgentGuard")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")
    return repo


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _config(repo: Path, limits: DiffLimits = DiffLimits()):
    return replace(
        load_config(ROOT / "examples/configs/fix_auth_bug.yaml"),
        repo_template=repo,
        diff_limits=limits,
    )


def _write_run_config(tmp_path: Path, agent_script: Path) -> Path:
    repo = tmp_path / "fixture"
    (repo / "src").mkdir(parents=True)
    (repo / "src/app.py").write_text(
        "old-one\nold-two\nold-three\n",
        encoding="utf-8",
    )
    config = tmp_path / "live-lines.yaml"
    config.write_text(
        f"""
task_id: live_lines
description: Live line measurement test.
repo_template: {repo}
agent_command: {shlex.join([sys.executable, str(agent_script)])}
test_command: {shlex.join([sys.executable, "-c", "print('pass')"])}
allowed_paths:
  - src/**
forbidden_paths: []
test_paths: []
expected_modified_files:
  min: 0
  max: 10
unsafe_commands: []
policy:
  diff_size:
    severity: warning
diff_limits:
  max_files_changed: 10
  max_lines_added: 1
  max_lines_deleted: 1
secret_patterns: []
""",
        encoding="utf-8",
    )
    return config
