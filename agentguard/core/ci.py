import subprocess
import warnings
from dataclasses import asdict, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from agentguard.config.loader import load_config
from agentguard.checks.secret_content import with_secret_content_scan
from agentguard.core.orchestrator import default_checks
from agentguard.core.result import CiResult, ReportPaths
from agentguard.core.timeline import TimelineRecorder
from agentguard.history.store import HistoryRecord, record_history, utc_now_iso
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.instrumentation.command_tracker import CommandTracker
from agentguard.instrumentation.test_runner import TestRunner
from agentguard.repo.git_diff import collect_diff, collect_diff_between_refs
from agentguard.provenance.manifest import sanitize_text
from agentguard.scoring.scorer import score_checks


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _git(repo_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def detect_repo_dir(start_dir: Optional[Path] = None) -> Path:
    cwd = (start_dir or Path.cwd()).resolve()
    try:
        root = _git(cwd, "rev-parse", "--show-toplevel")
    except subprocess.CalledProcessError as error:
        raise ValueError(f"{cwd} is not inside a git repository.") from error
    return Path(root).resolve()


def _run_dir(task_id: str, repo_dir: Path, ci_root: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    root = ci_root if ci_root.is_absolute() else repo_dir / ci_root
    return root / f"{task_id}-{timestamp}-{uuid4().hex[:8]}"


def _write_json_report(result: CiResult) -> Path:
    report_path = result.report_paths.json
    data = asdict(result)
    data["command_log_path"] = result.report_paths.command_log
    data["evidence"] = [
        evidence for check in result.check_results for evidence in check.evidence
    ]
    atomic_write_json(report_path, data, default=_json_default)
    return report_path


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def _event_flags(event) -> str:
    flags = []
    if event.timed_out:
        flags.append("timed out")
    if event.stdout_truncated:
        flags.append("stdout truncated")
    if event.stderr_truncated:
        flags.append("stderr truncated")
    return f" ({', '.join(flags)})" if flags else ""


def _write_markdown_report(result: CiResult) -> Path:
    report_path = result.report_paths.markdown
    lines = [
        "# AgentGuard CI Report",
        "",
        f"Task: {result.task_id}",
        f"Result: {result.result}",
        f"Score: {result.score}/100",
        f"Config: {result.config_path}",
        f"Repository: {result.repo_dir}",
        "",
        "## Test Result",
        f"- Command: {result.test_result.command}",
        f"- Exit code: {result.test_result.exit_code}",
        "",
        "## Diff Summary",
        f"- Modified: {len(result.diff_summary.modified_files)}",
        f"- Added: {len(result.diff_summary.added_files)}",
        f"- Deleted: {len(result.diff_summary.deleted_files)}",
        f"- Lines added: {result.diff_summary.lines_added}",
        f"- Lines deleted: {result.diff_summary.lines_deleted}",
        "",
        "## Checks",
    ]
    for check in result.check_results:
        lines.append(
            f"- {_status(check.passed)} [{check.severity}] "
            f"{check.name}: {check.message}"
        )
        if not check.passed and check.evidence:
            lines.append("  Evidence:")
            lines.extend(f"  - {evidence}" for evidence in check.evidence)

    lines.extend(["", "## Modified Files"])
    if result.diff_summary.changed_files:
        lines.extend(f"- {path}" for path in result.diff_summary.changed_files)
    else:
        lines.append("- None")

    lines.extend(["", "## Timeline"])
    if result.timeline:
        lines.extend(
            f"{event.order}. [{event.event_type}] {event.message}"
            for event in result.timeline
        )
    else:
        lines.append("- None")

    lines.extend(["", "## Command Events"])
    if result.report_paths.command_log is not None:
        lines.append(f"Command log: {result.report_paths.command_log}")
    if result.command_events:
        for event in result.command_events:
            status = "executed" if event.executed else "blocked"
            lines.append(f"- [{status}] {event.command_text}{_event_flags(event)}")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Reports",
            f"- JSON: {result.report_paths.json}",
            f"- Markdown: {result.report_paths.markdown}",
            "",
        ]
    )
    atomic_write_text(report_path, "\n".join(lines))
    return report_path


def _record_ci_history(result: CiResult) -> None:
    try:
        record_history(
            HistoryRecord(
                id=result.run_dir.name,
                run_type="ci",
                name=result.task_id,
                result=result.result,
                score=result.score,
                created_at=utc_now_iso(),
                json_report_path=result.report_paths.json,
                markdown_report_path=result.report_paths.markdown,
                command_log_path=result.report_paths.command_log,
                failed_checks=[
                    check.name for check in result.check_results if not check.passed
                ],
            )
        )
    except Exception as error:
        warnings.warn(
            f"AgentGuard history write failed: {error}",
            RuntimeWarning,
            stacklevel=2,
        )


def run_ci(
    config_path: Path,
    repo_dir: Optional[Path] = None,
    ci_root: Path = Path(".agentguard/ci"),
    base_ref: Optional[str] = None,
    head_ref: Optional[str] = None,
) -> CiResult:
    config = load_config(config_path)
    timeline = TimelineRecorder()
    timeline.add(
        "ci_started",
        f"CI run started for task {config.task_id}",
        {"task_id": config.task_id},
    )

    detected_repo_dir = detect_repo_dir(repo_dir)
    timeline.add(
        "repo_detected",
        "Detected git repository",
        {"repo_dir": str(detected_repo_dir)},
    )

    run_dir = _run_dir(config.task_id, detected_repo_dir, ci_root)
    run_dir.mkdir(parents=True, exist_ok=False)

    command_tracker = CommandTracker()
    timeline.add(
        "tests_started",
        f"Tests started: {config.test_command}",
        {"command": config.test_command},
    )
    test_result = TestRunner(
        command_tracker,
        timeout_seconds=config.command_timeout_seconds,
        max_output_bytes=config.max_output_bytes,
    ).run(
        detected_repo_dir,
        config.test_command,
    )
    timeline.add(
        "tests_completed",
        f"Tests completed with exit code {test_result.exit_code}",
        {"test_exit_code": test_result.exit_code},
    )

    if base_ref is not None and head_ref is not None:
        diff_mode = "refs"
        diff_summary = collect_diff_between_refs(
            detected_repo_dir,
            base_ref,
            head_ref,
        )
        diff_metadata = {
            "diff_mode": diff_mode,
            "base_ref": base_ref,
            "head_ref": head_ref,
        }
    else:
        diff_mode = "working_tree"
        diff_summary = collect_diff(detected_repo_dir)
        diff_metadata = {"diff_mode": diff_mode}
    diff_summary = with_secret_content_scan(
        detected_repo_dir,
        diff_summary,
        config.secret_content_patterns,
    )

    timeline.add(
        "diff_collected",
        (
            "Collected diff: "
            f"{len(diff_summary.modified_files)} modified, "
            f"{len(diff_summary.added_files)} added, "
            f"{len(diff_summary.deleted_files)} deleted"
        ),
        {
            **diff_metadata,
            "modified_files": diff_summary.modified_files,
            "added_files": diff_summary.added_files,
            "deleted_files": diff_summary.deleted_files,
        },
    )

    check_results = [
        check.run(config, test_result, diff_summary, command_tracker.events)
        for check in default_checks()
    ]
    if config.secret_content_patterns:
        sensitive_values = [
            pattern.contains
            for pattern in config.secret_content_patterns
            if pattern.contains
        ]
        test_result = replace(
            test_result,
            command=sanitize_text(test_result.command, sensitive_values),
            stdout=sanitize_text(test_result.stdout, sensitive_values),
            stderr=sanitize_text(test_result.stderr, sensitive_values),
        )
        diff_summary = replace(
            diff_summary,
            unified_diff=sanitize_text(
                diff_summary.unified_diff, sensitive_values
            ),
        )
        check_results = [
            replace(
                check,
                message=sanitize_text(check.message, sensitive_values),
                evidence=[
                    sanitize_text(item, sensitive_values)
                    for item in check.evidence
                ],
            )
            for check in check_results
        ]
    score_result = score_checks(check_results)
    failed_check_names = [check.name for check in check_results if not check.passed]
    blocking_failures = [
        check.name
        for check in check_results
        if not check.passed and check.severity in {"error", "critical"}
    ]
    timeline.add(
        "checks_completed",
        f"Checks completed: {len(blocking_failures)} blocking failures",
        {
            "failed_check_names": failed_check_names,
            "blocking_failure_count": len(blocking_failures),
            "score": score_result.score,
            "result": score_result.result,
        },
    )

    command_log_path = command_tracker.write_json(run_dir)
    report_paths = ReportPaths(
        json=run_dir / "report.json",
        markdown=run_dir / "report.md",
        command_log=command_log_path,
    )
    timeline.add(
        "reports_written",
        "Reports written",
        {
            "json_report_path": str(report_paths.json),
            "markdown_report_path": str(report_paths.markdown),
            "command_log_path": str(command_log_path),
        },
    )
    timeline.add(
        "ci_completed",
        f"Final result: {score_result.result}, score {score_result.score}/100",
        {
            "result": score_result.result,
            "score": score_result.score,
            "failed_check_names": failed_check_names,
        },
    )

    result = CiResult(
        task_id=config.task_id,
        result=score_result.result,
        score=score_result.score,
        config_path=config.config_path,
        run_dir=run_dir,
        repo_dir=detected_repo_dir,
        test_result=test_result,
        diff_summary=diff_summary,
        check_results=check_results,
        report_paths=report_paths,
        command_events=command_tracker.events,
        timeline=timeline.events,
    )
    json_path = _write_json_report(result)
    markdown_path = _write_markdown_report(result)

    result = CiResult(
        task_id=result.task_id,
        result=result.result,
        score=result.score,
        config_path=result.config_path,
        run_dir=result.run_dir,
        repo_dir=result.repo_dir,
        test_result=result.test_result,
        diff_summary=result.diff_summary,
        check_results=result.check_results,
        report_paths=ReportPaths(
            json=json_path,
            markdown=markdown_path,
            command_log=command_log_path,
        ),
        command_events=result.command_events,
        timeline=result.timeline,
    )
    _record_ci_history(result)
    return result
