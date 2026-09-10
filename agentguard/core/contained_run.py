from __future__ import annotations

import os
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Sequence
from uuid import uuid4

from agentguard.artifact_paths import artifact_directory
from agentguard.checks.secret_content import with_secret_content_scan
from agentguard.config.loader import load_config
from agentguard.config.schema import AgentGuardConfig
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.instrumentation.output_limits import (
    BoundedProcessOutput,
    LimitedOutput,
    ProcessOutput,
    limit_output,
)
from agentguard.instrumentation.processes import (
    PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS,
    ProcessCleanupResult,
    append_cleanup_message,
    cleanup_process_after_exception,
    process_timeout_message,
    terminate_process_tree,
)
from agentguard.io import atomic_write_json
from agentguard.policy.command_policy import evaluate_command_policy
from agentguard.policy.evaluation import PolicyEvaluationContext, evaluate_policy_checks
from agentguard.provenance.manifest import sanitize_text
from agentguard.redaction import redact_credential_arguments, redact_credentials
from agentguard.sandbox.contained_workspace import (
    DEFAULT_AGENT_WORKSPACE_PATH,
    ContainedWorkspaceError,
    ContainedWorkspaceMutationError,
    PreparedContainedWorkspace,
    prepare_contained_workspace,
)
from agentguard.sandbox.docker_exec_spec import (
    build_contained_docker_run_argv,
    contained_exec_spec_from_config,
    validate_workspace_mount_containment,
)
from agentguard.sandbox.docker_preflight import (
    DockerPreflightResult,
    DockerPreflightStatus,
    run_docker_preflight,
)
from agentguard.scoring.scorer import score_checks


CONTAINED_RUNNER_SCHEMA_VERSION = 1
CONTAINED_RUNNER_NAME = "contained-run"


class ContainedRunStage(str):
    CONFIG = "config"
    PREFLIGHT = "preflight"
    WORKSPACE_PREP = "workspace_prep"
    POLICY = "policy"
    DOCKER = "docker"
    TIMEOUT = "timeout"
    CLEANUP = "cleanup"
    COMPLETE = "complete"


EXIT_CONFIG = 2
EXIT_PREFLIGHT = 3
EXIT_WORKSPACE_PREP = 4
EXIT_POLICY = 5
EXIT_DOCKER = 6
EXIT_TIMEOUT = 7
EXIT_CLEANUP = 8


DockerCommandExecutor = Callable[
    [list[str], Path, int, int],
    CommandResult,
]


@dataclass(frozen=True)
class ContainedRunFailure:
    stage: str
    exit_code: int
    message: str


@dataclass(frozen=True)
class ContainedRunResult:
    task_id: str
    config_path: Path
    source_dir: Path
    run_dir: Path
    command: list[str]
    docker_argv: list[str]
    preflight: Optional[DockerPreflightResult]
    command_result: Optional[CommandResult]
    diff_summary: DiffSummary
    check_results: list[CheckResult]
    result: str
    score: int
    mutations: dict[str, object]
    cleanup_complete: bool
    failure: Optional[ContainedRunFailure] = None
    report_path: Optional[Path] = None

    @property
    def exit_code(self) -> int:
        if self.failure is not None:
            return self.failure.exit_code
        return 0 if self.result == "PASS" else 1


def run_contained_agent_command(
    config_path: Path,
    command: Sequence[str],
    *,
    source_dir: Optional[Path] = None,
    runs_root: Path = Path(".agentguard/contained-runs"),
    docker_executor: Optional[DockerCommandExecutor] = None,
) -> ContainedRunResult:
    started = time.monotonic()
    if not command:
        raise ValueError("contained-run requires an argv after '--'.")
    if not all(isinstance(item, str) and item for item in command):
        raise ValueError("contained-run argv items must be non-empty strings.")

    config = load_config(config_path)
    _validate_contained_config(config)
    source = (source_dir or config.repo_template or Path.cwd()).expanduser().resolve()
    if not source.is_dir():
        raise ValueError("contained-run source repository must be a directory.")

    run_id = _run_id(config.task_id)
    run_dir = artifact_directory(runs_root, run_id)
    run_dir.mkdir(parents=True, exist_ok=False)

    preflight: Optional[DockerPreflightResult] = None
    prepared: Optional[PreparedContainedWorkspace] = None
    docker_argv: list[str] = []
    command_result: Optional[CommandResult] = None
    diff_summary = _empty_diff_summary()
    check_results: list[CheckResult] = []
    mutations: dict[str, object] = {}
    cleanup_complete = True
    failure: Optional[ContainedRunFailure] = None

    try:
        preflight = run_docker_preflight(config)
        if preflight.status not in {
            DockerPreflightStatus.SUPPORTED,
            DockerPreflightStatus.EXPERIMENTAL,
        }:
            failure = ContainedRunFailure(
                ContainedRunStage.PREFLIGHT,
                EXIT_PREFLIGHT,
                f"Docker contained-execution preflight failed: {preflight.status.value}.",
            )
            return _finalize(
                config=config,
                source=source,
                run_dir=run_dir,
                command=list(command),
                docker_argv=docker_argv,
                preflight=preflight,
                command_result=command_result,
                diff_summary=diff_summary,
                check_results=check_results,
                mutations=mutations,
                cleanup_complete=cleanup_complete,
                failure=failure,
            )

        prepared = prepare_contained_workspace(
            source,
            run_dir / "workspace-lifecycle",
            workspace_id="agent-workspace",
        )
        workspace = validate_workspace_mount_containment(
            prepared.workspace_dir,
            run_dir,
        )
        container_name = f"agentguard-{run_id[-32:]}".lower()
        spec = contained_exec_spec_from_config(
            config.contained_execution,
            image=config.sandbox.image or "",
            workspace_host_path=workspace,
            workspace_container_path=DEFAULT_AGENT_WORKSPACE_PATH,
            command=list(command),
            container_name=container_name,
        )
        docker_argv = build_contained_docker_run_argv(spec)
        policy = evaluate_command_policy(
            command_text=shlex.join(command),
            unsafe_patterns=config.unsafe_commands,
            mode=config.command_policy.mode,
        )
        if not policy.allowed:
            command_result = CommandResult(
                command=_display_command(command),
                exit_code=126,
                stdout="",
                stderr=policy.message,
                duration_seconds=0.0,
            )
            failure = ContainedRunFailure(
                ContainedRunStage.POLICY,
                EXIT_POLICY,
                policy.message,
            )
        else:
            executor = docker_executor or _execute_docker_argv
            command_result = executor(
                docker_argv,
                prepared.workspace_dir,
                config.command_timeout_seconds,
                config.max_output_bytes,
            )
            if command_result.timed_out:
                failure = ContainedRunFailure(
                    ContainedRunStage.TIMEOUT,
                    EXIT_TIMEOUT,
                    "contained agent command timed out.",
                )
            elif command_result.exit_code in {125, 126, 127}:
                failure = ContainedRunFailure(
                    ContainedRunStage.DOCKER,
                    EXIT_DOCKER,
                    "Docker failed before or while launching the contained command.",
                )

        try:
            captured = prepared.capture_mutations()
            mutations = {
                "modified_files": list(captured.modified_files),
                "added_files": list(captured.added_files),
                "deleted_files": list(captured.deleted_files),
                "renamed_files": [
                    {"old": old, "new": new}
                    for old, new in captured.renamed_files
                ],
                "changed_files": list(captured.changed_files),
                "current_digest": captured.current_digest,
            }
            diff_summary = _diff_summary_from_mutations(captured)
            diff_summary = with_secret_content_scan(
                prepared.workspace_dir,
                diff_summary,
                config.secret_content_patterns,
                baseline_ref=None,
            )
        except ContainedWorkspaceMutationError as error:
            failure = failure or ContainedRunFailure(
                ContainedRunStage.WORKSPACE_PREP,
                EXIT_WORKSPACE_PREP,
                _sanitize_diagnostic(error),
            )

        if command_result is not None:
            check_results = evaluate_policy_checks(
                PolicyEvaluationContext(
                    config=config,
                    test_result=command_result,
                    diff_summary=diff_summary,
                    command_events=[],
                )
            )
    except ContainedWorkspaceError as error:
        failure = ContainedRunFailure(
            ContainedRunStage.WORKSPACE_PREP,
            EXIT_WORKSPACE_PREP,
            _sanitize_diagnostic(error),
        )
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        failure = ContainedRunFailure(
            ContainedRunStage.CONFIG,
            EXIT_CONFIG,
            _sanitize_diagnostic(error),
        )
    finally:
        if prepared is not None:
            cleanup = prepared.cleanup()
            cleanup_complete = cleanup.complete
            if not cleanup.complete and failure is None:
                failure = ContainedRunFailure(
                    ContainedRunStage.CLEANUP,
                    EXIT_CLEANUP,
                    cleanup.message or "contained workspace cleanup failed.",
                )
            container_cleanup = (
                _remove_container(container_name if "container_name" in locals() else None)
                if docker_executor is None
                else None
            )
            if container_cleanup is not None:
                cleanup_complete = False
                if failure is None:
                    failure = ContainedRunFailure(
                        ContainedRunStage.CLEANUP,
                        EXIT_CLEANUP,
                        container_cleanup,
                    )

    score = score_checks(check_results).score if check_results else 0
    result = "PASS" if command_result is not None and command_result.exit_code == 0 else "FAIL"
    if check_results:
        result = score_checks(check_results).result
    elapsed = round(time.monotonic() - started, 6)
    if command_result is not None:
        command_result = _sanitize_command_result(command_result, config, source, run_dir)
    final = ContainedRunResult(
        task_id=config.task_id,
        config_path=config.config_path,
        source_dir=source,
        run_dir=run_dir,
        command=list(command),
        docker_argv=_sanitize_argv(docker_argv, config, source, run_dir),
        preflight=preflight,
        command_result=command_result,
        diff_summary=diff_summary,
        check_results=check_results,
        result=result,
        score=score,
        mutations=mutations,
        cleanup_complete=cleanup_complete,
        failure=failure,
    )
    return _write_report(final, elapsed)


def _validate_contained_config(config: AgentGuardConfig) -> None:
    if config.contained_execution is None:
        raise ValueError("Config field 'contained_execution' is required for contained-run.")
    if config.sandbox.type != "docker":
        raise ValueError("Config field 'sandbox.type' must be 'docker' for contained-run.")
    if not config.sandbox.image:
        raise ValueError("Config field 'sandbox.image' is required for contained-run.")
    if config.sandbox.network != config.contained_execution.network:
        raise ValueError(
            "Config field 'sandbox.network' must match contained_execution.network."
        )


def _execute_docker_argv(
    argv: list[str],
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> CommandResult:
    started = time.monotonic()
    process = None
    capture = None
    cleanup = ProcessCleanupResult()
    timed_out = False
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "")},
            start_new_session=True,
        )
        capture = BoundedProcessOutput(process, max_output_bytes)
        exit_code = capture.wait(timeout=timeout_seconds)
        captured = capture.finish()
    except FileNotFoundError as error:
        return CommandResult(
            command=CONTAINED_RUNNER_NAME,
            exit_code=127,
            stdout="",
            stderr=f"Docker executable not found: {redact_credentials(error.filename)}",
            duration_seconds=round(time.monotonic() - started, 6),
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = 124
        if process is not None:
            cleanup = terminate_process_tree(process)
        try:
            capture.wait(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
        except BaseException:
            pass
        try:
            captured = capture.finish(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
        except BaseException:
            captured = ProcessOutput(
                stdout=LimitedOutput(text="", truncated=False),
                stderr=LimitedOutput(text="", truncated=False),
            )
    except BaseException:
        cleanup_process_after_exception(process, capture)
        raise

    stdout = captured.stdout.text
    stderr = captured.stderr.text
    if timed_out:
        stderr = (
            f"{stderr}\nContained command timed out after {timeout_seconds} seconds."
            f"\n{process_timeout_message(cleanup)}"
        ).strip()
        stderr = append_cleanup_message(stderr, cleanup)
    limited_stdout = limit_output(stdout, max_output_bytes)
    limited_stderr = limit_output(stderr, max_output_bytes)
    return CommandResult(
        command=CONTAINED_RUNNER_NAME,
        exit_code=exit_code,
        stdout=limited_stdout.text,
        stderr=limited_stderr.text,
        duration_seconds=round(time.monotonic() - started, 6),
        timed_out=timed_out,
        stdout_truncated=captured.stdout.truncated or limited_stdout.truncated,
        stderr_truncated=captured.stderr.truncated or limited_stderr.truncated,
        process_cleanup_attempted=cleanup.attempted,
        process_cleanup_complete=cleanup.complete,
        process_cleanup_message=cleanup.message,
    )


def _remove_container(container_name: Optional[str]) -> Optional[str]:
    if not container_name:
        return None
    try:
        completed = subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env={"PATH": os.environ.get("PATH", "")},
        )
        diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
        if completed.returncode != 0 and "no such container" not in diagnostic:
            return "contained container cleanup failed."
    except (OSError, subprocess.SubprocessError):
        return "contained container cleanup failed."
    return None


def _diff_summary_from_mutations(mutations) -> DiffSummary:
    return DiffSummary(
        modified_files=list(mutations.modified_files),
        added_files=list(mutations.added_files),
        deleted_files=list(mutations.deleted_files),
        lines_added=0,
        lines_deleted=0,
        unified_diff="",
    )


def _empty_diff_summary() -> DiffSummary:
    return DiffSummary([], [], [], 0, 0, "")


def _run_id(task_id: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"{task_id}-contained-{timestamp}-{uuid4().hex[:8]}"


def _display_command(command: Sequence[str]) -> str:
    return f"{CONTAINED_RUNNER_NAME}: {shlex.join(list(command))}"


def _sanitize_diagnostic(error: object) -> str:
    text = error.__class__.__name__ if isinstance(error, OSError) else str(error)
    return _sanitize_host_text(redact_credentials(text))


def _sensitive_values(
    config: AgentGuardConfig,
    source: Path,
    run_dir: Path,
) -> list[str]:
    return [
        str(source),
        str(source.resolve()),
        str(run_dir),
        str(run_dir.resolve()),
        *config.agent_environment.values(),
    ]


def _sanitize_host_text(value: object, sensitive_values: Optional[list[str]] = None) -> str:
    text = redact_credentials(value, sensitive_values)
    for marker in ("/Users/", "/home/", "/private/tmp", "/private/var", "/tmp/"):
        if marker in text:
            return "[REDACTED_PATH]"
    return text


def _sanitize_argv(
    argv: list[str],
    config: AgentGuardConfig,
    source: Path,
    run_dir: Path,
) -> list[str]:
    sensitive = _sensitive_values(config, source, run_dir)
    return redact_credential_arguments(argv, sensitive)


def _sanitize_command_result(
    result: CommandResult,
    config: AgentGuardConfig,
    source: Path,
    run_dir: Path,
) -> CommandResult:
    sensitive = _sensitive_values(config, source, run_dir)
    stdout = limit_output(sanitize_text(result.stdout, sensitive), config.max_output_bytes)
    stderr = limit_output(sanitize_text(result.stderr, sensitive), config.max_output_bytes)
    return CommandResult(
        command=sanitize_text(result.command, sensitive),
        exit_code=result.exit_code,
        stdout=stdout.text,
        stderr=stderr.text,
        duration_seconds=result.duration_seconds,
        timed_out=result.timed_out,
        stdout_truncated=result.stdout_truncated or stdout.truncated,
        stderr_truncated=result.stderr_truncated or stderr.truncated,
        process_cleanup_attempted=result.process_cleanup_attempted,
        process_cleanup_complete=result.process_cleanup_complete,
        process_cleanup_message=(
            sanitize_text(result.process_cleanup_message, sensitive)
            if result.process_cleanup_message is not None
            else None
        ),
        docker_image=result.docker_image,
    )


def _finalize(**kwargs) -> ContainedRunResult:
    result = ContainedRunResult(
        task_id=kwargs["config"].task_id,
        config_path=kwargs["config"].config_path,
        source_dir=kwargs["source"],
        run_dir=kwargs["run_dir"],
        command=kwargs["command"],
        docker_argv=kwargs["docker_argv"],
        preflight=kwargs["preflight"],
        command_result=kwargs["command_result"],
        diff_summary=kwargs["diff_summary"],
        check_results=kwargs["check_results"],
        result="FAIL",
        score=0,
        mutations=kwargs["mutations"],
        cleanup_complete=kwargs["cleanup_complete"],
        failure=kwargs["failure"],
    )
    return _write_report(result, 0.0)


def _write_report(result: ContainedRunResult, elapsed: float) -> ContainedRunResult:
    report_path = result.run_dir / "contained-run.json"
    payload = {
        "schema": "agentguard.contained-run",
        "schema_version": CONTAINED_RUNNER_SCHEMA_VERSION,
        "task_id": result.task_id,
        "result": result.result,
        "score": result.score,
        "exit_code": result.exit_code,
        "duration_seconds": elapsed,
        "config_path": _sanitize_host_text(result.config_path),
        "source_dir": _sanitize_host_text(result.source_dir),
        "run_dir": _sanitize_host_text(result.run_dir),
        "command": redact_credential_arguments(result.command),
        "docker_argv": result.docker_argv,
        "preflight": result.preflight.to_evidence() if result.preflight else None,
        "command_result": asdict(result.command_result) if result.command_result else None,
        "mutations": result.mutations,
        "checks": [asdict(check) for check in result.check_results],
        "cleanup_complete": result.cleanup_complete,
        "failure": asdict(result.failure) if result.failure else None,
    }
    atomic_write_json(report_path, payload)
    return ContainedRunResult(
        **{**result.__dict__, "report_path": report_path}
    )
