from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import asdict, dataclass, field
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
from agentguard.sandbox.contained_environment import (
    ContainedEnvironmentDiagnostics,
    resolve_contained_environment,
)
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
    object,
]

DOCKER_CONTROL_TIMEOUT_SECONDS = 5
DOCKER_STOP_TIMEOUT_SECONDS = 2
DOCKER_OUTPUT_MAX_BYTES = 4096
DOCKER_INSPECT_MAX_BYTES = 65536
DOCKER_DIAGNOSTIC_MAX_BYTES = 512
CONTAINER_ID_PATTERN = re.compile(r"^[a-f0-9]{12,64}$")
CONTAINER_ID_TEXT_PATTERN = re.compile(r"\b[a-f0-9]{12,64}\b", re.IGNORECASE)
CONTAINER_NAME_TEXT_PATTERN = re.compile(r"\bagentguard-[a-z0-9_.-]{1,80}\b")
CONTAINER_RUN_LABEL_TEXT_PATTERN = re.compile(
    r"agentguard\.contained-run\.id=[A-Za-z0-9_.:-]+"
)
PRIVATE_PATH_TEXT_PATTERN = re.compile(
    r"(?:/Users/[^/\s,;]+|/home/[^/\s,;]+|/private/tmp|/private/var|/tmp)"
    r"(?:/[^\s,;]*)?"
)
DOCKER_ENV_ASSIGNMENT_TEXT_PATTERN = re.compile(
    r"\b[A-Z_][A-Z0-9_]{0,63}=[^\s,;]+"
)
CONTAINER_CLEANUP_COMPLETE_STATUSES = {
    "removed",
    "already_absent",
}


@dataclass(frozen=True)
class ContainedRunFailure:
    stage: str
    exit_code: int
    message: str


@dataclass(frozen=True)
class ContainedContainerIdentity:
    container_id: str
    container_name: str
    owner_label: str


@dataclass(frozen=True)
class ContainedCleanupResult:
    attempted: bool = False
    complete: bool = True
    status: str = "not_created"
    container: Optional[dict[str, str]] = None
    message: Optional[str] = None
    workspace_complete: Optional[bool] = None
    workspace_status: Optional[str] = None
    workspace_message: Optional[str] = None


@dataclass(frozen=True)
class ContainedDockerExecution:
    command_result: CommandResult
    cleanup: ContainedCleanupResult


class DockerContainerCreatedError(subprocess.SubprocessError):
    def __init__(self, identity: ContainedContainerIdentity) -> None:
        super().__init__("docker container was created before launch failure")
        self.identity = identity


class DockerOperationalError(subprocess.SubprocessError):
    def __init__(self, diagnostic: str) -> None:
        super().__init__(diagnostic)
        self.diagnostic = diagnostic


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
    cleanup: ContainedCleanupResult = field(default_factory=ContainedCleanupResult)
    failure: Optional[ContainedRunFailure] = None
    cleanup_failure: Optional[ContainedRunFailure] = None
    report_path: Optional[Path] = None
    environment: ContainedEnvironmentDiagnostics = field(
        default_factory=ContainedEnvironmentDiagnostics
    )

    @property
    def exit_code(self) -> int:
        if self.failure is not None:
            return self.failure.exit_code
        if self.cleanup_failure is not None:
            return self.cleanup_failure.exit_code
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
    _validate_host_bind_identity(config)

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
    environment = ContainedEnvironmentDiagnostics()
    sensitive_values = _sensitive_values(config, source, run_dir)
    cleanup = ContainedCleanupResult()
    cleanup_complete = True
    failure: Optional[ContainedRunFailure] = None
    cleanup_failure: Optional[ContainedRunFailure] = None

    try:
        try:
            resolved_environment = resolve_contained_environment(
                config.contained_execution.environment,
            )
            environment = resolved_environment.diagnostics
            sensitive_values.extend(resolved_environment.sensitive_values)
        except ValueError as error:
            failure = ContainedRunFailure(
                ContainedRunStage.CONFIG,
                EXIT_CONFIG,
                _sanitize_diagnostic(error, sensitive_values),
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
                environment=environment,
            )
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
                environment=environment,
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
        owner_label = f"agentguard.contained-run.id={run_id[-48:].lower()}"
        spec = contained_exec_spec_from_config(
            config.contained_execution,
            image=config.sandbox.image or "",
            workspace_host_path=workspace,
            workspace_container_path=DEFAULT_AGENT_WORKSPACE_PATH,
            command=list(command),
            container_name=container_name,
            environment=resolved_environment.values,
        )
        docker_argv = _add_container_owner_labels(
            build_contained_docker_run_argv(spec),
            owner_label=owner_label,
        )
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
            execution = executor(
                docker_argv,
                prepared.workspace_dir,
                config.command_timeout_seconds,
                config.max_output_bytes,
            )
            if isinstance(execution, ContainedDockerExecution):
                command_result = execution.command_result
                cleanup = execution.cleanup
                cleanup_complete = cleanup.complete
            elif isinstance(execution, CommandResult):
                command_result = execution
            else:
                raise TypeError("contained docker executor returned an unsupported result.")
            if command_result.timed_out:
                failure = ContainedRunFailure(
                    ContainedRunStage.TIMEOUT,
                    EXIT_TIMEOUT,
                    "contained agent command timed out.",
                )
            elif command_result.exit_code == 125:
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
                _sanitize_diagnostic(error, sensitive_values),
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
            _sanitize_diagnostic(error, sensitive_values),
        )
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        failure = ContainedRunFailure(
            ContainedRunStage.CONFIG,
            EXIT_CONFIG,
            _sanitize_diagnostic(error, sensitive_values),
        )
    finally:
        if prepared is not None:
            workspace_cleanup = (
                prepared.cleanup()
                if cleanup.complete
                else None
            )
            if workspace_cleanup is None:
                cleanup = _with_workspace_cleanup(
                    cleanup,
                    complete=False,
                    status="retained",
                    message=(
                        "contained workspace retained because container cleanup "
                        "or liveness verification did not complete."
                    ),
                )
            else:
                cleanup = _with_workspace_cleanup(
                    cleanup,
                    complete=workspace_cleanup.complete,
                    status="removed" if workspace_cleanup.complete else "incomplete",
                    message=workspace_cleanup.message,
                )
            cleanup_complete = cleanup.complete and cleanup.workspace_complete is not False
            if not cleanup_complete:
                cleanup_failure = ContainedRunFailure(
                    ContainedRunStage.CLEANUP,
                    EXIT_CLEANUP,
                    _cleanup_failure_message(cleanup),
                )
                if failure is None:
                    failure = cleanup_failure

    score = score_checks(check_results).score if check_results else 0
    result = "PASS" if command_result is not None and command_result.exit_code == 0 else "FAIL"
    if check_results:
        result = score_checks(check_results).result
    if cleanup_failure is not None or not cleanup_complete:
        result = "FAIL"
    elapsed = round(time.monotonic() - started, 6)
    if command_result is not None:
        command_result = _sanitize_command_result(
            command_result,
            config,
            source,
            run_dir,
            sensitive_values,
        )
    final = ContainedRunResult(
        task_id=config.task_id,
        config_path=config.config_path,
        source_dir=source,
        run_dir=run_dir,
        command=redact_credential_arguments(list(command), sensitive_values),
        docker_argv=_sanitize_argv(docker_argv, sensitive_values),
        preflight=preflight,
        command_result=command_result,
        diff_summary=diff_summary,
        check_results=check_results,
        result=result,
        score=score,
        mutations=mutations,
        cleanup_complete=cleanup_complete,
        cleanup=cleanup,
        failure=failure,
        cleanup_failure=cleanup_failure if cleanup_failure != failure else None,
        environment=environment,
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


def _validate_host_bind_identity(config: AgentGuardConfig) -> None:
    if config.contained_execution is None:
        return
    if (
        config.contained_execution.required_uid != os.geteuid()
        or config.contained_execution.required_gid != os.getegid()
    ):
        raise ValueError(
            "contained-run host bind mounts require contained_execution.required_uid "
            "and required_gid to match the current host user."
        )


def _execute_docker_argv(
    argv: list[str],
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
) -> ContainedDockerExecution:
    started = time.monotonic()
    process = None
    capture = None
    cleanup = ContainedCleanupResult()
    timed_out = False
    identity: Optional[ContainedContainerIdentity] = None
    try:
        identity = _create_owned_container(argv)
        process = subprocess.Popen(
            ["docker", "start", "-a", identity.container_id],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": os.environ.get("PATH", "")},
            start_new_session=True,
        )
        capture = BoundedProcessOutput(process, max_output_bytes)
        exit_code = capture.wait(timeout=timeout_seconds)
        captured = capture.finish()
        if _looks_like_docker_start_failure(exit_code, captured.stderr.text):
            cleanup = _cleanup_owned_container(identity)
            diagnostic = _sanitize_docker_operational_text(captured.stderr.text)
            return ContainedDockerExecution(
                CommandResult(
                    command=CONTAINED_RUNNER_NAME,
                    exit_code=125,
                    stdout="",
                    stderr=f"Docker launch failed: start failed: {diagnostic}",
                    duration_seconds=round(time.monotonic() - started, 6),
                    process_cleanup_attempted=cleanup.attempted,
                    process_cleanup_complete=cleanup.complete,
                    process_cleanup_message=cleanup.message,
                ),
                cleanup,
            )
    except FileNotFoundError as error:
        cleanup = _cleanup_owned_container(identity)
        return ContainedDockerExecution(
            CommandResult(
                command=CONTAINED_RUNNER_NAME,
                exit_code=125,
                stdout="",
                stderr=f"Docker executable not found: {redact_credentials(error.filename)}",
                duration_seconds=round(time.monotonic() - started, 6),
                process_cleanup_attempted=cleanup.attempted,
                process_cleanup_complete=cleanup.complete,
                process_cleanup_message=cleanup.message,
            ),
            cleanup,
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = 124
        cleanup = _cleanup_owned_container(identity)
        process_cleanup = ProcessCleanupResult()
        captured = ProcessOutput(
            stdout=LimitedOutput(text="", truncated=False),
            stderr=LimitedOutput(text="", truncated=False),
        )
        if capture is not None:
            try:
                capture.wait(timeout=PROCESS_OUTPUT_DRAIN_TIMEOUT_SECONDS)
            except BaseException:
                if process is not None:
                    process_cleanup = terminate_process_tree(process)
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
        elif process is not None:
            process_cleanup = terminate_process_tree(process)
        if (
            process_cleanup.attempted
            and process_cleanup.message
            and cleanup.complete
            and not process_cleanup.complete
        ):
            cleanup = ContainedCleanupResult(
                attempted=cleanup.attempted,
                complete=False,
                status=cleanup.status,
                container=cleanup.container,
                message=(
                    f"{cleanup.message}; {process_cleanup.message}"
                    if cleanup.message
                    else process_cleanup.message
                ),
            )
    except DockerContainerCreatedError as error:
        cleanup = _cleanup_owned_container(error.identity)
        return ContainedDockerExecution(
            CommandResult(
                command=CONTAINED_RUNNER_NAME,
                exit_code=125,
                stdout="",
                stderr="Docker launch failed: container identity cleanup required",
                duration_seconds=round(time.monotonic() - started, 6),
                process_cleanup_attempted=cleanup.attempted,
                process_cleanup_complete=cleanup.complete,
                process_cleanup_message=cleanup.message,
            ),
            cleanup,
        )
    except DockerOperationalError as error:
        cleanup_process_after_exception(process, capture)
        cleanup = _cleanup_owned_container(identity)
        return ContainedDockerExecution(
            CommandResult(
                command=CONTAINED_RUNNER_NAME,
                exit_code=125,
                stdout="",
                stderr=f"Docker launch failed: {error.diagnostic}",
                duration_seconds=round(time.monotonic() - started, 6),
                process_cleanup_attempted=cleanup.attempted,
                process_cleanup_complete=cleanup.complete,
                process_cleanup_message=cleanup.message,
            ),
            cleanup,
        )
    except (OSError, subprocess.SubprocessError) as error:
        cleanup_process_after_exception(process, capture)
        cleanup = _cleanup_owned_container(identity)
        return ContainedDockerExecution(
            CommandResult(
                command=CONTAINED_RUNNER_NAME,
                exit_code=125,
                stdout="",
                stderr=f"Docker launch failed: {redact_credentials(error.__class__.__name__)}",
                duration_seconds=round(time.monotonic() - started, 6),
                process_cleanup_attempted=cleanup.attempted,
                process_cleanup_complete=cleanup.complete,
                process_cleanup_message=cleanup.message,
            ),
            cleanup,
        )
    except BaseException:
        cleanup_process_after_exception(process, capture)
        cleanup = _cleanup_owned_container(identity)
        return ContainedDockerExecution(
            CommandResult(
                command=CONTAINED_RUNNER_NAME,
                exit_code=125,
                stdout="",
                stderr="Docker launch interrupted before completion.",
                duration_seconds=round(time.monotonic() - started, 6),
                process_cleanup_attempted=cleanup.attempted,
                process_cleanup_complete=cleanup.complete,
                process_cleanup_message=cleanup.message,
            ),
            cleanup,
        )
    if not timed_out:
        cleanup = _cleanup_owned_container(identity)

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
    return ContainedDockerExecution(
        CommandResult(
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
        ),
        cleanup,
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


def _add_container_owner_labels(argv: list[str], *, owner_label: str) -> list[str]:
    if "--" not in argv:
        return list(argv)
    boundary = argv.index("--")
    return [
        *argv[:boundary],
        "--label",
        "agentguard.owner=contained-run",
        "--label",
        owner_label,
        *argv[boundary:],
    ]


def _docker_create_argv(argv: list[str]) -> list[str]:
    create = list(argv)
    if len(create) < 2 or create[0] != "docker" or create[1] != "run":
        raise ValueError("contained Docker argv must start with docker run.")
    create[1] = "create"
    boundary = create.index("--") if "--" in create else len(create)
    if boundary < len(create):
        del create[boundary]
    create = [
        item
        for index, item in enumerate(create)
        if item != "--rm" or index >= boundary
    ]
    return create


def _create_owned_container(argv: list[str]) -> ContainedContainerIdentity:
    create_argv = _docker_create_argv(argv)
    completed = _run_docker_control(create_argv)
    container_name = _argv_option(create_argv, "--name") or ""
    owner_label = _argv_option(create_argv, "--label", prefix="agentguard.contained-run.id=")
    if completed.returncode != 0:
        bind = _bind_container_identity_detail(
            container_name,
            expected_name=container_name,
            expected_owner_label=owner_label or "",
        )
        if bind.identity is not None:
            raise DockerContainerCreatedError(bind.identity)
        raise DockerOperationalError(
            _docker_control_failure_diagnostic("create", completed, bind.reason)
        )
    container_id = _first_container_id(completed.stdout)
    bind = _bind_container_identity_detail(
        container_id or container_name,
        expected_name=container_name,
        expected_owner_label=owner_label or "",
    )
    if bind.identity is None:
        raise DockerOperationalError(f"identity verification failed: {bind.reason}")
    return bind.identity


def _cleanup_owned_container(
    identity: Optional[ContainedContainerIdentity],
) -> ContainedCleanupResult:
    if identity is None:
        return ContainedCleanupResult()
    container = _container_evidence(identity)
    first = _inspect_owned_container(identity)
    was_running = first.running
    if first.status == "already_absent":
        return ContainedCleanupResult(
            attempted=True,
            complete=True,
            status="already_absent",
            container=container,
            message="contained container already absent",
        )
    if first.status == "verification_unavailable":
        return ContainedCleanupResult(
            attempted=True,
            complete=False,
            status="verification_unavailable",
            container=container,
            message="contained container liveness verification unavailable",
        )
    if first.running:
        stopped = _run_docker_control(
            [
                "docker",
                "stop",
                "--time",
                str(DOCKER_STOP_TIMEOUT_SECONDS),
                identity.container_id,
            ]
        )
        if stopped.returncode != 0 and not _is_no_such_container(stopped):
            return ContainedCleanupResult(
                attempted=True,
                complete=False,
                status="cleanup_incomplete",
                container=container,
                message="contained container graceful stop failed",
            )
    after_stop = _inspect_owned_container(identity)
    force_killed = False
    graceful_stop = was_running and after_stop.status != "already_absent" and not after_stop.running
    if after_stop.status == "verification_unavailable":
        return ContainedCleanupResult(
            attempted=True,
            complete=False,
            status="verification_unavailable",
            container=container,
            message="contained container liveness verification unavailable",
        )
    if after_stop.status == "already_absent":
        return ContainedCleanupResult(
            attempted=True,
            complete=True,
            status="already_absent",
            container=container,
            message="contained container already absent",
        )
    if after_stop.running:
        killed = _run_docker_control(["docker", "kill", identity.container_id])
        force_killed = killed.returncode == 0
        if killed.returncode != 0 and not _is_no_such_container(killed):
            return ContainedCleanupResult(
                attempted=True,
                complete=False,
                status="cleanup_incomplete",
                container=container,
                message="contained container force kill failed",
            )
    after_kill = _inspect_owned_container(identity)
    if after_kill.status == "verification_unavailable":
        return ContainedCleanupResult(
            attempted=True,
            complete=False,
            status="verification_unavailable",
            container=container,
            message="contained container liveness verification unavailable",
        )
    if after_kill.status != "already_absent" and after_kill.running:
        return ContainedCleanupResult(
            attempted=True,
            complete=False,
            status="cleanup_incomplete",
            container=container,
            message="contained container remained alive after cleanup",
        )
    removed = _run_docker_control(["docker", "rm", identity.container_id])
    if removed.returncode != 0 and not _is_no_such_container(removed):
        return ContainedCleanupResult(
            attempted=True,
            complete=False,
            status="cleanup_incomplete",
            container=container,
            message="contained container removal failed",
        )
    final = _inspect_owned_container(identity)
    if final.status == "already_absent":
        if force_killed:
            status = "force_killed"
            message = "contained container force-killed and removed"
        elif graceful_stop:
            status = "cleanly_terminated"
            message = "contained container gracefully stopped and removed"
        else:
            status = "removed"
            message = "contained container removed"
        return ContainedCleanupResult(
            attempted=True,
            complete=True,
            status=status,
            container=container,
            message=message,
        )
    if final.status == "verification_unavailable":
        return ContainedCleanupResult(
            attempted=True,
            complete=False,
            status="verification_unavailable",
            container=container,
            message="contained container absence verification unavailable",
        )
    return ContainedCleanupResult(
        attempted=True,
        complete=False,
        status="cleanup_incomplete",
        container=container,
        message="contained container removal could not be verified",
    )


@dataclass(frozen=True)
class _ContainerInspection:
    status: str
    running: bool = False


@dataclass(frozen=True)
class _InspectJsonResult:
    status: str
    payload: Optional[dict[str, object]] = None


def _bind_container_identity(
    target: str,
    *,
    expected_name: str,
    expected_owner_label: str,
) -> Optional[ContainedContainerIdentity]:
    return _bind_container_identity_detail(
        target,
        expected_name=expected_name,
        expected_owner_label=expected_owner_label,
    ).identity


@dataclass(frozen=True)
class _BindIdentityResult:
    identity: Optional[ContainedContainerIdentity]
    reason: str = ""


def _bind_container_identity_detail(
    target: str,
    *,
    expected_name: str,
    expected_owner_label: str,
) -> _BindIdentityResult:
    if not target:
        return _BindIdentityResult(None, "inspect target unavailable")
    inspect = _inspect_container_json(target)
    if inspect.status != "present" or inspect.payload is None:
        return _BindIdentityResult(None, f"identity inspect {inspect.status}")
    container_id = _normal_container_id(inspect.payload.get("Id"))
    name = str(inspect.payload.get("Name") or "").lstrip("/")
    config = inspect.payload.get("Config")
    labels = config.get("Labels", {}) if isinstance(config, dict) else {}
    if not isinstance(labels, dict):
        labels = {}
    label_name, _, label_value = expected_owner_label.partition("=")
    if not container_id:
        return _BindIdentityResult(None, "identity inspect returned invalid id")
    if name != expected_name:
        return _BindIdentityResult(None, "identity name mismatch")
    if labels.get("agentguard.owner") != "contained-run":
        return _BindIdentityResult(None, "identity owner label mismatch")
    if not label_name or labels.get(label_name) != label_value:
        return _BindIdentityResult(None, "identity run label mismatch")
    return _BindIdentityResult(
        ContainedContainerIdentity(
            container_id=container_id,
            container_name=expected_name,
            owner_label=expected_owner_label,
        )
    )


def _inspect_owned_container(identity: ContainedContainerIdentity) -> _ContainerInspection:
    inspect = _inspect_container_json(identity.container_id)
    if inspect.status == "absent":
        return _ContainerInspection("already_absent")
    if inspect.status != "present" or inspect.payload is None:
        return _ContainerInspection("verification_unavailable")
    rebound = _bind_container_identity(
        identity.container_id,
        expected_name=identity.container_name,
        expected_owner_label=identity.owner_label,
    )
    if rebound is None or rebound.container_id != identity.container_id:
        return _ContainerInspection("verification_unavailable")
    state = inspect.payload.get("State", {})
    running = bool(state.get("Running")) if isinstance(state, dict) else False
    return _ContainerInspection("running" if running else "stopped", running=running)


def _inspect_container_json(target: str) -> _InspectJsonResult:
    completed = _run_docker_control(
        ["docker", "container", "inspect", "--format", "{{json .}}", target]
    )
    if completed.returncode != 0:
        if _is_no_such_container(completed):
            return _InspectJsonResult("absent")
        return _InspectJsonResult("unavailable")
    try:
        bounded = limit_output(completed.stdout, DOCKER_INSPECT_MAX_BYTES)
        if bounded.truncated:
            return _InspectJsonResult("unavailable")
        data = json.loads(bounded.text)
    except (ValueError, TypeError):
        return _InspectJsonResult("unavailable")
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    return (
        _InspectJsonResult("present", data)
        if isinstance(data, dict)
        else _InspectJsonResult("unavailable")
    )


def _run_docker_control(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=DOCKER_CONTROL_TIMEOUT_SECONDS,
            env={"PATH": os.environ.get("PATH", "")},
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, stdout="", stderr="timeout")
    except OSError as error:
        return subprocess.CompletedProcess(
            argv,
            125,
            stdout="",
            stderr=redact_credentials(error.__class__.__name__),
        )


def _docker_control_failure_diagnostic(
    operation: str,
    completed: subprocess.CompletedProcess,
    detail: str = "",
) -> str:
    parts = [f"{operation} failed", f"rc={completed.returncode}"]
    if detail:
        parts.append(detail)
    stdout = _sanitize_docker_operational_text(completed.stdout)
    stderr = _sanitize_docker_operational_text(completed.stderr)
    if stdout:
        parts.append(f"stdout={stdout}")
    if stderr:
        parts.append(f"stderr={stderr}")
    return limit_output("; ".join(parts), DOCKER_DIAGNOSTIC_MAX_BYTES).text


def _sanitize_docker_operational_text(value: object) -> str:
    text = redact_credentials(str(value))
    text = CONTAINER_RUN_LABEL_TEXT_PATTERN.sub(
        "agentguard.contained-run.id=[REDACTED]",
        text,
    )
    text = CONTAINER_NAME_TEXT_PATTERN.sub("agentguard-[REDACTED]", text)
    text = CONTAINER_ID_TEXT_PATTERN.sub("[REDACTED_CONTAINER_ID]", text)
    text = DOCKER_ENV_ASSIGNMENT_TEXT_PATTERN.sub(_redact_safe_env_assignment, text)
    text = PRIVATE_PATH_TEXT_PATTERN.sub("[REDACTED_PATH]", text)
    return limit_output(text.strip(), DOCKER_DIAGNOSTIC_MAX_BYTES).text


def _redact_safe_env_assignment(match: re.Match) -> str:
    name = match.group(0).split("=", 1)[0]
    return f"{name}=[REDACTED]"


def _looks_like_docker_start_failure(exit_code: int, stderr: str) -> bool:
    if exit_code == 0:
        return False
    lowered = stderr.lower()
    return (
        "error response from daemon" in lowered
        or "no such container" in lowered
        or "docker: error" in lowered
    )


def _argv_option(argv: list[str], option: str, *, prefix: Optional[str] = None) -> Optional[str]:
    for index, item in enumerate(argv[:-1]):
        if item != option:
            continue
        value = argv[index + 1]
        if prefix is None or value.startswith(prefix):
            return value
    return None


def _first_container_id(output: str) -> str:
    for line in output.splitlines():
        candidate = line.strip().lower()
        if CONTAINER_ID_PATTERN.fullmatch(candidate):
            return candidate
    return ""


def _normal_container_id(value: object) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip().lower()
    if CONTAINER_ID_PATTERN.fullmatch(candidate):
        return candidate
    return ""


def _container_evidence(identity: ContainedContainerIdentity) -> dict[str, str]:
    return {
        "id_sha256": _sha256_short(identity.container_id),
        "name_sha256": _sha256_short(identity.container_name),
        "owner_label_sha256": _sha256_short(identity.owner_label),
    }


def _sha256_short(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _is_no_such_container(completed: subprocess.CompletedProcess) -> bool:
    output = f"{completed.stdout}\n{completed.stderr}".lower()
    return "no such container" in output or "no such object" in output


def _with_workspace_cleanup(
    cleanup: ContainedCleanupResult,
    *,
    complete: bool,
    status: str,
    message: str,
) -> ContainedCleanupResult:
    return ContainedCleanupResult(
        attempted=cleanup.attempted,
        complete=cleanup.complete,
        status=cleanup.status,
        container=cleanup.container,
        message=cleanup.message,
        workspace_complete=complete,
        workspace_status=status,
        workspace_message=message,
    )


def _cleanup_failure_message(cleanup: ContainedCleanupResult) -> str:
    parts = []
    if not cleanup.complete:
        parts.append(cleanup.message or "contained container cleanup failed")
    if cleanup.workspace_complete is False:
        parts.append(cleanup.workspace_message or "contained workspace cleanup failed")
    return "; ".join(parts) or "contained cleanup failed"


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


def _sanitize_diagnostic(
    error: object,
    sensitive_values: Optional[list[str]] = None,
) -> str:
    text = error.__class__.__name__ if isinstance(error, OSError) else str(error)
    return _sanitize_host_text(redact_credentials(text, sensitive_values))


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
    sensitive_values: list[str],
) -> list[str]:
    sanitized = redact_credential_arguments(argv, sensitive_values)
    for index, argument in enumerate(list(sanitized[:-1])):
        if argument == "--env":
            env_argument = sanitized[index + 1]
            if "=" in env_argument:
                sanitized[index + 1] = f"{env_argument.split('=', 1)[0]}=[REDACTED]"
        elif argument == "--name":
            sanitized[index + 1] = "agentguard-[REDACTED]"
        elif argument == "--label":
            label_argument = sanitized[index + 1]
            if label_argument.startswith("agentguard.contained-run.id="):
                sanitized[index + 1] = "agentguard.contained-run.id=[REDACTED]"
    return sanitized


def _sanitize_command_result(
    result: CommandResult,
    config: AgentGuardConfig,
    source: Path,
    run_dir: Path,
    extra_sensitive_values: Optional[list[str]] = None,
) -> CommandResult:
    sensitive = _sensitive_values(config, source, run_dir)
    if extra_sensitive_values:
        sensitive.extend(extra_sensitive_values)
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
        cleanup=kwargs.get("cleanup", ContainedCleanupResult()),
        failure=kwargs["failure"],
        cleanup_failure=kwargs.get("cleanup_failure"),
        environment=kwargs.get("environment", ContainedEnvironmentDiagnostics()),
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
        "command": result.command,
        "docker_argv": result.docker_argv,
        "preflight": result.preflight.to_evidence() if result.preflight else None,
        "environment": asdict(result.environment),
        "command_result": asdict(result.command_result) if result.command_result else None,
        "mutations": result.mutations,
        "checks": [asdict(check) for check in result.check_results],
        "cleanup_complete": result.cleanup_complete,
        "cleanup": asdict(result.cleanup),
        "failure": asdict(result.failure) if result.failure else None,
        "cleanup_failure": (
            asdict(result.cleanup_failure) if result.cleanup_failure else None
        ),
    }
    atomic_write_json(report_path, payload)
    return ContainedRunResult(
        **{**result.__dict__, "report_path": report_path}
    )
