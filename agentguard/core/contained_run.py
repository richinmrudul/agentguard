from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional, Sequence
from uuid import uuid4

from agentguard.artifact_paths import artifact_directory
from agentguard.checks.secret_content import with_secret_content_scan
from agentguard.config.loader import load_config
from agentguard.config.schema import AgentGuardConfig
from agentguard.containment.evidence import (
    ContainmentEvidence,
    evidence_from_contained_run,
)
from agentguard.core.result import CheckResult, CommandResult, DiffSummary, FileRename
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
from agentguard.policy.path_matcher import matching_patterns
from agentguard.provenance.manifest import sanitize_text
from agentguard.redaction import redact_credential_arguments, redact_credentials
from agentguard.sandbox.contained_environment import (
    ContainedEnvironmentDiagnostics,
    resolve_contained_environment,
)
from agentguard.sandbox.contained_workspace import (
    CONTAINED_RUN_ARTIFACT_MARKER,
    CONTAINED_RUN_ARTIFACT_SCHEMA,
    CONTAINED_RUN_ARTIFACT_SCHEMA_VERSION,
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
from agentguard.sandbox.docker_identity import IMAGE_ID_PATTERN
from agentguard.sandbox.docker_preflight import (
    DockerPreflightResult,
    DockerPreflightStatus,
    run_docker_preflight,
)
from agentguard.scoring.scorer import score_checks


CONTAINED_RUNNER_SCHEMA_VERSION = 1
CONTAINED_RUNNER_NAME = "contained-run"
CONTAINED_DIFF_MAX_TEXT_BYTES = 16 * 1024 * 1024
CONTAINED_DIFF_MAX_TOTAL_TEXT_BYTES = 64 * 1024 * 1024


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
    image_id: Optional[str] = None


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
    containment_evidence: Optional[ContainmentEvidence] = None

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
    _write_contained_run_artifact_marker(run_dir, run_id, lifecycle_state="created")

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
                sensitive_values=sensitive_values,
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
                sensitive_values=sensitive_values,
            )

        prepared = prepare_contained_workspace(
            source,
            run_dir / "workspace-lifecycle",
            workspace_id="agent-workspace",
            agentguard_owned_artifact_roots=_discover_contained_run_artifacts(
                source,
                runs_root,
                current_run_dir=run_dir,
            ),
            agentguard_current_artifact_roots=(run_dir,),
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
                    _rename_mutation_evidence(old, new, config)
                    for old, new in captured.renamed_files
                ],
                "changed_files": list(captured.changed_files),
                "current_digest": captured.current_digest,
            }
            diff_summary = _diff_summary_from_mutations(
                captured,
                workspace_dir=prepared.workspace_dir,
            )
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
    if failure is not None:
        result = "FAIL"
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
    if diff_summary.unified_diff:
        diff_summary = replace(
            diff_summary,
            unified_diff=sanitize_text(diff_summary.unified_diff, sensitive_values),
        )
    final = ContainedRunResult(
        task_id=config.task_id,
        config_path=config.config_path,
        source_dir=source,
        run_dir=run_dir,
        command=[
            _sanitize_host_text(argument, sensitive_values)
            for argument in redact_credential_arguments(list(command), sensitive_values)
        ],
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
    final = _with_containment_evidence(
        final,
        config=config,
        source=source,
        run_dir=run_dir,
        prepared=prepared,
        sensitive_values=sensitive_values,
    )
    _write_contained_run_artifact_marker(
        run_dir,
        run_id,
        lifecycle_state="complete" if cleanup_complete else "retained",
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
            image_id=_normal_image_id(inspect.payload.get("Image")),
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


def _normal_image_id(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    return candidate if IMAGE_ID_PATTERN.fullmatch(candidate) else None


def _container_evidence(identity: ContainedContainerIdentity) -> dict[str, str]:
    evidence = {
        "id_sha256": _sha256_short(identity.container_id),
        "name_sha256": _sha256_short(identity.container_name),
        "owner_label_sha256": _sha256_short(identity.owner_label),
    }
    if identity.image_id is not None:
        evidence["image_id"] = identity.image_id
    return evidence


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


@dataclass(frozen=True)
class _ContainedText:
    lines: list[str]
    byte_count: int


@dataclass(frozen=True)
class _ContainedTextError:
    status: str
    message: str


@dataclass(frozen=True)
class _ContainedDiffBuild:
    lines_added: int
    lines_deleted: int
    unified_diff: str
    line_count_status: str
    line_count_complete: bool
    line_count_error: Optional[str]
    unified_diff_status: str
    unified_diff_truncated: bool


def _diff_summary_from_mutations(
    mutations,
    *,
    workspace_dir: Path,
) -> DiffSummary:
    diff = _contained_diff_build(
        mutations,
        workspace_dir=workspace_dir,
    )
    return DiffSummary(
        modified_files=list(mutations.modified_files),
        added_files=list(mutations.added_files),
        deleted_files=list(mutations.deleted_files),
        lines_added=diff.lines_added,
        lines_deleted=diff.lines_deleted,
        unified_diff=diff.unified_diff,
        renamed_files=[
            FileRename(source_path=old, destination_path=new)
            for old, new in mutations.renamed_files
        ],
        line_count_status=diff.line_count_status,
        line_count_complete=diff.line_count_complete,
        line_count_error=diff.line_count_error,
        unified_diff_status=diff.unified_diff_status,
        unified_diff_truncated=diff.unified_diff_truncated,
    )


def _empty_diff_summary() -> DiffSummary:
    return DiffSummary([], [], [], 0, 0, "")


def _contained_diff_build(
    mutations,
    *,
    workspace_dir: Path,
) -> _ContainedDiffBuild:
    baseline_by_path = {entry.path: entry for entry in mutations.baseline_files}
    current_by_path = {entry.path: entry for entry in mutations.current_files}
    baseline_text_files = getattr(mutations, "baseline_text_files", None)
    builder = _ContainedDiffAccumulator()
    for path in mutations.modified_files:
        old = _read_contained_baseline_text(
            path,
            baseline_by_path.get(path),
            baseline_text_files,
        )
        new = _read_contained_workspace_text(workspace_dir, path)
        builder.add_file_diff(old, new)
    for path in mutations.added_files:
        builder.add_file_counts(
            added=_snapshot_line_count(
                current_by_path.get(path),
                unavailable_message="current evidence unavailable",
            ),
            deleted=0,
        )
    for path in mutations.deleted_files:
        builder.add_file_counts(
            added=0,
            deleted=_snapshot_line_count(
                baseline_by_path.get(path),
                unavailable_message="baseline evidence unavailable",
            ),
        )
    for old_path, new_path in mutations.renamed_files:
        old_snapshot = baseline_by_path.get(old_path)
        if old_snapshot is not None:
            current_identity = _contained_path_identity(workspace_dir, new_path)
            if current_identity == _contained_snapshot_identity(old_snapshot):
                continue
        old = _read_contained_baseline_text(
            old_path,
            old_snapshot,
            baseline_text_files,
        )
        new = _read_contained_workspace_text(workspace_dir, new_path)
        builder.add_file_diff(old, new)
    return builder.finish()


class _ContainedDiffAccumulator:
    def __init__(self) -> None:
        self.lines_added = 0
        self.lines_deleted = 0
        self._text_bytes = 0
        self._error: Optional[_ContainedTextError] = None

    def add_file_diff(
        self,
        old: _ContainedText | _ContainedTextError,
        new: _ContainedText | _ContainedTextError,
    ) -> None:
        error = old if isinstance(old, _ContainedTextError) else new
        if isinstance(error, _ContainedTextError):
            self._record_error(error)
            return
        self._text_bytes += old.byte_count + new.byte_count
        if self._text_bytes > CONTAINED_DIFF_MAX_TOTAL_TEXT_BYTES:
            self._record_error(
                _ContainedTextError("incomplete", "total diff byte limit exceeded")
            )
            return
        added, deleted = _contained_line_delta(old.lines, new.lines)
        self.lines_added += added
        self.lines_deleted += deleted

    def add_file_counts(
        self,
        *,
        added: int | _ContainedTextError,
        deleted: int | _ContainedTextError,
    ) -> None:
        error = added if isinstance(added, _ContainedTextError) else deleted
        if isinstance(error, _ContainedTextError):
            self._record_error(error)
            return
        self.lines_added += added
        self.lines_deleted += deleted

    def finish(self) -> _ContainedDiffBuild:
        status = self._error.status if self._error is not None else "exact"
        return _ContainedDiffBuild(
            lines_added=self.lines_added,
            lines_deleted=self.lines_deleted,
            unified_diff="",
            line_count_status=status,
            line_count_complete=self._error is None,
            line_count_error=self._error.message if self._error is not None else None,
            unified_diff_status="not_recorded",
            unified_diff_truncated=False,
        )

    def _record_error(self, error: _ContainedTextError) -> None:
        if self._error is None:
            self._error = error
            return
        priority = {
            "malformed": 4,
            "unavailable": 3,
            "binary": 2,
            "incomplete": 1,
        }
        if priority.get(error.status, 0) > priority.get(self._error.status, 0):
            self._error = error


def _contained_line_delta(old_lines: list[str], new_lines: list[str]) -> tuple[int, int]:
    added = 0
    deleted = 0
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        deleted += old_end - old_start
        added += new_end - new_start
    return added, deleted


def _read_contained_baseline_text(
    path: str,
    snapshot,
    baseline_text_files,
) -> _ContainedText | _ContainedTextError:
    if snapshot is None:
        return _ContainedTextError("malformed", "baseline evidence unavailable")
    if snapshot.kind != "file":
        return _ContainedTextError("binary", "non-text mutation cannot be counted safely")
    content_kind = getattr(snapshot, "content_kind", "not_applicable")
    if content_kind in {"binary", "non_utf8", "symlink"}:
        return _ContainedTextError("binary", "baseline mutation is not UTF-8 text")
    if getattr(snapshot, "line_count_complete", True) is False:
        return _ContainedTextError("incomplete", "baseline line count is incomplete")
    if baseline_text_files is not None and path not in baseline_text_files:
        return _ContainedTextError("unavailable", "baseline text evidence unavailable")
    baseline_lines = (
        baseline_text_files.get(path) if baseline_text_files is not None else None
    )
    if baseline_lines is not None:
        try:
            lines = [line.decode("utf-8") for line in baseline_lines]
        except UnicodeDecodeError:
            return _ContainedTextError("binary", "baseline mutation is not UTF-8 text")
        byte_count = sum(len(line) for line in baseline_lines)
        return _ContainedText(lines, byte_count)
    return _ContainedTextError("unavailable", "baseline content unavailable")


def _snapshot_line_count(
    snapshot,
    *,
    unavailable_message: str,
) -> int | _ContainedTextError:
    if snapshot is None:
        return _ContainedTextError("malformed", unavailable_message)
    if snapshot.kind != "file":
        return _ContainedTextError("binary", "non-text mutation cannot be counted safely")
    content_kind = getattr(snapshot, "content_kind", "not_applicable")
    if content_kind in {"binary", "non_utf8", "symlink"}:
        return _ContainedTextError("binary", "non-text mutation cannot be counted safely")
    if getattr(snapshot, "line_count_complete", True) is False:
        return _ContainedTextError("incomplete", "line count is incomplete")
    line_count = getattr(snapshot, "line_count", None)
    if line_count is None:
        return _ContainedTextError("unavailable", unavailable_message)
    return int(line_count)


def _read_contained_workspace_text(
    workspace_dir: Path,
    path: str,
) -> _ContainedText | _ContainedTextError:
    return _read_contained_text(workspace_dir, path)


def _read_contained_text(
    root: Path,
    path: str,
) -> _ContainedText | _ContainedTextError:
    target = _contained_target(root, path)
    if target is None:
        return _ContainedTextError("malformed", "mutation path is malformed")
    try:
        info = target.lstat()
    except OSError:
        return _ContainedTextError("unavailable", "file content unavailable")
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        return _ContainedTextError("binary", "non-text mutation cannot be counted safely")
    if info.st_size > CONTAINED_DIFF_MAX_TEXT_BYTES:
        return _ContainedTextError("incomplete", "file byte limit exceeded")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(target, flags)
        opened = os.fstat(descriptor)
        if (
            stat.S_IFMT(info.st_mode) != stat.S_IFMT(opened.st_mode)
            or info.st_ino != opened.st_ino
            or info.st_dev != opened.st_dev
            or not stat.S_ISREG(opened.st_mode)
        ):
            return _ContainedTextError("unavailable", "file content unavailable")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read(CONTAINED_DIFF_MAX_TEXT_BYTES + 1)
    except OSError:
        return _ContainedTextError("unavailable", "file content unavailable")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(data) > CONTAINED_DIFF_MAX_TEXT_BYTES:
        return _ContainedTextError("incomplete", "file byte limit exceeded")
    if b"\0" in data:
        return _ContainedTextError("binary", "binary mutation cannot be counted safely")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _ContainedTextError("binary", "non-UTF-8 mutation cannot be counted safely")
    return _ContainedText(text.splitlines(keepends=True), len(data))


def _contained_target(root: Path, path: str) -> Optional[Path]:
    if not path or path.startswith("/") or "\\" in path or "\0" in path:
        return None
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return None
    try:
        root_resolved = root.resolve(strict=True)
        target = root_resolved / Path(*parts)
        target.relative_to(root_resolved)
    except (OSError, RuntimeError, ValueError):
        return None
    return target


def _contained_snapshot_identity(snapshot) -> tuple[str, int, Optional[str], int]:
    return snapshot.kind, snapshot.size, snapshot.sha256, snapshot.mode


def _contained_path_identity(
    root: Path,
    path: str,
) -> Optional[tuple[str, int, Optional[str], int]]:
    target = _contained_target(root, path)
    if target is None:
        return None
    try:
        info = target.lstat()
    except OSError:
        return None
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISREG(info.st_mode):
        digest = _contained_file_sha256(target)
        return None if digest is None else ("file", info.st_size, digest, mode)
    if stat.S_ISLNK(info.st_mode):
        try:
            target_text = os.readlink(target)
        except OSError:
            return None
        digest = hashlib.sha256(target_text.encode("utf-8")).hexdigest()
        return "symlink", len(target_text.encode("utf-8")), digest, mode
    return None


def _contained_file_sha256(path: Path) -> Optional[str]:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _rename_mutation_evidence(
    source_path: str,
    destination_path: str,
    config: AgentGuardConfig,
) -> dict[str, object]:
    return {
        "old": source_path,
        "new": destination_path,
        "source_path": source_path,
        "destination_path": destination_path,
        "change_type": "renamed",
        "policy": {
            "source": _path_policy_evidence(source_path, config),
            "destination": _path_policy_evidence(destination_path, config),
        },
    }


def _path_policy_evidence(path: str, config: AgentGuardConfig) -> dict[str, object]:
    forbidden = matching_patterns(path, config.forbidden_paths)
    test = matching_patterns(path, config.test_paths)
    secret = matching_patterns(path, config.secret_patterns)
    allowed = matching_patterns(path, config.allowed_paths)
    return {
        "path": path,
        "allowed": bool(allowed),
        "allowed_patterns": allowed,
        "outside_allowed": not bool(allowed),
        "forbidden_patterns": forbidden,
        "test_patterns": test,
        "secret_patterns": secret,
        "policy_outcome": "fail" if forbidden or test or secret or not allowed else "pass",
    }


def _run_id(task_id: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    return f"{task_id}-contained-{timestamp}-{uuid4().hex[:8]}"


def _write_contained_run_artifact_marker(
    run_dir: Path,
    run_id: str,
    *,
    lifecycle_state: str,
) -> None:
    atomic_write_json(
        run_dir / CONTAINED_RUN_ARTIFACT_MARKER,
        {
            "schema": CONTAINED_RUN_ARTIFACT_SCHEMA,
            "schema_version": CONTAINED_RUN_ARTIFACT_SCHEMA_VERSION,
            "owner": "agentguard",
            "artifact_kind": "contained-run",
            "run_id": run_id,
            "lifecycle_state": lifecycle_state,
        },
    )


def _discover_contained_run_artifacts(
    source: Path,
    runs_root: Path,
    *,
    current_run_dir: Path,
    max_artifacts: int = 4096,
) -> tuple[Path, ...]:
    try:
        resolved_source = source.resolve()
        resolved_root = runs_root.expanduser().resolve(strict=False)
        resolved_root.relative_to(resolved_source)
    except (OSError, RuntimeError, ValueError):
        return ()
    if not resolved_root.is_dir():
        return ()
    artifacts: list[Path] = []
    try:
        children = sorted(resolved_root.iterdir(), key=lambda path: path.name)
    except OSError:
        return ()
    current_resolved = current_run_dir.expanduser().resolve(strict=False)
    for child in children:
        if len(artifacts) >= max_artifacts:
            break
        try:
            child_resolved = child.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if child_resolved == current_resolved:
            continue
        artifacts.append(child)
    return tuple(artifacts)


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
    return [_sanitize_host_text(argument, sensitive_values) for argument in sanitized]


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
    result = _with_containment_evidence(
        result,
        config=kwargs["config"],
        source=kwargs["source"],
        run_dir=kwargs["run_dir"],
        prepared=kwargs.get("prepared"),
        sensitive_values=kwargs.get("sensitive_values", []),
    )
    return _write_report(result, 0.0)


def _with_containment_evidence(
    result: ContainedRunResult,
    *,
    config: AgentGuardConfig,
    source: Path,
    run_dir: Path,
    prepared: Optional[PreparedContainedWorkspace],
    sensitive_values: list[str],
) -> ContainedRunResult:
    evidence = evidence_from_contained_run(
        config=config,
        source=source,
        run_dir=run_dir,
        command=result.command,
        preflight=result.preflight,
        prepared=prepared,
        environment=result.environment,
        command_result=result.command_result,
        cleanup=result.cleanup,
        cleanup_complete=result.cleanup_complete,
        mutations=result.mutations,
        failure=result.failure,
        sensitive_values=sensitive_values,
    )
    return ContainedRunResult(
        **{**result.__dict__, "containment_evidence": evidence}
    )


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
        "containment_evidence": (
            result.containment_evidence.to_dict()
            if result.containment_evidence is not None
            else None
        ),
        "environment": asdict(result.environment),
        "command_result": asdict(result.command_result) if result.command_result else None,
        "mutations": result.mutations,
        "diff_summary": {
            **asdict(result.diff_summary),
            "changed_files": result.diff_summary.changed_files,
        },
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
