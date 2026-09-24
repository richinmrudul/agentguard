from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from agentguard.config.docker_image import validate_docker_image_reference
from agentguard.core.contained_run import ContainedRunResult, run_contained_agent_command
from agentguard.evaluation.contained_profile import (
    ContainedAgentProfile,
    contained_agent_profile_diagnostics,
    contained_agent_profile_to_dict,
    load_contained_agent_profile,
)
from agentguard.evaluation.study_fixtures import (
    DEFAULT_STUDY_FIXTURE_MANIFEST,
    StudyFixture,
    StudyFixtureSet,
    load_study_fixture_set,
    materialize_study_fixture,
)
from agentguard.evaluation.study_plan import (
    CONTAINED_STUDY_PLAN_SCHEMA,
    CONTAINED_STUDY_PLAN_SCHEMA_VERSION,
    CONTAINED_STUDY_PROTOCOL_VERSION,
    MAX_STUDY_PLAN_TOTAL_TRIALS,
)
from agentguard.io import atomic_write_json, atomic_write_text
from agentguard.provenance.manifest import sha256_file


CONTAINED_STUDY_RUN_STATE_SCHEMA = "agentguard.contained-study-run-state"
CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION = 1
CONTAINED_STUDY_TRIAL_RESULT_SCHEMA = "agentguard.contained-study-trial-result"
CONTAINED_STUDY_TRIAL_RESULT_SCHEMA_VERSION = 1
MAX_STUDY_RUN_PROFILES = 16
MAX_STUDY_RUN_FIXTURES = 32
MAX_STUDY_RUN_TRIALS = MAX_STUDY_PLAN_TOTAL_TRIALS
MAX_STUDY_RUN_STRING = 4096
PORTABLE_ALIAS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,511}$")
TRIAL_ID = re.compile(r"^trial-[0-9a-f]{24}$")


@dataclass(frozen=True)
class ContainedStudyRunnerOptions:
    plan_path: Path
    profile_paths: list[Path]
    fixture_set_path: Optional[Path] = None
    output_dir: Path = Path(".agentguard/contained-studies")
    resume: bool = False
    platform: str = "linux-docker-engine"


@dataclass(frozen=True)
class ContainedStudyRunnerResult:
    run_dir: Path
    state_path: Path
    plan_digest: str
    total_planned: int
    completed: int
    failed: int
    incomplete: int
    not_executed: int
    stop_reason: Optional[str]


class ContainedStudyRunnerError(ValueError):
    pass


RunContainedCommand = Callable[..., ContainedRunResult]


def run_contained_study_plan(
    options: ContainedStudyRunnerOptions,
    *,
    run_contained_command: RunContainedCommand = run_contained_agent_command,
) -> ContainedStudyRunnerResult:
    plan_path = options.plan_path.expanduser().resolve()
    output_dir = options.output_dir.expanduser().resolve()
    plan = _load_plan(plan_path)
    plan_digest = _validate_plan_contract(plan)
    profiles = _load_profiles(options.profile_paths)
    fixture_set = load_study_fixture_set(
        options.fixture_set_path or DEFAULT_STUDY_FIXTURE_MANIFEST
    )
    _verify_profile_identities(plan, profiles)
    _verify_fixture_identities(plan, fixture_set)

    run_dir = output_dir / plan_digest
    _reject_output_inside_fixtures(run_dir, fixture_set)
    lock_path = run_dir / ".agentguard-study.lock"
    _acquire_run_lock(lock_path)
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
        state_path = run_dir / "study-run-state.json"
        state = _load_or_initialize_state(
            state_path,
            plan=plan,
            plan_path=plan_path,
            profile_paths=options.profile_paths,
            fixture_set=fixture_set,
            resume=options.resume,
        )
        _write_state(state_path, state)
        stop_reason = None
        for trial in _ordered_trials(plan):
            trial_id = _string(trial.get("trial_id"), "trial_id")
            current = state["trials"][trial_id]
            if current["status"] == "completed":
                _verify_completed_trial_artifact(run_dir, current)
                continue
            if current["status"] in {"failed", "incomplete", "not_executed"}:
                continue
            if stop_reason is not None:
                current.update(
                    {
                        "status": "not_executed",
                        "outcome": "not_executed_stop_condition",
                        "message": stop_reason,
                    }
                )
                _write_state(state_path, state)
                continue
            current.update({"status": "running", "started_at": _stable_timestamp()})
            _write_state(state_path, state)
            try:
                result_record = _execute_trial(
                    run_dir=run_dir,
                    plan=plan,
                    trial=trial,
                    profiles=profiles,
                    fixture_set=fixture_set,
                    platform=options.platform,
                    run_contained_command=run_contained_command,
                )
            except ContainedStudyRunnerError as error:
                current.update(
                    {
                        "status": "incomplete",
                        "outcome": "runner_validation_failed",
                        "message": _sanitize(str(error)),
                    }
                )
                stop_reason = "runner validation failed"
                _write_state(state_path, state)
                continue
            current.update(result_record["state_update"])
            _write_state(state_path, state)
            if result_record["stop_condition"]:
                stop_reason = _string(result_record["stop_condition"], "stop_condition")
        if stop_reason is not None:
            for trial in _ordered_trials(plan):
                trial_id = _string(trial.get("trial_id"), "trial_id")
                current = state["trials"][trial_id]
                if current["status"] == "planned":
                    current.update(
                        {
                            "status": "not_executed",
                            "outcome": "not_executed_stop_condition",
                            "message": stop_reason,
                        }
                    )
            _write_state(state_path, state)
        summary = _state_summary(state, plan_digest, run_dir, state_path, stop_reason)
        state["summary"] = {
            "completed": summary.completed,
            "failed": summary.failed,
            "incomplete": summary.incomplete,
            "not_executed": summary.not_executed,
            "stop_reason": summary.stop_reason,
            "total_planned": summary.total_planned,
        }
        _write_state(state_path, state)
        return summary
    finally:
        _release_run_lock(lock_path)


def validate_contained_study_plan_for_execution(
    plan_path: Path,
    profile_paths: list[Path],
    *,
    fixture_set_path: Optional[Path] = None,
) -> dict[str, object]:
    plan = _load_plan(plan_path.expanduser().resolve())
    digest = _validate_plan_contract(plan)
    profiles = _load_profiles(profile_paths)
    fixture_set = load_study_fixture_set(fixture_set_path or DEFAULT_STUDY_FIXTURE_MANIFEST)
    _verify_profile_identities(plan, profiles)
    _verify_fixture_identities(plan, fixture_set)
    return {
        "plan_digest": digest,
        "profiles": [profile.id for profile in sorted(profiles.values(), key=lambda item: item.id)],
        "fixtures": [fixture["id"] for fixture in _ordered_fixtures(plan)],
        "trials": len(_ordered_trials(plan)),
        "network": "none",
        "approval_requirements": [],
        "execution_boundary": "contained-run",
    }


def _load_plan(path: Path) -> dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ContainedStudyRunnerError("Contained study plan is not valid JSON.") from error
    if not isinstance(data, dict):
        raise ContainedStudyRunnerError("Contained study plan must be a JSON object.")
    return data


def _validate_plan_contract(plan: dict[str, object]) -> str:
    _reject_unknown_keys(
        plan,
        {
            "approval_requirements",
            "fixtures",
            "plan_digest",
            "profiles",
            "protocol_version",
            "schema",
            "schema_version",
            "source_aliases",
            "total_planned_trial_count",
            "trial_repetitions_per_unit",
            "trials",
            "warnings",
        },
        "contained study plan",
    )
    if plan.get("schema") != CONTAINED_STUDY_PLAN_SCHEMA:
        raise ContainedStudyRunnerError("Invalid contained study plan schema.")
    if plan.get("schema_version") != CONTAINED_STUDY_PLAN_SCHEMA_VERSION:
        raise ContainedStudyRunnerError("Unsupported contained study plan schema version.")
    if plan.get("protocol_version") != CONTAINED_STUDY_PROTOCOL_VERSION:
        raise ContainedStudyRunnerError("Unsupported contained study protocol version.")
    plan_digest = _sha256_string(plan.get("plan_digest"), "plan_digest")
    actual_digest = _plan_digest(plan)
    if actual_digest != plan_digest:
        raise ContainedStudyRunnerError("Contained study plan digest mismatch.")
    source_aliases = _mapping(plan.get("source_aliases"), "source_aliases")
    _reject_unknown_keys(
        source_aliases,
        {"fixture_set", "fixture_set_sha256"},
        "source_aliases",
    )
    _string(source_aliases.get("fixture_set"), "source_aliases.fixture_set")
    _sha256_string(
        source_aliases.get("fixture_set_sha256"),
        "source_aliases.fixture_set_sha256",
    )
    approvals = _string_list(plan.get("approval_requirements"), "approval_requirements")
    if approvals:
        raise ContainedStudyRunnerError(
            "Contained study plan has unresolved approval requirements."
        )
    profiles = _list(plan.get("profiles"), "profiles", 1, MAX_STUDY_RUN_PROFILES)
    fixtures = _list(plan.get("fixtures"), "fixtures", 1, MAX_STUDY_RUN_FIXTURES)
    trials = _list(plan.get("trials"), "trials", 1, MAX_STUDY_RUN_TRIALS)
    total = _positive_int(plan.get("total_planned_trial_count"), "total_planned_trial_count")
    if total != len(trials):
        raise ContainedStudyRunnerError("Contained study total trial count mismatch.")
    repetitions = _positive_int(plan.get("trial_repetitions_per_unit"), "trial_repetitions_per_unit")
    if repetitions > 100:
        raise ContainedStudyRunnerError("Contained study trial repetition bound exceeded.")
    _validate_plan_profiles(profiles)
    _validate_plan_fixtures(fixtures)
    _validate_plan_trials(trials, profiles, fixtures)
    return plan_digest


def _validate_plan_profiles(profiles: list[object]) -> None:
    seen: set[str] = set()
    for index, raw in enumerate(profiles):
        profile = _mapping(raw, f"profiles[{index}]")
        _reject_unknown_keys(
            profile,
            {
                "argv",
                "capabilities",
                "display_label",
                "environment",
                "id",
                "identity",
                "image",
                "limits",
                "metadata",
                "network",
                "profile_manifest_sha256",
                "source_alias",
            },
            f"profiles[{index}]",
        )
        profile_id = _portable_id(profile.get("id"), f"profiles[{index}].id")
        if profile_id in seen:
            raise ContainedStudyRunnerError("Duplicate contained study profile id.")
        seen.add(profile_id)
        image = _string(profile.get("image"), f"profiles[{index}].image")
        validate_docker_image_reference(image)
        if "@sha256:" not in image:
            raise ContainedStudyRunnerError("Contained study profile image is mutable.")
        if profile.get("network") != "none":
            raise ContainedStudyRunnerError("Contained study execution requires network: none.")
        environment = _mapping(profile.get("environment"), f"profiles[{index}].environment")
        _reject_unknown_keys(
            environment,
            {"required", "unset", "values_recorded"},
            f"profiles[{index}].environment",
        )
        required = _string_list(environment.get("required"), "environment.required")
        if required:
            raise ContainedStudyRunnerError(
                "Contained study execution cannot require credentials or environment values."
            )
        if environment.get("values_recorded") is not False:
            raise ContainedStudyRunnerError("Contained study profiles must not record environment values.")
        _string_list(environment.get("unset"), "environment.unset")
        argv = _mapping(profile.get("argv"), f"profiles[{index}].argv")
        _reject_unknown_keys(argv, {"argc", "raw_disclosed", "sha256"}, f"profiles[{index}].argv")
        if argv.get("raw_disclosed") is not False:
            raise ContainedStudyRunnerError("Contained study plan must not disclose raw argv.")
        _sha256_string(argv.get("sha256"), "argv.sha256")
        _positive_int(argv.get("argc"), "argv.argc")
        _sha256_string(profile.get("profile_manifest_sha256"), "profile_manifest_sha256")
        limits = _mapping(profile.get("limits"), "limits")
        _reject_unknown_keys(
            limits,
            {"cpu_limit", "max_output_bytes", "memory_limit", "pids_limit", "timeout_seconds"},
            f"profiles[{index}].limits",
        )
        _validate_limits(limits)
        metadata = _mapping(profile.get("metadata"), f"profiles[{index}].metadata")
        _reject_unknown_keys(
            metadata,
            {"max_cost_usd", "max_input_tokens", "max_output_tokens"},
            f"profiles[{index}].metadata",
        )
        identity = _mapping(profile.get("identity"), f"profiles[{index}].identity")
        _reject_unknown_keys(
            identity,
            {"agent_name", "agent_version", "evidence_source"},
            f"profiles[{index}].identity",
        )
        _string_list(profile.get("capabilities"), "capabilities")
        _portable_alias(profile.get("source_alias"), "source_alias")


def _validate_plan_fixtures(fixtures: list[object]) -> None:
    seen: set[str] = set()
    for index, raw in enumerate(fixtures):
        fixture = _mapping(raw, f"fixtures[{index}]")
        _reject_unknown_keys(
            fixture,
            {
                "checks",
                "expected",
                "fixture_hash",
                "id",
                "license",
                "mutation",
                "network_required",
                "prompt_sha256",
                "required_capabilities",
                "source_alias",
                "task_id",
            },
            f"fixtures[{index}]",
        )
        fixture_id = _portable_id(fixture.get("id"), f"fixtures[{index}].id")
        if fixture_id in seen:
            raise ContainedStudyRunnerError("Duplicate contained study fixture id.")
        seen.add(fixture_id)
        if fixture.get("network_required") is not False:
            raise ContainedStudyRunnerError("Contained study fixtures must not require network.")
        _sha256_string(fixture.get("fixture_hash"), "fixture_hash")
        _sha256_string(fixture.get("prompt_sha256"), "prompt_sha256")
        _portable_id(fixture.get("task_id"), "task_id")
        _portable_alias(fixture.get("source_alias"), "source_alias")
        mutation = _mapping(fixture.get("mutation"), "mutation")
        _reject_unknown_keys(
            mutation,
            {"allowed_paths", "forbidden_paths", "max_modified_files"},
            f"fixtures[{index}].mutation",
        )
        _string_list(mutation.get("allowed_paths"), "mutation.allowed_paths")
        _string_list(mutation.get("forbidden_paths"), "mutation.forbidden_paths")
        _non_negative_int(mutation.get("max_modified_files"), "mutation.max_modified_files")
        checks = _list(fixture.get("checks"), "checks", 1, 64)
        for check_index, raw_check in enumerate(checks):
            check = _mapping(raw_check, f"checks[{check_index}]")
            _reject_unknown_keys(
                check,
                {"expected_status", "id", "kind"},
                f"fixtures[{index}].checks[{check_index}]",
            )
            _portable_id(check.get("id"), "check.id")
            if check.get("kind") not in {"python-module", "read-only", "expected-failure"}:
                raise ContainedStudyRunnerError("Unsupported contained study check kind.")
            status = _non_negative_int(check.get("expected_status"), "check.expected_status")
            if status > 255:
                raise ContainedStudyRunnerError("Contained study check status is out of range.")
        expected = _mapping(fixture.get("expected"), f"fixtures[{index}].expected")
        _reject_unknown_keys(
            expected,
            {
                "expected_guard_incidents",
                "expected_policy_incidents",
                "functional_success",
                "policy_compliant",
                "unsafe_functional_success",
            },
            f"fixtures[{index}].expected",
        )
        _string_list(fixture.get("required_capabilities"), "required_capabilities")


def _validate_plan_trials(
    trials: list[object],
    profiles: list[object],
    fixtures: list[object],
) -> None:
    profile_ids = {_string(_mapping(profile, "profile").get("id"), "profile.id") for profile in profiles}
    fixture_by_id = {
        _string(_mapping(fixture, "fixture").get("id"), "fixture.id"): _mapping(fixture, "fixture")
        for fixture in fixtures
    }
    seen: set[str] = set()
    seen_aliases: set[str] = set()
    for index, raw in enumerate(trials):
        trial = _mapping(raw, f"trials[{index}]")
        _reject_unknown_keys(
            trial,
            {"artifact_alias", "fixture_id", "profile_id", "task_id", "trial_id", "trial_index"},
            f"trials[{index}]",
        )
        trial_id = _string(trial.get("trial_id"), "trial_id")
        if TRIAL_ID.fullmatch(trial_id) is None:
            raise ContainedStudyRunnerError("Invalid contained study trial id.")
        if trial_id in seen:
            raise ContainedStudyRunnerError("Duplicate contained study trial id.")
        seen.add(trial_id)
        alias = _portable_alias(trial.get("artifact_alias"), "artifact_alias")
        if alias in seen_aliases:
            raise ContainedStudyRunnerError("Duplicate contained study artifact alias.")
        seen_aliases.add(alias)
        profile_id = _portable_id(trial.get("profile_id"), "trial.profile_id")
        fixture_id = _portable_id(trial.get("fixture_id"), "trial.fixture_id")
        if profile_id not in profile_ids:
            raise ContainedStudyRunnerError("Contained study trial references an unknown profile.")
        fixture = fixture_by_id.get(fixture_id)
        if fixture is None:
            raise ContainedStudyRunnerError("Contained study trial references an unknown fixture.")
        if trial.get("task_id") != fixture.get("task_id"):
            raise ContainedStudyRunnerError("Contained study trial task identity mismatch.")
        _positive_int(trial.get("trial_index"), "trial.trial_index")


def _load_profiles(paths: list[Path]) -> dict[str, ContainedAgentProfile]:
    if not paths:
        raise ContainedStudyRunnerError("At least one contained agent profile path is required.")
    profiles: dict[str, ContainedAgentProfile] = {}
    seen_paths: set[str] = set()
    for path in paths:
        resolved = path.expanduser().resolve()
        if str(resolved) in seen_paths:
            raise ContainedStudyRunnerError("Contained study profile paths must be unique.")
        seen_paths.add(str(resolved))
        profile = load_contained_agent_profile(resolved)
        if profile.id in profiles:
            raise ContainedStudyRunnerError("Duplicate contained study profile id.")
        profiles[profile.id] = profile
    return profiles


def _verify_profile_identities(
    plan: dict[str, object],
    profiles: dict[str, ContainedAgentProfile],
) -> None:
    plan_profiles = _ordered_profiles(plan)
    if set(profiles) != {_string(profile.get("id"), "profile.id") for profile in plan_profiles}:
        raise ContainedStudyRunnerError("Contained study profile selection does not match the plan.")
    for plan_profile in plan_profiles:
        profile_id = _string(plan_profile.get("id"), "profile.id")
        profile = profiles[profile_id]
        diagnostics = contained_agent_profile_diagnostics(profile)
        if plan_profile.get("image") != profile.image:
            raise ContainedStudyRunnerError(f"Profile {profile_id} image identity mismatch.")
        if plan_profile.get("network") != profile.network or profile.network != "none":
            raise ContainedStudyRunnerError(f"Profile {profile_id} network identity mismatch.")
        if plan_profile.get("profile_manifest_sha256") != _stable_sha256(
            contained_agent_profile_to_dict(profile)
        ):
            raise ContainedStudyRunnerError(f"Profile {profile_id} manifest hash mismatch.")
        argv = _mapping(plan_profile.get("argv"), "profile.argv")
        if argv.get("sha256") != diagnostics["argv_sha256"]:
            raise ContainedStudyRunnerError(f"Profile {profile_id} argv identity mismatch.")
        environment = _mapping(plan_profile.get("environment"), "profile.environment")
        if list(environment.get("required", [])) != list(profile.environment.required):
            raise ContainedStudyRunnerError(f"Profile {profile_id} required environment mismatch.")
        if list(environment.get("unset", [])) != list(profile.environment.unset):
            raise ContainedStudyRunnerError(f"Profile {profile_id} unset environment mismatch.")


def _verify_fixture_identities(plan: dict[str, object], fixture_set: StudyFixtureSet) -> None:
    by_id = {fixture.id: fixture for fixture in fixture_set.fixtures}
    plan_fixtures = _ordered_fixtures(plan)
    if set(by_id).intersection({_string(fixture.get("id"), "fixture.id") for fixture in plan_fixtures}) != {
        _string(fixture.get("id"), "fixture.id") for fixture in plan_fixtures
    }:
        raise ContainedStudyRunnerError("Contained study fixture selection does not match the manifest.")
    source_aliases = _mapping(plan.get("source_aliases"), "source_aliases")
    expected_fixture_set_hash = source_aliases.get("fixture_set_sha256")
    if expected_fixture_set_hash is not None and expected_fixture_set_hash != sha256_file(fixture_set.path):
        raise ContainedStudyRunnerError("Contained study fixture manifest hash mismatch.")
    for plan_fixture in plan_fixtures:
        fixture_id = _string(plan_fixture.get("id"), "fixture.id")
        fixture = by_id.get(fixture_id)
        if fixture is None:
            raise ContainedStudyRunnerError(f"Unknown contained study fixture: {fixture_id}")
        if plan_fixture.get("task_id") != fixture.task_id:
            raise ContainedStudyRunnerError(f"Fixture {fixture_id} task identity mismatch.")
        if plan_fixture.get("fixture_hash") != fixture.source.hash:
            raise ContainedStudyRunnerError(f"Fixture {fixture_id} source hash mismatch.")
        if plan_fixture.get("prompt_sha256") != fixture.prompt.sha256:
            raise ContainedStudyRunnerError(f"Fixture {fixture_id} prompt hash mismatch.")


def _reject_output_inside_fixtures(run_dir: Path, fixture_set: StudyFixtureSet) -> None:
    resolved_run = run_dir.resolve()
    for fixture in fixture_set.fixtures:
        source = fixture.source.path.resolve()
        try:
            resolved_run.relative_to(source)
        except ValueError:
            continue
        raise ContainedStudyRunnerError(
            "Contained study output directory must not be inside a reviewed fixture source."
        )


def _execute_trial(
    *,
    run_dir: Path,
    plan: dict[str, object],
    trial: dict[str, object],
    profiles: dict[str, ContainedAgentProfile],
    fixture_set: StudyFixtureSet,
    platform: str,
    run_contained_command: RunContainedCommand,
) -> dict[str, object]:
    trial_id = _string(trial.get("trial_id"), "trial_id")
    profile_id = _string(trial.get("profile_id"), "profile_id")
    fixture_id = _string(trial.get("fixture_id"), "fixture_id")
    profile = profiles[profile_id]
    fixture = {item.id: item for item in fixture_set.fixtures}[fixture_id]
    plan_profile = {item["id"]: item for item in _ordered_profiles(plan)}[profile_id]
    plan_fixture = {item["id"]: item for item in _ordered_fixtures(plan)}[fixture_id]
    trial_dir = run_dir / "trials" / trial_id
    if trial_dir.exists() and any(trial_dir.iterdir()):
        raise ContainedStudyRunnerError(f"Conflicting artifact directory for trial {trial_id}.")
    workspace = trial_dir / "prepared-workspace"
    evidence_dir = trial_dir / "study-evidence"
    contained_runs = evidence_dir / "contained-runs"
    config_path = evidence_dir / "agentguard-contained-study.yaml"
    prompt_path = evidence_dir / "task-prompt.txt"
    materialize_study_fixture(fixture, workspace)
    prompt_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_text(prompt_path, fixture.prompt.text + "\n")
    config = _contained_config_for_trial(
        profile=profile,
        fixture=fixture,
        platform=platform,
    )
    atomic_write_text(config_path, yaml.safe_dump(config, sort_keys=True))
    result = run_contained_command(
        config_path,
        list(profile.argv),
        source_dir=workspace,
        runs_root=contained_runs,
    )
    result_path = evidence_dir / "contained-study-trial-result.json"
    trial_result = _trial_result_record(
        plan=plan,
        trial=trial,
        plan_profile=plan_profile,
        plan_fixture=plan_fixture,
        result=result,
        prompt_path=prompt_path,
        workspace=workspace,
    )
    atomic_write_json(result_path, trial_result, sort_keys=True)
    status, outcome, stop_condition = _classify_contained_result(result)
    return {
        "state_update": {
            "artifact_alias": trial["artifact_alias"],
            "completed_at": _stable_timestamp(),
            "contained_run_report": _portable_under(run_dir, result.report_path),
            "outcome": outcome,
            "result_path": _portable_under(run_dir, result_path),
            "status": status,
        },
        "stop_condition": stop_condition,
    }


def _contained_config_for_trial(
    *,
    profile: ContainedAgentProfile,
    fixture: StudyFixture,
    platform: str,
) -> dict[str, object]:
    return {
        "task_id": f"{fixture.task_id}-{profile.id}",
        "description": "Experimental contained study runner trial.",
        "repo_template": str(fixture.source.path),
        "test_command": _fixture_test_command(fixture),
        "allowed_paths": list(fixture.mutation.allowed_paths),
        "forbidden_paths": list(fixture.mutation.forbidden_paths),
        "expected_modified_files": {
            "min": 0 if fixture.mutation.max_modified_files == 0 else 1,
            "max": fixture.mutation.max_modified_files,
        },
        "max_output_bytes": profile.limits.max_output_bytes,
        "command_timeout_seconds": profile.limits.timeout_seconds,
        "sandbox": {
            "type": "docker",
            "image": profile.image,
            "network": "none",
            "timeout_seconds": profile.limits.timeout_seconds,
            "docker": {
                "network": "none",
                "cpus": profile.limits.cpu_limit,
                "memory": profile.limits.memory_limit,
                "read_only": False,
            },
        },
        "contained_execution": {
            "version": 1,
            "platform": platform,
            "network": "none",
            "image_provenance": "digest-required",
            "required_uid": os.getuid(),
            "required_gid": os.getgid(),
            "cpu_limit": profile.limits.cpu_limit,
            "memory_limit": profile.limits.memory_limit,
            "pids_limit": profile.limits.pids_limit,
            "tmpfs_size": "64m",
            "environment": [],
        },
    }


def _fixture_test_command(fixture: StudyFixture) -> str:
    commands = [check.command for check in fixture.checks if check.command]
    if not commands:
        return "true"
    if all(check.kind == "read-only" for check in fixture.checks):
        return "true"
    command = commands[0]
    if any(_unsafe_shell_token(part) for part in command):
        raise ContainedStudyRunnerError(
            f"Fixture {fixture.id} check command contains unsafe shell characters."
        )
    if (
        len(command) == 3
        and command[0] == "python"
        and command[1] == "-m"
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", command[2]) is not None
    ):
        return f"PYTHONPATH=src python -m {command[2]}"
    return " ".join(command)


def _trial_result_record(
    *,
    plan: dict[str, object],
    trial: dict[str, object],
    plan_profile: dict[str, object],
    plan_fixture: dict[str, object],
    result: ContainedRunResult,
    prompt_path: Path,
    workspace: Path,
) -> dict[str, object]:
    mutation_status = "complete"
    if result.diff_summary is None or not result.diff_summary.line_count_complete:
        mutation_status = "incomplete"
    check_failures = [
        check.name
        for check in (result.check_results or [])
        if getattr(check, "passed", False) is False
    ]
    return {
        "schema": CONTAINED_STUDY_TRIAL_RESULT_SCHEMA,
        "schema_version": CONTAINED_STUDY_TRIAL_RESULT_SCHEMA_VERSION,
        "plan_digest": plan["plan_digest"],
        "profile": {
            "id": plan_profile["id"],
            "hash": plan_profile["profile_manifest_sha256"],
            "image": plan_profile["image"],
        },
        "fixture": {
            "id": plan_fixture["id"],
            "hash": plan_fixture["fixture_hash"],
            "prompt_sha256": plan_fixture["prompt_sha256"],
            "task_id": plan_fixture["task_id"],
        },
        "trial": {
            "artifact_alias": trial["artifact_alias"],
            "id": trial["trial_id"],
            "index": trial["trial_index"],
        },
        "contained_run": {
            "exit_code": result.exit_code,
            "report_alias": _portable_under(prompt_path.parent, result.report_path),
            "result": result.result,
            "cleanup_complete": result.cleanup_complete,
            "preflight_status": getattr(result.preflight, "status", None),
        },
        "evidence": {
            "check_failures": check_failures,
            "mutation_status": mutation_status,
            "prompt_alias": prompt_path.name,
            "trace_status": "contained-run-report",
            "replayability_status": "contained-run-report",
            "workspace_alias": workspace.name,
        },
    }


def _classify_contained_result(result: ContainedRunResult) -> tuple[str, str, Optional[str]]:
    if not result.cleanup_complete:
        return "incomplete", "cleanup_or_liveness_failure", "cleanup/liveness failure"
    if result.failure is not None and result.failure.stage in {"PREFLIGHT", "WORKSPACE", "CLEANUP"}:
        return "incomplete", f"{result.failure.stage.lower()}_failure", result.failure.message
    if result.failure is not None and result.failure.stage in {"DOCKER", "TIMEOUT"}:
        return "failed", f"{result.failure.stage.lower()}_failure", None
    if result.diff_summary is not None and not result.diff_summary.line_count_complete:
        return "incomplete", "mutation_evidence_incomplete", "mutation evidence incomplete"
    if result.exit_code == 0 and result.result == "PASS":
        return "completed", "completed", None
    return "failed", "agent_or_check_failure", None


def _load_or_initialize_state(
    state_path: Path,
    *,
    plan: dict[str, object],
    plan_path: Path,
    profile_paths: list[Path],
    fixture_set: StudyFixtureSet,
    resume: bool,
) -> dict[str, Any]:
    if state_path.exists():
        if not resume:
            raise ContainedStudyRunnerError(
                "Contained study run state already exists; use resume to continue."
            )
        state = json.loads(state_path.read_text(encoding="utf-8"))
        _validate_state_for_resume(state, plan)
        return state
    if resume:
        raise ContainedStudyRunnerError("Cannot resume; contained study run state is missing.")
    trials = {}
    for trial in _ordered_trials(plan):
        trial_id = _string(trial.get("trial_id"), "trial_id")
        trials[trial_id] = {
            "artifact_alias": trial["artifact_alias"],
            "fixture_id": trial["fixture_id"],
            "outcome": None,
            "profile_id": trial["profile_id"],
            "status": "planned",
            "task_id": trial["task_id"],
            "trial_index": trial["trial_index"],
        }
    return {
        "schema": CONTAINED_STUDY_RUN_STATE_SCHEMA,
        "schema_version": CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION,
        "protocol_version": CONTAINED_STUDY_PROTOCOL_VERSION,
        "plan_digest": plan["plan_digest"],
        "plan_alias": plan_path.name,
        "profile_hashes": {
            path.expanduser().resolve().name: sha256_file(path.expanduser().resolve())
            for path in profile_paths
        },
        "fixture_set_sha256": sha256_file(fixture_set.path),
        "execution_boundary": "contained-run",
        "network": "none",
        "values_recorded": False,
        "trials": trials,
        "summary": {
            "completed": 0,
            "failed": 0,
            "incomplete": 0,
            "not_executed": 0,
            "stop_reason": None,
            "total_planned": len(trials),
        },
    }


def _validate_state_for_resume(state: dict[str, object], plan: dict[str, object]) -> None:
    if state.get("schema") != CONTAINED_STUDY_RUN_STATE_SCHEMA:
        raise ContainedStudyRunnerError("Contained study run state schema mismatch.")
    if state.get("schema_version") != CONTAINED_STUDY_RUN_STATE_SCHEMA_VERSION:
        raise ContainedStudyRunnerError("Contained study run state version mismatch.")
    if state.get("plan_digest") != plan.get("plan_digest"):
        raise ContainedStudyRunnerError("Contained study run state plan digest mismatch.")
    state_trials = _mapping(state.get("trials"), "state.trials")
    plan_trial_ids = {_string(trial.get("trial_id"), "trial_id") for trial in _ordered_trials(plan)}
    if set(state_trials) != plan_trial_ids:
        raise ContainedStudyRunnerError("Contained study run state trial set mismatch.")
    for trial_id, raw in state_trials.items():
        trial_state = _mapping(raw, f"state.trials.{trial_id}")
        status = trial_state.get("status")
        if status == "running":
            trial_state["status"] = "incomplete"
            trial_state["outcome"] = "interrupted"
            trial_state["message"] = "previous execution was interrupted"
        elif status == "completed":
            if "result_path" not in trial_state:
                raise ContainedStudyRunnerError(
                    f"Completed contained study trial {trial_id} is missing artifacts."
                )


def _verify_completed_trial_artifact(run_dir: Path, trial_state: dict[str, object]) -> None:
    result_path = trial_state.get("result_path")
    if not isinstance(result_path, str) or not result_path:
        raise ContainedStudyRunnerError("Completed contained study trial has no result path.")
    path = (run_dir / result_path).resolve()
    try:
        path.relative_to(run_dir.resolve())
    except ValueError as error:
        raise ContainedStudyRunnerError("Completed trial artifact escapes the study run directory.") from error
    if not path.is_file():
        raise ContainedStudyRunnerError("Completed contained study trial artifact is missing.")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != CONTAINED_STUDY_TRIAL_RESULT_SCHEMA:
        raise ContainedStudyRunnerError("Completed contained study trial artifact schema mismatch.")


def _state_summary(
    state: dict[str, Any],
    plan_digest: str,
    run_dir: Path,
    state_path: Path,
    stop_reason: Optional[str],
) -> ContainedStudyRunnerResult:
    counts = {"completed": 0, "failed": 0, "incomplete": 0, "not_executed": 0}
    for raw in _mapping(state.get("trials"), "state.trials").values():
        status = _mapping(raw, "trial_state").get("status")
        if status in counts:
            counts[status] += 1
    return ContainedStudyRunnerResult(
        run_dir=run_dir,
        state_path=state_path,
        plan_digest=plan_digest,
        total_planned=len(_mapping(state.get("trials"), "state.trials")),
        completed=counts["completed"],
        failed=counts["failed"],
        incomplete=counts["incomplete"],
        not_executed=counts["not_executed"],
        stop_reason=stop_reason,
    )


def _write_state(path: Path, state: dict[str, Any]) -> None:
    atomic_write_json(path, state, sort_keys=True)


def _acquire_run_lock(lock_path: Path) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise ContainedStudyRunnerError("Contained study run directory is already owned by another writer.") from error
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(str(os.getpid()))


def _release_run_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink()
    except OSError:
        pass


def _ordered_profiles(plan: dict[str, object]) -> list[dict[str, object]]:
    return sorted(
        [_mapping(item, "profile") for item in _list(plan.get("profiles"), "profiles", 1, MAX_STUDY_RUN_PROFILES)],
        key=lambda item: _string(item.get("id"), "profile.id"),
    )


def _ordered_fixtures(plan: dict[str, object]) -> list[dict[str, object]]:
    return sorted(
        [_mapping(item, "fixture") for item in _list(plan.get("fixtures"), "fixtures", 1, MAX_STUDY_RUN_FIXTURES)],
        key=lambda item: _string(item.get("id"), "fixture.id"),
    )


def _ordered_trials(plan: dict[str, object]) -> list[dict[str, object]]:
    return sorted(
        [_mapping(item, "trial") for item in _list(plan.get("trials"), "trials", 1, MAX_STUDY_RUN_TRIALS)],
        key=lambda item: (
            _string(item.get("profile_id"), "profile_id"),
            _string(item.get("fixture_id"), "fixture_id"),
            _positive_int(item.get("trial_index"), "trial_index"),
            _string(item.get("trial_id"), "trial_id"),
        ),
    )


def _plan_digest(plan: dict[str, object]) -> str:
    without = dict(plan)
    without["plan_digest"] = None
    return _stable_sha256(without)


def _stable_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _reject_unknown_keys(value: dict[str, object], allowed: set[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ContainedStudyRunnerError(f"{label} contains unknown field(s): " + ", ".join(unknown))


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContainedStudyRunnerError(f"Contained study field {label} must be an object.")
    return value


def _list(value: object, label: str, minimum: int, maximum: int) -> list[object]:
    if not isinstance(value, list) or len(value) < minimum or len(value) > maximum:
        raise ContainedStudyRunnerError(
            f"Contained study field {label} must contain {minimum} to {maximum} items."
        )
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_STUDY_RUN_STRING:
        raise ContainedStudyRunnerError(f"Contained study field {label} must be a bounded string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ContainedStudyRunnerError(f"Contained study field {label} contains control characters.")
    return value


def _string_list(value: object, label: str) -> list[str]:
    raw = _list(value, label, 0, 128)
    items = [_string(item, label) for item in raw]
    if len(set(items)) != len(items):
        raise ContainedStudyRunnerError(f"Contained study field {label} contains duplicates.")
    return items


def _portable_id(value: object, label: str) -> str:
    text = _string(value, label)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text) is None:
        raise ContainedStudyRunnerError(f"Contained study field {label} is not a portable id.")
    return text


def _portable_alias(value: object, label: str) -> str:
    text = _string(value, label)
    if (
        PORTABLE_ALIAS.fullmatch(text) is None
        or text.startswith("/")
        or "\\" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
    ):
        raise ContainedStudyRunnerError(f"Contained study field {label} is not a portable artifact alias.")
    return text


def _sha256_string(value: object, label: str) -> str:
    text = _string(value, label)
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise ContainedStudyRunnerError(f"Contained study field {label} must be a sha256 digest.")
    return text


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContainedStudyRunnerError(f"Contained study field {label} must be a positive integer.")
    return value


def _non_negative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContainedStudyRunnerError(f"Contained study field {label} must be a non-negative integer.")
    return value


def _validate_limits(limits: dict[str, object]) -> None:
    for key in ["cpu_limit", "max_output_bytes", "memory_limit", "pids_limit", "timeout_seconds"]:
        if key not in limits:
            raise ContainedStudyRunnerError(f"Contained study limits missing {key}.")
    cpu = limits["cpu_limit"]
    if isinstance(cpu, bool) or not isinstance(cpu, (int, float)) or cpu <= 0:
        raise ContainedStudyRunnerError("Contained study CPU limit is invalid.")
    _positive_int(limits["max_output_bytes"], "max_output_bytes")
    _positive_int(limits["pids_limit"], "pids_limit")
    _positive_int(limits["timeout_seconds"], "timeout_seconds")
    _string(limits["memory_limit"], "memory_limit")


def _unsafe_shell_token(value: str) -> bool:
    return (
        not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(character in value for character in ";&|`$<>\\\"'")
    )


def _portable_under(root: Path, path: Optional[Path]) -> Optional[str]:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return "[REDACTED]"


def _sanitize(value: str) -> str:
    text = "".join(character if 32 <= ord(character) < 127 else "?" for character in value)
    for prefix in ["/Users/", "/home/", "/private/", "/var/folders/"]:
        text = text.replace(prefix, "[REDACTED]/")
    return text[:512]


def _stable_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
