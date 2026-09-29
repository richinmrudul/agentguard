import json
import copy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import pytest
import yaml
from typer.testing import CliRunner

import agentguard.cli.main as cli_main
import agentguard.evaluation.study_runner as study_runner
from agentguard.cli.main import app
from agentguard.core.contained_run import (
    ContainedCleanupResult,
    ContainedRunFailure,
    ContainedRunResult,
)
from agentguard.core.result import CheckResult, CommandResult, DiffSummary
from agentguard.evaluation.study_plan import (
    ContainedStudyPlanOptions,
    build_contained_study_plan,
    serialize_contained_study_plan,
)
from agentguard.evaluation.contained_profile import (
    contained_agent_profile_to_dict,
    load_contained_agent_profile,
)
from agentguard.evaluation.live_egress_contract import (
    LIVE_STUDY_EGRESS_EXECUTION_MODE,
    LIVE_STUDY_EGRESS_NETWORK_MODE,
)
from agentguard.evaluation.live_egress_gateway import (
    EgressDestinationRule,
    LiveStudyEgressPolicy,
    LiveStudyEgressTrialResult,
    build_live_study_egress_manifest,
    evaluate_live_study_egress_destination,
    live_study_egress_policy_digest,
)
from agentguard.evaluation.live_study_authorization import (
    LiveStudyAuthorizationError,
    canonical_live_study_authorization,
)
from agentguard.evaluation.study_runner import (
    ContainedStudyRunnerError,
    ContainedStudyRunnerOptions,
    ContainedStudyRunnerResult,
    run_contained_study_plan,
    validate_contained_study_plan_for_execution,
)
from agentguard.evaluation.live_study_authorization_creation import (
    LiveStudyAuthorizationCreateOptions,
    create_live_study_authorization,
)
from agentguard.sandbox.docker_preflight import DockerPreflightResult, DockerPreflightStatus


IMAGE = "ghcr.io/example/offline-agent@sha256:" + "c" * 64
GATEWAY_IMAGE = "ghcr.io/example/study-egress-gateway@sha256:" + "d" * 64
GATEWAY_IDENTITY = {
    "configured_reference": GATEWAY_IMAGE,
    "local_image_id": "sha256:" + "e" * 64,
    "executed_image_id": "sha256:" + "e" * 64,
    "registry_digest": GATEWAY_IMAGE,
    "platform": "linux/amd64",
    "pull_policy": "docker-default",
    "cache_status": "present",
}
runner = CliRunner()


def _profile_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema": "agentguard.contained-agent-profile",
        "schema_version": 1,
        "id": "offline-profile",
        "display_label": "Offline Profile",
        "image": IMAGE,
        "argv": ["/usr/local/bin/agent", "--task-file", "/workspace/TASK.md"],
        "capabilities": ["python-edit", "read-only"],
        "limits": {
            "timeout_seconds": 30,
            "cpu_limit": 1.0,
            "memory_limit": "128m",
            "pids_limit": 64,
            "max_output_bytes": 4096,
        },
    }
    data.update(overrides)
    return data


def _write_profile(tmp_path: Path, **overrides: object) -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(
        yaml.safe_dump(_profile_data(**overrides), sort_keys=False),
        encoding="utf-8",
    )
    return path


def _plan_file(
    tmp_path: Path,
    profile: Path,
    *,
    fixture_ids: Optional[list[str]] = None,
    approvals: Optional[list[str]] = None,
    trials: int = 1,
) -> Path:
    plan = build_contained_study_plan(
        ContainedStudyPlanOptions(
            profile_paths=[profile],
            fixture_ids=fixture_ids or ["read-only-control"],
            trials=trials,
        )
    )
    data = json.loads(serialize_contained_study_plan(plan))
    if approvals is not None:
        data["approval_requirements"] = approvals
        data["plan_digest"] = _digest(data)
    path = tmp_path / "contained-study-plan.json"
    path.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return path


def _digest(data: dict[str, object]) -> str:
    cloned = dict(data)
    cloned["plan_digest"] = None
    return __import__("hashlib").sha256(
        json.dumps(cloned, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def _live_plan_file(tmp_path: Path, profile: Path, *, trials: int = 1) -> Path:
    plan_path = _plan_file(tmp_path, profile, approvals=[], trials=trials)
    profile_data = yaml.safe_load(profile.read_text(encoding="utf-8"))
    profile_data["network"] = LIVE_STUDY_EGRESS_NETWORK_MODE
    profile.write_text(yaml.safe_dump(profile_data, sort_keys=False), encoding="utf-8")
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    live_profile = load_contained_agent_profile(profile)
    data["profiles"][0]["network"] = LIVE_STUDY_EGRESS_NETWORK_MODE
    data["profiles"][0]["profile_manifest_sha256"] = _digest_profile(live_profile)
    data["plan_digest"] = _digest(data)
    plan_path.write_text(
        json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return plan_path


def _credential_live_plan_file(
    tmp_path: Path,
    profile: Path,
    *,
    credential_names: list[str],
) -> Path:
    plan_path = _live_plan_file(tmp_path, profile)
    profile_data = yaml.safe_load(profile.read_text(encoding="utf-8"))
    profile_data["environment"] = {
        "required": list(credential_names),
        "unset": [],
    }
    profile.write_text(yaml.safe_dump(profile_data, sort_keys=False), encoding="utf-8")
    live_profile = load_contained_agent_profile(profile)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    data["profiles"][0]["environment"] = {
        "required": list(credential_names),
        "unset": [],
        "values_recorded": False,
    }
    data["profiles"][0]["profile_manifest_sha256"] = _digest_profile(live_profile)
    data["plan_digest"] = _digest(data)
    plan_path.write_text(
        json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return plan_path


def _digest_profile(profile) -> str:
    return __import__("hashlib").sha256(
        json.dumps(
            contained_agent_profile_to_dict(profile),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _egress_policy() -> LiveStudyEgressPolicy:
    return LiveStudyEgressPolicy(
        destinations=(
            EgressDestinationRule("mock-approved.test", 443, test_only=True),
        )
    )


def _authorization_file(
    tmp_path: Path,
    plan_path: Path,
    policy: LiveStudyEgressPolicy,
    *,
    credential_env_names: Optional[list[str]] = None,
) -> Path:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    profile = plan["profiles"][0]
    fixtures = [
        {"hash": item["fixture_hash"], "id": item["id"], "task_id": item["task_id"]}
        for item in plan["fixtures"]
    ]
    now = datetime.now(timezone.utc)
    artifact = {
        "authorization_id": "auth-contained-runner",
        "credential_env_names": credential_env_names or [],
        "destinations": [{"host": "mock-approved.test", "port": 443}],
        "egress_policy_digest": live_study_egress_policy_digest(policy),
        "evidence_bounds": {"max_output_bytes": 4096},
        "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "fixtures": fixtures,
        "images": {"agent": profile["image"], "gateway": GATEWAY_IMAGE},
        "issued_at": (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "issuer": "unit-test",
        "limits": {
            "max_turns": 1,
            "per_trial_cost_usd": 0.0,
            "per_trial_input_tokens": 0,
            "per_trial_output_tokens": 0,
            "per_trial_timeout_seconds": 30,
            "total_cost_usd": 0.0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
        },
        "max_trial_count": len(plan["trials"]),
        "not_before": (now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "plan_digest": plan["plan_digest"],
        "profile": {
            "hash": profile["profile_manifest_sha256"],
            "id": profile["id"],
        },
        "protocol_version": plan["protocol_version"],
        "provider": {"model_id": "mock-model", "provider_id": "mock-provider"},
        "publication_redaction_policy_digest": "5" * 64,
        "schema": "agentguard.live-study-authorization",
        "schema_version": 1,
        "stop_thresholds": {"max_failures": 1},
        "trials": [trial["trial_id"] for trial in plan["trials"]],
    }
    path = tmp_path / "live-study-authorization.json"
    path.write_text(canonical_live_study_authorization(artifact) + "\n", encoding="utf-8")
    return path


def _create_options(
    tmp_path: Path,
    plan_path: Path,
    *,
    model_id: str = "mock-model",
) -> LiveStudyAuthorizationCreateOptions:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    profile = plan["profiles"][0]
    fixture = plan["fixtures"][0]
    now = datetime.now(timezone.utc)
    return LiveStudyAuthorizationCreateOptions(
        plan_path=plan_path,
        authorization_id="auth-created-offline",
        issuer="unit-test-reviewer",
        issued_at=(now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        not_before=(now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        expires_at=(now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        profile_id=profile["id"],
        fixture_ids=[fixture["id"]],
        trial_ids=[trial["trial_id"] for trial in plan["trials"]],
        agent_image=profile["image"],
        gateway_image=GATEWAY_IMAGE,
        destinations=[("mock-approved.test", 443)],
        credential_env_names=[],
        provider_id="mock-provider",
        model_id=model_id,
        limits={
            "max_turns": 1,
            "per_trial_cost_usd": 0.0,
            "per_trial_input_tokens": 0,
            "per_trial_output_tokens": 0,
            "per_trial_timeout_seconds": 30,
            "total_cost_usd": 0.0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
        },
        evidence_bounds={"max_output_bytes": 4096},
        stop_thresholds={"max_failures": 1},
        publication_redaction_policy_digest="5" * 64,
    )


def test_live_study_authorization_create_binds_reviewed_inputs(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)

    created = create_live_study_authorization(_create_options(tmp_path, plan))
    data = json.loads(created.canonical_json)

    assert data["schema"] == "agentguard.live-study-authorization"
    assert data["authorization_id"] == "auth-created-offline"
    assert data["plan_digest"] == created.plan_digest
    assert data["images"] == {"agent": IMAGE, "gateway": GATEWAY_IMAGE}
    assert data["destinations"] == [{"host": "mock-approved.test", "port": 443}]
    assert data["trials"] == [json.loads(plan.read_text(encoding="utf-8"))["trials"][0]["trial_id"]]
    assert data["max_trial_count"] == 1
    assert created.digest


def test_live_study_authorization_create_rejects_wildcards(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)

    with pytest.raises(ValueError, match="wildcards"):
        create_live_study_authorization(
            _create_options(tmp_path, plan, model_id="mock-*")
        )


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda options, _plan: replace(
                options,
                agent_image="ghcr.io/example/offline-agent@sha256:" + "0" * 64,
            ),
            "agent image mismatch",
        ),
        (
            lambda options, _plan: replace(options, credential_env_names=["API_KEY"]),
            "credential names",
        ),
        (
            lambda options, _plan: replace(options, profile_id="missing-profile"),
            "profile must be explicit",
        ),
        (
            lambda options, _plan: replace(options, trial_ids=[]),
            "explicit trials",
        ),
        (
            lambda options, _plan: replace(
                options,
                trial_ids=[options.trial_ids[0], options.trial_ids[0]],
            ),
            "Duplicate live-study authorization trial",
        ),
        (
            lambda options, _plan: replace(options, trial_ids=["missing-trial"]),
            "Unknown live-study authorization trial",
        ),
        (
            lambda options, _plan: replace(options, fixture_ids=[]),
            "explicit fixtures",
        ),
        (
            lambda options, _plan: replace(
                options,
                fixture_ids=[options.fixture_ids[0], options.fixture_ids[0]],
            ),
            "Duplicate live-study authorization fixture",
        ),
        (
            lambda options, _plan: replace(options, fixture_ids=["safe-bounded-edit"]),
            "fixtures must exactly match",
        ),
        (
            lambda options, _plan: replace(
                options,
                destinations=[("mock-approved.test", 443)],
                egress_policy=LiveStudyEgressPolicy(
                    destinations=(
                        EgressDestinationRule("other-approved.test", 443, test_only=True),
                    )
                ),
            ),
            "egress policy destination mismatch",
        ),
    ],
)
def test_live_study_authorization_create_rejects_unreviewed_inputs(
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)
    options = mutate(_create_options(tmp_path, plan), plan)

    with pytest.raises(LiveStudyAuthorizationError, match=match):
        create_live_study_authorization(options)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda data: data.update({"profiles": "not-a-list"}),
            "profiles must contain",
        ),
        (
            lambda data: data["profiles"].__setitem__(0, "not-an-object"),
            "profiles\\[0\\] must be an object",
        ),
        (
            lambda data: data["profiles"][0].update({"environment": []}),
            "profiles\\[0\\].environment must be an object",
        ),
        (
            lambda data: data["profiles"][0].update({"environment": {"required": "API_KEY"}}),
            "environment.required must contain",
        ),
        (
            lambda data: data.update({"trials": "not-a-list"}),
            "trials must contain",
        ),
        (
            lambda data: data["trials"].__setitem__(0, "not-an-object"),
            "trials\\[0\\] must be an object",
        ),
        (
            lambda data: data.update({"fixtures": "not-a-list"}),
            "fixtures must contain",
        ),
        (
            lambda data: data["fixtures"].__setitem__(0, "not-an-object"),
            "fixtures\\[0\\] must be an object",
        ),
    ],
)
def test_live_study_authorization_create_rejects_malformed_plan_parts(
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)
    options = _create_options(tmp_path, plan)
    data = json.loads(plan.read_text(encoding="utf-8"))
    mutate(data)
    data["plan_digest"] = _digest(data)
    plan.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    with pytest.raises(LiveStudyAuthorizationError, match=match):
        create_live_study_authorization(options)


def _fake_result(tmp_path: Path, *, cleanup: bool = True, result: str = "PASS") -> ContainedRunResult:
    report = tmp_path / "contained-run.json"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text('{"schema":"agentguard.contained-run"}\n', encoding="utf-8")
    return ContainedRunResult(
        task_id="study-control",
        config_path=tmp_path / "agentguard.yaml",
        source_dir=tmp_path / "workspace",
        run_dir=tmp_path,
        command=["/usr/local/bin/agent", "--task-file", "/workspace/TASK.md"],
        docker_argv=["docker", "run", "--network", "none", "--", IMAGE],
        preflight=DockerPreflightResult(
            DockerPreflightStatus.SUPPORTED,
            "linux-docker-engine",
            True,
            [],
        ),
        command_result=CommandResult("contained-run", 0 if result == "PASS" else 1, "", "", 0.01),
        diff_summary=DiffSummary([], [], [], 0, 0, ""),
        check_results=[CheckResult("Functional checks", result == "PASS", "error", "")],
        result=result,
        score=100 if result == "PASS" else 0,
        mutations={},
        cleanup_complete=cleanup,
        cleanup=ContainedCleanupResult(complete=cleanup),
        failure=None,
        report_path=report,
    )


def test_valid_canonical_offline_plan_executes_through_contained_run(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    calls: list[tuple[Path, list[str], Path, Path]] = []

    def fake_run(config_path, command, *, source_dir, runs_root):
        calls.append((config_path, command, source_dir, runs_root))
        assert command == ["/usr/local/bin/agent", "--task-file", "/workspace/TASK.md"]
        assert source_dir.name == "prepared-workspace"
        assert runs_root.name == "contained-runs"
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert config["sandbox"]["network"] == "none"
        assert config["sandbox"]["timeout_seconds"] == 30
        assert config["sandbox"]["docker"] == {
            "cpus": 1.0,
            "memory": "128m",
            "network": "none",
            "read_only": False,
        }
        assert config["contained_execution"]["network"] == "none"
        return _fake_result(runs_root)

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(
            plan_path=plan,
            profile_paths=[profile],
            output_dir=tmp_path / "runs",
        ),
        run_contained_command=fake_run,
    )

    assert len(calls) == 1
    assert result.completed == 1
    state = json.loads(result.state_path.read_text(encoding="utf-8"))
    assert state["execution_boundary"] == "contained-run"
    assert state["network"] == "none"
    assert state["values_recorded"] is False
    assert str(tmp_path) not in json.dumps(state, sort_keys=True)


def test_valid_plan_validation_summary_is_sanitized(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])

    summary = validate_contained_study_plan_for_execution(plan, [profile])

    assert summary == {
        "approval_requirements": [],
        "execution_boundary": "contained-run",
        "fixtures": ["read-only-control"],
        "network": "none",
        "plan_digest": summary["plan_digest"],
        "profiles": ["offline-profile"],
        "trials": 1,
    }
    assert str(tmp_path) not in json.dumps(summary, sort_keys=True)


def test_study_egress_mode_requires_explicit_options_and_records_live_boundary(
    tmp_path: Path,
) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)
    policy = _egress_policy()
    authorization = _authorization_file(tmp_path, plan, policy)
    calls = []

    def fake_egress(request):
        calls.append(request)
        event = evaluate_live_study_egress_destination(
            request.policy,
            host="mock-approved.test",
            port=443,
            protocol="https",
            resolved_addresses=["203.0.113.10"],
        )
        manifest = build_live_study_egress_manifest(
            plan_digest=request.plan_digest,
            profile_hash=request.profile_hash,
            fixture_hash=request.fixture_hash,
            trial_id=request.trial_id,
            policy=request.policy,
            gateway_image=GATEWAY_IDENTITY,
            approved_host="mock-approved.test",
            approved_port=443,
            events=[event],
            gateway_status={"status": "running", "evidence_complete": True},
            cleanup_status={"overall_complete": True},
            liveness_status={"verified": True},
        )
        manifest_path = request.evidence_dir / "live-study-egress-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return LiveStudyEgressTrialResult(
            manifest=manifest,
            manifest_path=manifest_path,
            status="completed",
            outcome="completed",
        )

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(
            plan,
            [profile],
            output_dir=tmp_path / "runs",
            execution_mode=LIVE_STUDY_EGRESS_EXECUTION_MODE,
            egress_policy=policy,
            gateway_image=GATEWAY_IMAGE,
            authorization_path=authorization,
        ),
        run_contained_command=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("contained-run executed")),
        run_study_egress_command=fake_egress,
    )

    assert len(calls) == 1
    assert result.completed == 1
    state = json.loads(result.state_path.read_text(encoding="utf-8"))
    assert state["execution_boundary"] == LIVE_STUDY_EGRESS_EXECUTION_MODE
    assert state["network"] == LIVE_STUDY_EGRESS_NETWORK_MODE
    trial_state = next(iter(state["trials"].values()))
    assert trial_state["egress_manifest"].endswith("live-study-egress-manifest.json")


def test_study_egress_gateway_failure_stops_later_trials(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile, trials=2)
    policy = _egress_policy()
    authorization = _authorization_file(tmp_path, plan, policy)
    calls = 0

    def fake_crash(request):
        nonlocal calls
        calls += 1
        manifest = build_live_study_egress_manifest(
            plan_digest=request.plan_digest,
            profile_hash=request.profile_hash,
            fixture_hash=request.fixture_hash,
            trial_id=request.trial_id,
            policy=request.policy,
            gateway_image=GATEWAY_IDENTITY,
            approved_host=None,
            approved_port=None,
            events=[],
            gateway_status={
                "status": "running",
                "crashed": True,
                "evidence_complete": True,
            },
            cleanup_status={"overall_complete": True},
            liveness_status={"verified": True},
        )
        manifest_path = request.evidence_dir / "live-study-egress-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return LiveStudyEgressTrialResult(
            manifest=manifest,
            manifest_path=manifest_path,
            status="failed",
            outcome="gateway_crash",
            stop_condition="gateway failure",
        )

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(
            plan,
            [profile],
            output_dir=tmp_path / "runs",
            execution_mode=LIVE_STUDY_EGRESS_EXECUTION_MODE,
            egress_policy=policy,
            gateway_image=GATEWAY_IMAGE,
            authorization_path=authorization,
        ),
        run_study_egress_command=fake_crash,
    )

    assert calls == 1
    assert result.failed == 1
    assert result.not_executed == 1
    assert result.stop_reason == "gateway failure"


def test_python_fixture_checks_use_source_layout_path(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, fixture_ids=["safe-bounded-edit"], approvals=[])

    def fake_run(config_path, command, *, source_dir, runs_root):
        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        assert config["test_command"] == "PYTHONPATH=src python -m calc_tools.mini_pytest"
        return _fake_result(runs_root)

    run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=tmp_path / "runs"),
        run_contained_command=fake_run,
    )


def test_unresolved_approval_requirement_rejects_before_execution(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile)

    def fail_run(*_args, **_kwargs):
        raise AssertionError("contained-run should not execute")

    with pytest.raises(ContainedStudyRunnerError, match="unresolved approval"):
        run_contained_study_plan(
            ContainedStudyRunnerOptions(plan, [profile], output_dir=tmp_path / "runs"),
            run_contained_command=fail_run,
        )


def test_runner_validation_error_stops_remaining_trials(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[], trials=2)
    calls = 0

    def fake_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise ContainedStudyRunnerError("/Users/private/control failure")

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=tmp_path / "runs"),
        run_contained_command=fake_run,
    )

    assert calls == 1
    assert result.incomplete == 1
    assert result.not_executed == 1
    state = json.loads(result.state_path.read_text(encoding="utf-8"))
    interrupted = [trial for trial in state["trials"].values() if trial["status"] == "incomplete"][0]
    assert "control failure" in interrupted["message"]
    assert "/Users/" not in interrupted["message"]


def test_plan_digest_profile_fixture_and_prompt_mismatch_reject(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    data = json.loads(plan.read_text(encoding="utf-8"))

    tampered = copy.deepcopy(data)
    tampered["profiles"][0]["image"] = "ghcr.io/example/offline-agent@sha256:" + "d" * 64
    tampered["plan_digest"] = _digest(tampered)
    bad_profile_plan = tmp_path / "bad-profile-plan.json"
    bad_profile_plan.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ContainedStudyRunnerError, match="image identity mismatch"):
        validate_contained_study_plan_for_execution(bad_profile_plan, [profile])

    bad_digest = copy.deepcopy(data)
    bad_digest["total_planned_trial_count"] = 2
    bad_digest_plan = tmp_path / "bad-digest-plan.json"
    bad_digest_plan.write_text(json.dumps(bad_digest), encoding="utf-8")
    with pytest.raises(ContainedStudyRunnerError, match="digest mismatch"):
        validate_contained_study_plan_for_execution(bad_digest_plan, [profile])

    tampered_fixture = copy.deepcopy(data)
    tampered_fixture["fixtures"][0]["prompt_sha256"] = "0" * 64
    tampered_fixture["plan_digest"] = _digest(tampered_fixture)
    bad_fixture_plan = tmp_path / "bad-fixture-plan.json"
    bad_fixture_plan.write_text(json.dumps(tampered_fixture), encoding="utf-8")
    with pytest.raises(ContainedStudyRunnerError, match="prompt hash mismatch"):
        validate_contained_study_plan_for_execution(bad_fixture_plan, [profile])


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda data: data["trials"].append(dict(data["trials"][0])), "trial count mismatch"),
        (lambda data: data["trials"][0].update({"artifact_alias": "../escape"}), "artifact alias"),
        (lambda data: data["profiles"][0].update({"network": "bridge"}), "network: none"),
        (lambda data: data["profiles"][0]["environment"].update({"required": ["API_TOKEN"]}), "credentials"),
        (lambda data: data["profiles"][0].update({"image": "alpine:latest"}), "mutable"),
        (lambda data: data.update({"external_verifier": "nope"}), "unknown"),
    ],
)
def test_invalid_plan_contracts_reject_before_execution(tmp_path: Path, mutate, match: str) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    data = json.loads(plan.read_text(encoding="utf-8"))
    mutate(data)
    data["plan_digest"] = _digest(data)
    if "external_verifier" in data:
        data["plan_digest"] = _digest(data)
    bad = tmp_path / f"bad-{match.replace(' ', '-')}.json"
    bad.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")

    with pytest.raises(ContainedStudyRunnerError, match=match):
        run_contained_study_plan(
            ContainedStudyRunnerOptions(bad, [profile], output_dir=tmp_path / "runs"),
            run_contained_command=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("executed")),
        )


def test_resume_never_reruns_completed_trial_and_rejects_corruption(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    output = tmp_path / "runs"
    first = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=output),
        run_contained_command=lambda *_args, **kwargs: _fake_result(kwargs["runs_root"]),
    )

    rerun = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=output, resume=True),
        run_contained_command=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("reran")),
    )

    assert rerun.completed == 1
    state = json.loads(first.state_path.read_text(encoding="utf-8"))
    trial_state = next(iter(state["trials"].values()))
    (first.run_dir / trial_state["result_path"]).unlink()
    with pytest.raises(ContainedStudyRunnerError, match="artifact is missing"):
        run_contained_study_plan(
            ContainedStudyRunnerOptions(plan, [profile], output_dir=output, resume=True),
            run_contained_command=lambda *_args, **_kwargs: _fake_result(tmp_path),
        )


def test_resume_rejects_state_mismatches_and_marks_running_interrupted(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    output = tmp_path / "runs"
    first = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=output),
        run_contained_command=lambda *_args, **kwargs: _fake_result(kwargs["runs_root"]),
    )
    state = json.loads(first.state_path.read_text(encoding="utf-8"))
    trial_id = next(iter(state["trials"]))

    state["trials"][trial_id]["status"] = "running"
    first.state_path.write_text(json.dumps(state), encoding="utf-8")
    resumed = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=output, resume=True),
        run_contained_command=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("reran")),
    )
    assert resumed.incomplete == 1
    state = json.loads(first.state_path.read_text(encoding="utf-8"))
    assert state["trials"][trial_id]["outcome"] == "interrupted"

    state["schema"] = "wrong"
    first.state_path.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(ContainedStudyRunnerError, match="schema mismatch"):
        run_contained_study_plan(
            ContainedStudyRunnerOptions(plan, [profile], output_dir=output, resume=True),
            run_contained_command=lambda *_args, **_kwargs: _fake_result(tmp_path),
        )


def test_concurrent_ownership_and_interrupted_state(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    digest = json.loads(plan.read_text(encoding="utf-8"))["plan_digest"]
    run_dir = tmp_path / "runs" / digest
    run_dir.mkdir(parents=True)
    (run_dir / ".agentguard-study.lock").write_text("other", encoding="utf-8")

    with pytest.raises(ContainedStudyRunnerError, match="already owned"):
        run_contained_study_plan(
            ContainedStudyRunnerOptions(plan, [profile], output_dir=tmp_path / "runs"),
            run_contained_command=lambda *_args, **_kwargs: _fake_result(tmp_path),
        )


def test_cleanup_failure_stops_later_trials(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[], trials=2)
    calls = 0

    def fake_run(*_args, **kwargs):
        nonlocal calls
        calls += 1
        return _fake_result(kwargs["runs_root"], cleanup=False)

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=tmp_path / "runs"),
        run_contained_command=fake_run,
    )

    assert calls == 1
    assert result.incomplete == 1
    assert result.not_executed == 1
    assert result.stop_reason == "cleanup/liveness failure"


def test_failure_stage_and_incomplete_evidence_classification(tmp_path: Path) -> None:
    preflight = _fake_result(
        tmp_path,
        result="FAIL",
    )
    preflight = ContainedRunResult(
        **{
            **preflight.__dict__,
            "failure": ContainedRunFailure("PREFLIGHT", 3, "preflight denied"),
        }
    )
    assert study_runner._classify_contained_result(preflight) == (
        "incomplete",
        "preflight_failure",
        "preflight denied",
    )

    docker = _fake_result(tmp_path, result="FAIL")
    docker = ContainedRunResult(
        **{
            **docker.__dict__,
            "failure": ContainedRunFailure("DOCKER", 6, "docker denied"),
        }
    )
    assert study_runner._classify_contained_result(docker) == (
        "failed",
        "docker_failure",
        None,
    )

    incomplete_diff = _fake_result(tmp_path)
    incomplete_diff = ContainedRunResult(
        **{
            **incomplete_diff.__dict__,
            "diff_summary": DiffSummary(
                [],
                [],
                [],
                0,
                0,
                "",
                line_count_complete=False,
            ),
        }
    )
    assert study_runner._classify_contained_result(incomplete_diff) == (
        "incomplete",
        "mutation_evidence_incomplete",
        "mutation evidence incomplete",
    )


def test_agent_or_check_failure_is_recorded_and_later_trials_continue(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[], trials=2)
    calls = 0

    def fake_run(*_args, **kwargs):
        nonlocal calls
        calls += 1
        return _fake_result(kwargs["runs_root"], result="FAIL" if calls == 1 else "PASS")

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(plan, [profile], output_dir=tmp_path / "runs"),
        run_contained_command=fake_run,
    )

    assert calls == 2
    assert result.failed == 1
    assert result.completed == 1
    state = json.loads(result.state_path.read_text(encoding="utf-8"))
    outcomes = sorted(trial["outcome"] for trial in state["trials"].values())
    assert outcomes == ["agent_or_check_failure", "completed"]


def test_cli_help_and_controlled_error(tmp_path: Path) -> None:
    help_result = runner.invoke(app, ["evaluation", "study-run", "--help"])
    assert help_result.exit_code == 0
    assert "contained-run only" in help_result.output

    result = runner.invoke(app, ["evaluation", "study-run", "--plan", str(tmp_path / "missing.json")])
    assert result.exit_code == 2
    assert "Error:" in result.output


def test_study_auth_create_cli_writes_canonical_authorization(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)
    output = tmp_path / "created-authorization.json"
    now = datetime.now(timezone.utc)
    trial_id = json.loads(plan.read_text(encoding="utf-8"))["trials"][0]["trial_id"]

    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-auth",
            "create",
            "--plan",
            str(plan),
            "--authorization-id",
            "auth-created-cli",
            "--issuer",
            "unit-test-reviewer",
            "--issued-at",
            (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--not-before",
            (now - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--expires-at",
            (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "--profile-id",
            "offline-profile",
            "--fixture",
            "read-only-control",
            "--trial",
            trial_id,
            "--agent-image",
            IMAGE,
            "--gateway-image",
            GATEWAY_IMAGE,
            "--destination",
            "mock-approved.test:443",
            "--provider-id",
            "mock-provider",
            "--model-id",
            "mock-model",
            "--max-turns",
            "1",
            "--per-trial-cost-usd",
            "0",
            "--per-trial-input-tokens",
            "0",
            "--per-trial-output-tokens",
            "0",
            "--per-trial-timeout-seconds",
            "30",
            "--total-cost-usd",
            "0",
            "--total-input-tokens",
            "0",
            "--total-output-tokens",
            "0",
            "--evidence-bound",
            "max_output_bytes=4096",
            "--stop-threshold",
            "max_failures=1",
            "--publication-redaction-policy-digest",
            "5" * 64,
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["authorization_id"] == "auth-created-cli"
    assert data["trials"] == [trial_id]
    assert "Credential values: not inspected" in result.output


def test_study_auth_live_run_cli_requires_confirmation(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)
    authorization = _authorization_file(tmp_path, plan, _egress_policy())

    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-auth",
            "live-run",
            str(authorization),
            "--plan",
            str(plan),
            "--profile",
            str(profile),
            "--ledger",
            str(tmp_path / "ledger.json"),
            "--gateway-image",
            GATEWAY_IMAGE,
            "--destination",
            "mock-approved.test:443",
            "--confirm-authorization-id",
            "wrong-auth",
        ],
    )

    assert result.exit_code == 2
    assert "confirmation" in result.output


def test_study_auth_live_run_cli_wraps_study_egress_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = _write_profile(tmp_path)
    plan = _live_plan_file(tmp_path, profile)
    authorization = _authorization_file(tmp_path, plan, _egress_policy())
    ledger = tmp_path / "ledger.json"
    captured = {}

    def fake_run(options: ContainedStudyRunnerOptions) -> ContainedStudyRunnerResult:
        captured["options"] = options
        state_path = tmp_path / "state.json"
        state_path.write_text("{}", encoding="utf-8")
        return ContainedStudyRunnerResult(
            run_dir=tmp_path,
            state_path=state_path,
            plan_digest="1" * 64,
            total_planned=1,
            completed=1,
            failed=0,
            incomplete=0,
            not_executed=0,
            stop_reason=None,
        )

    monkeypatch.setattr(cli_main, "run_contained_study_plan", fake_run)
    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-auth",
            "live-run",
            str(authorization),
            "--plan",
            str(plan),
            "--profile",
            str(profile),
            "--ledger",
            str(ledger),
            "--gateway-image",
            GATEWAY_IMAGE,
            "--destination",
            "mock-approved.test:443",
            "--confirm-authorization-id",
            "auth-contained-runner",
        ],
    )

    assert result.exit_code == 0, result.output
    options = captured["options"]
    assert options.execution_mode == LIVE_STUDY_EGRESS_EXECUTION_MODE
    assert options.authorization_path == authorization
    assert options.authorization_ledger_path == ledger
    assert options.gateway_image == GATEWAY_IMAGE
    assert options.credential_environment is None


def test_study_auth_live_run_cli_does_not_read_credentials_before_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_name = "AGENTGUARD_FAKE_API_KEY"
    profile = _write_profile(tmp_path)
    plan = _credential_live_plan_file(
        tmp_path,
        profile,
        credential_names=[credential_name],
    )
    authorization = _authorization_file(
        tmp_path,
        plan,
        _egress_policy(),
        credential_env_names=[credential_name],
    )
    monkeypatch.delenv(credential_name, raising=False)
    called = False

    def fake_run(options: ContainedStudyRunnerOptions) -> ContainedStudyRunnerResult:
        nonlocal called
        called = True
        assert options.credential_environment is None
        state_path = tmp_path / "state.json"
        state_path.write_text("{}", encoding="utf-8")
        return ContainedStudyRunnerResult(
            run_dir=tmp_path,
            state_path=state_path,
            plan_digest="1" * 64,
            total_planned=1,
            completed=1,
            failed=0,
            incomplete=0,
            not_executed=0,
            stop_reason=None,
        )

    monkeypatch.setattr(cli_main, "run_contained_study_plan", fake_run)
    result = runner.invoke(
        app,
        [
            "evaluation",
            "study-auth",
            "live-run",
            str(authorization),
            "--plan",
            str(plan),
            "--profile",
            str(profile),
            "--ledger",
            str(tmp_path / "ledger.json"),
            "--gateway-image",
            GATEWAY_IMAGE,
            "--destination",
            "mock-approved.test:443",
            "--credential-env",
            credential_name,
            "--confirm-authorization-id",
            "auth-contained-runner",
        ],
    )

    assert result.exit_code == 0, result.output
    assert called is True


def test_study_egress_credentials_resolve_only_when_request_resolver_invoked(
    tmp_path: Path,
) -> None:
    credential_name = "AGENTGUARD_FAKE_API_KEY"
    profile = _write_profile(tmp_path)
    plan = _credential_live_plan_file(
        tmp_path,
        profile,
        credential_names=[credential_name],
    )
    policy = _egress_policy()
    authorization = _authorization_file(
        tmp_path,
        plan,
        policy,
        credential_env_names=[credential_name],
    )
    ledger = tmp_path / "authorization-ledger.json"
    lookups = []

    def credential_reader(names: list[str]) -> dict[str, str]:
        lookups.append(list(names))
        return {credential_name: "fake-secret-value"}

    def fake_egress(request):
        assert lookups == []
        ledger_data = json.loads(ledger.read_text(encoding="utf-8"))
        uses = list(ledger_data["uses"].values())
        assert uses and uses[0]["status"] == "reserved"
        assert request.agent_environment_names == (credential_name,)
        assert request.agent_environment_resolver is not None
        assert request.agent_environment_resolver() == {
            credential_name: "fake-secret-value"
        }
        assert lookups == [[credential_name]]
        manifest = build_live_study_egress_manifest(
            plan_digest=request.plan_digest,
            profile_hash=request.profile_hash,
            fixture_hash=request.fixture_hash,
            trial_id=request.trial_id,
            policy=request.policy,
            gateway_image=GATEWAY_IDENTITY,
            approved_host="mock-approved.test",
            approved_port=443,
            events=[
                evaluate_live_study_egress_destination(
                    request.policy,
                    host="mock-approved.test",
                    port=443,
                    protocol="https",
                    resolved_addresses=["203.0.113.10"],
                    resolution_status="stable",
                )
            ],
            gateway_status={"status": "running", "evidence_complete": True},
            cleanup_status={"overall_complete": True},
            liveness_status={"verified": True},
        )
        manifest_path = request.evidence_dir / "live-study-egress-manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
        return LiveStudyEgressTrialResult(
            manifest=manifest,
            manifest_path=manifest_path,
            status="completed",
            outcome="completed",
        )

    result = run_contained_study_plan(
        ContainedStudyRunnerOptions(
            plan,
            [profile],
            output_dir=tmp_path / "runs",
            execution_mode=LIVE_STUDY_EGRESS_EXECUTION_MODE,
            egress_policy=policy,
            gateway_image=GATEWAY_IMAGE,
            authorization_path=authorization,
            authorization_ledger_path=ledger,
            credential_environment_reader=credential_reader,
        ),
        run_study_egress_command=fake_egress,
    )

    assert result.completed == 1
    assert lookups == [[credential_name]]


def test_malformed_plan_and_output_path_rejections(tmp_path: Path) -> None:
    profile = _write_profile(tmp_path)
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(ContainedStudyRunnerError, match="valid JSON"):
        validate_contained_study_plan_for_execution(invalid_json, [profile])

    non_object = tmp_path / "list.json"
    non_object.write_text("[]", encoding="utf-8")
    with pytest.raises(ContainedStudyRunnerError, match="JSON object"):
        validate_contained_study_plan_for_execution(non_object, [profile])

    plan = _plan_file(tmp_path, profile, approvals=[])
    with pytest.raises(ContainedStudyRunnerError, match="profile paths"):
        validate_contained_study_plan_for_execution(plan, [profile, profile])

    fixture = __import__(
        "agentguard.evaluation.study_fixtures",
        fromlist=["load_study_fixture_set"],
    ).load_study_fixture_set().fixtures[0]
    with pytest.raises(ContainedStudyRunnerError, match="output directory"):
        study_runner._reject_output_inside_fixtures(
            fixture.source.path / "nested-output",
            __import__(
                "agentguard.evaluation.study_fixtures",
                fromlist=["load_study_fixture_set"],
            ).load_study_fixture_set(),
        )


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda data: data.update({"schema": "wrong"}), "Invalid"),
        (lambda data: data.update({"schema_version": 2}), "version"),
        (lambda data: data.update({"protocol_version": "future"}), "protocol"),
        (lambda data: data.update({"trial_repetitions_per_unit": 101}), "repetition"),
    ],
)
def test_plan_contract_header_and_bound_rejections(
    tmp_path: Path,
    mutate,
    match: str,
) -> None:
    profile = _write_profile(tmp_path)
    plan = _plan_file(tmp_path, profile, approvals=[])
    data = json.loads(plan.read_text(encoding="utf-8"))
    mutate(data)
    if match == "repetition":
        data["plan_digest"] = _digest(data)

    with pytest.raises(ContainedStudyRunnerError, match=match):
        study_runner._validate_plan_contract(data)


def test_bounded_validation_helpers_reject_hostile_values(tmp_path: Path) -> None:
    with pytest.raises(ContainedStudyRunnerError, match="object"):
        study_runner._mapping([], "field")
    with pytest.raises(ContainedStudyRunnerError, match="1 to 1"):
        study_runner._list([], "items", 1, 1)
    with pytest.raises(ContainedStudyRunnerError, match="bounded string"):
        study_runner._string("", "name")
    with pytest.raises(ContainedStudyRunnerError, match="control"):
        study_runner._string("bad\nvalue", "name")
    with pytest.raises(ContainedStudyRunnerError, match="duplicates"):
        study_runner._string_list(["A", "A"], "names")
    with pytest.raises(ContainedStudyRunnerError, match="portable id"):
        study_runner._portable_id("bad/slash", "id")
    with pytest.raises(ContainedStudyRunnerError, match="artifact alias"):
        study_runner._portable_alias("../escape", "alias")
    with pytest.raises(ContainedStudyRunnerError, match="sha256"):
        study_runner._sha256_string("abc", "digest")
    with pytest.raises(ContainedStudyRunnerError, match="positive"):
        study_runner._positive_int(True, "count")
    with pytest.raises(ContainedStudyRunnerError, match="non-negative"):
        study_runner._non_negative_int(-1, "count")
    with pytest.raises(ContainedStudyRunnerError, match="missing"):
        study_runner._validate_limits({})
    bad_limits = {
        "cpu_limit": False,
        "max_output_bytes": 1024,
        "memory_limit": "128m",
        "pids_limit": 64,
        "timeout_seconds": 1,
    }
    with pytest.raises(ContainedStudyRunnerError, match="CPU"):
        study_runner._validate_limits(bad_limits)

    assert study_runner._portable_under(tmp_path, None) is None
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    assert study_runner._portable_under(tmp_path, outside) == "[REDACTED]"
