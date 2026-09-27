import json
import subprocess
from pathlib import Path

import pytest

import agentguard.evaluation.live_egress_gateway as gateway
from agentguard.evaluation.live_egress_gateway import (
    DockerControlResult,
    EgressDestinationRule,
    LiveStudyEgressError,
    LiveStudyEgressPolicy,
    LiveStudyGatewayResources,
    authorize_connect_authority,
    authorize_url_destination,
    build_live_study_egress_docker_plan,
    build_live_study_egress_manifest,
    canonical_live_study_egress_manifest,
    classify_live_study_egress_manifest,
    evaluate_live_study_egress_destination,
    inspect_docker_image_identity,
    live_study_egress_policy_from_dict,
    live_study_egress_policy_digest,
    load_gateway_evidence,
    parse_gateway_image_identity,
    record_blocked_route,
    run_live_study_egress_trial,
    run_live_study_egress_docker_plan,
    validate_live_study_egress_docker_plan,
    validate_live_study_egress_policy,
    LiveStudyEgressTrialRequest,
)


IMAGE = "example.com/agentguard/agent@sha256:" + "a" * 64
GATEWAY_IMAGE = "example.com/agentguard/gateway@sha256:" + "b" * 64
PLAN_DIGEST = "1" * 64
PROFILE_HASH = "2" * 64
FIXTURE_HASH = "3" * 64
GATEWAY_IDENTITY = {
    "configured_reference": "example.com/agentguard/gateway@sha256:" + "b" * 64,
    "local_image_id": "sha256:" + "c" * 64,
    "executed_image_id": "sha256:" + "c" * 64,
    "registry_digest": "example.com/agentguard/gateway@sha256:" + "b" * 64,
    "platform": "linux/amd64",
    "pull_policy": "docker-default",
    "cache_status": "present",
}


def _policy() -> LiveStudyEgressPolicy:
    return LiveStudyEgressPolicy(
        destinations=(
            EgressDestinationRule(
                "mock-approved.test",
                443,
                purpose="mock https",
                test_only=True,
            ),
        )
    )


def test_policy_digest_is_deterministic_and_exact_host_port_only() -> None:
    policy = _policy()
    same = LiveStudyEgressPolicy(
        destinations=(
            EgressDestinationRule(
                "MOCK-APPROVED.TEST",
                443,
                purpose="mock https",
                test_only=True,
            ),
        )
    )

    assert live_study_egress_policy_digest(policy) == live_study_egress_policy_digest(same)

    allowed = evaluate_live_study_egress_destination(
        policy,
        host="mock-approved.test",
        port=443,
        protocol="connect",
        resolved_addresses=["203.0.113.10"],
    )
    assert allowed["decision"] == "allow"
    assert allowed["effective"] == {"host": "mock-approved.test", "port": 443}

    assert (
        evaluate_live_study_egress_destination(
            policy,
            host="mock-approved.test",
            port=8443,
            resolved_addresses=["203.0.113.10"],
        )["decision"]
        == "deny"
    )
    assert (
        evaluate_live_study_egress_destination(
            policy,
            host="unapproved.test",
            port=443,
            resolved_addresses=["203.0.113.11"],
        )["reason"]
        == "destination_not_approved"
    )


@pytest.mark.parametrize(
    "host",
    [
        "*.example.test",
        "localhost",
        "host.docker.internal",
        "gateway.docker.internal",
        "metadata.google.internal",
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "224.0.0.1",
        "::1",
        "fc00::1",
    ],
)
def test_policy_rejects_wildcards_ip_literals_and_internal_names(host: str) -> None:
    with pytest.raises(LiveStudyEgressError):
        validate_live_study_egress_policy(
            LiveStudyEgressPolicy(destinations=(EgressDestinationRule(host, 443),))
        )


def test_test_only_ip_literal_exception_is_narrow_and_still_blocks_unsafe_ranges() -> None:
    validate_live_study_egress_policy(
        LiveStudyEgressPolicy(
            destinations=(
                EgressDestinationRule(
                    "203.0.113.42",
                    443,
                    test_only=True,
                    test_only_ip_literal=True,
                ),
            )
        )
    )

    with pytest.raises(LiveStudyEgressError, match="Unsafe IP"):
        validate_live_study_egress_policy(
            LiveStudyEgressPolicy(
                destinations=(
                    EgressDestinationRule(
                        "127.0.0.1",
                        443,
                        test_only=True,
                        test_only_ip_literal=True,
                    ),
                )
            )
        )


def test_connect_url_redirect_and_resolution_evidence_fail_closed() -> None:
    policy = _policy()

    assert (
        authorize_connect_authority(
            policy,
            "mock-approved.test:443",
            resolved_addresses=["203.0.113.10"],
        )["decision"]
        == "allow"
    )
    assert authorize_connect_authority(policy, "bad\nhost:443")["decision"] == "deny"
    assert authorize_connect_authority(policy, "mock-approved.test:notaport")["decision"] == "deny"

    redirect = authorize_url_destination(
        policy,
        "https://evil.test/path?token=super-secret",
        resolved_addresses=["203.0.113.11"],
        event_type="redirect",
    )
    assert redirect["decision"] == "deny"
    assert "token=super-secret" not in json.dumps(redirect, sort_keys=True)

    ambiguous = evaluate_live_study_egress_destination(
        policy,
        host="mock-approved.test",
        port=443,
        resolved_addresses=["203.0.113.10", "203.0.113.11"],
    )
    assert ambiguous["decision"] == "deny"
    assert ambiguous["reason"] == "resolution_ambiguous"

    changed = evaluate_live_study_egress_destination(
        policy,
        host="mock-approved.test",
        port=443,
        resolved_addresses=["203.0.113.10"],
        resolution_status="changed",
    )
    assert changed["decision"] == "deny"
    assert changed["reason"] == "resolution_uncertain"


@pytest.mark.parametrize(
    "event",
    [
        record_blocked_route(route_kind="direct-outbound", host="example.test", port=443),
        record_blocked_route(route_kind="alternate-dns", host="8.8.8.8", port=53),
        record_blocked_route(route_kind="udp", host="mock-approved.test", port=443),
        record_blocked_route(route_kind="quic", host="mock-approved.test", port=443),
        record_blocked_route(route_kind="unix-socket"),
        evaluate_live_study_egress_destination(
            _policy(),
            host="mock-approved.test",
            port=443,
            protocol="udp",
            resolved_addresses=["203.0.113.10"],
        ),
        evaluate_live_study_egress_destination(
            _policy(),
            host="registry.npmjs.org",
            port=443,
            protocol="https",
            resolved_addresses=["203.0.113.12"],
        ),
        evaluate_live_study_egress_destination(
            _policy(),
            host="telemetry.example.test",
            port=443,
            protocol="https",
            resolved_addresses=["203.0.113.12"],
        ),
    ],
)
def test_bypass_udp_quic_package_update_and_telemetry_destinations_deny(event) -> None:
    assert event["decision"] == "deny"


def test_manifest_is_canonical_bounded_sanitized_and_success_requires_complete_evidence() -> None:
    policy = _policy()
    event = evaluate_live_study_egress_destination(
        policy,
        host="mock-approved.test",
        port=443,
        protocol="https",
        resolved_addresses=["203.0.113.10"],
        bytes_in=123,
        bytes_out=456,
        timestamp_start=1.25,
        timestamp_end=2.5,
    )
    manifest = build_live_study_egress_manifest(
        plan_digest=PLAN_DIGEST,
        profile_hash=PROFILE_HASH,
        fixture_hash=FIXTURE_HASH,
        trial_id="trial-0123456789abcdef01234567",
        policy=policy,
        gateway_image=GATEWAY_IDENTITY,
        approved_host="mock-approved.test?secret=AGENTGUARD_SECRET_CANARY_1",
        approved_port=443,
        events=[event],
        gateway_status={"status": "running", "evidence_complete": True},
        cleanup_status={"overall_complete": True},
        liveness_status={"verified": True},
    )

    canonical = canonical_live_study_egress_manifest(manifest)
    assert canonical == canonical_live_study_egress_manifest(json.loads(canonical))
    assert "AGENTGUARD_SECRET_CANARY" not in canonical
    assert "/Users/" not in canonical
    assert manifest["completion"]["success_eligible"] is True

    incomplete = dict(manifest)
    incomplete["events"] = [{**event, "evidence_complete": False}]
    assert classify_live_study_egress_manifest(incomplete)["status"] == "incomplete"

    denied = dict(manifest)
    denied["events"] = [record_blocked_route(route_kind="direct-outbound")]
    assert classify_live_study_egress_manifest(denied)["status"] == "failed"


def test_docker_plan_builds_internal_gateway_topology_without_widening_exec_spec(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    plan = build_live_study_egress_docker_plan(
        trial_id="trial-0123456789abcdef01234567",
        agent_image=IMAGE,
        gateway_image=GATEWAY_IMAGE,
        workspace_host_path=workspace,
        agent_command=["python", "-m", "agent"],
        gateway_command=["/gateway", "--policy", "/policy/policy.json"],
        uid=1000,
        gid=1000,
        resources=LiveStudyGatewayResources(cpu_limit=0.5, memory_limit="128m"),
        run_token="abc123abc123",
    )

    validate_live_study_egress_docker_plan(plan)
    internal = plan.commands["create_internal_network"]
    assert "--internal" in internal
    gateway = plan.commands["create_gateway"]
    agent = plan.commands["create_agent"]
    assert gateway[gateway.index("--network") + 1] == plan.internal_network
    assert agent[agent.index("--network") + 1] == plan.internal_network
    assert plan.outbound_network not in agent
    for argv in [gateway, agent]:
        assert "--security-opt" in argv
        assert "no-new-privileges" in argv
        assert "--cap-drop" in argv
        assert "ALL" in argv
        assert "--read-only" in argv
        assert "--tmpfs" in argv
        assert "--privileged" not in argv
        assert "--device" not in argv
        assert "/var/run/docker.sock" not in argv

    with pytest.raises(LiveStudyEgressError, match="digest"):
        build_live_study_egress_docker_plan(
            trial_id="trial-0123456789abcdef01234567",
            agent_image=IMAGE,
            gateway_image="example.com/agentguard/gateway:latest",
            workspace_host_path=workspace,
            agent_command=["python"],
            gateway_command=["/gateway"],
            uid=1000,
            gid=1000,
        )


def test_docker_plan_cleanup_reports_liveness_uncertainty_as_incomplete(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    plan = build_live_study_egress_docker_plan(
        trial_id="trial-0123456789abcdef01234567",
        agent_image=IMAGE,
        gateway_image=GATEWAY_IMAGE,
        workspace_host_path=workspace,
        agent_command=["python"],
        gateway_command=["/gateway"],
        uid=1000,
        gid=1000,
        run_token="def456def456",
    )
    calls = []

    def fake_runner(argv, timeout_seconds):
        calls.append(argv)
        if argv[:3] == ["docker", "rm", "-f"] and argv[-1] == plan.gateway_container:
            return DockerControlResult(argv, 1, stderr="still running")
        return DockerControlResult(argv, 0, stdout="ok")

    result = run_live_study_egress_docker_plan(plan, command_runner=fake_runner)

    assert result["status"] == "incomplete"
    assert result["cleanup"]["gateway_container"] == "incomplete"
    assert result["cleanup"]["overall_complete"] is False
    assert any(call[:2] == ["docker", "network"] for call in calls)


def test_policy_loader_rejects_malformed_duplicate_and_unknown_rules() -> None:
    payload = {
        "schema": "agentguard.live-study-egress-policy",
        "schema_version": 1,
        "destinations": [
            {"host": "mock-approved.test", "port": 443, "purpose": "one", "test_only": True}
        ],
    }
    assert live_study_egress_policy_from_dict(payload).destinations[0].host == (
        "mock-approved.test"
    )

    for bad in [
        None,
        {"schema": "wrong", "schema_version": 1, "destinations": []},
        {"schema": payload["schema"], "schema_version": 99, "destinations": []},
        {**payload, "destinations": [{"host": "mock.test", "port": 443, "extra": True}]},
        {
            **payload,
            "destinations": [
                {"host": "mock.test", "port": 443},
                {"host": "MOCK.TEST", "port": 443},
            ],
        },
    ]:
        with pytest.raises(LiveStudyEgressError):
            live_study_egress_policy_from_dict(bad)


def test_gateway_evidence_loader_bounds_and_sanitizes(tmp_path: Path) -> None:
    missing = load_gateway_evidence(tmp_path / "missing.json")
    assert missing["status"] == "missing"
    assert missing["gateway_status"]["evidence_complete"] is False

    malformed = tmp_path / "malformed.json"
    malformed.write_text("[1, 2]\n", encoding="utf-8")
    assert load_gateway_evidence(malformed)["status"] == "malformed"

    truncated = tmp_path / "truncated.json"
    truncated.write_text("x" * (gateway.MAX_EGRESS_SERIALIZED_BYTES + 1), encoding="utf-8")
    assert load_gateway_evidence(truncated)["status"] == "truncated"

    recorded = tmp_path / "recorded.json"
    recorded.write_text(
        json.dumps(
            {
                "events": [
                    evaluate_live_study_egress_destination(
                        _policy(),
                        host="mock-approved.test",
                        port=443,
                        resolved_addresses=["203.0.113.10"],
                    )
                ],
                "gateway_status": {
                    "status": "running",
                    "evidence_complete": True,
                    "reason": "ok?token=secret",
                },
            }
        ),
        encoding="utf-8",
    )
    loaded = load_gateway_evidence(recorded)
    assert loaded["status"] == "recorded"
    assert "token=secret" not in json.dumps(loaded, sort_keys=True)


def test_manifest_completion_fails_closed_for_missing_identity_gateway_cleanup_and_liveness() -> None:
    policy = _policy()
    event = evaluate_live_study_egress_destination(
        policy,
        host="mock-approved.test",
        port=443,
        resolved_addresses=["203.0.113.10"],
    )
    base = {
        "schema": "agentguard.live-study-egress-manifest",
        "schema_version": 1,
        "plan_digest": PLAN_DIGEST,
        "profile_hash": PROFILE_HASH,
        "fixture_hash": FIXTURE_HASH,
        "trial_id": "trial-0123456789abcdef01234567",
        "egress_policy_digest": live_study_egress_policy_digest(policy),
        "approved_destination": {"host": "mock-approved.test", "port": 443},
        "gateway_image_identity": GATEWAY_IDENTITY,
        "events": [event],
        "gateway_status": {"status": "running", "evidence_complete": True},
        "cleanup_status": {"overall_complete": True},
        "liveness_status": {"verified": True},
    }
    for mutation, reason in [
        ({"gateway_image_identity": None}, "gateway image identity"),
        ({"gateway_status": {"status": "crashed", "crashed": True}}, "gateway crashed"),
        ({"gateway_status": {"status": "running", "evidence_complete": False}}, "gateway evidence"),
        ({"cleanup_status": {"overall_complete": False}}, "cleanup"),
        ({"liveness_status": {"verified": False}}, "liveness"),
        ({"events": [{"decision": "mystery"}]}, "evidence"),
    ]:
        candidate = {**base, **mutation}
        completion = classify_live_study_egress_manifest(candidate)
        assert completion["success_eligible"] is False
        assert reason in str(completion["reason"])


def test_docker_image_identity_inspection_and_local_image_id_gating(monkeypatch) -> None:
    image_id = "sha256:" + "d" * 64
    digest = "example.com/agentguard/gateway@sha256:" + "e" * 64

    def fake_control(argv, timeout_seconds):
        assert argv[:3] == ["docker", "image", "inspect"]
        return DockerControlResult(
            argv,
            0,
            stdout=json.dumps(
                {
                    "Id": image_id,
                    "Os": "linux",
                    "Architecture": "amd64",
                    "RepoDigests": [digest],
                }
            ),
        )

    monkeypatch.setattr(gateway, "_run_docker_control", fake_control)
    identity = inspect_docker_image_identity(digest)
    assert identity.local_image_id == image_id
    assert identity.registry_digest == digest

    with pytest.raises(LiveStudyEgressError, match="digest-pinned"):
        inspect_docker_image_identity(image_id)

    local = inspect_docker_image_identity(image_id, allow_local_image_id=True)
    assert local["executed_image_id"] == image_id
    assert parse_gateway_image_identity(
        {
            "configured_reference": digest,
            "local_image_id": image_id,
            "executed_image_id": image_id,
            "registry_digest": digest,
            "platform": "linux/amd64",
            "pull_policy": "docker-default",
            "cache_status": "present",
        }
    ).configured_reference == digest


def test_run_live_study_egress_trial_uses_gateway_evidence_and_fails_when_incomplete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    workspace = tmp_path / "workspace"
    evidence_dir = tmp_path / "evidence"
    workspace.mkdir()

    def fake_identity(image, *, allow_local_image_id=False):
        return GATEWAY_IDENTITY

    def fake_plan(*args, **kwargs):
        return build_live_study_egress_docker_plan(
            trial_id="trial-0123456789abcdef01234567",
            agent_image=IMAGE,
            gateway_image=GATEWAY_IMAGE,
            workspace_host_path=workspace,
            agent_command=["agent"],
            gateway_command=["gateway"],
            uid=1000,
            gid=1000,
            run_token="fedcba654321",
        )

    def fake_run(plan, *, command_runner=None, timeout_seconds=30):
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "gateway-evidence.json").write_text(
            json.dumps(
                {
                    "events": [
                        evaluate_live_study_egress_destination(
                            _policy(),
                            host="mock-approved.test",
                            port=443,
                            protocol="https",
                            resolved_addresses=["203.0.113.10"],
                        )
                    ],
                    "gateway_status": {"status": "running", "evidence_complete": True},
                }
            ),
            encoding="utf-8",
        )
        return {
            "status": "completed",
            "gateway_liveness_verified": True,
            "cleanup": {"overall_complete": True, "liveness_verified": True},
        }

    monkeypatch.setattr(gateway, "inspect_docker_image_identity", fake_identity)
    monkeypatch.setattr(gateway, "build_live_study_egress_docker_plan", fake_plan)
    monkeypatch.setattr(gateway, "run_live_study_egress_docker_plan", fake_run)

    request = LiveStudyEgressTrialRequest(
        plan_digest=PLAN_DIGEST,
        profile_hash=PROFILE_HASH,
        fixture_hash=FIXTURE_HASH,
        trial_id="trial-0123456789abcdef01234567",
        profile_id="profile",
        fixture_id="fixture",
        workspace=workspace,
        evidence_dir=evidence_dir,
        prompt_path=evidence_dir / "prompt.txt",
        agent_image=IMAGE,
        agent_command=["agent"],
        policy=_policy(),
        gateway_image=GATEWAY_IMAGE,
        platform="linux-docker-engine",
    )
    result = run_live_study_egress_trial(request)
    assert result.status == "completed"
    assert result.manifest["completion"]["success_eligible"] is True

    def fake_incomplete(plan, *, command_runner=None, timeout_seconds=30):
        return {
            "status": "failed",
            "failure_step": "gateway_liveness",
            "cleanup": {"overall_complete": False, "liveness_verified": False},
        }

    (evidence_dir / "gateway-evidence.json").unlink()
    monkeypatch.setattr(gateway, "run_live_study_egress_docker_plan", fake_incomplete)
    failed = run_live_study_egress_trial(request)
    assert failed.status in {"failed", "incomplete"}
    assert failed.stop_condition


def test_fail_closed_private_bounds_and_sanitizers_cover_edge_cases(tmp_path: Path) -> None:
    assert gateway._image_id(123) is None
    assert gateway._docker_network_aliases(("mock-approved.test", "MOCK-APPROVED.TEST")) == (
        "mock-approved.test",
    )
    with pytest.raises(LiveStudyEgressError):
        gateway._docker_network_aliases(("203.0.113.9",))
    assert gateway._single_policy_destination(LiveStudyEgressPolicy(destinations=())) == (
        None,
        None,
    )
    crashed = gateway._combined_gateway_status(
        docker_result={"failure_step": "gateway_liveness"},
        gateway_evidence={"status": "recorded", "gateway_status": {"evidence_complete": True}},
    )
    assert crashed["crashed"] is True
    missing = gateway._combined_gateway_status(
        docker_result={},
        gateway_evidence={"status": "missing", "gateway_status": {"reason": "lost?token=x"}},
    )
    assert missing["evidence_complete"] is False
    assert "token=x" not in json.dumps(missing, sort_keys=True)
    assert gateway._cleanup_status_from_docker_result({})["overall_complete"] is False
    assert gateway._liveness_status_from_docker_result({})["verified"] is False
    assert gateway._gateway_inspect_running(json.dumps([{"State": {"Running": True}}])) is True
    assert gateway._gateway_inspect_running("not-json") is False
    assert gateway._sanitize_value(Path("/Users/test/secret.txt"), depth=0) == "[REDACTED_PATH]"
    for value in [
        10**13,
        -1.0,
        ["x"] * (gateway.MAX_EGRESS_LIST_ITEMS + 1),
        {str(index): index for index in range(gateway.MAX_EGRESS_OBJECT_ITEMS + 1)},
        {"": "bad"},
    ]:
        with pytest.raises(LiveStudyEgressError):
            gateway._sanitize_value(value, depth=0)
    for function, args in [
        (gateway._bounded_string, ("", "field")),
        (gateway._sha256_string, ("bad", "hash")),
        (gateway._port, (0, "port")),
        (gateway._bool, ("true", "flag")),
        (gateway._optional_bounded_nonnegative_int, (-1, "count")),
        (gateway._optional_timestamp, (-1,)),
        (gateway._non_root, (0, "uid")),
        (gateway._bounded_positive_int, (0, "pids")),
        (gateway._bounded_size, ("0m", "memory")),
        (gateway._format_cpu, (99.0,)),
        (gateway._validate_network_name, ("bad",)),
        (gateway._validate_container_name, ("bad",)),
        (gateway._label_value, ("bad,value",)),
    ]:
        with pytest.raises(LiveStudyEgressError):
            function(*args)
    assert gateway._option_values(["docker", "--network", "none"], "--network") == ["none"]


def test_docker_control_timeout_and_oserror_paths(monkeypatch) -> None:
    def timeout_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("docker", 1, output="out", stderr="err")

    monkeypatch.setattr(gateway.subprocess, "run", timeout_run)
    timed_out = gateway._run_docker_control(["docker", "info"], 1)
    assert timed_out.timed_out is True
    assert timed_out.returncode == 124

    def os_error_run(*_args, **_kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(gateway.subprocess, "run", os_error_run)
    missing = gateway._run_docker_control(["docker", "info"], 1)
    assert missing.returncode == 125
    assert "FileNotFoundError" in missing.stderr
