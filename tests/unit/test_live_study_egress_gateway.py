import json
from pathlib import Path

import pytest

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
    live_study_egress_policy_digest,
    record_blocked_route,
    run_live_study_egress_docker_plan,
    validate_live_study_egress_docker_plan,
    validate_live_study_egress_policy,
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
