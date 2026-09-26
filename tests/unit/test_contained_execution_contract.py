from pathlib import Path

import pytest

from agentguard.evaluation.live_egress_contract import (
    LIVE_STUDY_APPROVED_PROVIDER_DESTINATIONS,
    LIVE_STUDY_EGRESS_AUTHORIZATION_RULES,
    LIVE_STUDY_EGRESS_BLOCKED_ROUTES,
    LIVE_STUDY_EGRESS_CLEANUP_REQUIREMENTS,
    LIVE_STUDY_EGRESS_EVIDENCE_FIELDS,
    LIVE_STUDY_EGRESS_GATEWAY_HARDENING,
    LIVE_STUDY_EGRESS_NETWORK_MODE,
    LIVE_STUDY_EGRESS_STOP_CONDITIONS,
    LIVE_STUDY_EGRESS_THREAT_MODEL,
    LIVE_STUDY_EGRESS_TOPOLOGY,
    ORDINARY_DOCKER_NETWORKS_NOT_RESTRICTED_EGRESS,
    classify_live_study_network,
    validate_live_study_restricted_egress_network,
)


def test_contained_execution_contract_documents_required_boundaries() -> None:
    page = Path("docs/contained-execution.md").read_text(encoding="utf-8")
    architecture = Path("docs/architecture.md").read_text(encoding="utf-8")
    real_agent_evaluation = Path("docs/real-agent-evaluation.md").read_text(
        encoding="utf-8"
    )
    mkdocs = Path("mkdocs.yml").read_text(encoding="utf-8")
    combined = f"{page}\n{architecture}\n{real_agent_evaluation}".lower()
    normalized = " ".join(combined.split())

    required_phrases = [
        "linux docker engine is the authoritative contained-execution platform",
        "docker desktop is experimental and carries reduced claims",
        "the host operating system, host kernel",
        "the docker daemon api",
        "host networking",
        "privileged containers",
        "docker socket mounts",
        "host device exposure",
        "host pid, ipc, user, uts, cgroup, or other namespace sharing",
        "the default network mode is `none`",
        "bridge networking is accepted only as an explicit v1 opt-in",
        "ordinary docker `bridge` networking is not restricted egress",
        "deterministic docker argv list directly",
        "does not accept raw docker flag strings",
        "evidence outside the repository mounted for the untrusted agent",
        "fail before launching the agent",
        "container escape",
        "malicious or vulnerable host kernels",
        "existing execution modes remain unchanged",
        "future contained-agent application-level boundary",
        "experimental `untrusted-agent` preset is available only for this contained-run workflow",
        "contained workspace lifecycle foundation",
        "the original repository is never mounted as the writable agent workspace",
        "without inheriting `.git` control metadata",
        "fixed baseline snapshot",
        "writable paths must be unique and non-overlapping",
        "`.` is accepted only as the sole writable path",
        "agent-created `.git` control metadata inside the prepared workspace",
        "causes capture to fail closed",
        "regular-file copy uses a copy-time identity check",
        "user-visible errors do not expose private absolute host paths or credentials",
        "does not change existing benchmark, local-command, agent-command, suite, matrix, or ci behavior",
        "live-study egress contract",
        "authorizes no provider-specific destination",
        "no direct route to the public internet",
        "isolated internal docker network",
        "separately owned egress gateway",
        "traffic can leave only through the gateway",
        "clients that ignore proxy configuration cannot reach the internet",
        "dns resolution occurs only through the controlled gateway path",
        "direct ip access",
        "alternate dns",
        "udp",
        "quic",
        "host gateway access",
        "metadata services",
        "private destinations",
        "loopback destinations",
        "multicast destinations",
        "link-local destinations",
        "docker-internal destinations",
        "proxy bypass routes",
        "unix-socket egress",
        "non-approved ports",
        "every redirected or newly discovered destination is independently authorized",
        "ip literals are rejected unless explicitly approved",
        "package registries",
        "update endpoints",
        "telemetry endpoints",
        "arbitrary https",
        "destination host",
        "destination port",
        "resolved address",
        "byte counts",
        "timestamps",
        "trial id",
        "policy digest",
        "redirect destination",
        "evidence loss",
        "ambiguous resolution",
        "unexpected destination",
        "gateway failure",
        "cleanup failure",
        "gateway image must be digest-pinned",
        "gateway runs non-root",
        "linux capabilities dropped",
        "`no-new-privileges`",
        "read-only root filesystem",
        "no docker socket",
        "agent containers, gateway containers, and agentguard-owned networks",
        "checked for liveness on every exit path",
        "proxy environment variables ignored by clients",
        "direct tcp",
        "dns rebinding or dns changes between validation and connection",
        "multiple a/aaaa records",
        "ipv4 and ipv6",
        "connect",
        "http vs https",
        "websockets and streaming",
        "tls validation ownership",
        "cdn/shared-address limitations",
        "container-to-host access",
        "gateway compromise",
        "docker daemon/kernel trust",
    ]

    for phrase in required_phrases:
        assert phrase in normalized

    unsupported_claims = [
        "fully sandboxed",
        "certified sandbox",
        "guarantees safe behavior",
        "hostile-code containment",
        "prevents every secret leak",
        "docker desktop provides linux docker engine equivalent containment",
    ]
    for claim in unsupported_claims:
        assert claim not in normalized

    assert "Contained Execution Contract: contained-execution.md" in mkdocs


def test_live_study_egress_contract_constants_are_enforceable() -> None:
    assert classify_live_study_network("none") == "offline"
    assert classify_live_study_network(LIVE_STUDY_EGRESS_NETWORK_MODE) == (
        "restricted-egress"
    )
    assert classify_live_study_network("bridge") == "not-restricted-egress"
    assert "bridge" in ORDINARY_DOCKER_NETWORKS_NOT_RESTRICTED_EGRESS
    assert LIVE_STUDY_APPROVED_PROVIDER_DESTINATIONS == ()

    required_topology = {
        "agent-container-no-direct-public-internet-route",
        "agent-container-on-isolated-internal-docker-network",
        "separately-owned-egress-gateway-on-study-and-outbound-networks",
        "agent-traffic-leaves-only-through-gateway",
        "clients-ignoring-proxy-cannot-reach-internet",
        "dns-resolution-only-through-controlled-gateway-path",
    }
    assert required_topology <= set(LIVE_STUDY_EGRESS_TOPOLOGY)

    assert {
        "direct-ip",
        "alternate-dns",
        "udp",
        "quic",
        "host-gateway",
        "metadata-service",
        "private-destinations",
        "loopback-destinations",
        "multicast-destinations",
        "link-local-destinations",
        "docker-internal-destinations",
        "proxy-bypass-routes",
        "unix-sockets",
        "non-approved-ports",
    } <= set(LIVE_STUDY_EGRESS_BLOCKED_ROUTES)

    assert {
        "trial_id",
        "policy_digest",
        "destination_host",
        "destination_port",
        "resolved_address",
        "decision",
        "bytes",
        "timestamps",
        "redirect_destination",
    } <= set(LIVE_STUDY_EGRESS_EVIDENCE_FIELDS)

    assert "no-provider-specific-destination-approved-by-contract" in (
        LIVE_STUDY_EGRESS_AUTHORIZATION_RULES
    )
    assert "image-digest-pinned" in LIVE_STUDY_EGRESS_GATEWAY_HARDENING
    assert "no-docker-socket" in LIVE_STUDY_EGRESS_GATEWAY_HARDENING
    assert "owned-networks-terminated-and-liveness-checked-on-every-exit-path" in (
        LIVE_STUDY_EGRESS_CLEANUP_REQUIREMENTS
    )
    assert {
        "unexpected-destination",
        "ambiguous-resolution",
        "evidence-loss",
        "gateway-failure",
        "cleanup-failure",
    } <= set(LIVE_STUDY_EGRESS_STOP_CONDITIONS)
    assert {
        "proxy-env-vars-ignored",
        "direct-tcp",
        "dns-rebinding-or-change-between-validation-and-connection",
        "redirects",
        "multiple-a-aaaa-records",
        "ipv4",
        "ipv6",
        "connect",
        "http",
        "https",
        "websockets",
        "streaming",
        "tls-validation-ownership",
        "cdn-shared-address-limitations",
        "telemetry-update-endpoints",
        "container-to-host-access",
        "gateway-compromise",
        "docker-daemon-and-kernel-trust",
    } <= set(LIVE_STUDY_EGRESS_THREAT_MODEL)

    with pytest.raises(ValueError, match="bridge networking is not restricted"):
        validate_live_study_restricted_egress_network("bridge")
