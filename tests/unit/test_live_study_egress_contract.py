from pathlib import Path

from agentguard.evaluation.live_egress_contract import (
    LIVE_STUDY_APPROVED_PROVIDER_DESTINATIONS,
    LIVE_STUDY_EGRESS_EVIDENCE_FIELDS,
    LIVE_STUDY_EGRESS_NETWORK_MODE,
    LIVE_STUDY_EGRESS_THREAT_MODEL,
    classify_live_study_network,
    live_study_egress_contract_summary,
    validate_live_study_restricted_egress_network,
)


def _normalized_documentation() -> str:
    docs = [
        Path("docs/real-agent-evaluation.md").read_text(encoding="utf-8"),
        Path("docs/contained-execution.md").read_text(encoding="utf-8"),
    ]
    return " ".join("\n".join(docs).lower().split())


def test_live_study_egress_contract_records_required_invariants() -> None:
    summary = live_study_egress_contract_summary()

    assert summary["schema"] == "agentguard.live-study-egress-contract"
    assert summary["schema_version"] == 1
    assert summary["network_mode"] == LIVE_STUDY_EGRESS_NETWORK_MODE
    assert summary["approved_provider_destinations"] == []
    assert LIVE_STUDY_APPROVED_PROVIDER_DESTINATIONS == ()

    required_invariants = set(summary["required_invariants"])
    for invariant in [
        "agent-container-no-direct-public-internet-route",
        "agent-container-on-isolated-internal-docker-network",
        "separately-owned-egress-gateway-on-study-and-outbound-networks",
        "clients-ignoring-proxy-cannot-reach-internet",
        "dns-resolution-only-through-controlled-gateway-path",
        "every-redirect-or-new-destination-independently-authorized",
        "package-registries-blocked-unless-explicitly-listed",
        "docker-application-level-containment-not-hostile-code-sandbox",
    ]:
        assert invariant in required_invariants

    assert set(summary["evidence_fields"]) == set(LIVE_STUDY_EGRESS_EVIDENCE_FIELDS)


def test_live_study_egress_network_classification_rejects_plain_bridge() -> None:
    assert classify_live_study_network("none") == "offline"
    assert classify_live_study_network(LIVE_STUDY_EGRESS_NETWORK_MODE) == (
        "restricted-egress"
    )
    assert classify_live_study_network("bridge") == "not-restricted-egress"

    validate_live_study_restricted_egress_network(LIVE_STUDY_EGRESS_NETWORK_MODE)

    try:
        validate_live_study_restricted_egress_network("bridge")
    except ValueError as exc:
        message = str(exc)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("ordinary bridge must not be accepted as restricted egress")

    assert "ordinary Docker bridge networking is not restricted" in message
    assert "egress gateway" in message


def test_live_study_egress_contract_documentation_covers_bypass_cases() -> None:
    docs = _normalized_documentation()

    required_phrases = [
        "ordinary docker `bridge` is not restricted egress",
        "the agent container has no direct route to the public internet",
        "isolated internal docker network",
        "controlled outbound network",
        "clients that ignore proxy environment variables cannot reach the internet",
        "direct ip, alternate dns, udp, quic, host gateway, metadata services",
        "dns resolution occurs only through the controlled gateway path",
        "every connect request",
        "redirect",
        "ip literals are rejected unless explicitly approved",
        "package registries, update endpoints, telemetry endpoints, and arbitrary https",
        "the gateway image is digest-pinned",
        "no docker socket",
        "terminated and checked for liveness on every exit path",
        "evidence loss",
        "gateway failure",
        "cleanup failure",
        "linux docker engine is authoritative",
        "no provider-specific destination is approved",
    ]
    for phrase in required_phrases:
        assert phrase in docs

    unsupported_claims = [
        "bridge networking prevents public internet access",
        "docker bridge is restricted egress",
    ]
    for claim in unsupported_claims:
        assert claim not in docs
    assert "docker is an absolute hostile-code sandbox" in docs
    assert "not an absolute hostile-code sandbox" in docs


def test_live_study_egress_threat_model_cases_are_documented() -> None:
    docs = _normalized_documentation()

    expected_phrases = {
        "proxy environment variables",
        "direct tcp",
        "dns rebinding",
        "redirects",
        "multiple a/aaaa records",
        "ipv4 and ipv6",
        "connect",
        "http vs https",
        "websockets",
        "streaming",
        "tls validation ownership",
        "cdn/shared-address limitations",
        "telemetry and update endpoints",
        "container-to-host access",
        "gateway compromise",
        "docker daemon/kernel trust",
    }
    for phrase in expected_phrases:
        assert phrase in docs
    assert len(LIVE_STUDY_EGRESS_THREAT_MODEL) >= len(expected_phrases)


def test_live_study_egress_evidence_fields_are_documented() -> None:
    docs = _normalized_documentation()

    expected_terms = [
        "trial id",
        "policy digest",
        "destination host",
        "destination port",
        "resolved addresses",
        "decision",
        "byte counts",
        "timestamps",
        "redirect destination",
        "must not record url query strings",
        "authorization headers",
        "cookies",
        "request bodies",
        "credential values",
        "raw prompts",
        "model output",
    ]
    for term in expected_terms:
        assert term in docs
