from __future__ import annotations

from typing import Literal


LIVE_STUDY_EGRESS_CONTRACT_SCHEMA = "agentguard.live-study-egress-contract"
LIVE_STUDY_EGRESS_CONTRACT_VERSION = 1
LIVE_STUDY_EGRESS_NETWORK_MODE = "controlled-egress-gateway"
LIVE_STUDY_EGRESS_EXECUTION_MODE = "study-egress"

LiveStudyNetworkClassification = Literal[
    "offline",
    "restricted-egress",
    "not-restricted-egress",
]

LIVE_STUDY_EGRESS_TOPOLOGY = (
    "agent-container-no-direct-public-internet-route",
    "agent-container-on-isolated-internal-docker-network",
    "separately-owned-egress-gateway-on-study-and-outbound-networks",
    "agent-traffic-leaves-only-through-gateway",
    "clients-ignoring-proxy-cannot-reach-internet",
    "dns-resolution-only-through-controlled-gateway-path",
)

LIVE_STUDY_EGRESS_BLOCKED_ROUTES = (
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
)

LIVE_STUDY_EGRESS_EVIDENCE_FIELDS = (
    "schema",
    "schema_version",
    "plan_digest",
    "profile_hash",
    "fixture_hash",
    "trial_id",
    "policy_digest",
    "egress_policy_digest",
    "gateway_image_identity",
    "destination_host",
    "destination_port",
    "resolved_address",
    "resolved_addresses",
    "decision",
    "bytes",
    "byte_counts",
    "timestamps",
    "redirect_destination",
    "gateway_status",
    "cleanup_status",
    "liveness_status",
)

LIVE_STUDY_EGRESS_AUTHORIZATION_RULES = (
    "every-redirect-or-new-destination-independently-authorized",
    "ip-literals-rejected-unless-explicitly-approved",
    "package-registries-blocked-unless-explicitly-listed",
    "update-endpoints-blocked-unless-explicitly-listed",
    "telemetry-endpoints-blocked-unless-explicitly-listed",
    "arbitrary-https-blocked-unless-explicitly-listed",
    "no-provider-specific-destination-approved-by-contract",
)

LIVE_STUDY_EGRESS_GATEWAY_HARDENING = (
    "image-digest-pinned",
    "non-root",
    "capabilities-dropped",
    "no-new-privileges",
    "read-only-root-filesystem",
    "resource-bounded",
    "no-docker-socket",
)

LIVE_STUDY_EGRESS_CLEANUP_REQUIREMENTS = (
    "agent-containers-terminated-and-liveness-checked-on-every-exit-path",
    "gateway-containers-terminated-and-liveness-checked-on-every-exit-path",
    "owned-networks-terminated-and-liveness-checked-on-every-exit-path",
)

LIVE_STUDY_EGRESS_STOP_CONDITIONS = (
    "unexpected-destination",
    "ambiguous-resolution",
    "evidence-loss",
    "gateway-failure",
    "cleanup-failure",
)

LIVE_STUDY_EGRESS_THREAT_MODEL = (
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
)

ORDINARY_DOCKER_NETWORKS_NOT_RESTRICTED_EGRESS = frozenset({"bridge"})
LIVE_STUDY_APPROVED_PROVIDER_DESTINATIONS: tuple[str, ...] = ()

LIVE_STUDY_EGRESS_REQUIRED_INVARIANTS = (
    *LIVE_STUDY_EGRESS_TOPOLOGY,
    *LIVE_STUDY_EGRESS_BLOCKED_ROUTES,
    *LIVE_STUDY_EGRESS_AUTHORIZATION_RULES,
    *LIVE_STUDY_EGRESS_GATEWAY_HARDENING,
    *LIVE_STUDY_EGRESS_CLEANUP_REQUIREMENTS,
    *LIVE_STUDY_EGRESS_STOP_CONDITIONS,
    "docker-application-level-containment-not-hostile-code-sandbox",
    "linux-docker-engine-authoritative",
)


def classify_live_study_network(network: str) -> LiveStudyNetworkClassification:
    if network == "none":
        return "offline"
    if network == LIVE_STUDY_EGRESS_NETWORK_MODE:
        return "restricted-egress"
    return "not-restricted-egress"


def validate_live_study_restricted_egress_network(network: str) -> None:
    classification = classify_live_study_network(network)
    if classification == "restricted-egress":
        return
    if network in ORDINARY_DOCKER_NETWORKS_NOT_RESTRICTED_EGRESS:
        raise ValueError(
            "Contained study dry-run plans are offline-only; ordinary Docker bridge "
            "networking is not restricted live-study egress. Live network trials "
            "require an isolated internal study network and a separately owned "
            "controlled egress gateway."
        )
    raise ValueError(
        f"Network mode {network!r} is not an approved restricted live-study "
        "egress boundary."
    )


def live_study_egress_contract_summary() -> dict[str, object]:
    return {
        "schema": LIVE_STUDY_EGRESS_CONTRACT_SCHEMA,
        "schema_version": LIVE_STUDY_EGRESS_CONTRACT_VERSION,
        "network_mode": LIVE_STUDY_EGRESS_NETWORK_MODE,
        "execution_mode": LIVE_STUDY_EGRESS_EXECUTION_MODE,
        "required_invariants": list(LIVE_STUDY_EGRESS_REQUIRED_INVARIANTS),
        "threat_model": list(LIVE_STUDY_EGRESS_THREAT_MODEL),
        "evidence_fields": list(LIVE_STUDY_EGRESS_EVIDENCE_FIELDS),
        "approved_provider_destinations": list(
            LIVE_STUDY_APPROVED_PROVIDER_DESTINATIONS
        ),
    }
