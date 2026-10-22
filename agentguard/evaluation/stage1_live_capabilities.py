"""Stage 1 live-study activation remains unavailable before Phase B2."""

from __future__ import annotations


REQUIRED_STAGE1_CAPABILITIES = frozenset({
    "exact_static_model_metadata",
    "exact_ordered_tool_contract",
    "provider_aware_metering",
    "gateway_only_real_credential",
    "authoritative_input_token_count",
    "crash_safe_study_ledger",
    "reviewed_exact_pricing_policy",
    "exact_tls_destination",
    "replacement_agent_and_gateway_subjects",
})


def stage1_subject(value: str) -> bool:
    return value.startswith("ghcr.io/richinmrudul/agentguard/stage1-")


def stage1_live_unavailable(
    agent_image: str, gateway_image: str, *, model_id: str = "", profile_id: str = "",
) -> bool:
    return (
        stage1_subject(agent_image) or stage1_subject(gateway_image)
        or model_id == "gpt-5.2-2025-12-11"
        or profile_id.startswith("stage1-")
    )
