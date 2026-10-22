"""Reviewed GPT-5.2 token-price contract; no mutable price lookup."""

from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal, ROUND_UP
from importlib.resources import files
from typing import Mapping

from agentguard.evaluation.stage1_metering import MeteringError, canonical_bytes, digest


_EXPECTED = {
    "schema": "agentguard.stage1-pricing-policy",
    "schema_version": 2,
    "provider": "openai-api",
    "model": "gpt-5.2-2025-12-11",
    "currency": "USD",
    "tokens_per_unit": 1_000_000,
    "uncached_input_usd": "1.75",
    "cached_input_usd": "0.175",
    "output_usd": "14.00",
    "output_includes_nonvisible_and_reasoning_tokens": True,
    "service_tier": "standard",
    "regional_processing": False,
    "cache_write_allowed": False,
    "rounding": "ROUND_UP_TO_0.000001_USD_PER_REQUEST",
    "source_urls": [
        "https://developers.openai.com/api/docs/models/gpt-5.2",
        "https://developers.openai.com/api/docs/guides/token-counting",
        "https://developers.openai.com/api/docs/guides/prompt-caching",
    ],
    "retrieved_on": "2026-10-22",
    "source_effective_date": None,
}
_QUANTUM = Decimal("0.000001")


def load_pricing_policy() -> dict[str, object]:
    raw = files("agentguard.evaluation").joinpath("stage1_pricing_v2.json").read_bytes()
    if len(raw) > 4096:
        raise MeteringError("pricing policy exceeds its bound")
    try:
        policy = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MeteringError("pricing policy is malformed") from error
    if policy != _EXPECTED or canonical_bytes(policy) != canonical_bytes(_EXPECTED):
        raise MeteringError("pricing policy differs from reviewed rates")
    return policy


def pricing_policy_digest() -> str:
    return digest(load_pricing_policy())


def _tokens(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 10_000_000:
        raise MeteringError(f"{field} is not a bounded token count")
    return value


@dataclass(frozen=True)
class TokenUsage:
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    cache_write_tokens: int = 0

    @classmethod
    def from_response(cls, response: Mapping[str, object], counted_input: int) -> TokenUsage:
        if response.get("model") != _EXPECTED["model"]:
            raise MeteringError("terminal model differs from pricing policy")
        if response.get("service_tier") not in (None, "default"):
            raise MeteringError("nonstandard service tier is forbidden")
        usage = response.get("usage")
        if not isinstance(usage, dict) or set(usage) != {
            "input_tokens", "output_tokens", "total_tokens", "input_tokens_details",
            "output_tokens_details",
        }:
            raise MeteringError("terminal usage categories are missing or unknown")
        input_details = usage["input_tokens_details"]
        output_details = usage["output_tokens_details"]
        if not isinstance(input_details, dict) or set(input_details) != {
            "cached_tokens", "cache_write_tokens",
        }:
            raise MeteringError("input usage categories are missing or unknown")
        if not isinstance(output_details, dict) or set(output_details) != {"reasoning_tokens"}:
            raise MeteringError("output usage categories are missing or unknown")
        input_tokens = _tokens(usage["input_tokens"], "input_tokens")
        cached = _tokens(input_details["cached_tokens"], "cached_tokens")
        output = _tokens(usage["output_tokens"], "output_tokens")
        reasoning = _tokens(output_details["reasoning_tokens"], "reasoning_tokens")
        writes = _tokens(input_details["cache_write_tokens"], "cache_write_tokens")
        total = _tokens(usage["total_tokens"], "total_tokens")
        if input_tokens != counted_input or cached > input_tokens or reasoning > output:
            raise MeteringError("counted and terminal token usage disagree")
        if total != input_tokens + output or writes:
            raise MeteringError("total usage is contradictory or cache-write usage is unpriced")
        return cls(input_tokens, cached, output, reasoning, writes)


def cost_usd(usage: TokenUsage) -> Decimal:
    if usage.cache_write_tokens:
        raise MeteringError("cache-write usage is unpriced")
    for name, value in vars(usage).items():
        _tokens(value, name)
    if usage.cached_input_tokens > usage.input_tokens or usage.reasoning_tokens > usage.output_tokens:
        raise MeteringError("token usage is contradictory")
    value = (
        Decimal(usage.input_tokens - usage.cached_input_tokens) * Decimal("1.75")
        + Decimal(usage.cached_input_tokens) * Decimal("0.175")
        + Decimal(usage.output_tokens) * Decimal("14.00")
    ) / Decimal(1_000_000)
    return value.quantize(_QUANTUM, rounding=ROUND_UP)


def worst_case_cost_usd(input_tokens: int, max_output_tokens: int) -> Decimal:
    return cost_usd(TokenUsage(
        _tokens(input_tokens, "input_tokens"), 0,
        _tokens(max_output_tokens, "max_output_tokens"), 0,
    ))
