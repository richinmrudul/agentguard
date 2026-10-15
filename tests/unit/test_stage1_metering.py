from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from agentguard.evaluation.stage1_metering import (
    MeteringError,
    MeteringLimits,
    MeteringScope,
    MeteringSession,
    PricingPolicy,
    StudyBudget,
    UpstreamReply,
    canonical_bytes,
    codex_metered_argv,
)


MODEL = "stage1-mock-2026-10-14"
CANARY = "AGENTGUARD_FAKE_CREDENTIAL_CANARY"
SHA = "sha256:" + "a" * 64


class MockResponses:
    def __init__(self) -> None:
        self.paths: list[str] = []
        self.requests: list[dict[str, object]] = []
        self.count = 7
        self.output = 3
        self.cached = 0
        self.stream = True
        self.malformed = ""

    def post(self, path: str, body: bytes) -> UpstreamReply:
        payload = json.loads(body)
        self.paths.append(path)
        self.requests.append(payload)
        if path == "/v1/responses/input_tokens":
            if self.malformed == "count":
                return UpstreamReply(200, "application/json", b"{}")
            return UpstreamReply(
                200,
                "application/json",
                canonical_bytes({"object": "response.input_tokens", "input_tokens": self.count}),
            )
        assert path == "/v1/responses"
        response = {
            "id": (
                "mock-response" if self.malformed == "reused_id"
                else f"mock-response-{len(self.paths)}"
            ),
            "model": MODEL if self.malformed != "model" else "wrong-model",
            "status": "completed",
            "usage": {
                "input_tokens": self.count + (1 if self.malformed == "input" else 0),
                "output_tokens": self.output,
                "total_tokens": self.count + self.output,
                "input_tokens_details": {"cached_tokens": self.cached},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        }
        if self.malformed == "missing_usage":
            del response["usage"]
        if self.malformed == "unknown_usage":
            response["usage"]["mystery_tokens"] = 1
        if self.malformed == "output_overcap":
            response["usage"]["output_tokens"] = 9
            response["usage"]["total_tokens"] = self.count + 9
        if self.malformed == "cached_overinput":
            response["usage"]["input_tokens_details"]["cached_tokens"] = self.count + 1
        if self.malformed == "missing_cached":
            response["usage"]["input_tokens_details"] = {}
        if self.malformed == "unknown_input_detail":
            response["usage"]["input_tokens_details"]["unknown"] = 1
        if self.malformed == "unknown_output_detail":
            response["usage"]["output_tokens_details"]["unknown"] = 1
        if self.malformed == "reasoning_overoutput":
            response["usage"]["output_tokens_details"]["reasoning_tokens"] = self.output + 1
        if self.malformed == "negative_usage":
            response["usage"]["input_tokens"] = -1
        if self.malformed == "redirect":
            return UpstreamReply(302, "text/plain", b"moved", "https://not-approved.example")
        if self.malformed == "error":
            return UpstreamReply(500, "application/json", b"{}")
        if self.stream:
            frames = [
                canonical_bytes({"type": "response.created", "sequence_number": 0}),
                canonical_bytes({
                    "type": "response.completed", "sequence_number": 1, "response": response,
                }),
            ]
            if self.malformed == "duplicate_terminal":
                frames.append(canonical_bytes({
                    "type": "response.completed", "sequence_number": 2, "response": response,
                }))
            if self.malformed == "duplicate_sequence":
                frames[1] = canonical_bytes({
                    "type": "response.completed", "sequence_number": 0, "response": response,
                })
            if self.malformed == "no_terminal":
                frames.pop()
            body = b"".join(b"data: " + frame.rstrip(b"\n") + b"\n\n" for frame in frames)
            if self.malformed == "truncated":
                body = body[:-1]
            return UpstreamReply(200, "text/event-stream", body)
        return UpstreamReply(200, "application/json", canonical_bytes(response))


def session(mock: MockResponses | None = None, **limit_overrides: object) -> tuple[MeteringSession, MockResponses]:
    backend = mock or MockResponses()
    pricing = PricingPolicy(
        model=MODEL,
        source_date="2026-10-14",
        effective_date="2026-10-14",
        input_per_million="2.00",
        cached_input_per_million="0.50",
        output_per_million="8.00",
    )
    values = {
        "max_generations": 2,
        "max_count_requests": 2,
        "max_input_tokens": 20,
        "max_output_tokens": 20,
        "max_total_tokens": 40,
        "max_output_tokens_per_request": 8,
        "max_elapsed_seconds": 60,
        "max_trial_cost_usd": "0.01",
        "max_study_cost_usd": "0.02",
    }
    values.update(limit_overrides)
    limits = MeteringLimits(**values)
    scope = MeteringScope("trial-001", SHA, SHA, MODEL, pricing.canonical_digest)
    return MeteringSession(scope, limits, pricing, StudyBudget("0.02"), CANARY, backend), backend


def request(stream: bool = True, **overrides: object) -> bytes:
    value: dict[str, object] = {
        "model": MODEL,
        "input": [{"role": "user", "content": "hello"}],
        "tools": [],
        "store": False,
        "stream": stream,
    }
    value.update(overrides)
    return canonical_bytes(value)


@pytest.mark.parametrize("stream", [True, False])
def test_sequential_metering_records_only_bound_usage(stream: bool) -> None:
    meter, backend = session()
    backend.stream = stream
    meter.generate(request(stream), CANARY)
    meter.generate(request(stream), CANARY)
    assert backend.paths == [
        "/v1/responses/input_tokens", "/v1/responses",
        "/v1/responses/input_tokens", "/v1/responses",
    ]
    assert meter.generations == 2
    assert meter.count_requests == 2
    assert meter.input_tokens == 14
    assert meter.output_tokens == 6
    assert meter.spent == Decimal("0.000076")
    assert [row["request_sequence"] for row in meter.evidence] == [1, 2]
    assert all(row["authorization_digest"] == SHA for row in meter.evidence)
    assert CANARY not in json.dumps(meter.evidence)
    assert "hello" not in json.dumps(meter.evidence)
    assert "max_output_tokens" not in backend.requests[0]
    assert backend.requests[1]["max_output_tokens"] == 8


@pytest.mark.parametrize("fault", [
    "count", "model", "input", "missing_usage", "unknown_usage", "redirect",
    "error", "duplicate_terminal", "truncated",
    "output_overcap", "cached_overinput", "missing_cached", "unknown_input_detail",
    "unknown_output_detail", "reasoning_overoutput", "negative_usage",
    "duplicate_sequence", "no_terminal",
])
def test_provider_uncertainty_closes_trial(fault: str) -> None:
    meter, backend = session()
    backend.malformed = fault
    with pytest.raises(MeteringError):
        meter.generate(request(), CANARY)
    assert meter.closed
    assert meter.evidence == []
    assert meter.count_requests == 1
    with pytest.raises(MeteringError):
        meter.generate(request(), CANARY)


@pytest.mark.parametrize("raw", [
    request(model="other-model"),
    request(background=True),
    request(max_output_tokens=100),
    request(input=[{"file_url": "https://example.test/file"}]),
    request(tools=[{"type": "web_search_preview"}]),
    b'{"model":"stage1-mock-2026-10-14","model":"other"}',
    b"{}" * 200_000,
])
def test_unapproved_request_never_reaches_provider(raw: bytes) -> None:
    meter, backend = session()
    with pytest.raises(MeteringError):
        meter.generate(raw, CANARY)
    assert backend.paths == []


@pytest.mark.parametrize("change", [
    {"stream": "true"}, {"input": []}, {"tools": "not a list"},
    {"tools": [{"type": "namespace"}]}, {"tools": [{"type": "future_tool"}]},
    {"tool_choice": "required"}, {"include": ["file_search_call.results"]},
    {"instructions": 42}, {"client_metadata": "not an object"},
    {"previous_response_id": "resp_previous"},
    {"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://x"}]}]},
])
def test_invalid_protocol_shape_is_denied_before_token_count(change: dict[str, object]) -> None:
    meter, backend = session()
    with pytest.raises(MeteringError):
        meter.generate(request(**change), CANARY)
    assert backend.paths == []
    assert meter.closed


def test_large_tool_schema_is_denied_before_token_count() -> None:
    meter, backend = session()
    with pytest.raises(MeteringError, match="tool schemas"):
        meter.generate(request(tools=[{
            "type": "function", "name": "local_tool", "description": "x" * 70_000,
        }]), CANARY)
    assert backend.paths == []


def test_frozen_local_namespace_tool_is_counted_but_hosted_child_is_denied() -> None:
    local_tool = {
        "type": "namespace", "name": "functions", "description": "local tools",
        "tools": [{"type": "function", "name": "exec_command", "parameters": {}}],
    }
    meter, backend = session()
    meter.generate(request(tools=[local_tool]), CANARY)
    assert backend.requests[0]["tools"] == [local_tool]
    assert backend.requests[1]["tools"] == [local_tool]

    meter, backend = session()
    local_tool["tools"] = [{"type": "web_search", "name": "external"}]
    with pytest.raises(MeteringError, match="child type"):
        meter.generate(request(tools=[local_tool]), CANARY)
    assert backend.paths == []


@pytest.mark.parametrize("kind,reason", [
    ("tool_search", "hosted tool search"),
    ("web_search", "hosted web search"),
    ("image_generation", "hosted image generation"),
])
def test_hosted_tool_categories_are_explicitly_denied(kind: str, reason: str) -> None:
    meter, backend = session()
    with pytest.raises(MeteringError, match=reason):
        meter.generate(request(tools=[{"type": kind}]), CANARY)
    assert backend.paths == []


def test_budget_failure_occurs_before_generation() -> None:
    meter, backend = session(max_input_tokens=6)
    with pytest.raises(MeteringError, match="input token limit"):
        meter.generate(request(), CANARY)
    assert backend.paths == ["/v1/responses/input_tokens"]


def test_reused_provider_response_id_closes_trial() -> None:
    meter, backend = session()
    backend.malformed = "reused_id"
    meter.generate(request(), CANARY)
    with pytest.raises(MeteringError, match="already used"):
        meter.generate(request(), CANARY)
    assert meter.closed
    assert len(meter.evidence) == 1


def test_elapsed_time_is_checked_before_and_after_generation() -> None:
    meter, backend = session()
    meter.clock = lambda: meter.started + 61
    with pytest.raises(MeteringError, match="elapsed-time"):
        meter.generate(request(), CANARY)
    assert backend.paths == []

    meter, backend = session()
    before = meter.started
    meter.clock = lambda: before + 61 if backend.paths else before
    with pytest.raises(MeteringError, match="after token count"):
        meter.generate(request(), CANARY)
    assert backend.paths == ["/v1/responses/input_tokens"]

    meter, backend = session()
    before = meter.started
    meter.clock = lambda: before + 61 if len(backend.paths) == 2 else before
    with pytest.raises(MeteringError, match="after generation"):
        meter.generate(request(), CANARY)
    assert backend.paths == ["/v1/responses/input_tokens", "/v1/responses"]
    assert meter.closed


@pytest.mark.parametrize("limit,match", [
    ({"max_generations": 1}, "generation request limit"),
    ({"max_count_requests": 1}, "input-token-count request limit"),
    ({"max_input_tokens": 10}, "input token limit"),
    ({"max_output_tokens": 8}, "output token reservation"),
    ({"max_total_tokens": 15}, "total token reservation"),
    ({"max_trial_cost_usd": "0.000100"}, "trial cost reservation"),
])
def test_second_request_is_denied_before_generation_when_budget_exhausted(
    limit: dict[str, object], match: str
) -> None:
    meter, backend = session(**limit)
    meter.generate(request(), CANARY)
    with pytest.raises(MeteringError, match=match):
        meter.generate(request(), CANARY)
    assert backend.paths.count("/v1/responses") == 1
    assert meter.closed


def test_study_budget_is_shared_across_trials() -> None:
    meter, _ = session()
    meter.study.limit = Decimal("0.000100")
    meter.generate(request(), CANARY)
    with pytest.raises(MeteringError, match="study cost reservation"):
        meter.generate(request(), CANARY)
    assert meter.study.spent == Decimal("0.000038")


def test_price_digest_mismatch_and_overflow_fail() -> None:
    pricing = PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "2.00", "0.50", "8.00")
    limits = MeteringLimits(2, 2, 20, 20, 40, 8, 60, "0.01", "0.02")
    with pytest.raises(MeteringError, match="pricing policy"):
        MeteringSession(
            MeteringScope("trial-001", SHA, SHA, MODEL, "sha256:" + "b" * 64),
            limits, pricing, StudyBudget("0.02"), CANARY, MockResponses(),
        )
    with pytest.raises(MeteringError, match="bounded"):
        pricing.cost(10_000_001, 0, 0)


def test_price_policy_digest_and_rounding() -> None:
    pricing = PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "2.00", "0.50", "8.00")
    assert pricing.canonical_digest.startswith("sha256:")
    assert pricing.cost(7, 2, 3) == Decimal("0.000035")
    assert pricing.cost(1, 0, 0) == Decimal("0.000002")
    with pytest.raises(MeteringError):
        pricing.cost(1, 2, 0)
    with pytest.raises(MeteringError):
        PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "1.00", "2.00", "8.00")
    with pytest.raises(MeteringError):
        PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "NaN", "0.50", "8.00")
    with pytest.raises(MeteringError, match="calendar date"):
        PricingPolicy(MODEL, "2026-13-99", "2026-10-14", "2.00", "0.50", "8.00")


def test_codex_argv_has_only_internal_static_provider() -> None:
    argv = codex_metered_argv(MODEL)
    joined = " ".join(argv)
    assert "--ignore-user-config" in argv
    assert "model_provider=stage1_metered" in argv
    assert 'web_search="disabled"' in argv
    assert 'env_key="CODEX_API_KEY"' in joined
    assert 'supports_websockets=false' in joined
    assert 'requires_openai_auth=false' in joined
    assert "stage1-metering-gateway:8080/v1" in joined
    assert "api.openai.com" not in joined
    assert CANARY not in joined


def test_versioned_pricing_and_evidence_schemas() -> None:
    root = Path(__file__).parents[2] / "agentguard/schemas"
    pricing_schema = json.loads((root / "stage1-pricing-policy-v1.schema.json").read_text())
    evidence_schema = json.loads((root / "stage1-metering-evidence-v1.schema.json").read_text())
    pricing = PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "2.00", "0.50", "8.00")
    Draft202012Validator(pricing_schema, format_checker=FormatChecker()).validate(pricing.__dict__)
    meter, _ = session()
    meter.generate(request(), CANARY)
    evidence = {
        "schema": "agentguard.stage1-metering-evidence",
        "schema_version": 1,
        "events": meter.evidence,
        "trial_closed": meter.closed,
    }
    Draft202012Validator(evidence_schema).validate(evidence)
    assert pricing.canonical_digest == PricingPolicy(
        MODEL, "2026-10-14", "2026-10-14", "2.00", "0.50", "8.00"
    ).canonical_digest
