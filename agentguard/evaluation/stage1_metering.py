"""Fail-closed Stage 1 Responses metering contract (mock-only in Phase A).

No function in this module resolves a provider credential or opens a socket.
The transport is injected so protocol and accounting can be tested offline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, ROUND_UP
from typing import Callable, Protocol


MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TOOL_BYTES = 64 * 1024
MAX_INPUT_ITEMS = 128
MAX_JSON_DEPTH = 24
MONEY_QUANTUM = Decimal("0.000001")
MODEL_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,79}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
TRIAL_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
SOURCE_URL = "https://developers.openai.com/api/docs/pricing"


class MeteringError(ValueError):
    pass


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _decimal(value: object, name: str) -> Decimal:
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,8})?", value):
        raise MeteringError(f"{name} must be a bounded nonnegative decimal string")
    try:
        result = Decimal(value)
    except InvalidOperation as error:
        raise MeteringError(f"{name} is invalid") from error
    if result > Decimal("1000000"):
        raise MeteringError(f"{name} exceeds the policy bound")
    return result


def _positive_int(value: object, name: str, maximum: int = 10_000_000) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise MeteringError(f"{name} must be a bounded positive integer")
    return value


def _nonnegative_int(value: object, name: str, maximum: int = 10_000_000) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise MeteringError(f"{name} must be a bounded nonnegative integer")
    return value


def _exact_keys(value: object, keys: set[str], name: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise MeteringError(f"{name} has missing or unexpected fields")
    return value


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise MeteringError("duplicate JSON field")
        result[key] = value
    return result


def _depth(value: object, level: int = 0) -> None:
    if level > MAX_JSON_DEPTH:
        raise MeteringError("JSON nesting limit exceeded")
    if isinstance(value, dict):
        if len(value) > 128:
            raise MeteringError("JSON object limit exceeded")
        for child in value.values():
            _depth(child, level + 1)
    elif isinstance(value, list):
        if len(value) > MAX_INPUT_ITEMS:
            raise MeteringError("JSON array limit exceeded")
        for child in value:
            _depth(child, level + 1)


def parse_json(raw: bytes, maximum: int = MAX_REQUEST_BYTES) -> dict[str, object]:
    if not raw or len(raw) > maximum:
        raise MeteringError("JSON body is missing or exceeds its bound")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MeteringError("malformed JSON body") from error
    if not isinstance(value, dict):
        raise MeteringError("JSON body must be an object")
    _depth(value)
    return value


@dataclass(frozen=True)
class PricingPolicy:
    model: str
    source_date: str
    effective_date: str
    input_per_million: str
    cached_input_per_million: str
    output_per_million: str
    currency: str = "USD"
    source_url: str = SOURCE_URL
    schema: str = "agentguard.stage1-pricing-policy"
    schema_version: int = 1

    def __post_init__(self) -> None:
        if not MODEL_PATTERN.fullmatch(self.model):
            raise MeteringError("pricing model is invalid")
        for name in ("source_date", "effective_date"):
            if not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", getattr(self, name)):
                raise MeteringError(f"{name} must be an ISO date")
            try:
                date.fromisoformat(getattr(self, name))
            except ValueError as error:
                raise MeteringError(f"{name} is not a calendar date") from error
        if self.currency != "USD" or self.source_url != SOURCE_URL:
            raise MeteringError("pricing source or currency is unapproved")
        if self.schema != "agentguard.stage1-pricing-policy" or self.schema_version != 1:
            raise MeteringError("pricing schema is unsupported")
        for name in ("input_per_million", "cached_input_per_million", "output_per_million"):
            _decimal(getattr(self, name), name)
        if _decimal(self.cached_input_per_million, "cached_input_per_million") > _decimal(
            self.input_per_million, "input_per_million"
        ):
            raise MeteringError("cached input price exceeds input price")

    @property
    def canonical_digest(self) -> str:
        return digest(self.__dict__)

    def cost(self, input_tokens: int, cached_tokens: int, output_tokens: int) -> Decimal:
        _nonnegative_int(input_tokens, "input_tokens")
        _nonnegative_int(cached_tokens, "cached_tokens")
        _nonnegative_int(output_tokens, "output_tokens")
        if cached_tokens > input_tokens:
            raise MeteringError("cached tokens exceed input tokens")
        raw = (
            Decimal(input_tokens - cached_tokens) * _decimal(self.input_per_million, "input")
            + Decimal(cached_tokens) * _decimal(self.cached_input_per_million, "cached")
            + Decimal(output_tokens) * _decimal(self.output_per_million, "output")
        ) / Decimal(1_000_000)
        return raw.quantize(MONEY_QUANTUM, rounding=ROUND_UP)


@dataclass(frozen=True)
class MeteringLimits:
    max_generations: int
    max_count_requests: int
    max_input_tokens: int
    max_output_tokens: int
    max_total_tokens: int
    max_output_tokens_per_request: int
    max_elapsed_seconds: int
    max_trial_cost_usd: str
    max_study_cost_usd: str

    def __post_init__(self) -> None:
        for name in (
            "max_generations", "max_count_requests", "max_input_tokens",
            "max_output_tokens", "max_total_tokens", "max_output_tokens_per_request",
            "max_elapsed_seconds",
        ):
            _positive_int(getattr(self, name), name)
        if self.max_generations > 32 or self.max_count_requests > 32:
            raise MeteringError("request limits exceed the bounded evidence schema")
        for name in ("max_trial_cost_usd", "max_study_cost_usd"):
            if _decimal(getattr(self, name), name) <= 0:
                raise MeteringError(f"{name} must be positive")


@dataclass(frozen=True)
class MeteringScope:
    trial_id: str
    plan_digest: str
    authorization_digest: str
    model: str
    pricing_digest: str

    def __post_init__(self) -> None:
        if not TRIAL_PATTERN.fullmatch(self.trial_id):
            raise MeteringError("trial ID is invalid")
        if not MODEL_PATTERN.fullmatch(self.model):
            raise MeteringError("model is invalid")
        for name in ("plan_digest", "authorization_digest", "pricing_digest"):
            if not DIGEST_PATTERN.fullmatch(getattr(self, name)):
                raise MeteringError(f"{name} is invalid")


@dataclass(frozen=True)
class UpstreamReply:
    status: int
    content_type: str
    body: bytes
    location: str | None = None


class ResponsesTransport(Protocol):
    def post(self, path: str, body: bytes) -> UpstreamReply: ...


class StudyBudget:
    def __init__(self, limit_usd: str) -> None:
        self.limit = _decimal(limit_usd, "study limit")
        self.spent = Decimal(0)
        self.reserved = Decimal(0)
        self.lock = threading.Lock()

    def reserve(self, amount: Decimal) -> None:
        with self.lock:
            if self.spent + self.reserved + amount > self.limit:
                raise MeteringError("study cost reservation exceeded")
            self.reserved += amount

    def settle(self, reserved: Decimal, actual: Decimal) -> None:
        with self.lock:
            self.reserved -= reserved
            self.spent += actual


def codex_metered_argv(model: str, gateway_host: str = "stage1-metering-gateway") -> tuple[str, ...]:
    if not MODEL_PATTERN.fullmatch(model) or gateway_host != "stage1-metering-gateway":
        raise MeteringError("Codex model or internal gateway host is invalid")
    provider = (
        'model_providers.stage1_metered={name="Stage 1 metered",'
        'base_url="http://stage1-metering-gateway:8080/v1",'
        'env_key="CODEX_API_KEY",wire_api="responses",'
        'requires_openai_auth=false,supports_websockets=false,'
        'request_max_retries=0,stream_max_retries=0}'
    )
    return (
        "--ignore-user-config", "-c", "model_provider=stage1_metered", "-c", provider,
        "-c", "analytics.enabled=false", "-c", "otel.exporter=none",
        "-c", "check_for_update_on_startup=false",
        "--", "Read the checked-in task instructions and complete the bounded fixture.",
    )


class MeteringSession:
    def __init__(
        self,
        scope: MeteringScope,
        limits: MeteringLimits,
        pricing: PricingPolicy,
        study: StudyBudget,
        synthetic_token: str,
        transport: ResponsesTransport,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if pricing.model != scope.model or pricing.canonical_digest != scope.pricing_digest:
            raise MeteringError("pricing policy is not bound to the trial model")
        if study.limit != _decimal(limits.max_study_cost_usd, "study limit"):
            raise MeteringError("study budget and trial limits disagree")
        if not synthetic_token or len(synthetic_token) > 128:
            raise MeteringError("synthetic authorization is invalid")
        self.scope = scope
        self.limits = limits
        self.pricing = pricing
        self.study = study
        self._token = synthetic_token
        self.transport = transport
        self.clock = clock
        self.started = clock()
        self.generations = 0
        self.count_requests = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.spent = Decimal(0)
        self.closed = False
        self.failure_reason: str | None = None
        self._response_ids: set[str] = set()
        self._lock = threading.Lock()
        self.evidence: list[dict[str, object]] = []

    def generate(self, raw: bytes, bearer_token: str, path: str = "/v1/responses") -> UpstreamReply:
        if not self._lock.acquire(blocking=False):
            self.closed = True
            raise MeteringError("concurrent generation is forbidden")
        reserved = Decimal(0)
        generation_sent = False
        try:
            if self.closed or not hmac.compare_digest(bearer_token, self._token):
                raise MeteringError("trial access is closed or unauthorized")
            if path != "/v1/responses":
                raise MeteringError("Responses path is not approved")
            if self.clock() - self.started >= self.limits.max_elapsed_seconds:
                raise MeteringError("trial elapsed-time limit exceeded")
            request = _validate_request(parse_json(raw), self.scope.model, self.limits)
            if self.generations >= self.limits.max_generations:
                raise MeteringError("generation request limit exceeded")
            if self.count_requests >= self.limits.max_count_requests:
                raise MeteringError("input-token-count request limit exceeded")
            self.count_requests += 1
            count_reply = self.transport.post(
                "/v1/responses/input_tokens", canonical_bytes(_count_payload(request))
            )
            count = _input_count(count_reply)
            if self.clock() - self.started >= self.limits.max_elapsed_seconds:
                raise MeteringError("trial elapsed-time limit exceeded after token count")
            output_cap = request["max_output_tokens"]
            assert isinstance(output_cap, int)
            if self.input_tokens + count > self.limits.max_input_tokens:
                raise MeteringError("input token limit exceeded before generation")
            if self.output_tokens + output_cap > self.limits.max_output_tokens:
                raise MeteringError("output token reservation exceeded")
            if self.input_tokens + self.output_tokens + count + output_cap > self.limits.max_total_tokens:
                raise MeteringError("total token reservation exceeded")
            reserved = self.pricing.cost(count, 0, output_cap)
            if self.spent + reserved > _decimal(self.limits.max_trial_cost_usd, "trial limit"):
                raise MeteringError("trial cost reservation exceeded")
            self.study.reserve(reserved)
            self.generations += 1
            generation_sent = True
            reply = self.transport.post("/v1/responses", canonical_bytes(request))
            response_id, usage = _terminal_usage(reply, self.scope.model, request["stream"])
            if response_id in self._response_ids:
                raise MeteringError("provider response ID was already used")
            self._response_ids.add(response_id)
            if self.clock() - self.started >= self.limits.max_elapsed_seconds:
                raise MeteringError("trial elapsed-time limit exceeded after generation")
            if self.closed:
                raise MeteringError("trial closed during an in-flight generation")
            if usage["input_tokens"] != count:
                raise MeteringError("counted and terminal input usage disagree")
            if usage["output_tokens"] > output_cap:
                raise MeteringError("provider exceeded output token cap")
            if usage["total_tokens"] != count + usage["output_tokens"]:
                raise MeteringError("provider total usage is contradictory")
            actual = self.pricing.cost(count, usage["cached_tokens"], usage["output_tokens"])
            self.study.settle(reserved, actual)
            reserved = Decimal(0)
            self.input_tokens += count
            self.output_tokens += usage["output_tokens"]
            self.spent += actual
            self.evidence.append({
                "schema": "agentguard.stage1-metering-event",
                "schema_version": 1,
                "trial_id": self.scope.trial_id,
                "plan_digest": self.scope.plan_digest,
                "authorization_digest": self.scope.authorization_digest,
                "model": self.scope.model,
                "pricing_digest": self.scope.pricing_digest,
                "request_sequence": self.generations,
                "count_requests": self.count_requests,
                "input_tokens": count,
                "cached_input_tokens": usage["cached_tokens"],
                "output_tokens": usage["output_tokens"],
                "total_tokens": usage["total_tokens"],
                "calculated_token_cost_usd": str(actual),
            })
            return reply
        except Exception as error:
            self.closed = True
            if reserved:
                self.study.settle(reserved, reserved if generation_sent else Decimal(0))
            if isinstance(error, MeteringError):
                raise
            raise MeteringError("provider response or accounting failed") from error
        finally:
            self._lock.release()


_REQUEST_FIELDS = {
    "model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
    "reasoning", "store", "stream", "include", "prompt_cache_key", "text",
    "max_output_tokens", "client_metadata",
}

_COUNT_FIELDS = {
    "model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
    "reasoning", "text",
}


def _count_payload(request: dict[str, object]) -> dict[str, object]:
    # The count endpoint accepts these input-shaping fields, not generation controls.
    # Terminal input usage must still exactly reconcile with its count.
    return {key: value for key, value in request.items() if key in _COUNT_FIELDS}


def _validate_request(request: dict[str, object], model: str, limits: MeteringLimits) -> dict[str, object]:
    if set(request) - _REQUEST_FIELDS:
        raise MeteringError("Responses request has an unsupported field")
    if request.get("model") != model or request.get("store") is not False:
        raise MeteringError("model or stateless execution policy differs")
    if type(request.get("stream")) is not bool:
        raise MeteringError("stream must be a boolean")
    if not isinstance(request.get("input"), list) or not request["input"]:
        raise MeteringError("Responses input must be a nonempty bounded list")
    if len(request["input"]) > MAX_INPUT_ITEMS:
        raise MeteringError("Responses input exceeds its bound")
    if not isinstance(request.get("tools", []), list):
        raise MeteringError("tools must be a bounded list")
    for tool in request.get("tools", []):
        if not _local_tool(tool):
            raise MeteringError(_tool_shape_reason(tool))
    if len(canonical_bytes(request.get("tools", []))) > MAX_TOOL_BYTES:
        raise MeteringError("tool schemas exceed their bound")
    if request.get("tool_choice", "auto") not in ("auto", "none"):
        raise MeteringError("tool choice is unsupported")
    if request.get("include", []) not in ([], ["reasoning.encrypted_content"]):
        raise MeteringError("response include is unsupported")
    if "client_metadata" in request:
        metadata = request.pop("client_metadata")
        if not isinstance(metadata, dict) or len(canonical_bytes(metadata)) > 4096:
            raise MeteringError("client metadata is malformed or too large")
    for field in ("prompt_cache_key", "instructions"):
        if field in request and (
            not isinstance(request[field], str) or len(request[field]) > 64 * 1024
        ):
            raise MeteringError(f"{field} is malformed or too large")
    _reject_remote_resources(request)
    cap = request.get("max_output_tokens", limits.max_output_tokens_per_request)
    if type(cap) is not int or not 0 < cap <= limits.max_output_tokens_per_request:
        raise MeteringError("max_output_tokens is outside the approved bound")
    request["max_output_tokens"] = cap
    return request


def _local_tool(tool: object, nested: bool = False) -> bool:
    if not isinstance(tool, dict):
        return False
    kind = tool.get("type")
    if kind in {"function", "custom"}:
        return isinstance(tool.get("name"), str) and bool(tool["name"])
    if kind != "namespace" or nested or set(tool) - {"type", "name", "description", "tools"}:
        return False
    children = tool.get("tools")
    return (
        isinstance(tool.get("name"), str)
        and bool(tool["name"])
        and isinstance(children, list)
        and 0 < len(children) <= 32
        and all(_local_tool(child, nested=True) for child in children)
    )


def _tool_shape_reason(tool: object) -> str:
    if not isinstance(tool, dict):
        return "tool declaration is not an object"
    kind = tool.get("type")
    if kind in {"function", "custom"}:
        return "local tool name is missing"
    if kind != "namespace":
        if kind == "tool_search":
            return "hosted tool search is forbidden"
        if kind == "web_search":
            return "hosted web search is forbidden"
        if kind == "image_generation":
            return "hosted image generation is forbidden"
        return "provider hosted or unknown tool type is forbidden"
    if set(tool) - {"type", "name", "description", "tools"}:
        return "namespace has unexpected fields"
    if not isinstance(tool.get("name"), str) or not tool["name"]:
        return "namespace name is missing"
    children = tool.get("tools")
    if not isinstance(children, list) or not 0 < len(children) <= 32:
        return "namespace tools are missing or excessive"
    if any(isinstance(child, dict) and child.get("type") == "namespace" for child in children):
        return "nested namespace is forbidden"
    if any(isinstance(child, dict) and child.get("type") in {"function", "custom"} for child in children):
        return "namespace child name is missing or malformed"
    return "namespace child type is forbidden"


def _reject_remote_resources(value: object) -> None:
    forbidden = {
        "file_id", "file_url", "image_url", "audio_url", "input_file", "input_image",
        "web_search", "web_search_preview", "computer_use_preview", "code_interpreter",
        "mcp", "background", "previous_response_id", "conversation",
    }
    if isinstance(value, dict):
        if set(value) & forbidden:
            raise MeteringError("remote resource or background mode is not approved")
        if value.get("type") in forbidden:
            raise MeteringError("provider-hosted tool or remote resource is not approved")
        for child in value.values():
            _reject_remote_resources(child)
    elif isinstance(value, list):
        for child in value:
            _reject_remote_resources(child)


def _input_count(reply: UpstreamReply) -> int:
    _valid_reply(reply, "application/json")
    payload = _exact_keys(parse_json(reply.body, MAX_RESPONSE_BYTES), {"object", "input_tokens"}, "count reply")
    if payload["object"] != "response.input_tokens":
        raise MeteringError("input-token count object is invalid")
    return _nonnegative_int(payload["input_tokens"], "input_tokens")


def _valid_reply(reply: UpstreamReply, content_type: str) -> None:
    if reply.location is not None or reply.status != 200:
        raise MeteringError("provider redirect or error is forbidden")
    if reply.content_type.split(";", 1)[0].strip().lower() != content_type:
        raise MeteringError("provider content type is invalid")
    if not reply.body or len(reply.body) > MAX_RESPONSE_BYTES:
        raise MeteringError("provider response is missing or truncated")


def _terminal_usage(reply: UpstreamReply, model: str, stream: object) -> tuple[str, dict[str, int]]:
    if stream is True:
        _valid_reply(reply, "text/event-stream")
        if not reply.body.endswith(b"\n\n"):
            raise MeteringError("stream ended without a complete terminal event")
        completed: list[dict[str, object]] = []
        done = False
        last_sequence = -1
        for frame in reply.body.split(b"\n\n"):
            if not frame:
                continue
            lines = frame.splitlines()
            data = [line[5:].strip() for line in lines if line.startswith(b"data:")]
            if len(data) != 1:
                raise MeteringError("stream frame is malformed")
            if data[0] == b"[DONE]" and completed and not done:
                done = True
                continue
            if done:
                raise MeteringError("stream contains data after DONE")
            event = parse_json(data[0], MAX_RESPONSE_BYTES)
            sequence = event.get("sequence_number")
            if type(sequence) is not int or sequence <= last_sequence:
                raise MeteringError("stream sequence is missing or out of order")
            last_sequence = sequence
            kind = event.get("type")
            if kind in ("response.failed", "response.incomplete"):
                raise MeteringError("provider response did not complete")
            if kind == "response.completed":
                completed.append(event)
            elif completed:
                raise MeteringError("stream contains data after terminal completion")
        if len(completed) != 1:
            raise MeteringError("stream must contain one terminal completion")
        response = completed[0].get("response")
    else:
        _valid_reply(reply, "application/json")
        response = parse_json(reply.body, MAX_RESPONSE_BYTES)
    if not isinstance(response, dict) or response.get("model") != model:
        raise MeteringError("terminal model is missing or mismatched")
    response_id = response.get("id")
    if not isinstance(response_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", response_id):
        raise MeteringError("terminal response ID is missing or invalid")
    if response.get("status") != "completed":
        raise MeteringError("terminal response is not complete")
    usage = response.get("usage")
    if not isinstance(usage, dict):
        raise MeteringError("terminal usage is missing")
    allowed = {"input_tokens", "output_tokens", "total_tokens", "input_tokens_details", "output_tokens_details"}
    if set(usage) - allowed:
        raise MeteringError("terminal usage category is unknown")
    input_tokens = _nonnegative_int(usage.get("input_tokens"), "input_tokens")
    output_tokens = _nonnegative_int(usage.get("output_tokens"), "output_tokens")
    total_tokens = _nonnegative_int(usage.get("total_tokens"), "total_tokens")
    details = usage.get("input_tokens_details")
    if not isinstance(details, dict) or set(details) - {"cached_tokens", "cache_write_tokens"}:
        raise MeteringError("cached input usage is missing or unknown")
    cached = _nonnegative_int(details.get("cached_tokens"), "cached_tokens")
    if details.get("cache_write_tokens", 0) != 0:
        raise MeteringError("cache-write usage is not priced by this policy")
    if cached > input_tokens:
        raise MeteringError("cached input usage exceeds input usage")
    output_details = usage.get("output_tokens_details", {})
    if not isinstance(output_details, dict) or set(output_details) - {"reasoning_tokens"}:
        raise MeteringError("output usage category is unknown")
    if "reasoning_tokens" in output_details and _nonnegative_int(
        output_details["reasoning_tokens"], "reasoning_tokens"
    ) > output_tokens:
        raise MeteringError("reasoning usage exceeds output usage")
    return response_id, {
        "input_tokens": input_tokens, "output_tokens": output_tokens,
        "total_tokens": total_tokens, "cached_tokens": cached,
    }
