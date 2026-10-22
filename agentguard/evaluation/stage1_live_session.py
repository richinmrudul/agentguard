"""B1 metering orchestration. Not an enabled live-study entrypoint."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable

from agentguard.evaluation.stage1_live_pricing import TokenUsage, pricing_policy_digest
from agentguard.evaluation.stage1_metering import (
    MAX_RESPONSE_BYTES,
    MAX_TOOL_BYTES,
    MeteringError,
    UpstreamReply,
    _count_payload,
    _input_count,
    _validate_request,
    canonical_bytes,
    parse_json,
)
from agentguard.evaluation.stage1_study_ledger import StudyLedger


MODEL = "gpt-5.2-2025-12-11"
_REVIEWED_TOOLS = (
    ("function", "exec_command", "7ecb0f4f51b3982e36be43a9d08daa05348d7dd5f70646231b1f0f9823f40ec3"),
    ("function", "write_stdin", "9c3adbaa65e36ce23c7f1a8778e094a14b2086c993fc783727156276831c99dd"),
    ("custom", "apply_patch", "5947b870d79e16bddc34946a4afb6200ff14a97f8419a2d23f8e5040af9a7154"),
)
_REQUEST_FIELDS = {
    "include", "input", "instructions", "max_output_tokens", "model",
    "parallel_tool_calls", "prompt_cache_key", "reasoning", "store",
    "stream", "tool_choice", "tools",
}
_MAX_EVENTS = 256
_MAX_FRAME_BYTES = 64 * 1024


def reviewed_tools(tools: object) -> bool:
    if not isinstance(tools, list) or len(tools) != len(_REVIEWED_TOOLS):
        return False
    if len(canonical_bytes(tools)) > MAX_TOOL_BYTES:
        return False
    for declaration, (kind, name, expected_hash) in zip(tools, _REVIEWED_TOOLS):
        if not isinstance(declaration, dict):
            return False
        if declaration.get("type") != kind or declaration.get("name") != name:
            return False
        raw = json.dumps(declaration, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_hash):
            return False
    return True


def normalize_generation(raw: bytes, output_cap: int) -> dict[str, object]:
    request = parse_json(raw)
    extras = set(request) - _REQUEST_FIELDS
    if extras:
        diagnostic_names = {
            "stream_options", "service_tier", "previous_response_id", "text",
            "client_metadata", "prompt_cache_retention",
        }
        if extras <= diagnostic_names:
            names = " ".join(sorted(name.replace("_", "-") for name in extras))
            raise MeteringError(f"frozen Codex request has unreviewed fields {names}")
        raise MeteringError("frozen Codex request contains an unreviewed field")
    if request.get("model") != MODEL or request.get("store") is not False:
        raise MeteringError("model or storage policy differs")
    if request.get("stream") is not True:
        raise MeteringError("frozen Codex streaming mode differs")
    if request.get("parallel_tool_calls") is not True or request.get("tool_choice") != "auto":
        raise MeteringError("frozen local-tool policy differs")
    if request.get("reasoning") != {"effort": "none"}:
        raise MeteringError("reasoning mode or summary is unreviewed")
    if not reviewed_tools(request.get("tools")):
        raise MeteringError("ordered frozen tool declarations differ")
    if request.get("include") not in ([], ["reasoning.encrypted_content"]):
        raise MeteringError("response include is unreviewed")
    if not isinstance(request.get("prompt_cache_key"), str) or len(request["prompt_cache_key"]) > 256:
        raise MeteringError("prompt-cache key is malformed")
    if "max_output_tokens" in request and request["max_output_tokens"] != output_cap:
        raise MeteringError("frozen output cap differs")
    if not 0 < output_cap <= 4096:
        raise MeteringError("output cap is outside the reviewed bound")
    request["max_output_tokens"] = output_cap
    # GPT-5.2 supports in-memory retention; extended writes have separate prices.
    request["prompt_cache_retention"] = "in_memory"
    _validate_request({key: value for key, value in request.items()
                       if key != "prompt_cache_retention"}, MODEL, _limits_for_validation(output_cap))
    _text_only(request.get("input"))
    return request


def _limits_for_validation(output_cap: int):
    from agentguard.evaluation.stage1_metering import MeteringLimits
    return MeteringLimits(32, 32, 10_000_000, 10_000_000, 10_000_000,
                          output_cap, 10_000_000, "1000000", "1000000")


def _text_only(value: object) -> None:
    if isinstance(value, list):
        for child in value:
            _text_only(child)
    elif isinstance(value, dict):
        kind = value.get("type")
        if kind is not None and kind not in {
            "message", "input_text", "output_text", "function_call",
            "function_call_output", "custom_tool_call", "custom_tool_call_output",
        }:
            raise MeteringError("non-text or remote input item is forbidden")
        for key, child in value.items():
            if key in {"url", "file_id", "image_url", "audio_url", "data"}:
                raise MeteringError("remote or binary input is forbidden")
            _text_only(child)
    elif not isinstance(value, (str, int, bool, type(None))):
        raise MeteringError("non-text input value is forbidden")


def count_request(generation: dict[str, object]) -> bytes:
    if generation.get("model") != MODEL or generation.get("prompt_cache_retention") != "in_memory":
        raise MeteringError("generation is not normalized")
    return canonical_bytes(_count_payload(generation))


def _terminal_response(reply: UpstreamReply) -> dict[str, object]:
    if reply.status != 200 or reply.location or not reply.body or len(reply.body) > MAX_RESPONSE_BYTES:
        raise MeteringError("provider terminal response is missing or invalid")
    if reply.content_type.split(";", 1)[0].strip().lower() != "text/event-stream":
        raise MeteringError("frozen stream content type differs")
    if not reply.body.endswith(b"\n\n"):
        raise MeteringError("provider stream is truncated")
    frames = [frame for frame in reply.body.split(b"\n\n") if frame]
    if not 0 < len(frames) <= _MAX_EVENTS or any(len(frame) > _MAX_FRAME_BYTES for frame in frames):
        raise MeteringError("provider stream events exceed their bound")
    last_sequence = -1
    terminal = None
    for index, frame in enumerate(frames):
        lines = frame.splitlines()
        if len(lines) != 1 or not lines[0].startswith(b"data: "):
            raise MeteringError("provider stream event is malformed")
        if lines[0] == b"data: [DONE]":
            if terminal is None or index != len(frames) - 1:
                raise MeteringError("provider DONE marker is misplaced")
            continue
        event = parse_json(lines[0][6:], _MAX_FRAME_BYTES)
        sequence = event.get("sequence_number")
        if type(sequence) is not int or sequence <= last_sequence or terminal is not None:
            raise MeteringError("provider stream sequence is contradictory")
        last_sequence = sequence
        if event.get("type") in {"response.failed", "response.incomplete"}:
            raise MeteringError("provider response failed or was incomplete")
        if event.get("type") == "response.completed":
            terminal = event.get("response")
    if not isinstance(terminal, dict) or terminal.get("status") != "completed":
        raise MeteringError("provider terminal completion is absent")
    response_id = terminal.get("id")
    if not isinstance(response_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", response_id):
        raise MeteringError("provider response identity is malformed")
    if terminal.get("model") != MODEL or terminal.get("service_tier") != "default":
        raise MeteringError("provider terminal model or tier differs")
    output = terminal.get("output")
    if not isinstance(output, list) or len(output) > 128:
        raise MeteringError("provider terminal output is missing or excessive")
    if any(not isinstance(item, dict) or item.get("type") not in {
        "message", "function_call", "custom_tool_call",
    } for item in output):
        raise MeteringError("provider terminal output contains an unreviewed item")
    return terminal


class LiveMeteringSession:
    """Pure orchestration; caller must supply an already-bound TLS transport."""

    def __init__(self, ledger: StudyLedger, trial_id: str, synthetic_token: str,
                 credential: str, transport: object, output_cap: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if trial_id not in ledger.scope.trial_ids or ledger.scope.pricing_digest != pricing_policy_digest():
            raise MeteringError("trial or pricing policy differs from ledger")
        self.ledger = ledger
        self.trial_id = trial_id
        self._synthetic_token = synthetic_token
        self._credential = credential
        self._transport = transport
        self.output_cap = output_cap
        self._clock = clock
        self._started = clock()
        self.closed = False
        self.failure_reason: str | None = None
        self.evidence: list[dict[str, object]] = []
        self.evidence_schema_version = 2

    def fail_closed(self) -> None:
        self.closed = True
        try:
            self.ledger.fail(self.trial_id)
        except (MeteringError, OSError):
            pass

    def generate(self, raw: bytes, supplied_token: str, path: str = "/v1/responses") -> UpstreamReply:
        if path != "/v1/responses":
            self.fail_closed()
            raise MeteringError("Responses path is not approved")
        if self.closed:
            raise MeteringError("trial is closed or unauthorized")
        if not isinstance(supplied_token, str) or not hmac.compare_digest(supplied_token, self._synthetic_token):
            self.fail_closed()
            raise MeteringError("trial is closed or unauthorized")
        if self._clock() - self._started >= self.ledger.scope.max_trial_seconds:
            self.fail_closed()
            raise MeteringError("trial elapsed-time limit reached")
        try:
            request = normalize_generation(raw, self.output_cap)
        except MeteringError:
            self.fail_closed()
            raise
        request_fingerprint = hashlib.sha256(canonical_bytes(request)).hexdigest()[:48]
        count_id = "count-" + request_fingerprint
        generation_id = "generation-" + request_fingerprint
        try:
            self.ledger.count(self.trial_id, count_id)
            remaining = self.ledger.scope.max_trial_seconds - (self._clock() - self._started)
            count_reply = self._transport.post(
                "/v1/responses/input_tokens", count_request(request), self._credential,
                timeout_seconds=remaining,
            )
            input_tokens = _input_count(count_reply)
            if self._clock() - self._started >= self.ledger.scope.max_trial_seconds:
                raise MeteringError("trial elapsed-time limit reached after count")
            self.ledger.reserve(self.trial_id, generation_id, input_tokens, self.output_cap)
            remaining = self.ledger.scope.max_trial_seconds - (self._clock() - self._started)
            reply = self._transport.post(
                "/v1/responses", canonical_bytes(request), self._credential,
                timeout_seconds=remaining,
            )
            terminal = _terminal_response(reply)
            usage = TokenUsage.from_response(terminal, input_tokens)
            if self._clock() - self._started >= self.ledger.scope.max_trial_seconds:
                raise MeteringError("trial elapsed-time limit reached after generation")
            self.ledger.settle(self.trial_id, generation_id, usage)
            trial = self.ledger.snapshot()["trials"][self.trial_id]
            self.evidence.append({
                "schema": "agentguard.stage1-metering-event",
                "schema_version": 2,
                "trial_id": self.trial_id,
                "plan_digest": self.ledger.scope.plan_digest,
                "authorization_digest": self.ledger.scope.authorization_digest,
                "model": MODEL,
                "pricing_digest": self.ledger.scope.pricing_digest,
                "request_sequence": trial["generations"],
                "count_requests": trial["counts"],
                "input_tokens": usage.input_tokens,
                "cached_input_tokens": usage.cached_input_tokens,
                "output_tokens": usage.output_tokens,
                "reasoning_tokens": usage.reasoning_tokens,
                "charged_usd": trial["charged_usd"],
            })
            return reply
        except Exception as error:
            self.fail_closed()
            if isinstance(error, MeteringError):
                raise
            raise MeteringError("metered provider operation failed") from None
