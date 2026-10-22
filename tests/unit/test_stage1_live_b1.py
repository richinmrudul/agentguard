from __future__ import annotations

import json
import multiprocessing
import os
import socket
import ssl
import subprocess
import threading
from hashlib import sha256
from decimal import Decimal
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agentguard.evaluation import stage1_live_credential as credential_module
from agentguard.evaluation.stage1_live_credential import (
    LiveBindings, LiveCredentialResolver, agent_credential_environment,
    synthetic_trial_token,
)
from agentguard.evaluation.stage1_live_capabilities import (
    REQUIRED_STAGE1_CAPABILITIES, stage1_live_unavailable,
)
from agentguard.evaluation.stage1_live_pricing import (
    TokenUsage, cost_usd, load_pricing_policy, pricing_policy_digest,
    worst_case_cost_usd,
)
from agentguard.evaluation.stage1_live_session import (
    MODEL, _terminal_response, _text_only, count_request, normalize_generation,
    reviewed_tools,
)
from agentguard.evaluation import stage1_live_session as session_module
from agentguard.evaluation.stage1_live_session import LiveMeteringSession
from agentguard.evaluation.stage1_live_transport import (
    ExactTLSTransport, LocalTestTLSTransport, _public_addresses,
)
from agentguard.evaluation.stage1_metering import MeteringError, UpstreamReply, canonical_bytes
from agentguard.evaluation.stage1_study_ledger import LedgerScope, StudyLedger


SHA = "sha256:" + "a" * 64
GATEWAY = "ghcr.io/richinmrudul/agentguard/stage1-metering-gateway@" + SHA
AGENT = "ghcr.io/richinmrudul/agentguard/stage1-model-agent@" + SHA


def _scope() -> LedgerScope:
    return LedgerScope(
        SHA, SHA, SHA, pricing_policy_digest(), SHA, "openai-api", MODEL,
        ("trial-a", "trial-b"), 2, 2, 100, 40, 140, 60, "0.001", "0.0015",
    )


def _bindings() -> LiveBindings:
    return LiveBindings(SHA, SHA, "trial-a", SHA, pricing_policy_digest(), SHA,
                        GATEWAY, AGENT)


def test_frozen_pricing_is_canonical_and_exact() -> None:
    policy = load_pricing_policy()
    schema = json.loads((Path(__file__).parents[2] / "agentguard/schemas/stage1-pricing-policy-v2.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(policy)
    assert policy["model"] == MODEL
    assert policy["source_effective_date"] is None
    assert pricing_policy_digest().startswith("sha256:")
    assert cost_usd(TokenUsage(1000, 100, 50, 10)) == Decimal("0.002293")
    assert worst_case_cost_usd(1000, 50) == Decimal("0.002450")
    with pytest.raises(MeteringError, match="cache-write"):
        cost_usd(TokenUsage(1000, 0, 1, 0, 1))
    with pytest.raises(MeteringError):
        cost_usd(TokenUsage(True, 0, 1, 0))


@pytest.mark.parametrize("mutator", [
    lambda r: r["usage"].update(input_tokens=8),
    lambda r: r["usage"].update(extra_tokens=1),
    lambda r: r["usage"]["input_tokens_details"].update(cache_write_tokens=1),
    lambda r: r.update(service_tier="fast"),
    lambda r: r.update(model="gpt-5.2"),
    lambda r: r["usage"].update(total_tokens=999),
    lambda r: r["usage"]["output_tokens_details"].update(reasoning_tokens=999),
])
def test_usage_drift_fails_closed(mutator) -> None:
    response = {
        "model": MODEL, "service_tier": "default",
        "usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12,
                  "input_tokens_details": {"cached_tokens": 1, "cache_write_tokens": 0},
                  "output_tokens_details": {"reasoning_tokens": 0}},
    }
    mutator(response)
    with pytest.raises(MeteringError):
        TokenUsage.from_response(response, 10)


def test_ledger_reserves_and_reconciles_across_instances(tmp_path: Path) -> None:
    root = tmp_path / "private-ledger"
    first = StudyLedger(root, _scope())
    second = StudyLedger(root, _scope())
    first.count("trial-a", "count-one")
    reserved = first.reserve("trial-a", "generation-one", 20, 20)
    assert second.snapshot()["trials"]["trial-a"]["pending"]["reserved_usd"] == str(reserved)
    with pytest.raises(MeteringError, match="uncertain"):
        second.count("trial-b", "count-two")
    first.settle("trial-a", "generation-one", TokenUsage(20, 0, 2, 0))
    second.count("trial-b", "count-two")
    with pytest.raises(MeteringError, match="replayed"):
        second.count("trial-b", "count-two")
    state = second.snapshot()
    schema = json.loads((Path(__file__).parents[2] / "agentguard/schemas/stage1-study-ledger-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(state)
    assert state["trials"]["trial-a"]["pending"] is None
    assert Decimal(state["trials"]["trial-a"]["charged_usd"]) < reserved
    assert len((root / "journal.jsonl").read_bytes()) < 256 * 1024
    assert (root.stat().st_mode & 0o077) == 0


def test_ledger_crash_reservation_cannot_be_released(tmp_path: Path) -> None:
    root = tmp_path / "private-ledger"
    ledger = StudyLedger(root, _scope())
    ledger.count("trial-a", "count-one")
    reservation = ledger.reserve("trial-a", "generation-one", 20, 20)
    restarted = StudyLedger(root, _scope())
    assert Decimal(restarted.snapshot()["trials"]["trial-a"]["charged_usd"]) == reservation
    with pytest.raises(MeteringError, match="restarted process"):
        restarted.settle("trial-a", "generation-one", TokenUsage(20, 0, 2, 0))
    with pytest.raises(MeteringError, match="uncertain"):
        restarted.reserve("trial-b", "generation-two", 20, 20)
    restarted.fail("trial-a")
    with pytest.raises(MeteringError, match="uncertain"):
        restarted.count("trial-b", "count-two")


@pytest.mark.parametrize("file_name", ["snapshot.json", "journal.jsonl"])
def test_ledger_corruption_or_rollback_fails_closed(tmp_path: Path, file_name: str) -> None:
    root = tmp_path / "private-ledger"
    ledger = StudyLedger(root, _scope())
    ledger.count("trial-a", "count-one")
    path = root / file_name
    path.write_bytes(path.read_bytes()[:20])
    with pytest.raises(MeteringError):
        StudyLedger(root, _scope())


def test_ledger_scope_conflict_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "private-ledger"
    StudyLedger(root, _scope())
    scope = _scope()
    changed = LedgerScope(**{**vars(scope), "plan_digest": "sha256:" + "b" * 64})
    with pytest.raises(MeteringError):
        StudyLedger(root, changed)


def test_real_credential_is_disabled_until_replacement_subjects_approved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    bindings = _bindings()
    ledger = StudyLedger(tmp_path / "ledger", _scope())
    canary = "FAKE_CANARY_NOT_A_REAL_PROVIDER_KEY"
    with pytest.raises(MeteringError, match="not been approved"):
        LiveCredentialResolver(bindings).resolve(bindings, ledger, {"CODEX_API_KEY": canary})
    monkeypatch.setattr(credential_module, "_APPROVED_REPLACEMENT_SUBJECTS", frozenset({
        GATEWAY, AGENT,
    }))
    resolver = LiveCredentialResolver(bindings)
    with pytest.raises(MeteringError, match="binding"):
        resolver.resolve(LiveBindings(**{**vars(bindings), "plan_digest": "sha256:" + "b" * 64}),
                         ledger, {"CODEX_API_KEY": canary})
    assert resolver.resolve(bindings, ledger, {"CODEX_API_KEY": canary}) == canary
    with pytest.raises(MeteringError):
        resolver.resolve(bindings, ledger, {"CODEX_API_KEY": canary})
    assert canary not in json.dumps(vars(bindings))


def test_credential_rejects_ambiguous_and_malformed_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    ledger = StudyLedger(tmp_path / "ledger", _scope())
    monkeypatch.setattr(credential_module, "_APPROVED_REPLACEMENT_SUBJECTS", frozenset({
        GATEWAY, AGENT,
    }))
    for mapping in ({}, {"CODEX_API_KEY": "short"},
                    {"CODEX_API_KEY": "FAKE\nCANARY_THAT_IS_MALFORMED"},
                    {"CODEX_API_KEY": "FAKE_CANARY_NOT_REAL", "codex_api_key": "OTHER"}):
        with pytest.raises(MeteringError):
            LiveCredentialResolver(_bindings()).resolve(_bindings(), ledger, mapping)
    token = synthetic_trial_token()
    assert set(agent_credential_environment(token)) == {"CODEX_API_KEY"}
    assert agent_credential_environment(token)["CODEX_API_KEY"] == token


def test_live_transport_rejects_public_route_controls_and_private_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = ExactTLSTransport()
    assert (transport.host, transport.port) == ("api.openai.com", 443)
    with pytest.raises(MeteringError):
        transport.post("/v1/models", b"{}", "FAKE_CANARY_NOT_REAL")
    monkeypatch.setattr("socket.getaddrinfo", lambda *_args, **_kwargs: [
        (2, 1, 6, "", ("127.0.0.1", 443)),
    ])
    with pytest.raises(MeteringError, match="not public"):
        _public_addresses("api.openai.com", 443)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1234")
    with pytest.raises(MeteringError, match="proxy"):
        transport.post("/v1/responses", b"{}", "FAKE_CANARY_NOT_REAL")


@pytest.mark.parametrize("records", [
    [],
    [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 443))],
    [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))],
    [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 443, 0, 0))],
    [(socket.AF_UNIX, socket.SOCK_STREAM, 0, "", ("/tmp/socket",))],
    [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 443))],
    [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))] * 33,
])
def test_live_dns_rejects_every_unreviewed_answer(
    records: list[tuple], monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: records)
    with pytest.raises(MeteringError):
        _public_addresses("api.openai.com", 443)


def test_live_dns_accepts_only_public_answers_without_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: records)
    assert _public_addresses("api.openai.com", 443) == [(socket.AF_INET, ("8.8.8.8", 443))]


def test_live_transport_rejects_proxy_before_trust_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", "/private/fake-ca.pem")
    with pytest.raises(MeteringError, match="proxy or alternate trust"):
        ExactTLSTransport()


@pytest.mark.parametrize(("path", "body", "credential", "timeout"), [
    ("/v1/models", b"{}", "FAKE_CANARY_NOT_REAL", 10),
    ("/v1/responses?x=1", b"{}", "FAKE_CANARY_NOT_REAL", 10),
    ("/v1/responses", b"", "FAKE_CANARY_NOT_REAL", 10),
    ("/v1/responses", "{}", "FAKE_CANARY_NOT_REAL", 10),
    ("/v1/responses", b"{}", "", 10),
    ("/v1/responses", b"{}", "FAKE\nCANARY", 10),
    ("/v1/responses", b"{}", "FAKE_CANARY_NOT_REAL", 0),
    ("/v1/responses", b"{}", "FAKE_CANARY_NOT_REAL", 601),
])
def test_live_transport_rejects_invalid_request_without_network(
    path: str, body: object, credential: str, timeout: int,
) -> None:
    transport = ExactTLSTransport()
    with pytest.raises(MeteringError):
        transport.post(path, body, credential, timeout_seconds=timeout)


def test_live_transport_rejects_dns_resolution_error_without_leaking_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_resolution(*_args, **_kwargs):
        raise OSError("FAKE_PRIVATE_PATH_CANARY")

    monkeypatch.setattr(socket, "getaddrinfo", broken_resolution)
    with pytest.raises(MeteringError, match="provider DNS resolution failed") as caught:
        _public_addresses("api.openai.com", 443)
    assert "FAKE_PRIVATE_PATH_CANARY" not in str(caught.value)


@pytest.mark.parametrize("value", [
    [{"type": "input_image", "image_url": "FAKE_PRIVATE_URL"}],
    [{"type": "input_text", "file_id": "FAKE_FILE"}],
    [{"type": "input_text", "url": "FAKE_URL"}],
    [{"type": "input_text", "data": "FAKE_BINARY"}],
    [{"type": "input_text", "text": {"audio_url": "FAKE_AUDIO"}}],
    [{"type": "input_text", "text": object()}],
])
def test_live_request_rejects_remote_or_nontext_nested_inputs(value: object) -> None:
    with pytest.raises(MeteringError):
        _text_only(value)


def test_unreviewed_request_field_diagnostic_exposes_name_only() -> None:
    with pytest.raises(MeteringError, match="previous-response-id") as caught:
        normalize_generation(canonical_bytes({
            "previous_response_id": "FAKE_PRIVATE_CANARY",
        }), 8)
    assert "FAKE_PRIVATE_CANARY" not in str(caught.value)


def test_local_tls_transport_has_test_only_destination(tmp_path: Path) -> None:
    with pytest.raises(MeteringError):
        LocalTestTLSTransport(str(tmp_path / "missing"), 443, "api.openai.com")


def test_live_request_rejects_unknown_or_missing_tool_contract() -> None:
    assert not reviewed_tools([])
    assert not reviewed_tools([{"type": "function", "name": "exec_command"}])
    request = {"model": MODEL, "input": [{"role": "user", "content": "fixture"}],
               "tools": [], "store": False, "stream": True,
               "parallel_tool_calls": True, "tool_choice": "auto",
               "reasoning": {"effort": "none"}, "prompt_cache_key": "fixture"}
    with pytest.raises(MeteringError, match="tool declarations"):
        normalize_generation(canonical_bytes(request), 256)
    request["tools"] = [{"type": "web_search", "name": "search"}]
    with pytest.raises(MeteringError):
        normalize_generation(canonical_bytes(request), 256)


def test_stage1_live_capabilities_remain_unavailable() -> None:
    assert len(REQUIRED_STAGE1_CAPABILITIES) == 9
    assert stage1_live_unavailable(GATEWAY, AGENT)
    assert stage1_live_unavailable(
        "ghcr.io/richinmrudul/agentguard/stage1-gateway@" + SHA,
        "ghcr.io/richinmrudul/agentguard/stage1-codex-agent@" + SHA,
    )
    assert not stage1_live_unavailable("sha256:" + "c" * 64, "sha256:" + "d" * 64)
    assert stage1_live_unavailable("sha256:" + "c" * 64, "sha256:" + "d" * 64,
                                   model_id=MODEL)
    assert stage1_live_unavailable("sha256:" + "c" * 64, "sha256:" + "d" * 64,
                                   profile_id="stage1-pilot")


def test_live_normalization_rejects_unreviewed_fields_and_tool_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = [
        {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
        {"type": "function", "name": "write_stdin", "parameters": {"type": "object"}},
        {"type": "custom", "name": "apply_patch", "format": {"type": "text"}},
    ]
    contract = tuple((item["type"], item["name"], sha256(json.dumps(
        item, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode()).hexdigest()) for item in tools)
    monkeypatch.setattr(session_module, "_REVIEWED_TOOLS", contract)
    request = {
        "model": MODEL, "instructions": "fixture", "input": [
            {"role": "user", "content": [{"type": "input_text", "text": "fake fixture"}]},
        ], "tools": tools, "tool_choice": "auto", "parallel_tool_calls": True,
        "reasoning": {"effort": "none"}, "store": False, "stream": True,
        "include": [], "prompt_cache_key": "fixture",
    }
    normalized = normalize_generation(canonical_bytes(request), 32)
    assert normalized["max_output_tokens"] == 32
    assert normalized["prompt_cache_retention"] == "in_memory"
    assert set(json.loads(count_request(normalized))) == {
        "model", "instructions", "input", "tools", "tool_choice",
        "parallel_tool_calls", "reasoning",
    }
    variants = []
    for field, value in (
        ("model", "gpt-5.2"), ("service_tier", "fast"),
        ("background", True), ("stream", False),
        ("parallel_tool_calls", False), ("prompt_cache_retention", "24h"),
        ("text", {"verbosity": "high"}), ("reasoning", {"effort": "none", "summary": None}),
    ):
        changed = json.loads(canonical_bytes(request))
        changed[field] = value
        variants.append(changed)
    for changed_tools in (
        list(reversed(tools)), tools[:-1], tools + [tools[-1]],
        [{**tools[0], "name": "renamed"}, *tools[1:]],
        [{**tools[0], "description": "changed"}, *tools[1:]],
    ):
        changed = json.loads(canonical_bytes(request))
        changed["tools"] = changed_tools
        variants.append(changed)
    for forbidden_input in (
        {"type": "input_image", "image_url": "https://example.invalid/a"},
        {"type": "message", "role": "user", "content": "x", "file_id": "file_fake"},
    ):
        changed = json.loads(canonical_bytes(request))
        changed["input"].append(forbidden_input)
        variants.append(changed)
    for changed in variants:
        with pytest.raises(MeteringError):
            normalize_generation(canonical_bytes(changed), 32)


def _terminal_reply(response: dict[str, object], extra: bytes = b"") -> UpstreamReply:
    event = {"type": "response.completed", "sequence_number": 0, "response": response}
    return UpstreamReply(200, "text/event-stream", b"data: " + canonical_bytes(event).rstrip(b"\n")
                         + b"\n\n" + extra)


def test_terminal_stream_requires_exact_model_tier_identity_and_local_output() -> None:
    response = {
        "id": "resp_fake", "model": MODEL, "service_tier": "default",
        "status": "completed", "output": [{"type": "message"}],
    }
    assert _terminal_response(_terminal_reply(response)) == response
    variants = []
    for key, value in (
        ("id", "bad id"), ("model", "gpt-5.2"),
        ("service_tier", "fast"), ("status", "incomplete"),
        ("output", [{"type": "web_search_call"}]),
        ("output", "wrong"),
    ):
        changed = dict(response)
        changed[key] = value
        variants.append(_terminal_reply(changed))
    variants.extend([
        UpstreamReply(302, "text/event-stream", _terminal_reply(response).body),
        UpstreamReply(200, "application/json", _terminal_reply(response).body),
        UpstreamReply(200, "text/event-stream", _terminal_reply(response).body[:-1]),
        UpstreamReply(200, "text/event-stream", b"data: not-json\n\n"),
        UpstreamReply(200, "text/event-stream", b"data: [DONE]\n\n"),
        UpstreamReply(200, "text/event-stream", b"data: [DONE]\n\n" + _terminal_reply(response).body),
        _terminal_reply(response, b"data: [DONE]\n\ndata: [DONE]\n\n"),
        _terminal_reply(response, _terminal_reply(response).body),
        _terminal_reply(response, b"data: extra\nextra: field\n\n"),
        UpstreamReply(200, "text/event-stream", b"data: " + b"x" * 65537 + b"\n\n"),
    ])
    for reply in variants:
        with pytest.raises(MeteringError):
            _terminal_response(reply)


def _tls_certificate(tmp_path: Path) -> tuple[Path, Path]:
    certificate = tmp_path / "local-test-ca.pem"
    private_key = tmp_path / "local-test-key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "1", "-keyout", str(private_key), "-out", str(certificate),
        "-subj", "/CN=stage1-mock-provider",
        "-addext", "subjectAltName=DNS:stage1-mock-provider",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return certificate, private_key


def test_local_tls_mock_count_generation_and_durable_settlement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from importlib.util import module_from_spec, spec_from_file_location
    source = Path(__file__).parents[2] / "runtime-images/stage1-metering/mock_responses_provider.py"
    spec = spec_from_file_location("stage1_b1_local_mock", source)
    assert spec and spec.loader
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    module.MODEL = MODEL
    module.MockHandler.scenario = "success"
    module.MockHandler.count_requests = 0
    module.MockHandler.generations = 0
    certificate, private_key = _tls_certificate(tmp_path)
    monkeypatch.setenv("STAGE1_MOCK_TLS_FAKE_TOKEN", "FAKE_UPSTREAM_CANARY_ONLY")
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.delenv(key, raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.MockHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(private_key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    tools = [
        {"type": "function", "name": "exec_command", "parameters": {"type": "object"}},
        {"type": "function", "name": "write_stdin", "parameters": {"type": "object"}},
        {"type": "custom", "name": "apply_patch", "format": {"type": "text"}},
    ]
    fixture_contract = tuple(
        (item["type"], item["name"], sha256(json.dumps(item, sort_keys=True,
         separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()) for item in tools
    )
    monkeypatch.setattr(session_module, "_REVIEWED_TOOLS", fixture_contract)
    ledger = StudyLedger(tmp_path / "private-ledger", _scope())
    transport = LocalTestTLSTransport(str(certificate), server.server_port)
    session = LiveMeteringSession(ledger, "trial-a", "FAKE_INTERNAL_TOKEN_ONLY",
                                  "FAKE_UPSTREAM_CANARY_ONLY", transport, 8)
    request = canonical_bytes({
        "model": MODEL, "instructions": "fake task", "input": [
            {"role": "user", "content": "FAKE_PROMPT_CANARY"},
        ], "tools": tools, "tool_choice": "auto", "parallel_tool_calls": True,
        "reasoning": {"effort": "none"}, "store": False, "stream": True,
        "include": [], "prompt_cache_key": "fake-fixture",
    })
    try:
        unrelated = tmp_path / "unrelated-ca"
        unrelated.mkdir()
        wrong_certificate, _ = _tls_certificate(unrelated)
        wrong_transport = LocalTestTLSTransport(str(wrong_certificate), server.server_port)
        with pytest.raises(MeteringError, match="TLS connection"):
            wrong_transport.post("/v1/responses/input_tokens", b"{}", "FAKE_UPSTREAM_CANARY_ONLY")
        reply = session.generate(request, "FAKE_INTERNAL_TOKEN_ONLY")
        assert b"mock complete" in reply.body
        next_request = json.loads(request)
        next_request["input"][0]["content"] = "FAKE_SECOND_TURN"
        session.generate(canonical_bytes(next_request), "FAKE_INTERNAL_TOKEN_ONLY")
        assert module.MockHandler.count_requests == 2
        assert module.MockHandler.generations == 2
        state = ledger.snapshot()["trials"]["trial-a"]
        assert state["pending"] is None
        assert state["input_tokens"] == 14
        assert state["output_tokens"] == 6
        evidence = (tmp_path / "private-ledger" / "journal.jsonl").read_text()
        for secret in ("FAKE_UPSTREAM_CANARY_ONLY", "FAKE_INTERNAL_TOKEN_ONLY",
                       "FAKE_PROMPT_CANARY", "mock complete"):
            assert secret not in evidence
        with pytest.raises(MeteringError, match="replayed"):
            session.generate(request, "FAKE_INTERNAL_TOKEN_ONLY")
        module.MockHandler.scenario = "redirect"
        with pytest.raises(MeteringError, match="redirect"):
            transport.post("/v1/responses", request, "FAKE_UPSTREAM_CANARY_ONLY")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def test_local_tls_mock_rejects_wrong_ca_and_hostname(tmp_path: Path) -> None:
    certificate, _ = _tls_certificate(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    other_certificate, _ = _tls_certificate(other)
    with pytest.raises(MeteringError):
        LocalTestTLSTransport(str(other_certificate), 443, "api.openai.com")
    assert certificate.read_bytes() != other_certificate.read_bytes()


def _competing_reservation(root: str, trial: str, barrier, result) -> None:
    try:
        ledger = StudyLedger(Path(root), _scope())
        barrier.wait(timeout=10)
        ledger.count(trial, f"count-{trial}")
        ledger.reserve(trial, f"generation-{trial}", 20, 20)
        result.put("reserved")
    except (MeteringError, OSError):
        result.put("denied")


def test_cross_process_reservations_cannot_overlap(tmp_path: Path) -> None:
    root = tmp_path / "private-ledger"
    StudyLedger(root, _scope())
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    result = context.Queue()
    workers = [context.Process(target=_competing_reservation,
                               args=(str(root), trial, barrier, result))
               for trial in ("trial-a", "trial-b")]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=20)
        assert not worker.is_alive()
        assert worker.exitcode == 0
    assert sorted([result.get(timeout=2), result.get(timeout=2)]) == ["denied", "reserved"]
    state = StudyLedger(root, _scope()).snapshot()
    assert sum(item["pending"] is not None for item in state["trials"].values()) == 1


def test_ledger_denies_unknown_replay_overrun_and_failed_trial(tmp_path: Path) -> None:
    ledger = StudyLedger(tmp_path / "private-ledger", _scope())
    with pytest.raises(MeteringError):
        ledger.count("unknown", "count-one")
    ledger.count("trial-a", "count-one")
    with pytest.raises(MeteringError, match="replayed"):
        ledger.count("trial-a", "count-one")
    with pytest.raises(MeteringError, match="input-token"):
        ledger.reserve("trial-a", "generation-too-big", 101, 8)
    with pytest.raises(MeteringError, match="output-token"):
        ledger.reserve("trial-a", "generation-too-big", 7, 41)
    ledger.reserve("trial-a", "generation-one", 7, 8)
    with pytest.raises(MeteringError, match="uncertain"):
        ledger.reserve("trial-b", "generation-other", 7, 8)
    ledger.fail("trial-a")
    with pytest.raises(MeteringError, match="failed"):
        ledger.settle("trial-a", "generation-one", TokenUsage(7, 0, 3, 0))


def test_ledger_study_cap_blocks_second_trial_after_first_settlement(tmp_path: Path) -> None:
    scope = LedgerScope(**{**vars(_scope()), "max_study_cost_usd": "0.00035"})
    ledger = StudyLedger(tmp_path / "private-ledger", scope)
    ledger.count("trial-a", "count-a")
    ledger.reserve("trial-a", "generation-a", 20, 20)
    ledger.settle("trial-a", "generation-a", TokenUsage(20, 0, 2, 0))
    ledger.count("trial-b", "count-b")
    with pytest.raises(MeteringError, match="study cost"):
        ledger.reserve("trial-b", "generation-b", 20, 20)


def test_ledger_rejects_symlink_broad_permissions_and_stale_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "private-ledger"
    ledger = StudyLedger(root, _scope())
    ledger.count("trial-a", "count-a")
    state = ledger.snapshot()
    assert state["trials"]["trial-a"]["started_at"] is not None
    monkeypatch.setattr("agentguard.evaluation.stage1_study_ledger.time.time",
                        lambda: state["trials"]["trial-a"]["started_at"] - 1)
    with pytest.raises(MeteringError, match="elapsed-time"):
        ledger.count("trial-a", "count-b")
    monkeypatch.undo()
    os.chmod(root / "snapshot.json", 0o644)
    with pytest.raises(MeteringError, match="permissions"):
        StudyLedger(root, _scope())
    os.chmod(root / "snapshot.json", 0o600)
    alias = tmp_path / "ledger-alias"
    alias.symlink_to(root, target_is_directory=True)
    with pytest.raises(MeteringError, match="private"):
        StudyLedger(alias, _scope())


@pytest.mark.parametrize(("field", "value"), [
    ("authorization_digest", "not-a-digest"),
    ("plan_digest", "sha256:short"),
    ("provider", "other"),
    ("model", "gpt-5.2"),
    ("trial_ids", ()),
    ("trial_ids", ("trial-a", "trial-a")),
    ("trial_ids", ("INVALID",)),
    ("max_trial_generations", True),
    ("max_trial_counts", 0),
    ("max_trial_input_tokens", 10_000_001),
    ("max_trial_cost_usd", "0.0000001"),
    ("max_study_cost_usd", "0"),
])
def test_ledger_scope_rejects_unreviewed_binding_or_limit(field: str, value: object) -> None:
    with pytest.raises(MeteringError):
        LedgerScope(**{**vars(_scope()), field: value})


@pytest.mark.parametrize(("section", "field", "value"), [
    ("state", "schema", "other"),
    ("state", "schema_version", 2),
    ("state", "trials", {}),
    ("trial", "counts", True),
    ("trial", "generations", -1),
    ("trial", "input_tokens", "7"),
    ("trial", "charged_usd", "1e100"),
    ("trial", "failed", 0),
    ("trial", "request_ids", ["repeat", "repeat"]),
    ("trial", "request_ids", ["../escape"]),
    ("trial", "started_at", -1),
])
def test_ledger_rejects_malformed_recovered_state(
    tmp_path: Path, section: str, field: str, value: object,
) -> None:
    ledger = StudyLedger(tmp_path / "private-ledger", _scope())
    state = ledger.snapshot()
    target = state if section == "state" else state["trials"]["trial-a"]
    target[field] = value
    with pytest.raises(MeteringError):
        ledger._check_state(state)


@pytest.mark.parametrize(("field", "value"), [
    ("authorization_digest", "wrong"),
    ("plan_digest", "wrong"),
    ("trial_id", "INVALID"),
    ("profile_digest", "wrong"),
    ("pricing_digest", "wrong"),
    ("redaction_digest", "wrong"),
    ("gateway_image", "ghcr.io/other/gateway:latest"),
    ("agent_image", "ghcr.io/other/agent:latest"),
    ("model", "gpt-5.2"),
    ("destination", "example.com:443"),
])
def test_live_credential_bindings_reject_unreviewed_values(field: str, value: str) -> None:
    with pytest.raises(MeteringError):
        LiveBindings(**{**vars(_bindings()), field: value}).validate()


@pytest.mark.parametrize(("field", "value"), [
    ("owner_digest", "bad"),
    ("request_id", "unknown-request"),
    ("input_tokens", True),
    ("output_cap", -1),
    ("reserved_usd", "NaN"),
])
def test_ledger_rejects_malformed_pending_reservation(
    tmp_path: Path, field: str, value: object,
) -> None:
    ledger = StudyLedger(tmp_path / "private-ledger", _scope())
    ledger.count("trial-a", "count-one")
    ledger.reserve("trial-a", "generation-one", 7, 8)
    state = ledger.snapshot()
    state["trials"]["trial-a"]["pending"][field] = value
    with pytest.raises(MeteringError):
        ledger._check_state(state)


def test_ledger_rejects_corrupt_journal_and_missing_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "private-ledger"
    StudyLedger(root, _scope())
    journal = root / "journal.jsonl"
    journal.write_bytes(journal.read_bytes()[:-1])
    with pytest.raises(MeteringError):
        StudyLedger(root, _scope())
    journal.unlink()
    with pytest.raises(MeteringError):
        StudyLedger(root, _scope())


def test_pricing_rejects_conflicting_cached_and_reasoning_counts() -> None:
    with pytest.raises(MeteringError):
        cost_usd(TokenUsage(3, 4, 1, 0))
    with pytest.raises(MeteringError):
        cost_usd(TokenUsage(3, 0, 1, 2))
    with pytest.raises(MeteringError):
        worst_case_cost_usd(-1, 8)
    with pytest.raises(MeteringError):
        worst_case_cost_usd(8, 10_000_001)


def test_ledger_rejects_scope_change_and_restart_refund(tmp_path: Path) -> None:
    root = tmp_path / "private-ledger"
    first = StudyLedger(root, _scope())
    with pytest.raises(MeteringError):
        StudyLedger(root, LedgerScope(**{**vars(_scope()), "max_trial_counts": 3}))
    first.count("trial-a", "count-one")
    first.reserve("trial-a", "generation-one", 7, 8)
    restarted = StudyLedger(root, _scope())
    with pytest.raises(MeteringError, match="restarted process"):
        restarted.settle("trial-a", "generation-one", TokenUsage(7, 0, 1, 0))
    assert restarted.snapshot()["trials"]["trial-a"]["pending"] is not None


@pytest.mark.parametrize(("limit", "value", "reason"), [
    ("max_trial_generations", 1, "generation"),
    ("max_trial_input_tokens", 6, "input-token"),
    ("max_trial_output_tokens", 7, "output-token"),
    ("max_trial_total_tokens", 14, "total-token"),
    ("max_trial_cost_usd", "0.00001", "cost"),
    ("max_study_cost_usd", "0.00001", "study cost"),
])
def test_ledger_enforces_each_reservation_limit(
    tmp_path: Path, limit: str, value: object, reason: str,
) -> None:
    scope = LedgerScope(**{**vars(_scope()), limit: value})
    ledger = StudyLedger(tmp_path / "private-ledger", scope)
    ledger.count("trial-a", "count-one")
    if limit == "max_trial_generations":
        ledger.reserve("trial-a", "generation-one", 7, 8)
        ledger.settle("trial-a", "generation-one", TokenUsage(7, 0, 1, 0))
    with pytest.raises(MeteringError, match=reason):
        ledger.reserve("trial-a", "generation-two", 7, 8)


def test_ledger_count_limit_and_settlement_mismatch(tmp_path: Path) -> None:
    scope = LedgerScope(**{**vars(_scope()), "max_trial_counts": 1})
    ledger = StudyLedger(tmp_path / "private-ledger", scope)
    ledger.count("trial-a", "count-one")
    with pytest.raises(MeteringError, match="count-request"):
        ledger.count("trial-a", "count-two")
    ledger.reserve("trial-a", "generation-one", 7, 8)
    with pytest.raises(MeteringError, match="terminal usage"):
        ledger.settle("trial-a", "wrong-generation", TokenUsage(7, 0, 1, 0))
    with pytest.raises(MeteringError, match="differs from reservation"):
        ledger.settle("trial-a", "generation-one", TokenUsage(6, 0, 1, 0))
    with pytest.raises(MeteringError, match="differs from reservation"):
        ledger.settle("trial-a", "generation-one", TokenUsage(7, 0, 9, 0))
