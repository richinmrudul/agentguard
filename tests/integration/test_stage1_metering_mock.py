from __future__ import annotations

import http.client
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from agentguard.evaluation.stage1_metering import (
    MeteringError,
    MeteringLimits,
    MeteringScope,
    MeteringSession,
    PricingPolicy,
    StudyBudget,
    canonical_bytes,
)
from agentguard.evaluation.stage1_metering_gateway import (
    MockOnlyTransport,
    handler_for,
    main as gateway_main,
    mock_server_from_config,
)


MODEL = "stage1-mock-2026-10-14"
CANARY = "AGENTGUARD_FAKE_CREDENTIAL_CANARY"
SHA = "sha256:" + "a" * 64


def _mock_handler() -> type:
    path = (
        Path(__file__).parents[2]
        / "runtime-images/stage1-metering/mock_responses_provider.py"
    )
    spec = importlib.util.spec_from_file_location("stage1_mock_responses", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.MockHandler


def _session(port: int) -> MeteringSession:
    pricing = PricingPolicy(MODEL, "2026-10-14", "2026-10-14", "2.00", "0.50", "8.00")
    limits = MeteringLimits(2, 2, 20, 20, 40, 8, 60, "0.01", "0.02")
    scope = MeteringScope("mock-trial", SHA, SHA, MODEL, pricing.canonical_digest)
    return MeteringSession(
        scope, limits, pricing, StudyBudget("0.02"), CANARY,
        MockOnlyTransport("127.0.0.1", port),
    )


def _post(port: int, path: str, body: bytes, token: str = CANARY) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("POST", path, body=body, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        })
        result = connection.getresponse()
        return result.status, result.read()
    finally:
        connection.close()


@pytest.mark.parametrize("stream", [True, False])
def test_local_mock_http_gateway_counts_and_retains_only_sanitized_evidence(
    tmp_path: Path, stream: bool
) -> None:
    mock_handler = _mock_handler()
    mock_handler.scenario = "success"
    mock_handler.count_requests = 0
    mock_handler.generations = 0
    mock_server = ThreadingHTTPServer(("127.0.0.1", 0), mock_handler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    session = _session(mock_server.server_port)
    evidence = tmp_path / "current-run-evidence.json"
    gateway_server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(session, evidence))
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()
    try:
        body = canonical_bytes({
            "model": MODEL, "input": [{"role": "user", "content": "private prompt"}],
            "tools": [], "store": False, "stream": stream,
        })
        for _ in range(2):
            status, response = _post(gateway_server.server_port, "/v1/responses", body)
            assert status == 200
            assert b"mock complete" in response
            if stream:
                events = [
                    json.loads(frame.removeprefix(b"data: "))
                    for frame in response.split(b"\n\n") if frame
                ]
                assert [event["type"] for event in events] == [
                    "response.created", "response.output_item.added",
                    "response.output_text.delta", "response.output_item.done",
                    "response.completed",
                ]
                assert [event["sequence_number"] for event in events] == list(range(5))
        assert mock_handler.count_requests == 2
        assert mock_handler.generations == 2
        assert session.generations == 2
        assert session.count_requests == 2
        assert session.input_tokens == 14
        assert session.output_tokens == 6
        retained = evidence.read_text()
        assert len(retained) < 4096
        assert CANARY not in retained
        assert "private prompt" not in retained
        assert "mock complete" not in retained
        assert len(json.loads(retained)["events"]) == 2
        status, _ = _post(gateway_server.server_port, "/v1/models", body)
        assert status == 404
        assert session.closed
    finally:
        gateway_server.shutdown()
        gateway_server.server_close()
        mock_server.shutdown()
        mock_server.server_close()


def test_evidence_write_failure_closes_trial_after_generation(tmp_path: Path) -> None:
    mock_handler = _mock_handler()
    mock_server = ThreadingHTTPServer(("127.0.0.1", 0), mock_handler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    session = _session(mock_server.server_port)
    missing_parent = tmp_path / "missing" / "evidence.json"
    gateway_server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(session, missing_parent))
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()
    body = canonical_bytes({
        "model": MODEL, "input": [{"role": "user", "content": "mock task"}],
        "tools": [], "store": False, "stream": True,
    })
    try:
        status, response = _post(gateway_server.server_port, "/v1/responses", body)
        assert status == 500
        assert response == b"request denied\n"
        assert session.closed
        assert session.failure_reason == "evidence write failed"
        assert session.generations == 1
        status, _ = _post(gateway_server.server_port, "/v1/responses", body)
        assert status == 403
        assert session.generations == 1
        assert not missing_parent.exists()
    finally:
        gateway_server.shutdown()
        gateway_server.server_close()
        mock_server.shutdown()
        mock_server.server_close()
        gateway_thread.join(timeout=5)
        mock_thread.join(timeout=5)
        assert not gateway_thread.is_alive()
        assert not mock_thread.is_alive()


@pytest.mark.parametrize("scenario", [
    "count-error", "redirect", "error", "model-mismatch", "usage-mismatch",
    "missing-usage", "disconnect",
])
def test_local_mock_provider_fault_closes_trial(tmp_path: Path, scenario: str) -> None:
    mock_handler = _mock_handler()
    mock_handler.scenario = scenario
    mock_server = ThreadingHTTPServer(("127.0.0.1", 0), mock_handler)
    mock_thread = threading.Thread(target=mock_server.serve_forever, daemon=True)
    mock_thread.start()
    session = _session(mock_server.server_port)
    evidence = tmp_path / "failure-evidence.json"
    gateway_server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(session, evidence))
    gateway_thread = threading.Thread(target=gateway_server.serve_forever, daemon=True)
    gateway_thread.start()
    try:
        body = canonical_bytes({
            "model": MODEL, "input": [{"role": "user", "content": "private prompt"}],
            "tools": [], "store": False, "stream": True,
        })
        status, _ = _post(gateway_server.server_port, "/v1/responses", body)
        assert status == 403
        assert session.closed
        assert json.loads(evidence.read_text())["trial_closed"] is True
        assert CANARY not in evidence.read_text()
    finally:
        gateway_server.shutdown()
        gateway_server.server_close()
        mock_server.shutdown()
        mock_server.server_close()
        gateway_thread.join(timeout=5)
        mock_thread.join(timeout=5)


@pytest.mark.parametrize("method,path,headers,expected", [
    ("GET", "/healthz", {}, 200),
    ("GET", "/v1/models", {}, 404),
    ("PUT", "/v1/responses", {}, 405),
    ("DELETE", "/v1/responses", {}, 405),
    ("POST", "/v1/models", {}, 404),
    ("POST", "/v1/responses", {"Host": "api.openai.com"}, 403),
    ("POST", "/v1/responses", {"Content-Type": "text/plain"}, 400),
    ("POST", "/v1/responses", {"Content-Encoding": "gzip"}, 400),
    ("POST", "/v1/responses", {"Content-Length": "0"}, 413),
    ("POST", "/v1/responses", {"Authorization": "Basic fake"}, 403),
])
def test_http_boundary_denies_unapproved_routes_and_headers(
    tmp_path: Path, method: str, path: str, headers: dict[str, str], expected: int
) -> None:
    session = _session(1)
    evidence = tmp_path / "denied-evidence.json"
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(session, evidence))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        supplied = {
            "Content-Type": "application/json", "Authorization": f"Bearer {CANARY}",
        }
        supplied.update(headers)
        connection.request(method, path, body=b"{}" if method == "POST" else None, headers=supplied)
        reply = connection.getresponse()
        assert reply.status == expected
        reply.read()
        assert session.generations == 0
        if path == "/v1/models":
            assert session.closed
        if session.closed:
            assert json.loads(evidence.read_text())["trial_closed"] is True
            assert CANARY not in evidence.read_text()
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize("host,port", [
    ("api.openai.com", 443), ("stage1-mock-provider", 443), ("127.0.0.1", 0),
])
def test_mock_transport_rejects_nonlocal_or_unapproved_ports(host: str, port: int) -> None:
    with pytest.raises(MeteringError):
        MockOnlyTransport(host, port)


def test_mock_transport_rejects_path_and_disconnect(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = MockOnlyTransport("127.0.0.1", 8443)
    with pytest.raises(MeteringError, match="upstream path is not approved"):
        transport.post("/v1/models", b"{}")

    class BrokenConnection:
        closed = False

        def request(self, *_args: object, **_kwargs: object) -> None:
            raise OSError("synthetic disconnect")

        def close(self) -> None:
            self.closed = True

    connection = BrokenConnection()
    monkeypatch.setattr(
        "agentguard.evaluation.stage1_metering_gateway.http.client.HTTPConnection",
        lambda *_args, **_kwargs: connection,
    )
    with pytest.raises(MeteringError, match="mock upstream disconnected"):
        transport.post("/v1/responses", b"{}")
    assert connection.closed


def test_mock_gateway_main_requires_explicit_local_only_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("STAGE1_MOCK_ONLY", raising=False)
    with pytest.raises(SystemExit, match="mock-only operation"):
        gateway_main()
    monkeypatch.setenv("STAGE1_MOCK_ONLY", "true")
    monkeypatch.setenv("STAGE1_MOCK_UPSTREAM", "api.openai.com")
    with pytest.raises(SystemExit, match="fixed local mock upstream"):
        gateway_main()


@pytest.mark.parametrize("payload", [
    b"{}", b'{"scope":{},"limits":{},"pricing":{}}',
    b'{"scope":[],"limits":{},"pricing":{}}',
])
def test_mock_gateway_rejects_malformed_config_before_listening(
    tmp_path: Path, payload: bytes
) -> None:
    config = tmp_path / "config.json"
    config.write_bytes(payload)
    with pytest.raises(MeteringError):
        mock_server_from_config(config, tmp_path / "evidence.json", lambda: CANARY, "127.0.0.1")
