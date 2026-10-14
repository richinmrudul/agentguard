"""Mock-only HTTP host for the Stage 1 metering contract.

Phase A deliberately has no production transport or provider credential resolver.
Only a fixed repository-controlled mock host is accepted as an upstream.
"""

from __future__ import annotations

import http.client
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from agentguard.evaluation.stage1_metering import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    MeteringError,
    MeteringLimits,
    MeteringScope,
    MeteringSession,
    PricingPolicy,
    ResponsesTransport,
    StudyBudget,
    UpstreamReply,
    canonical_bytes,
    parse_json,
)


MOCK_HOSTS = frozenset({"127.0.0.1", "stage1-mock-provider"})
MOCK_PORT = 8443


class MockOnlyTransport(ResponsesTransport):
    def __init__(self, host: str, port: int = MOCK_PORT) -> None:
        if host not in MOCK_HOSTS:
            raise MeteringError("Phase A upstream must be the local mock provider")
        if type(port) is not int or not 0 < port <= 65535:
            raise MeteringError("mock provider port is invalid")
        if host != "127.0.0.1" and port != MOCK_PORT:
            raise MeteringError("Docker mock provider port is fixed")
        self.host = host
        self.port = port

    def post(self, path: str, body: bytes) -> UpstreamReply:
        if path not in {"/v1/responses/input_tokens", "/v1/responses"}:
            raise MeteringError("upstream path is not approved")
        connection = http.client.HTTPConnection(self.host, self.port, timeout=10)
        try:
            connection.request(
                "POST", path, body=body,
                headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
            )
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            return UpstreamReply(
                response.status,
                response.getheader("Content-Type", ""),
                payload,
                response.getheader("Location"),
            )
        except (OSError, http.client.HTTPException) as error:
            raise MeteringError("mock upstream disconnected") from error
        finally:
            connection.close()


def handler_for(session: MeteringSession, evidence_path: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Stage1Metering/1"
        sys_version = ""

        def do_GET(self) -> None:
            if self.path != "/healthz":
                self._deny(404)
                return
            self._send(200, "text/plain", b"ok\n")

        def do_POST(self) -> None:
            if self.path != "/v1/responses":
                session.closed = True
                self._deny(404)
                return
            host = self.headers.get("Host", "")
            if host not in {"stage1-metering-gateway:8080", f"127.0.0.1:{self.server.server_port}"}:
                session.closed = True
                session.failure_reason = "unapproved host"
                self._deny(403)
                return
            if (
                self.headers.get("Transfer-Encoding")
                or self.headers.get("Content-Encoding")
                or len(self.headers.get_all("Content-Length", [])) != 1
                or self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                session.closed = True
                self._deny(400)
                return
            length = self.headers.get("Content-Length", "")
            if not length.isdecimal() or not 0 < int(length) <= MAX_REQUEST_BYTES:
                session.closed = True
                self._deny(413)
                return
            header = self.headers.get("Authorization", "")
            if not header.startswith("Bearer ") or len(header) > 256:
                session.closed = True
                session.failure_reason = "missing synthetic authorization"
                self._deny(403)
                return
            try:
                reply = session.generate(self.rfile.read(int(length)), header[7:], self.path)
            except MeteringError as error:
                reason = str(error)
                session.failure_reason = reason if re.fullmatch(r"[A-Za-z0-9 -]{1,100}", reason) else "metering rejected"
                _write_evidence(evidence_path, session)
                self._deny(403)
                return
            _write_evidence(evidence_path, session)
            self._send(200, reply.content_type, reply.body)

        def do_PUT(self) -> None:
            session.closed = True
            self._deny(405)

        def do_DELETE(self) -> None:
            session.closed = True
            self._deny(405)

        def _deny(self, code: int) -> None:
            if session.closed:
                _write_evidence(evidence_path, session)
            self._send(code, "text/plain", b"request denied\n")

        def _send(self, code: int, content_type: str, body: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                session.closed = True
                _write_evidence(evidence_path, session)

        def log_message(self, *_args: object) -> None:
            return

    return Handler


def _write_evidence(path: Path, session: MeteringSession) -> None:
    path.write_bytes(canonical_bytes({
        "schema": "agentguard.stage1-metering-evidence",
        "schema_version": 1,
        "events": session.evidence,
        "trial_closed": session.closed,
        "failure_reason": session.failure_reason,
    }))


def mock_server_from_config(
    config_path: Path,
    evidence_path: Path,
    synthetic_token_reader: Callable[[], str],
    upstream_host: str,
) -> ThreadingHTTPServer:
    config = parse_json(config_path.read_bytes())
    if set(config) != {"scope", "limits", "pricing"}:
        raise MeteringError("metering configuration has unexpected fields")
    for name in ("scope", "limits", "pricing"):
        if not isinstance(config[name], dict):
            raise MeteringError(f"{name} must be an object")
    try:
        pricing = PricingPolicy(**config["pricing"])
        limits = MeteringLimits(**config["limits"])
        scope = MeteringScope(**config["scope"])
    except TypeError as error:
        raise MeteringError("metering configuration schema is invalid") from error
    session = MeteringSession(
        scope, limits, pricing, StudyBudget(limits.max_study_cost_usd),
        synthetic_token_reader(), MockOnlyTransport(upstream_host),
    )
    return ThreadingHTTPServer(("0.0.0.0", 8080), handler_for(session, evidence_path))


def main() -> None:
    if os.environ.get("STAGE1_MOCK_ONLY") != "true":
        raise SystemExit("Phase A gateway supports mock-only operation")
    upstream = os.environ.get("STAGE1_MOCK_UPSTREAM", "")
    if upstream not in MOCK_HOSTS:
        raise SystemExit("Phase A gateway requires the fixed local mock upstream")
    config = Path("/stage1-config/config.json")
    evidence = Path("/stage1-metering/evidence.json")
    if evidence.exists():
        raise SystemExit("stale metering evidence is forbidden")
    server = mock_server_from_config(
        config, evidence, lambda: os.environ["STAGE1_SYNTHETIC_TOKEN"], upstream
    )
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
