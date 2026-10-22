"""Exact TLS-only upstream for the future Stage 1 metering gateway.

This module is not wired to a live study entrypoint. The only production
destination is the reviewed OpenAI API hostname on port 443.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
import time
from collections.abc import Callable

from agentguard.evaluation.stage1_metering import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    MeteringError,
    UpstreamReply,
)


_HOST = "api.openai.com"
_PORT = 443
_PATHS = frozenset({"/v1/responses/input_tokens", "/v1/responses"})
_PROXY_NAMES = frozenset({
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "ssl_cert_file", "ssl_cert_dir", "requests_ca_bundle", "curl_ca_bundle",
})
_MAX_RESPONSE_HEADERS = 16 * 1024
_MAX_RESPONSE_HEADER_COUNT = 32


def _check_proxy_environment() -> None:
    if any(name.lower() in _PROXY_NAMES for name in os.environ):
        raise MeteringError("proxy or alternate trust configuration is forbidden")


def _public_addresses(host: str, port: int) -> list[tuple[int, tuple]]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise MeteringError("provider DNS resolution failed") from None
    if not records or len(records) > 32:
        raise MeteringError("provider DNS answer is empty or excessive")
    addresses: list[tuple[int, tuple]] = []
    for family, kind, proto, _, address in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM:
            raise MeteringError("provider DNS answer has an unsupported address family")
        try:
            parsed = ipaddress.ip_address(address[0])
        except ValueError:
            raise MeteringError("provider DNS answer is malformed") from None
        if not parsed.is_global:
            raise MeteringError("provider DNS answer is not public")
        addresses.append((family, address))
    return addresses


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, context: ssl.SSLContext,
                 resolver: Callable[[str, int], list[tuple[int, tuple]]],
                 deadline: float) -> None:
        super().__init__(host, port, timeout=max(0.1, min(15, deadline - time.monotonic())),
                         context=context)
        self._resolver = resolver
        self._deadline = deadline

    def connect(self) -> None:
        addresses = self._resolver(self.host, self.port)
        if time.monotonic() >= self._deadline:
            raise MeteringError("provider request deadline exceeded")
        for family, address in addresses:
            raw = socket.socket(family, socket.SOCK_STREAM)
            raw.settimeout(max(0.1, min(15, self._deadline - time.monotonic())))
            try:
                raw.connect(address)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except OSError:
                raw.close()
        raise MeteringError("provider TLS connection failed") from None


class ExactTLSTransport:
    def __init__(self) -> None:
        _check_proxy_environment()
        self.host = _HOST
        self.port = _PORT
        self._resolver = _public_addresses
        self._context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        self._context.check_hostname = True
        self._context.verify_mode = ssl.CERT_REQUIRED
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2

    def post(self, path: str, body: bytes, credential: str,
             timeout_seconds: float = 60) -> UpstreamReply:
        if path not in _PATHS or not isinstance(body, bytes) or not 0 < len(body) <= MAX_REQUEST_BYTES:
            raise MeteringError("upstream method, path, or body is unapproved")
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 600:
            raise MeteringError("provider request timeout is invalid")
        if not isinstance(credential, str) or not credential or "\r" in credential or "\n" in credential:
            raise MeteringError("provider credential is unavailable")
        _check_proxy_environment()
        deadline = time.monotonic() + timeout_seconds
        connection = _PinnedHTTPSConnection(self.host, self.port, self._context,
                                            self._resolver, deadline)
        try:
            connection.request("POST", path, body=body, headers={
                "Host": self.host,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Authorization": "Bearer " + credential,
                "Connection": "close",
            })
            response = connection.getresponse()
            headers = response.getheaders()
            if len(headers) > _MAX_RESPONSE_HEADER_COUNT or sum(len(k) + len(v) for k, v in headers) > _MAX_RESPONSE_HEADERS:
                raise MeteringError("provider response headers exceed their bound")
            if response.status != 200 or response.getheader("Location") is not None:
                raise MeteringError("provider error or redirect is forbidden")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
                raise MeteringError("provider response size is invalid")
            content_type = response.getheader("Content-Type", "")
            if content_type.split(";", 1)[0].strip().lower() not in {
                "application/json", "text/event-stream",
            }:
                raise MeteringError("provider response type is invalid")
            chunks: list[bytes] = []
            total = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise MeteringError("provider request deadline exceeded")
                if connection.sock is not None:
                    connection.sock.settimeout(max(0.1, min(15, remaining)))
                part = response.read1(min(16 * 1024, MAX_RESPONSE_BYTES + 1 - total))
                if not part:
                    break
                total += len(part)
                if total > MAX_RESPONSE_BYTES:
                    raise MeteringError("provider response exceeds its byte bound")
                chunks.append(part)
            payload = b"".join(chunks)
            if not payload:
                raise MeteringError("provider response is missing or excessive")
            return UpstreamReply(response.status, content_type, payload)
        except (OSError, ssl.SSLError, http.client.HTTPException):
            raise MeteringError("provider TLS transport failed") from None
        finally:
            connection.close()


class LocalTestTLSTransport(ExactTLSTransport):
    """Only for loopback mock-provider tests; never an authorization capability."""

    def __init__(self, ca_file: str, port: int, hostname: str = "stage1-mock-provider",
                 docker_alias: bool = False) -> None:
        if hostname != "stage1-mock-provider" or type(port) is not int or not 0 < port <= 65535:
            raise MeteringError("test TLS destination is invalid")
        self.host = hostname
        self.port = port
        if docker_alias:
            self._resolver = lambda _host, current: [
                (family, address) for family, kind, _, _, address in
                socket.getaddrinfo("stage1-mock-provider", current, type=socket.SOCK_STREAM)
                if family in (socket.AF_INET, socket.AF_INET6) and kind == socket.SOCK_STREAM
            ]
        else:
            self._resolver = lambda _host, current: [(socket.AF_INET, ("127.0.0.1", current))]
        self._context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_file)
        self._context.check_hostname = True
        self._context.verify_mode = ssl.CERT_REQUIRED
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
