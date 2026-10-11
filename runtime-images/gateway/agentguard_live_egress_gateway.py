#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import selectors
import socket
import ssl
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

MAX_EVENTS = 256
MAX_BYTES = 1024 * 1024
BUFFER = 65536
BLOCKED_NETWORKS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    gateway = Gateway(Path(args.policy), Path(args.evidence))
    return gateway.serve(args.host, args.port)


class Gateway:
    def __init__(self, policy_path: Path, evidence_path: Path) -> None:
        self.policy = json.loads(policy_path.read_text(encoding="utf-8"))
        self.evidence_path = evidence_path
        self.events: list[dict[str, Any]] = []

    def serve(self, host: str, port: int) -> int:
        status = {"status": "running", "evidence_complete": True}
        try:
            with socket.create_server((host, port), family=socket.AF_INET) as server:
                server.settimeout(0.5)
                while len(self.events) < MAX_EVENTS:
                    try:
                        client, _ = server.accept()
                    except socket.timeout:
                        continue
                    with client:
                        self._handle_client(client)
        except KeyboardInterrupt:
            status = {"status": "shutdown", "evidence_complete": True}
        except Exception as error:
            status = {
                "status": "failed",
                "evidence_complete": False,
                "reason": sanitize(str(error)),
            }
            self._write(status)
            return 1
        self._write(status)
        return 0

    def _handle_client(self, client: socket.socket) -> None:
        start = time.time()
        request = client.recv(BUFFER)
        if not request:
            return
        first = request.splitlines()[0].decode("ascii", "replace")
        parts = first.split()
        method = parts[0].upper() if parts else ""
        target = parts[1] if len(parts) > 1 else ""
        host, port, protocol = destination_from_request(method, target, request)
        event = self._authorize(host, port, protocol, start)
        if event["decision"] != "allow":
            client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            self.events.append(event)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
            if protocol == "https":
                context = ssl.create_default_context()
                upstream = context.wrap_socket(upstream, server_hostname=host)
            with upstream:
                if method == "CONNECT":
                    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    bridge(client, upstream)
                else:
                    upstream.sendall(request)
                    bridge(client, upstream)
            event["timestamps"]["end"] = round(time.time(), 6)
        except Exception as error:
            event["decision"] = "deny"
            event["reason"] = sanitize(str(error))
            event["evidence_complete"] = True
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        self.events.append(event)

    def _authorize(self, host: str, port: int, protocol: str, start: float) -> dict[str, Any]:
        resolved = resolve(host)
        decision = "deny"
        reason = "destination_not_approved"
        if protocol not in {"http", "https", "connect"}:
            reason = "protocol_not_approved"
        elif is_unsafe_host(host, resolved):
            reason = "unsafe_destination"
        elif approved(self.policy, host, port):
            decision = "allow"
            reason = "approved_destination"
        return {
            "event_type": "connect" if protocol == "connect" else "request",
            "protocol": protocol,
            "requested": {"host": sanitize(host), "port": port},
            "effective": {"host": sanitize(host), "port": port},
            "resolved_addresses": resolved[:8],
            "resolution_status": "stable" if len(set(resolved)) == 1 else "ambiguous",
            "decision": decision,
            "reason": reason,
            "bytes": {"in": None, "out": None},
            "timestamps": {"start": round(start, 6), "end": None},
            "evidence_complete": True,
            "evidence_truncated": False,
        }

    def _write(self, status: dict[str, Any]) -> None:
        payload = {
            "gateway_status": status,
            "events": self.events[:MAX_EVENTS],
        }
        text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        if len(text.encode("utf-8")) > MAX_BYTES:
            payload = {
                "gateway_status": {
                    "status": "failed",
                    "evidence_complete": False,
                    "reason": "gateway evidence exceeded bound",
                },
                "events": [],
            }
            text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        self.evidence_path.write_text(text + "\n", encoding="utf-8")


def destination_from_request(method: str, target: str, request: bytes) -> tuple[str, int, str]:
    if method == "CONNECT":
        host, _, raw_port = target.partition(":")
        return host.lower(), int(raw_port or "443"), "connect"
    parsed = urlsplit(target)
    if parsed.hostname:
        return parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80), parsed.scheme
    for line in request.splitlines():
        if line.lower().startswith(b"host:"):
            value = line.split(b":", 1)[1].strip().decode("ascii", "replace")
            host, _, raw_port = value.partition(":")
            return host.lower(), int(raw_port or "80"), "http"
    return "", 0, "unknown"


def approved(policy: dict[str, Any], host: str, port: int) -> bool:
    return any(
        item.get("host") == host and item.get("port") == port
        for item in policy.get("destinations", [])
        if isinstance(item, dict)
    )


def resolve(host: str) -> list[str]:
    try:
        return sorted(
            {
                item[4][0]
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
        )
    except socket.gaierror:
        return []


def is_unsafe_host(host: str, addresses: list[str]) -> bool:
    import ipaddress

    if host in {"localhost", "host.docker.internal", "metadata.google.internal"}:
        return True
    networks = [ipaddress.ip_network(item) for item in BLOCKED_NETWORKS]
    values = list(addresses)
    try:
        values.append(str(ipaddress.ip_address(host)))
    except ValueError:
        pass
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return True
        if any(address in network for network in networks):
            return True
    return False


def bridge(left: socket.socket, right: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    left.setblocking(False)
    right.setblocking(False)
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)
    deadline = time.time() + 60
    while time.time() < deadline:
        for key, _ in selector.select(timeout=0.5):
            source = key.fileobj
            target = key.data
            data = source.recv(BUFFER)
            if not data:
                return
            target.sendall(data)


def sanitize(value: str) -> str:
    return value.split("?", 1)[0].replace("\n", " ")[:256]


if __name__ == "__main__":
    raise SystemExit(main())
