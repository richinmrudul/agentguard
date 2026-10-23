"""Repository-controlled Responses fixture; never forwards traffic."""

from __future__ import annotations

import json
import os
import ssl
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MODEL = os.environ.get("STAGE1_MOCK_MODEL", "stage1-mock-2026-10-14")
CANARY = "AGENTGUARD_FAKE_CREDENTIAL_CANARY"
MAX_BODY = 256 * 1024
SAFE_FIELDS = {
    "model", "instructions", "input", "tools", "tool_choice", "parallel_tool_calls",
    "reasoning", "store", "stream", "stream_options", "include", "service_tier",
    "prompt_cache_key", "text", "max_output_tokens", "previous_response_id",
    "prompt_cache_retention",
}
SAFE_TOOL_NAMES = {
    "exec_command", "write_stdin", "apply_patch",
}
REVIEWED_TOOL_DECLARATIONS = [
    {"index": 0, "type": "function", "name": "exec_command", "sha256": "7ecb0f4f51b3982e36be43a9d08daa05348d7dd5f70646231b1f0f9823f40ec3"},
    {"index": 1, "type": "function", "name": "write_stdin", "sha256": "9c3adbaa65e36ce23c7f1a8778e094a14b2086c993fc783727156276831c99dd"},
    {"index": 2, "type": "custom", "name": "apply_patch", "sha256": "5947b870d79e16bddc34946a4afb6200ff14a97f8419a2d23f8e5040af9a7154"},
]


def _choice(value: object, allowed: set[object]) -> object:
    return value if isinstance(value, (str, bool, type(None))) and value in allowed else "unexpected"


def _tool_shape(tools: object) -> tuple[list[object], list[object]]:
    if not isinstance(tools, list) or len(tools) > 32:
        return ["unexpected"], ["unexpected"]
    types: list[object] = []
    names: list[object] = []
    for tool in tools:
        if not isinstance(tool, dict):
            return ["unexpected"], ["unexpected"]
        if tool.get("type") == "namespace":
            members = tool.get("tools")
            if not isinstance(members, list) or len(members) > 32:
                return ["unexpected"], ["unexpected"]
            for member in members:
                if not isinstance(member, dict):
                    return ["unexpected"], ["unexpected"]
                types.append(_choice(member.get("type"), {"function", "custom"}))
                names.append(_choice(member.get("name"), SAFE_TOOL_NAMES))
        else:
            types.append(_choice(tool.get("type"), {"function", "custom"}))
            names.append(_choice(tool.get("name"), SAFE_TOOL_NAMES))
        if len(types) > 32:
            return ["unexpected"], ["unexpected"]
    return types, names


def _tool_diagnostic(tools: object) -> list[dict[str, object]]:
    if not isinstance(tools, list) or len(tools) > 32:
        return []
    result = []
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            return []
        tool_type = tool.get("type")
        name = tool.get("name")
        if not isinstance(tool_type, str) or len(tool_type) > 64 or not tool_type.isidentifier():
            return []
        if name is not None and (
            not isinstance(name, str) or len(name) > 64 or not name.isidentifier()
            or CANARY in name
        ):
            return []
        canonical = json.dumps(tool, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        record: dict[str, object] = {
            "index": index, "type": tool_type, "sha256": sha256(canonical).hexdigest(),
        }
        if name is not None:
            record["name"] = name
        result.append(record)
    return result


def _reviewed_tool_contract(tools: object) -> bool:
    return _tool_diagnostic(tools) == REVIEWED_TOOL_DECLARATIONS


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    scenario = "success"
    count_requests = 0
    generations = 0
    request_shapes: list[dict[str, object]] = []

    def do_GET(self) -> None:
        if self.path != "/inspection":
            self._send(404, "text/plain", b"not found\n")
            return
        self._send(200, "application/json", _json({"requests": type(self).request_shapes}))

    def do_POST(self) -> None:
        length = self.headers.get("Content-Length", "")
        if not length.isdecimal() or not 0 < int(length) <= MAX_BODY:
            self._send(413, "text/plain", b"invalid request\n")
            return
        raw = self.rfile.read(int(length))
        expected = os.environ.get("STAGE1_MOCK_TLS_FAKE_TOKEN")
        authorization = self.headers.get("Authorization")
        if CANARY.encode() in raw or (
            authorization != f"Bearer {expected}" if expected else bool(authorization)
        ):
            self._send(400, "text/plain", b"credential leaked to mock provider\n")
            return
        try:
            payload = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            self._send(400, "text/plain", b"invalid JSON\n")
            return
        tool_types, tool_names = _tool_shape(payload.get("tools"))
        reasoning = payload.get("reasoning")
        safe_reasoning = reasoning if isinstance(reasoning, dict) else {}
        text = payload.get("text")
        safe_text = text if isinstance(text, dict) else {}
        type(self).request_shapes.append({
            "path": _choice(self.path, {"/v1/responses/input_tokens", "/v1/responses"}),
            "model": payload.get("model") if payload.get("model") == MODEL else "unexpected",
            "keys": sorted(key if key in SAFE_FIELDS else "unexpected" for key in payload)[:64],
            "stream": payload.get("stream") is True,
            "reasoning_effort": _choice(safe_reasoning.get("effort"),
                                         {None, "none", "low", "medium", "high", "xhigh"}),
            "reasoning_summary": _choice(safe_reasoning.get("summary"),
                                          {None, "none", "auto", "concise", "detailed"}),
            "verbosity": _choice(safe_text.get("verbosity"),
                                 {None, "low", "medium", "high"}),
            "parallel_tool_calls": _choice(payload.get("parallel_tool_calls"),
                                           {None, True, False}),
            "prompt_cache_retention": _choice(payload.get("prompt_cache_retention"),
                                               {None, "in_memory"}),
            "store": _choice(payload.get("store"), {None, True, False}),
            "tool_types": tool_types,
            "tool_names": tool_names,
            "tool_declarations": _tool_diagnostic(payload.get("tools")),
            "reviewed_tool_contract": _reviewed_tool_contract(payload.get("tools")),
        })
        type(self).request_shapes = type(self).request_shapes[-16:]
        if payload.get("model") != MODEL:
            self._send(400, "text/plain", b"wrong model\n")
            return
        if self.path == "/v1/responses/input_tokens":
            type(self).count_requests += 1
            if self.scenario == "count-error":
                self._send(500, "text/plain", b"count failed\n")
            else:
                self._send(200, "application/json", _json({
                    "object": "response.input_tokens", "input_tokens": 7,
                }))
            return
        if self.path != "/v1/responses":
            self._send(404, "text/plain", b"not found\n")
            return
        type(self).generations += 1
        if self.scenario == "redirect":
            self.send_response(302)
            self.send_header("Location", "https://unapproved.example/v1/responses")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.scenario == "error":
            self._send(503, "text/plain", b"provider unavailable\n")
            return
        response = {
            "id": f"resp_stage1_mock_{self.generations}",
            "object": "response",
            "model": MODEL if self.scenario != "model-mismatch" else "wrong-model",
            "status": "completed",
            "output": [{
                "id": "msg_stage1_mock",
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "mock complete", "annotations": []}],
            }],
            "usage": {
                "input_tokens": 8 if self.scenario == "usage-mismatch" else 7,
                "output_tokens": 3,
                "total_tokens": 10,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        }
        if expected:
            response["service_tier"] = "default"
            response["usage"]["input_tokens_details"]["cache_write_tokens"] = 0
        if self.scenario == "missing-usage":
            response.pop("usage")
        if payload.get("stream") is True:
            message = response["output"][0]
            frames = [
                {"type": "response.created", "sequence_number": 0, "response": {
                    "id": response["id"], "model": response["model"], "status": "in_progress",
                }},
                {"type": "response.output_item.added", "sequence_number": 1,
                 "output_index": 0, "item": {
                     "id": message["id"], "type": "message", "status": "in_progress",
                     "role": "assistant", "content": [],
                 }},
                {"type": "response.output_text.delta", "sequence_number": 2,
                 "item_id": "msg_stage1_mock", "output_index": 0, "content_index": 0,
                 "delta": "mock complete"},
                {"type": "response.output_item.done", "sequence_number": 3,
                 "output_index": 0, "item": message},
                {"type": "response.completed", "sequence_number": 4, "response": response},
            ]
            body = b"".join(b"data: " + _json(frame).rstrip(b"\n") + b"\n\n" for frame in frames)
            if self.scenario == "disconnect":
                body = body[:-1]
            self._send(200, "text/event-stream", body)
        else:
            self._send(200, "application/json", _json(response))

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def main() -> None:
    if MODEL not in {"stage1-mock-2026-10-14", "gpt-5.2-2025-12-11"}:
        raise SystemExit("unknown mock model")
    scenario = os.environ.get("STAGE1_MOCK_SCENARIO", "success")
    if scenario not in {
        "success", "count-error", "redirect", "error", "model-mismatch",
        "usage-mismatch", "missing-usage", "disconnect",
    }:
        raise SystemExit("unknown mock scenario")
    MockHandler.scenario = scenario
    server = ThreadingHTTPServer(("0.0.0.0", 8443), MockHandler)
    if os.environ.get("STAGE1_MOCK_TLS") == "true":
        certificate = os.environ.get("STAGE1_MOCK_CERT", "")
        private_key = os.environ.get("STAGE1_MOCK_KEY", "")
        if not certificate or not private_key or not os.environ.get("STAGE1_MOCK_TLS_FAKE_TOKEN"):
            raise SystemExit("mock TLS fixtures are missing")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
