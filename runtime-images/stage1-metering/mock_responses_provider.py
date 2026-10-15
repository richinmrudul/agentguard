"""Repository-controlled Responses fixture; never forwards traffic."""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


MODEL = "stage1-mock-2026-10-14"
CANARY = "AGENTGUARD_FAKE_CREDENTIAL_CANARY"
MAX_BODY = 256 * 1024


class MockHandler(BaseHTTPRequestHandler):
    scenario = "success"
    count_requests = 0
    generations = 0

    def do_POST(self) -> None:
        length = self.headers.get("Content-Length", "")
        if not length.isdecimal() or not 0 < int(length) <= MAX_BODY:
            self._send(413, "text/plain", b"invalid request\n")
            return
        raw = self.rfile.read(int(length))
        if CANARY.encode() in raw or self.headers.get("Authorization"):
            self._send(400, "text/plain", b"credential leaked to mock provider\n")
            return
        try:
            payload = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError):
            self._send(400, "text/plain", b"invalid JSON\n")
            return
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
    scenario = os.environ.get("STAGE1_MOCK_SCENARIO", "success")
    if scenario not in {
        "success", "count-error", "redirect", "error", "model-mismatch",
        "usage-mismatch", "missing-usage", "disconnect",
    }:
        raise SystemExit("unknown mock scenario")
    MockHandler.scenario = scenario
    ThreadingHTTPServer(("0.0.0.0", 8443), MockHandler).serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
