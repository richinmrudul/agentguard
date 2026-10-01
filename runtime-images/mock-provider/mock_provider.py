#!/usr/bin/env python3
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        if b"AGENTGUARD_FAKE_CREDENTIAL_CANARY" in body:
            self.send_response(400)
            self.end_headers()
            return
        payload = {
            "id": "mock-response-310",
            "object": "response",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "mock ok"}]}],
            "usage": {
                "input_tokens": 7,
                "output_tokens": 3,
                "reasoning_tokens": 0,
                "total_tokens": 10,
            },
        }
        text = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(text)))
        self.end_headers()
        self.wfile.write(text)

    def log_message(self, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8443), Handler).serve_forever()
